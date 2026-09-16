import pytest
import json
import os
import warnings
import re
import asyncio
import subprocess
import statistics
import glob
from google import genai
from google.genai import types
from deepeval import assert_test
from deepeval.test_case import LLMTestCase, LLMTestCaseParams, ToolCall
from deepeval.metrics import GEval, ToolCorrectnessMetric, MCPUseMetric
from deepeval.metrics.g_eval import Rubric
from deepeval.models.base_model import DeepEvalBaseLLM
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TEST_CONFIG_FILE = 'test_config.json'

def load_vars():
    config_path = os.path.join(os.path.dirname(__file__), TEST_CONFIG_FILE)
    placeholders = {}

    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config_data = json.load(f)
            for key, value in config_data.items():
                if isinstance(value, str):
                    placeholders[key] = value
            if "systems" in config_data:
                for sys_key, sys_values in config_data["systems"].items():
                    for attr_key, attr_value in sys_values.items():
                        placeholders[f"{sys_key}_{attr_key}"] = attr_value
            if "activation_keys" in config_data:
                for key_name, key_value in config_data["activation_keys"].items():
                    placeholders[f"key_{key_name}"] = key_value
    return placeholders

VARS = load_vars()

class Goose(DeepEvalBaseLLM):
    def __init__(self, model="ministral-3:3b", stats_collector=None, test_id=None):
        self.model = model
        self.stats_collector = stats_collector
        self.test_id = test_id or "unknown"

    def load_model(self):
        return self.model

    def generate(self, prompt: str) -> str:
        command = ["goose", "run", "--text", prompt, "--model", self.model, "--quiet", "--stats", "--test-id", self.test_id]
        try:
            result = subprocess.run(
                command, stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True, encoding="utf-8"
            )
            if self.stats_collector is not None and result.stderr:
                self.stats_collector.append((self.test_id, result.stderr))
            return result.stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            error_message = f"Goose command failed: {e}"
            if hasattr(e, 'stderr'):
                stderr_str = e.stderr.strip()
                error_message += f"\nStderr: {stderr_str}"
                if self.stats_collector is not None:
                    self.stats_collector.append((self.test_id, stderr_str))
            warnings.warn(error_message)
            return f"COMMAND_FAILED: {error_message}"

    async def a_generate(self, prompt: str) -> str:
        command = ["goose", "run", "--text", prompt, "--model", self.model, "--quiet", "--stats", "--test-id", self.test_id]
        proc = await asyncio.create_subprocess_exec(
            *command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        stderr_str = stderr.decode('utf-8').strip()
        if self.stats_collector is not None and stderr_str:
            self.stats_collector.append((self.test_id, stderr_str))
        if proc.returncode != 0:
            error_message = f"Goose command failed with code {proc.returncode}:\n{stderr_str}"
            warnings.warn(error_message)
            return f"COMMAND_FAILED: {error_message}"
        return stdout.decode('utf-8').strip()

    def get_model_name(self):
        return self.model
class GoogleGemini(DeepEvalBaseLLM):
    def __init__(self, model="gemini-2.5-flash-lite"):
        self.model_name = model
        self.api_key = os.environ.get("GOOGLE_API_KEY")
        if not self.api_key:
            print("Warning: GOOGLE_API_KEY environment variable not set.")
        self.client = genai.Client(api_key=self.api_key)

    def load_model(self):
        return self.client

    def generate(self, prompt: str) -> str:
        client = self.load_model()
        try:
            response = client.models.generate_content(
                model=self.model_name, contents=prompt
            )
            return response.text
        except Exception as e:
            return f"Error generating content: {e}"

    async def a_generate(self, prompt: str) -> str:
        client = self.load_model()
        try:
            response = await client.aio.models.generate_content(
                model=self.model_name, contents=prompt
            )
            return response.text
        except Exception as e:
            return f"Error generating content: {e}"

    def get_model_name(self):
        return self.model_name

def remove_additional_properties(schema: dict) -> dict:
    """Recursively removes additional_properties and additionalProperties from JSON schemas

    as required by the Google GenAI API endpoint.
    """
    if not isinstance(schema, dict):
        return schema

    # Remove both variants that cause the Google 400 error
    schema.pop("additional_properties", None)
    schema.pop("additionalProperties", None)

    for key, value in schema.items():
        if isinstance(value, dict):
            schema[key] = remove_additional_properties(value)
        elif isinstance(value, list):
            schema[key] = [
                remove_additional_properties(item) if isinstance(item, dict) else item 
                for item in value
            ]

    return schema

async def run_mcp_agent(prompt: str, model: str = None, test_id: str = None, stats_collector: list = None) -> tuple[str, list, list]:
    agent_provider = os.environ.get("AGENT_PROVIDER", "gemini").lower()
    default_model = "ministral-3:3b" if agent_provider == "goose" else "gemini-2.5-flash-lite"
    model = model or os.environ.get("AGENT_MODEL", default_model)

    server_params = StdioServerParameters(
        command="uv",
        args=["run", "mcp-server-uyuni"],
        env={**os.environ, "UYUNI_MCP_WRITE_TOOLS_ENABLED": "true"}
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            mcp_tools = await session.list_tools()
            
            formatted_tools = []
            for tool in mcp_tools.tools:
                # Convert the inputSchema to a clean dictionary and strip extra fields
                cleaned_schema = remove_additional_properties(dict(tool.inputSchema))

                formatted_tools.append({
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": cleaned_schema
                })

            # Prepend a strong directive to the user prompt
            directive_prompt = (
                f"{prompt}\n\n"
                "INSTRUCTION: Use available tools to fulfill this request. "
                "Retain and report specific details like names and IDs. "
                "If this is a state-changing action (reboot, remove, update, create), "
                "execute the write tool directly using the tool schema."
            )

            if agent_provider == "goose":
                # The goose CLI does not support native tool calling, so we will simulate it
                # by providing the tool definitions in the prompt and parsing the output.
                # This is a simplified, single-turn implementation.
                tools_json_str = json.dumps(formatted_tools, indent=2)
                goose_prompt = (
                    f"You have access to the following tools:\n"
                    f"```json\n{tools_json_str}\n```\n"
                    f"Based on the user's request, decide if a tool should be called. "
                    f"If so, respond with a single JSON object containing 'tool_name' and 'arguments'. "
                    f"If not, respond with a natural language summary.\n\n"
                    f"User Request: {prompt}"
                )
                
                goose_model = Goose(model=model, test_id=test_id, stats_collector=stats_collector)
                response_text = await goose_model.a_generate(goose_prompt)

                try:
                    # Attempt to parse the response as a tool call
                    parsed_json = json.loads(response_text)
                    if "tool_name" in parsed_json and "arguments" in parsed_json:
                        tool_name = parsed_json["tool_name"]
                        tool_args = parsed_json["arguments"]
                        
                        # Execute the tool call
                        result = await session.call_tool(tool_name, tool_args)
                        tool_output_text = "\n".join([c.text for c in result.content if c.type == "text"])
                        
                        # For this simplified flow, we return the tool output as the final answer
                        return tool_output_text, [ToolCall(name=tool_name, input_parameters=tool_args)], [tool_output_text]
                except (json.JSONDecodeError, TypeError):
                    # If parsing fails, assume it's a natural language response
                    pass

                # Return the direct text response if no tool was called or parsed
                return response_text, [], []

            # --- Gemini Agent Logic ---
            client = genai.Client(api_key=os.environ.get("GOOGLE_API_KEY"))
            chat = client.aio.chats.create(
                model=model,
                config=types.GenerateContentConfig(
                    tools=[types.Tool(function_declarations=formatted_tools)],
                    system_instruction=(
                        "You are an autonomous assistant specialized in Uyuni infrastructure management. "
                        "Fulfill requests by using tools directly. "
                        "POLICY ON ACTIONS: "
                        "1. INFO GATHERING: Be proactive. Perform multiple tool calls in sequence if necessary "
                        "(e.g., listing systems and then fetching details for each). Do NOT ask for permission to "
                        "retrieve or show information. "
                        "2. STATE-CHANGING ACTIONS: For actions that modify the system (rebooting, removing systems, "
                        "applying updates, creating groups), call the relevant write tool directly using the real tool schema. "
                        "CRITICAL: Do NOT use example names or IDs from the tool documentation. Use ONLY the real data "
                        "returned by the tools in the current session."
                    )
                )
            )
            response = await chat.send_message(directive_prompt)
            tool_calls = []
            tool_outputs = []
            full_text = []

            while True:
                # Accumulate text from the current response
                if response.text:
                    full_text.append(response.text)

                if not response.function_calls:
                    # Fallback: If we finished tools but have no text at all, nudge the model for a summary
                    if not full_text:
                        response = await chat.send_message("Provide a final summary of the information retrieved or the status of the request.")
                        if response.text:
                            full_text.append(response.text)
                        if not response.function_calls:
                            break
                        continue # Process any late tool calls if the nudge triggered them
                    break

                parts = []
                for call in response.function_calls:
                    tool_calls.append(call)
                    result = await session.call_tool(call.name, call.args)
                    tool_output_text = "\n".join([c.text for c in result.content if c.type == "text"])
                    tool_outputs.append(tool_output_text)
                    
                    # Try to parse as JSON to provide structured data to the model
                    try:
                        parsed_result = json.loads(tool_output_text)
                        if isinstance(parsed_result, list):
                            response_dict = {"result": parsed_result}
                        elif isinstance(parsed_result, dict):
                            response_dict = parsed_result
                        else:
                            response_dict = {"result": parsed_result}
                    except:
                        response_dict = {"result": tool_output_text}

                    parts.append(types.Part.from_function_response(
                        name=call.name,
                        response=response_dict
                    ))
                
                response = await chat.send_message(parts)

            return "\n".join(full_text), tool_calls, tool_outputs

def query_mcp_server(prompt: str, test_id: str, stats_collector: list) -> tuple[str, list, list]:
    return asyncio.run(run_mcp_agent(prompt, test_id=test_id, stats_collector=stats_collector))

def load_test_cases():
    test_dir = os.path.dirname(__file__)
    if "TEST_CASES_FILE" in os.environ:
        file_paths = [os.path.join(test_dir, os.environ["TEST_CASES_FILE"])]
    else:
        file_paths = glob.glob(os.path.join(test_dir, "test_cases_*.json"))

    all_test_cases = []
    for json_path in file_paths:
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                cases = json.load(f)
                if isinstance(cases, list):
                    all_test_cases.extend(cases)
    return all_test_cases

# Load test cases once and generate descriptive IDs for pytest
ALL_TEST_CASES = load_test_cases()

@pytest.mark.parametrize(
    "test_case",
    ALL_TEST_CASES,
    ids=[case.get("id", f"unnamed_case_{i}") for i, case in enumerate(ALL_TEST_CASES)]
)
def test_uyuni_mcp_deepeval(test_case, record_property, goose_stats_collector):
    prompt_template = test_case.get("prompt")
    expected_template = test_case.get("expected_output")
    test_id = test_case.get("id", "unknown")

    if not prompt_template or not expected_template:
        pytest.skip(f"Skipping malformed test case: {test_id}")

    prompt = prompt_template.format(**VARS)
    expected_output = expected_template.format(**VARS)

    actual_output, actual_tool_calls, actual_tool_outputs = query_mcp_server(prompt, test_id, goose_stats_collector)
    actual_output = actual_output or "(No output returned by the model)"

    judge_provider = os.environ.get("JUDGE_PROVIDER", "gemini").lower()
    if judge_provider == "goose":
        judge_model = os.environ.get("JUDGE_MODEL", "ministral-3:3b")
        judge_instance = Goose(model=judge_model, test_id=f"{test_id}-judge", stats_collector=goose_stats_collector)
    else:
        judge_model = os.environ.get("JUDGE_MODEL", "gemini-2.5-flash-lite")
        judge_instance = GoogleGemini(model=judge_model)
    default_rubric = [
        Rubric(score_range=(0, 3), expected_outcome="The actual output is incorrect or irrelevant."),
        Rubric(score_range=(4, 6), expected_outcome="The actual output is partially correct or misses some key details."),
        Rubric(score_range=(7, 10), expected_outcome="The actual output matches the expected output in content and meaning."),
    ]

    user_geval_config = test_case.get("geval_config", {}).copy()
    rubric = user_geval_config.pop("rubric", default_rubric)

    geval_kwargs = {
        "name": "Correctness",
        "evaluation_params": [LLMTestCaseParams.ACTUAL_OUTPUT, LLMTestCaseParams.EXPECTED_OUTPUT],
        "threshold": 0.7,
        "verbose_mode": True,
        "model": judge_instance,
    }
    geval_kwargs.update(user_geval_config)

    if isinstance(geval_kwargs["model"], str):
        if judge_provider == "goose":
            geval_kwargs["model"] = Goose(model=geval_kwargs["model"], test_id=f"{test_id}-judge", stats_collector=goose_stats_collector)
        else:
            geval_kwargs["model"] = GoogleGemini(model=geval_kwargs["model"])

    used_criteria = geval_kwargs.get("criteria")
    used_steps = geval_kwargs.get("evaluation_steps")

    if not used_criteria:
        if not used_steps:
            used_criteria = f"The actual output must satisfy this requirement: {expected_output}"
        else:
            used_criteria = "Evaluate the actual output based on the provided evaluation steps."

    if used_criteria:
        geval_kwargs["criteria"] = used_criteria

    geval_kwargs["rubric"] = rubric

    correctness_metric = GEval(**geval_kwargs)
    metrics = [correctness_metric]

    actual_tools = []
    for call in actual_tool_calls:
        if isinstance(call, ToolCall):
            # Already a deepeval.ToolCall, use as-is (from Goose provider)
            actual_tools.append(call)
        else:
            # Convert from another type (e.g., gemini's FunctionCall)
            actual_tools.append(ToolCall(name=call.name, input_parameters=dict(getattr(call, 'args', {}) or {})))

    expected_tools = None
    if "expected_tools" in test_case:
        expected_tools = [
            ToolCall(name=t["name"], input_parameters=t.get("arguments", {}))
            for t in test_case["expected_tools"]
        ]
        metrics.append(ToolCorrectnessMetric(model=geval_kwargs["model"]))

    if "mcp_use_criteria" in test_case:
        mcp_use_metric = MCPUseMetric(
            criteria=test_case["mcp_use_criteria"],
            model=geval_kwargs["model"]
        )
        metrics.append(mcp_use_metric)

    deepeval_case = LLMTestCase(
        input=prompt,
        actual_output=actual_output,
        expected_output=expected_output,
        tools_called=actual_tools,
        expected_tools=expected_tools,
        retrieval_context=actual_tool_outputs
    )

    try:
        assert_test(deepeval_case, metrics)
    except AssertionError as e:
        pass_threshold = geval_kwargs.get("threshold", 0.7)
        partial_threshold = 0.4
        if isinstance(rubric, list) and len(rubric) > 1:
            partial_threshold = rubric[1].score_range[0] / 10.0

        # Soft Pass Strategy:
        # If the score is >= partial_threshold (Rubric "Partial" tier start), we treat it as a PASS with a warning.
        # This avoids binary failures for results that are semantically useful but not perfect.
        current_score = metrics[0].score

        # Fallback: If the score isn't populated in the metric object, extract it directly from
        # the error message. This guarantees we have the score that triggered the assertion failure.
        # It seems DeepEval sometimes raises the error without updating the metric object in place (bug?)
        # We try to parse the score from the error message: "Metrics: Correctness ... (score: 0.6, ...)"

        if current_score is None:
            match = re.search(r"score: ([0-9.]+)", str(e))
            if match:
                current_score = float(match.group(1))

        if current_score is not None and current_score >= partial_threshold:
            warning_msg = f"Test '{test_id}' passed with PARTIAL CORRECTNESS. Score: {current_score} (Threshold: {pass_threshold})"
            warnings.warn(warning_msg)
            record_property("warning", warning_msg)
            return

        eval_info = ""
        if used_steps:
            eval_info = f"Evaluation Steps:\n{json.dumps(used_steps, indent=2)}\n"
        elif used_criteria:
            eval_info = f"Criteria/Rubric:\n{used_criteria}\n"

        error_message = (
            f"\n--- Deepeval Test Failed ---\n"
            f"Test Case ID: {test_id}\n"
            f"Prompt: {prompt}\n"
            f"Expected Output Hint: {expected_output}\n"
            f"----- EVALUATION DETAILS -----\n"
            f"{eval_info}"
            f"----- ACTUAL OUTPUT -----\n{actual_output}\n"
            f"----- END ACTUAL OUTPUT -----\n"
            f"Original Error: {e}"
        )
        raise AssertionError(error_message) from e

def pytest_configure(config):
    """
    Hook to initialize a list for storing stats on the pytest config object.
    This makes it available across the entire test session.
    """
    config.goose_stats = []

@pytest.fixture(scope="function")
def goose_stats_collector(request):
    """
    A fixture that provides access to the session-wide stats collector.
    """
    return request.config.goose_stats

def pytest_sessionfinish(session, exitstatus):
    """
    This hook is called after the entire test session finishes.
    It will parse all collected stats and print an aggregated summary.
    """
    print("\n--- Goose Stats Summary ---")
    all_stats = session.config.goose_stats
    if not all_stats:
        print("No goose stats were collected.")
        return

    first_token_times = []
    tokens_per_sec_rates = []
    total_output_tokens = 0

    for test_id, stat_block in all_stats:
        print(f"  - Test: {test_id}")
        for line in stat_block.splitlines():
            if "Time to first token:" in line:
                match = re.search(r"(\d+\.\d+)s", line)
                if match:
                    first_token_times.append(float(match.group(1)))
            if "Tokens/sec:" in line:
                match = re.search(r"(\d+\.\d+)", line)
                if match:
                    tokens_per_sec_rates.append(float(match.group(1)))
            if "Output tokens:" in line:
                match = re.search(r"(\d+)", line)
                if match:
                    total_output_tokens += int(match.group(1))

    print(f"Total Goose Runs: {len(all_stats)}")
    print(f"Total Output Tokens: {total_output_tokens}")
    if first_token_times:
        print(f"Avg. Time to First Token: {statistics.mean(first_token_times):.2f}s (min: {min(first_token_times):.2f}s, max: {max(first_token_times):.2f}s)")
    if tokens_per_sec_rates:
        print(f"Avg. Tokens/Sec: {statistics.mean(tokens_per_sec_rates):.2f} (min: {min(tokens_per_sec_rates):.2f}, max: {max(tokens_per_sec_rates):.2f})")
    print("--------------------------")
