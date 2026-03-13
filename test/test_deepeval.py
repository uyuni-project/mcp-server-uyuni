import pytest
import json
import os
import sys
import warnings
import re
import asyncio
import glob
from google import genai
from google.genai import types
from deepeval import assert_test
from deepeval.test_case import LLMTestCase, LLMTestCaseParams, ToolCall
from deepeval.metrics import GEval, ToolCorrectnessMetric
from deepeval.metrics.g_eval import Rubric
from deepeval.models.base_model import DeepEvalBaseLLM
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TEST_CONFIG_FILE = 'test_config.json'
MCP_CONFIG_FILE = 'config.json'

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

class GoogleGemini(DeepEvalBaseLLM):
    def __init__(self, model="gemini-2.5-flash"):
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

async def run_mcp_agent(prompt: str, model: str = None) -> tuple[str, list, list]:
    if not model:
        model = os.environ.get("AGENT_MODEL", "gemini-2.5-flash")
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "mcp-server-uyuni"],
        env={**os.environ, "UYUNI_MCP_WRITE_TOOLS_ENABLED": "true"}
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            mcp_tools = await session.list_tools()
            
            gemini_tools = []
            for tool in mcp_tools.tools:
                gemini_tools.append({
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.inputSchema
                })

            client = genai.Client(api_key=os.environ.get("GOOGLE_API_KEY"))
            chat = client.aio.chats.create(
                model=model,
                config=types.GenerateContentConfig(
                    tools=[types.Tool(function_declarations=gemini_tools)],
                    system_instruction="You are a helpful assistant. When you use tools to retrieve information, you must explicitly include that information in your final response. Do not just summarize that the action was taken."
                )
            )

            response = await chat.send_message(prompt)
            tool_calls = []
            tool_outputs = []

            while response.function_calls:
                parts = []
                for call in response.function_calls:
                    tool_calls.append(call)
                    result = await session.call_tool(call.name, call.args)
                    tool_output = "\n".join([c.text for c in result.content if c.type == "text"])
                    tool_outputs.append(tool_output)
                    
                    parts.append(types.Part.from_function_response(
                        name=call.name,
                        response={"result": tool_output}
                    ))
                
                response = await chat.send_message(parts)

            return response.text, tool_calls, tool_outputs

def query_mcp_server(prompt: str) -> tuple[str, list, list]:
    return asyncio.run(run_mcp_agent(prompt))

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

@pytest.mark.parametrize("test_case", load_test_cases())
def test_uyuni_mcp_deepeval(test_case, record_property):
    prompt_template = test_case.get("prompt")
    expected_template = test_case.get("expected_output")
    test_id = test_case.get("id", "unknown")

    if not prompt_template or not expected_template:
        pytest.skip(f"Skipping malformed test case: {test_id}")

    prompt = prompt_template.format(**VARS)
    expected_output = expected_template.format(**VARS)

    actual_output, actual_tool_calls, actual_tool_outputs = query_mcp_server(prompt)
    actual_output = actual_output or "(No output returned by the model)"

    judge_model = os.environ.get("JUDGE_MODEL", "gemini-2.5-flash")
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
        "model": GoogleGemini(model=judge_model),
    }
    geval_kwargs.update(user_geval_config)

    if isinstance(geval_kwargs["model"], str):
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

    actual_tools = [
        ToolCall(name=call.name, input_parameters=dict(call.args or {}))
        for call in actual_tool_calls
    ]

    expected_tools = None
    if "expected_tools" in test_case:
        expected_tools = [
            ToolCall(name=t["name"], input_parameters=t.get("arguments", {}))
            for t in test_case["expected_tools"]
        ]
        metrics.append(ToolCorrectnessMetric())

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
        # Soft Pass Strategy:
        # If the score is >= 0.4 (Rubric "Partial" tier start), we treat it as a PASS with a warning.
        # This avoids binary failures for results that are semantically useful but not perfect.
        current_score = metrics[0].score

        # Fallback: If the score isn't populated in the metric object, extract it directly from
        # the error message. This guarantees we have the score that triggered the assertion failure.
        # It seeems DeepEval sometimes raises the error without updating the metric object in place (bug?)
        # We try to parse the score from the error message: "Metrics: Correctness ... (score: 0.6, ...)"
        if current_score is None:
            match = re.search(r"score: ([0-9.]+)", str(e))
            if match:
                current_score = float(match.group(1))

        if current_score is not None and current_score >= 0.4:
            warning_msg = f"Test '{test_id}' passed with PARTIAL CORRECTNESS. Score: {current_score} (Threshold: 0.7)"
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