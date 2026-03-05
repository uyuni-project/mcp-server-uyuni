import pytest
import json
import os
import sys
import asyncio
from google import genai
from google.genai import types
from deepeval import assert_test
from deepeval.test_case import LLMTestCase, LLMTestCaseParams, ToolCall
from deepeval.metrics import GEval, ToolCorrectnessMetric
from deepeval.models.base_model import DeepEvalBaseLLM
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TEST_CASES_FILE = 'test_cases_sys.json'
TEST_CONFIG_FILE = 'test_config.json'
MCP_CONFIG_FILE = 'config.json'

def load_vars():
    config_path = os.path.join(os.path.dirname(__file__), TEST_CONFIG_FILE)
    placeholders = {}

    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config_data = json.load(f)
            # Load top-level string values from config
            for key, value in config_data.items():
                if isinstance(value, str):
                    placeholders[key] = value
            # Load nested system values
            if "systems" in config_data:
                for sys_key, sys_values in config_data["systems"].items():
                    for attr_key, attr_value in sys_values.items():
                        placeholders[f"{sys_key}_{attr_key}"] = attr_value
            # Load nested activation key values
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

async def run_mcp_agent(prompt: str, model: str = None) -> tuple[str, list]:
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
                    tools=[types.Tool(function_declarations=gemini_tools)]
                )
            )

            response = await chat.send_message(prompt)
            tool_calls = []

            while response.function_calls:
                parts = []
                for call in response.function_calls:
                    tool_calls.append(call)
                    result = await session.call_tool(call.name, call.args)
                    tool_output = "\n".join([c.text for c in result.content if c.type == "text"])
                    
                    parts.append(types.Part.from_function_response(
                        name=call.name,
                        response={"result": tool_output}
                    ))
                
                response = await chat.send_message(parts)

            return response.text, tool_calls

def query_mcp_server(prompt: str) -> tuple[str, list]:
    return asyncio.run(run_mcp_agent(prompt))

def load_test_cases():
    json_path = os.path.join(os.path.dirname(__file__), TEST_CASES_FILE)
    if not os.path.exists(json_path):
        return []
    
    with open(json_path, 'r') as f:
        return json.load(f)

@pytest.mark.parametrize("test_case", load_test_cases())
def test_uyuni_mcp_deepeval(test_case):
    prompt_template = test_case.get("prompt")
    expected_template = test_case.get("expected_output")
    test_id = test_case.get("id", "unknown")

    if not prompt_template or not expected_template:
        pytest.skip(f"Skipping malformed test case: {test_id}")

    prompt = prompt_template.format(**VARS)
    expected_output = expected_template.format(**VARS)

    actual_output, actual_tool_calls = query_mcp_server(prompt)

    judge_model = os.environ.get("JUDGE_MODEL", "gemini-2.5-flash")
    geval_kwargs = {
        "name": "Correctness",
        "evaluation_params": [LLMTestCaseParams.ACTUAL_OUTPUT, LLMTestCaseParams.EXPECTED_OUTPUT],
        "threshold": 0.7,
        "verbose_mode": True,
        "model": GoogleGemini(model=judge_model)
    }
    user_geval_config = test_case.get("geval_config", {})
    geval_kwargs.update(user_geval_config)

    if isinstance(geval_kwargs["model"], str):
        geval_kwargs["model"] = GoogleGemini(model=geval_kwargs["model"])

    if "criteria" not in geval_kwargs and "evaluation_steps" not in geval_kwargs:
        geval_kwargs["criteria"] = f"The actual output must satisfy this requirement: {expected_output}"

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
        expected_tools=expected_tools
    )

    try:
        assert_test(deepeval_case, metrics)
    except AssertionError as e:
        error_message = (
            f"\n--- Deepeval Test Failed ---\n"
            f"Test Case ID: {test_id}\n"
            f"Prompt: {prompt}\n"
            f"Expected Output Hint: {expected_output}\n"
            f"----- ACTUAL OUTPUT -----\n{actual_output}\n"
            f"----- END ACTUAL OUTPUT -----\n"
            f"Original Error: {e}"
        )
        raise AssertionError(error_message) from e