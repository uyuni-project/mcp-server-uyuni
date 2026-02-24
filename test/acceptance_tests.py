import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

# ANSI escape codes for colors
class Colors:
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    WARN = '\033[93m'


JUDGE_PROMPT_TEMPLATE = """
You are an expert quality assurance engineer evaluating test case results for a command-line tool.
Your task is to determine if the 'Actual Output' from the tool meets the criteria described in the 'Expected Output'.

**Evaluation Rules:**
1.  **Semantic Equivalence:** Do not perform a simple string comparison. The 'Actual Output' must be semantically equivalent to the 'Expected Output'. Minor differences in wording, whitespace, or formatting are acceptable if the core meaning is the same.

2.  **Fact-Checking (Checklist):** If the 'Expected Output' begins with "The response must contain..." and is followed by a list, treat this as a **checklist of facts**. Your sole task is to verify that *every fact* from this list (e.g., every "system: id" pair) is present in the 'Actual Output'. The 'Actual Output' PASSES if all facts are present, **regardless of its formatting** (e.g., numbered lists, bold text, sentences, or tables are all acceptable).

3.  **No Implementation Details:** Base your judgment *only* on the provided text. Do not fail a test by inferring requirements from internal code or parameter names (like 'system_identifier') that are not explicitly mentioned in the 'Expected Output'.

4.  **Descriptive Expectations:** The 'Expected Output' might be a description of the desired result (e.g., "Returns a list of dicts", "Returns an empty dict"). In this case, you must verify that the 'Actual Output' is a valid representation of that description. For example, if the expectation is "Returns an empty list", an actual output of `[]` is a PASS.

5.  **Confirmation Prompts:** If the 'Expected Output' contains "CONFIRMATION REQUIRED", the 'Actual Output' does not need to contain that exact phrase. Instead, it must semantically ask the user for confirmation to proceed with the action. For example, "Do you want to continue?" is a valid confirmation prompt.

6.  **Dynamic Content:** If the 'Expected Output' contains placeholders like "...'", it means the beginning of the 'Actual Output' should match the part before the placeholder.

7.  **Skip thinking:** Skip any reasoning or thinking process in your response. Skip any content between <think> and </think>.

8.  **Ignore Thinking Steps in Actual Output:** If the 'Actual Output' contains thinking steps (e.g., content within <think>...</think> tags), ignore them. Evaluate the test based only on the final output.

9.  **Ignore Prefixes:** Disregard system messages like 'Data collection is disabled' if the requested data follows immediately after.

**Input for Evaluation:**

[Expected Output]:
{expected}

[Actual Output]:
{actual}

**Your Response:**
Based on the rules above, does the 'Actual Output' match the 'Expected Output'?
Respond with a single, valid JSON object containing two keys and nothing else:
- "status": A string, either "PASS" or "FAIL".
- "reason": A brief, one-sentence string explaining your decision.
"""


def _run_command(runner, prompt, config_path, model, debug=False):
    """Runs a prompt through the specified runner command and returns the output.

    Args:
        runner (str): The command to run ('mcphost' or 'gemini').
        prompt (str): The prompt to send to the model.
        config_path (str): Path to the config file.
        model (str): The model to use for the test.
        debug (bool): Whether to print debug information.

    Returns:
        str: The actual output from the command, or an error message.
    """
    if runner == "mcphost":
        command = [
            "mcphost",
            "--config",
            config_path,
            "--prompt",
            prompt,
            "--quiet",
            "--compact",
            "-m",
            model,
        ]
    elif runner == "gemini":
        command = [
            "gemini",
            "--yolo",
            "--prompt",
            prompt,
            "--model",
            model,
        ]
    else:
        return f"Error: Unsupported runner '{runner}'"

    if debug:
        print(f"DEBUG: Running command: {command}")

    try:
        # By providing `stdin=subprocess.DEVNULL`, we prevent the subprocess
        # from accidentally reading from a closed stdin pipe, which can cause
        # "file already closed" errors, especially in non-interactive tools
        # that are not robustly designed.
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True, encoding="utf-8"
        )
        output = result.stdout.strip()
        # The mcphost command can sometimes append an error to stdout even on
        # success. We explicitly remove this known intermittent error message
        # to prevent it from corrupting the test results.
        error_to_remove = "Error reading response: read |0: file already closed"
        cleaned_output = output.replace(error_to_remove, "").strip()
        return cleaned_output
    except FileNotFoundError:
        print(
            f"Error: '{runner}' command not found. Make sure it's installed and in your PATH.",
            file=sys.stderr,
        )
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        error_message = (
            f"  Return code: {e.returncode}\n"
            f"  Stdout: {e.stdout.strip()}\n"
            f"  Stderr: {e.stderr.strip()}"
        )
        print(error_message, file=sys.stderr)
        return f"COMMAND_FAILED: {e.stderr.strip()}"
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return f"UNEXPECTED_ERROR: {str(e)}"


def run_test_case(prompt, config_path, model, runner, debug=False):
    """Runs a single test case using the specified runner.

    Args:
        prompt (str): The prompt to send to the model.
        config_path (str): Path to the config file.
        model (str): The model to use for the test.
        runner (str): The tool to use for running the test.
        debug (bool): Whether to print debug information.

    Returns:
        str: The actual output from the command, or an error message.
    """
    if not prompt:
        return "Error: 'prompt' not found in test case"
    return _run_command(runner, prompt, config_path, model, debug=debug)


def evaluate_test_case(expected, actual, config_path, judge_model, runner, debug=False):
    """
    Uses an LLM judge to compare the actual output with the expected output.

    Args:
        expected (str): The expected output from the test case.
        actual (str): The actual output from the runner command.
        config_path (str): Path to the config file.
        judge_model (str): The model to use for the evaluation.
        runner (str): The tool to use for running the judge.
        debug (bool): Whether to print debug information.

    Returns:
        tuple: A tuple containing the status ('PASS' or 'FAIL') and a reason string.
    """
    if actual.startswith("COMMAND_FAILED") or actual.startswith("UNEXPECTED_ERROR"):
        return "FAIL", f"Command execution failed: {actual}"

    judge_prompt = JUDGE_PROMPT_TEMPLATE.format(expected=expected, actual=actual)

    judge_response_str = _run_command(runner, judge_prompt, config_path, judge_model, debug=debug)

    try:
        # The mcphost command can sometimes append a "file already closed" error
        # to stdout, corrupting the JSON output from the LLM. To handle this,
        # we robustly extract the JSON object from the response string by
        # finding the first '{' and the last '}'. This is more reliable than
        # simple string stripping.
        json_start_index = judge_response_str.find('{')
        if json_start_index == -1:
            raise json.JSONDecodeError("Could not find start of JSON object ('{').", judge_response_str, 0)

        json_end_index = judge_response_str.rfind('}')
        if json_end_index == -1:
            raise json.JSONDecodeError("Could not find end of JSON object ('}').", judge_response_str, 0)

        json_str = judge_response_str[json_start_index : json_end_index + 1]
        judge_result = json.loads(json_str)
        status = judge_result.get("status", "FAIL").upper()
        reason = judge_result.get("reason", "LLM judge did not provide a reason.")
        if status not in ["PASS", "FAIL"]:
            return "FAIL", f"LLM judge returned an invalid status: '{status}'"
        return status, reason
    except json.JSONDecodeError as e:
        # Fallback for when the LLM fails to produce valid JSON but might have
        # produced a string containing the status.
        response_upper = judge_response_str.upper()
        if "PASS" in response_upper:
            return "PASS", f"LLM judge returned non-JSON output but contained 'PASS': '{judge_response_str}'"
        if "FAIL" in response_upper:
            return "FAIL", f"LLM judge returned non-JSON output but contained 'FAIL': '{judge_response_str}'"

        return "FAIL", (
            f"LLM judge returned non-JSON output: '{judge_response_str}' (Error: {e})"
        )
    except (AttributeError, KeyError):
        return "FAIL", f"LLM judge returned malformed JSON: '{judge_response_str}'"


def _substitute_placeholders(text, placeholders):
    """Substitutes placeholders in a string with their values."""
    if not isinstance(text, str):
        return text
    return text.format(**placeholders)

def main():
    """Main function to run acceptance tests."""
    parser = argparse.ArgumentParser(
        description="Run acceptance tests for mcp-server-uyuni."
    )
    parser.add_argument(
        "--test-cases-file",
        type=Path,
        default=Path(__file__).parent / "test_cases.json",
        help="Path to the JSON file with test cases. Defaults to 'test_cases.json' in the same directory.",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        default=Path(__file__).parent / "test_results.json",
        help="Path to the output JSON file for test results. Defaults to 'test_results.json' in the same directory.",
    )
    parser.add_argument(
        "--test-config",
        type=Path,
        default=None,
        help="Path to the JSON file with test configuration values (for placeholder substitution).",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.json",
        help="Path to the mcphost config.json file. Defaults to 'config.json'.",
    )
    parser.add_argument(
        "-m",
        "--model",
        type=str,
        default="google:gemini-2.5-flash",
        help="Model to use for the tests (e.g., 'google:gemini-2.5-flash').",
    )
    parser.add_argument(
        "--runner",
        type=str,
        choices=["mcphost", "gemini"],
        default="gemini",
        help="Tool to run the prompts. Defaults to 'gemini'.",
    )
    parser.add_argument(
        "--judge-model",
        type=str,
        default=None,
        help="Model to use for judging the test results. Defaults to the test model if not specified.",
    )
    parser.add_argument(
        "--test-id",
        type=str,
        default=None,
        help="ID of a specific test case to run.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output (prints the exact command being run).",
    )
    args = parser.parse_args()

    if not args.test_cases_file.is_file():
        print(
            f"Error: Test cases file not found at '{args.test_cases_file}'",
            file=sys.stderr,
        )
        sys.exit(1)

    placeholders = {}
    if args.test_config:
        if not args.test_config.is_file():
            print(
                f"Error: Test config file not found at '{args.test_config}'",
                file=sys.stderr,
            )
            sys.exit(1)
        with open(args.test_config, "r", encoding="utf-8") as f:
            config_data = json.load(f)
            if "systems" in config_data:
                for sys_key, sys_values in config_data["systems"].items():
                    for attr_key, attr_value in sys_values.items():
                        placeholders[f"{sys_key}_{attr_key}"] = attr_value
            if "activation_keys" in config_data:
                for key_name, key_value in config_data["activation_keys"].items():
                    placeholders[f"key_{key_name}"] = key_value
            if "product_name" in config_data:
                placeholders["product_name"] = config_data["product_name"]
        print(f"Loaded {len(placeholders)} placeholders from '{args.test_config}'")

    judge_model = args.judge_model if args.judge_model else args.model
    print(f"Using model for tests: {args.model}")
    print(f"Using model for judging: {judge_model}\n")
    print(f"Using runner: {args.runner}\n")

    with open(args.test_cases_file, "r", encoding="utf-8") as f:
        test_cases = json.load(f)

    if args.test_id:
        test_cases = [tc for tc in test_cases if tc.get("id") == args.test_id]
        if not test_cases:
            print(f"Error: Test case '{args.test_id}' not found.", file=sys.stderr)
            sys.exit(1)

    results = []
    passed_count = 0
    failed_count = 0
    total_tests = len(test_cases)
    print(f"Found {total_tests} test cases. Starting execution...")

    total_start_time = time.monotonic()

    for i, tc in enumerate(test_cases, 1):
        test_start_time = time.monotonic()
        print(f"--- [{i}/{total_tests}] RUNNING: {Colors.BOLD}{tc.get('id', 'N/A')}{Colors.ENDC} ---")
        prompt = _substitute_placeholders(tc.get("prompt"), placeholders)
        expected_output = _substitute_placeholders(tc.get("expected_output"), placeholders)

        print(f"  PROMPT  : {prompt}")
        actual_output = run_test_case(prompt, args.config, args.model, args.runner, debug=args.debug)
        print(f"  EXPECTED: {expected_output}")
        print(f"  ACTUAL  : {actual_output}")

        print(f"  JUDGING with {judge_model}...")
        status, reason = evaluate_test_case(expected_output, actual_output, args.config, judge_model, args.runner, debug=args.debug)

        if status == "PASS":
            passed_count += 1
            print(f"  STATUS  : {Colors.OKGREEN}{status}{Colors.ENDC} ({reason})")
        else:
            failed_count += 1
            print(f"  STATUS  : {Colors.FAIL}{status}{Colors.ENDC}")
            print(f"  REASON  : {Colors.WARN}{reason}{Colors.ENDC}")

        test_end_time = time.monotonic()
        test_duration = test_end_time - test_start_time
        print(f"  TIME    : {test_duration:.2f}s\n")
        
        results.append(
            {
                "id": tc.get("id"),
                "prompt": prompt,
                "expected_output": expected_output,
                "actual_output": actual_output,
                "status": status,
                "reason": reason,
            }
        )

    total_end_time = time.monotonic()
    total_duration = total_end_time - total_start_time

    print("--- TEST SUMMARY ---")
    print(f"Total Tests: {total_tests}")
    print(f"  {Colors.OKGREEN}Passed: {passed_count}{Colors.ENDC}")
    print(f"  {Colors.FAIL}Failed: {failed_count}{Colors.ENDC}")
    print(f"Total Time : {total_duration:.2f}s")
    print("--------------------")

    print(
        f"\nAll tests completed. Saving {len(results)} results to '{args.output_file}'..."
    )
    with open(args.output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print("Done.")


if __name__ == "__main__":
    main()
