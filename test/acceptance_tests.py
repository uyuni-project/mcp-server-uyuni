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
2.  **Descriptive Expectations:** The 'Expected Output' might be a description of the desired result (e.g., "Returns a list of dicts", "Returns an empty dict"). In this case, you must verify that the 'Actual Output' is a valid representation of that description. For example, if the expectation is "Returns an empty list", an actual output of `[]` is a PASS.
3.  **Confirmation Prompts:** If the 'Expected Output' contains "CONFIRMATION REQUIRED", the 'Actual Output' must also contain this phrase.
4.  **Dynamic Content:** If the 'Expected Output' contains placeholders like "...'", it means the beginning of the 'Actual Output' should match the part before the placeholder.
5.  **Skip thinking:** Skip any reasoning or thinking process in your response. Skip any content between <think> and </think>.

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


def _run_mcphost_command(prompt, config_path, model):
    """Runs a prompt through the mcphost command and returns the output.

    Args:
        prompt (str): The prompt to send to the model.
        config_path (str): Path to the mcphost config file.
        model (str): The model to use for the test.

    Returns:
        str: The actual output from the command, or an error message.
    """
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

    try:
        # By providing `input=""`, we ensure that stdin is a pipe. This can
        # prevent errors in command-line tools that unexpectedly try to read
        # from stdin even when running in non-interactive mode. The error
        # "file already closed" often points to such an issue.
        result = subprocess.run(
            command, input="", capture_output=True, text=True, check=True,
            encoding="utf-8"
        )
        return result.stdout.strip()
    except FileNotFoundError:
        print(
            "Error: 'mcphost' command not found. Make sure it's installed and in your PATH.",
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


def run_test_case(test_case, config_path, model):
    """Runs a single test case using the mcphost command.

    Args:
        test_case (dict): The test case dictionary from the JSON file.
        config_path (str): Path to the mcphost config file.
        model (str): The model to use for the test.

    Returns:
        str: The actual output from the command, or an error message.
    """
    prompt = test_case.get("prompt")
    if not prompt:
        return "Error: 'prompt' not found in test case"
    return _run_mcphost_command(prompt, config_path, model)


def evaluate_test_case(expected, actual, config_path, judge_model):
    """
    Uses an LLM judge to compare the actual output with the expected output.

    Args:
        expected (str): The expected output from the test case.
        actual (str): The actual output from the mcphost command.
        config_path (str): Path to the mcphost config file.
        judge_model (str): The model to use for the evaluation.

    Returns:
        tuple: A tuple containing the status ('PASS' or 'FAIL') and a reason string.
    """
    if actual.startswith("COMMAND_FAILED") or actual.startswith("UNEXPECTED_ERROR"):
        return "FAIL", f"Command execution failed: {actual}"

    judge_prompt = JUDGE_PROMPT_TEMPLATE.format(expected=expected, actual=actual)

    judge_response_str = _run_mcphost_command(judge_prompt, config_path, judge_model)

    try:
        # The LLM response might be wrapped in markdown, so we clean it.
        cleaned_response = judge_response_str.strip().removeprefix("```json").removesuffix("```").strip()
        judge_result = json.loads(cleaned_response)
        status = judge_result.get("status", "FAIL").upper()
        reason = judge_result.get("reason", "LLM judge did not provide a reason.")
        if status not in ["PASS", "FAIL"]:
            return "FAIL", f"LLM judge returned an invalid status: '{status}'"
        return status, reason
    except json.JSONDecodeError:
        return "FAIL", f"LLM judge returned non-JSON output: '{judge_response_str}'"
    except (AttributeError, KeyError):
        return "FAIL", f"LLM judge returned malformed JSON: '{judge_response_str}'"


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
        "--judge-model",
        type=str,
        default=None,
        help="Model to use for judging the test results. Defaults to the test model if not specified.",
    )
    args = parser.parse_args()

    if not args.test_cases_file.is_file():
        print(
            f"Error: Test cases file not found at '{args.test_cases_file}'",
            file=sys.stderr,
        )
        sys.exit(1)

    judge_model = args.judge_model if args.judge_model else args.model
    print(f"Using model for tests: {args.model}")
    print(f"Using model for judging: {judge_model}\n")

    with open(args.test_cases_file, "r", encoding="utf-8") as f:
        test_cases = json.load(f)

    results = []
    passed_count = 0
    failed_count = 0
    total_tests = len(test_cases)
    print(f"Found {total_tests} test cases. Starting execution...")

    total_start_time = time.monotonic()

    for i, tc in enumerate(test_cases, 1):
        test_start_time = time.monotonic()
        print(f"--- [{i}/{total_tests}] RUNNING: {Colors.BOLD}{tc.get('id', 'N/A')}{Colors.ENDC} ---")
        prompt = tc.get("prompt")
        expected_output = tc.get("expected_output")

        print(f"  PROMPT  : {prompt}")
        actual_output = run_test_case(tc, args.config, args.model)
        print(f"  EXPECTED: {expected_output}")
        print(f"  ACTUAL  : {actual_output}")

        print(f"  JUDGING with {judge_model}...")
        status, reason = evaluate_test_case(expected_output, actual_output, args.config, judge_model)

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