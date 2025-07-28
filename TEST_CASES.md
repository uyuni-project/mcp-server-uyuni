# Manual Test Cases for mcp-server-uyuni

This document tracks manual test cases that cannot be covered by the automated test suite.

Most test cases are now automated in `test/acceptance_tests.py`. The table below lists only the tests that require manual execution, typically due to client-specific capabilities like elicitation that are not supported by the automated test runner.

## Test Environment (for v0.1 tests)

*   **MCP Client**: Open WebUI version 0.6.10 with MCP OpenAPI Proxy 1.0
*   **LLM**: Google Gemini 2.0 Flash

This document tracks the manual test cases executed for different versions/tags of the `mcp-server-uyuni` project.

To run any tests that perform write actions, the UYUNI_MCP_WRITE_TOOLS_ENABLED environment variable must be set to true.

## Test Case Table

| Test Case ID | Tool / Feature Tested | Prompt / Action                                        | Expected Result                                                                                                                                                           | Status (v0.4.0) | Notes                                                                                   |
|--------------|-----------------------|--------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------|-----------------------------------------------------------------------------------------|
| TC-ADV-001   | Elicitation           | Trigger elicitation for activation key in `add_system` | Verify that when `add_system` is called without an activation key, a compatible client (e.g., VS Code) prompts the user for the key, and the system is added successfully after providing it. | Pass ✅         | Client-specific test. Not automated due to lack of elicitation support in the test harness. |


## Running Automated Acceptance Tests

The test cases in this document have been automated in the `test/acceptance_tests.py` script. This script uses an LLM-as-a-judge to evaluate the results.

To run the tests, use the following command from the project root:

```bash
uv run python3 test/acceptance_tests.py [OPTIONS]
```

**Note:** If you are using a Google Gemini model (the default for both testing and judging), make sure to set the `GOOGLE_API_KEY` environment variable:

```bash
export GOOGLE_API_KEY="your-api-key-here"
```

### Options

You can customize the test run with the following command-line arguments. If you do not specify them, the script will use the defaults.

*   `--config <path>`: Path to the `config.json` file (default: `config.json`).
*   `--model <model_name>`: The model to use for running the test prompts (default: `google:gemini-1.5-flash`).
*   `--judge-model <model_name>`: The model to use for evaluating the test results. Defaults to the test model.

## How to Update for a New Tag/Release

1.  Before creating a new Git tag (e.g., `v1.0.1`):
2.  Add a new column to the table above, titling it `Status (v1.0.1)`.
3.  For each test case, manually execute the test against the codebase intended for `v1.0.1`.
4.  Fill in the status in the new column:
    *   `Pass`: The test case passed as expected.
    *   `Fail`: The test case failed. Add a note or Bug ID.
    *   `Blocked`: The test case could not be executed (e.g., due to an external dependency or an unresolved bug in another area).
    *   `N/A`: The test case is not applicable to this version.
5.  Commit this `TEST_CASES.md` file with a message like "Update manual test statuses for v1.0.1".
6.  Run the automated tests with "--output-file test_results.vx.y.z.json". Replace `vx.y.z` with the new version.
7.  Add the tests result file to git and commit with a message like "Update automatic test results for v1.0.1".
8.  Push the changes to GitHub.

