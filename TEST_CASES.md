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

The acceptance test cases in this document are automated using the **DeepEval** framework. To ensure an isolated and reproducible execution environment, tests are run inside a Docker container (used both locally and in CI pipelines).

The test suite is defined in `test/test_deepeval.py` and outputs results in JUnit XML format.

> **Note on Model Selection:** Do not use `flash-lite` model variants for acceptance testing. While `flash-lite` is optimized for fast conversational responses, it is prone to hallucinations during complex agent executions. Use `google:gemini-2.5-flash`, which is specifically optimized for Model Context Protocol (MCP) and reliable tool interaction.

### Prerequisites

1. **Docker**: Ensure Docker with the `buildx` plugin is installed.
2. **Secrets Configuration**: Create an environment secrets file at `$HOME/.ai_secrets` containing required credentials and sensitive settings:
   ```env
   GOOGLE_API_KEY="your-google-api-key"
   UYUNI_USER="your-uyuni-username"
   UYUNI_PASS="your-uyuni-password"
   UYUNI_SSH_PRIV_KEY="your-ssh-private-key"
   UYUNI_SSH_PRIV_KEY_PASS="your-ssh-key-passphrase"
   UYUNI_OAUTH_CLIENT_SECRET="your-oauth-client-secret"
   ```
3. **Target Environment Configuration**: Ensure the `.venv/config` file exists with the necessary MCP and server settings.

### Execution Steps

#### 1. Build the Docker Image
Build the testing container using `Dockerfile.test` from the root of the project:

```bash
docker build -f Dockerfile.test -t acceptance-tests:latest .
```

#### 2. Set Up Environment Configuration
Generate or update the `.venv/config` file with your target server parameters:

```bash
cat <<EOF> .venv/config
UYUNI_SERVER=uyuni-server.example.com
UYUNI_MCP_WRITE_TOOLS_ENABLED=true
UYUNI_MCP_TRANSPORT=stdio
UYUNI_MCP_LOG_FILE_PATH=/tmp/mcp-server-uyuni.log
UYUNI_MCP_LOG_LEVEL=DEBUG
UYUNI_MCP_SSL_VERIFY=true
EOF
```

#### 3. Run the Test Suite
Execute the test container by passing the models, config mounts, and secrets:

```bash
docker run --rm \
  --env-file .venv/config \
  -e AGENT_MODEL="google:gemini-2.5-flash" \
  -e JUDGE_MODEL="google:gemini-2.5-flash" \
  --env-file $HOME/.ai_secrets \
  -v $(pwd)/results:/app/results \
  -v $(pwd)/test/test_config.json:/app/test_config.json \
  --network=host \
  acceptance-tests:latest -s test/test_deepeval.py --junit-xml=results/test_results_all.VERSION.xml
```

### Configuration Parameters & Environment Variables

| Variable / Parameter | Description |
| :--- | :--- |
| `AGENT_MODEL` | Target model evaluated by the test suite (default: `google:gemini-2.5-flash`). |
| `JUDGE_MODEL` | Evaluator model used by DeepEval (default: `google:gemini-2.5-flash`). |
| `GOOGLE_API_KEY` | API key required for Gemini model calls. |
| `UYUNI_SERVER` | Target host or domain for the Uyuni server instance (e.g., `uyuni-server.example.com`). |
| `UYUNI_USER` / `UYUNI_PASS` | Authentication credentials for the Uyuni server. |
| `UYUNI_SSH_PRIV_KEY` | Private SSH key for server access. |
| `UYUNI_SSH_PRIV_KEY_PASS` | Passphrase for the SSH private key (if applicable). |
| `UYUNI_OAUTH_CLIENT_SECRET` | Secret token for OAuth authentication. |
| `UYUNI_MCP_SSL_VERIFY` | Toggles SSL certificate validation for MCP connections (`true`/`false`). |
| `$HOME/.ai_secrets` | Path to environment file holding API keys and sensitive credentials. |
| `.venv/config` | Path to environment file holding MCP server target settings. |
| `-v .../results` | Mounts local directory to capture test logs and `--junit-xml` outputs. |

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
6.  Run the automated tests with "--junit-xml=results/test_results_all.VERSION.xml". Replace `VERSION` with the new version.
7.  Add the tests result file to git and commit with a message like "Update automatic test results for vVERSION".
8.  Push the changes to GitHub.

