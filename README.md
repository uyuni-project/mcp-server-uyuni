# Uyuni MCP Server

The Uyuni MCP Server is a Model Context Protocol (MCP) server implementation that bridges the gap between Large Language Models (LLMs) and the Uyuni configuration and infrastructure management solution.

This project allows AI agents or MCP-compliant clients (such as Gemini CLI or Claude Desktop) to securely interact with your Uyuni server. The Uyuni MCP server enables users to manage their Linux infrastructure using natural language. Instead of navigating the web UI or writing complex API scripts, you can simply ask your AI assistant to perform tasks like getting system details, checking for updates, or scheduling maintenance.

Key Capabilities
This server exposes a suite of tools that allow LLMs to:

- Inspect Infrastructure: Retrieve lists of active systems and view system information.
- Manage Updates: Identify systems with pending security updates or CVEs and schedule patch applications.
- Execute Actions: Schedule reboots.

It is designed to be run as a container or locally, offering a streamlined way to integrate AI-driven automation into your system administration workflows.

## Table of Contents

- [Tool List](#tool-list)
- [Usage](#usage)
  - [1. Configuration](#1-configuration)
  - [2. Running as a Container (Recommended)](#2-running-as-a-container-recommended)
  - [3. Running Locally with uv](#3-running-locally-with-uv)
  - [4. Client Configuration Examples](#4-client-configuration-examples)
- [Feedback](#feedback)
- [License](#license)
- [Disclaimer](#disclaimer)

## Usage

There are two main ways to run the Uyuni MCP Server: using the pre-built container or running it locally with `uv`. Both methods require a `config` file.

To use the Uyuni MCP Server, you must first create a configuration file. Once configured, you can run the server using a container engine (i.e. docker) (recommended) or locally with uv.

### 1\. Configuration

Create a file (e.g., `uyuni-config.env`) to store your environment variables. You can place this file anywhere, but you must reference its path when running the server.

```bash
# Required: Basic server parameters.
UYUNI_SERVER=192.168.1.124:8443
UYUNI_USER=admin
UYUNI_PASS=admin

# Optional: Set to 'false' to disable SSL certificate verification. Defaults to 'true'.
# UYUNI_MCP_SSL_VERIFY=false

# Optional: Set to 'true' to enable tools that perform write actions (e.g., POST requests). Defaults to 'false'.
# UYUNI_MCP_WRITE_TOOLS_ENABLED=false

> [!WARNING]
> **Security Note on Write Tools:** Enabling `UYUNI_MCP_WRITE_TOOLS_ENABLED` allows the execution of state-changing and potentially destructive actions (e.g., removing systems, applying updates). When combined with `UYUNI_MCP_TRANSPORT=http`, this risk is amplified, as any client with network access can perform these actions. Only enable write tools in a trusted environment.

# Optional: Set the transport protocol. Can be 'stdio' (default) or 'http'.
# UYUNI_MCP_TRANSPORT=stdio

> [!WARNING]
> **Security Note on HTTP Transport:** When `UYUNI_MCP_TRANSPORT` is set to `http` but `AUTH_SERVER` is not set, the server runs without authentication. This means any client with network access can execute commands. Only use this mode in a trusted, isolated network environment. For more details, see the Security Policy.

# Optional: Set the path for the server log file. Defaults to logging to the console.
# UYUNI_MCP_LOG_FILE_PATH=/var/log/mcp-server-uyuni.log

# Optional: Set the logging level. Can be 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'. Defaults to 'INFO'.
# UYUNI_MCP_LOG_LEVEL=DEBUG

# Required to bootstrap new systems into Uyuni via the `add_system` tool.
UYUNI_SSH_PRIV_KEY="-----BEGIN OPENSSH PRIVATE KEY-----\n..."
UYUNI_SSH_PRIV_KEY_PASS=""
```

Replace the values with your Uyuni server details. **This file contains sensitive information and should not be committed to version control.**

> [!NOTE]
> **Formatting the SSH Private Key**
>
> The `UYUNI_SSH_PRIV_KEY` variable, used by the `add_system` tool, requires the entire private key as a single-line string. The newlines from the original key file must be replaced by the literal `\n` sequence.
>
> You can generate the correct format from your key file (e.g., `~/.ssh/id_rsa`) using the following command. You can then copy the output into your `config` file or environment variable.
>
> ```bash
> awk 'NF {printf "%s\\n", $0}' ~/.ssh/id_rsa
> ```
>
> To set it as an environment variable directly in your shell, run:
> ```bash
> export UYUNI_SSH_PRIV_KEY=$(awk 'NF {printf "%s\\n", $0}' ~/.ssh/id_rsa)
> ```

Alternatively, you can also set environment variables instead of using a file.



### 2\. Running as a Container (Recommended)

The easiest way to run the server is using the pre-built container image. This method isolates the environment and requires no local dependencies other than the container engine (i.e. docker).


This is the easiest method for deployment. Pre-built container images are available on the GitHub Container Registry.

 Replace `/path/to/your/config` with the absolute path to your `config` file. Replace `VERSION` with the desired release tag (e.g., `v0.2.1`) or use `latest` for the most recent build from the `main` branch.

```json
{
  "mcpServers": {
    "mcp-server-uyuni": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--env-file", "/path/to/your/config",
        "ghcr.io/uyuni-project/mcp-server-uyuni:VERSION"
      ]
    }
  }
}

```

Alternatively, you can use environment variables instead of a file.

```json
{
  "mcpServers": {
    "mcp-server-uyuni": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "UYUNI_SERVER=192.168.1.124:8443",
        "-e", "UYUNI_USER=admin",
        "-e", "UYUNI_PASS=admin",
        "ghcr.io/uyuni-project/mcp-server-uyuni:VERSION"
      ]
    }
  }
}
```

**Command:**

```bash
docker run -i --rm --env-file /path/to/uyuni-config.env ghcr.io/uyuni-project/mcp-server-uyuni:latest
```

  * **`-i`**: Keeps STDIN open (required for MCP communication).
  * **`--rm`**: Removes the container after it exits.
  * **`--env-file`**: Points to the configuration file you created in step 1.

### 3\. Running Locally with `uv`

If you are developing or prefer running Python directly, you can use `uv`.

**Prerequisites:**

  * Install `uv`: [https://docs.astral.sh/uv](https://docs.astral.sh/uv)
  * Clone this repository.

**Setup and Run:**

1.  Sync dependencies:
    ```bash
    uv sync
    ```
2.  Run the server:
    ```bash
    uv run --env-file /path/to/uyuni-config.env --directory /path/to/sources/ mcp-server-uyuni


### 4\. Client Configuration Examples

MCP servers are rarely run manually; they are usually configured within an MCP Client (like Gemini CLI). Below are examples of how to configure your client to use `mcp-server-uyuni`.

#### Gemini CLI Configuration

Add the following to your `config.gemini.json`:

**Container Method:**

```json
{
  "mcpServers": {
    "mcp-server-uyuni": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-v",
        "/path/to/mcp-server-uyuni.log:/tmp/mcp-server-uyuni.log",
        "--name",
        "mcp-server-uyuni",
        "--env-file",
        "/path/to/uyuni-connection-config-stdio.env",
        "registry.opensuse.org/systemsmanagement/uyuni/ai/devel_bci_16.0_containerfile/uyuni-ai/mcp-uyuni-server",
        "/usr/bin/mcp-server-uyuni"
      ]
    }
  },
  "security": {
    "auth": {
      "selectedType": "gemini-api-key"
    }
  }
}
```

**Local `uv` Method:**

```json
{
  "mcpServers": {
    "uyuni": {
      "command": "/path/to/uv",
      "args": [
        "run",
        "--env-file", "/path/to/uyuni-config.env",
        "--directory", "/path/to/mcp-server-uyuni-repo",
        "mcp-server-uyuni"
      ]
    }
  }
}
```

## Tool List

* `list_systems`: Fetches a list of active systems from the Uyuni server, returning their names and IDs.
* `get_system_details`: Gets details of the specified system.
* `get_system_event_history`: Gets the event/action history of the specified system.
* `get_system_event_details`: Gets the details of the event associated with the especified server and event ID.
* `find_systems_by_name`: Lists systems that match the provided hostname.
* `find_systems_by_ip`: Lists systems that match the provided IP address.
* `get_system_updates`: Checks if a specific system has pending updates (relevant errata).
* `check_all_systems_for_updates`: Checks all active systems for pending updates.
* `list_systems_needing_update_for_cve`: Finds systems requiring a security update for a specific CVE identifier.
* `list_systems_needing_reboot`: Fetches a list of systems from the Uyuni server that require a reboot.
* `get_unscheduled_errata`: Lists applicable and unscheduled patches for a system.
* `list_activation_keys`: Retrieves a list of available activation keys for bootstrapping new systems.
* `list_all_scheduled_actions`: Fetches a list of all scheduled, in-progress, completed, or failed actions.
* `list_system_groups`: Fetches a list of system groups from the Uyuni server.
* `list_group_systems`: Lists the systems in a system group.
* `schedule_pending_updates_to_system`: Checks for pending updates on a system, schedules all of them to be applied.
* `schedule_specific_update`: Schedules a specific update (erratum) to be applied to a system.
* `add_system`: Bootstraps and registers a new system with Uyuni using an activation key.
* `remove_system`: Decommissions and removes a system from Uyuni management.
* `schedule_system_reboot`: Schedules a reboot for a specified system.
* `cancel_action`: Cancels a previously scheduled action, such as an update or reboot.
* `create_system_group`: Creates a new system group in Uyuni.
* `add_systems_to_group`: Adds systems to a system group.
* `remove_systems_from_group`: Removes systems from a system group.


## Feedback

We would love to hear from you! Any idea you want to discuss or share, please do so at [https://github.com/uyuni-project/uyuni/discussions/10562](https://github.com/uyuni-project/uyuni/discussions/10562)

If you encounter any bug, be so kind to open a new bug report at [https://github.com/uyuni-project/mcp-server-uyuni/issues/new?type=bug](https://github.com/uyuni-project/mcp-server-uyuni/issues/new?type=bug)

Thanks in advance from the uyuni team!

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.


## Disclaimer

This is an open-source project provided "AS IS" without any warranty, express or implied. Use at your own risk. For full details, please refer to the [License](#license) section.
