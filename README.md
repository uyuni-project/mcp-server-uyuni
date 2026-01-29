# Uyuni MCP Server

The Uyuni MCP Server is a Model Context Protocol (MCP) server implementation that bridges the gap between Large Language Models (LLMs) and the Uyuni configuration and infrastructure management solution.

This project allows AI agents or MCP-compliant clients (such as Gemini CLI or Claude Desktop) to securely interact with your Uyuni server. The Uyuni MCP server enables users to manage their Linux infrastructure using natural language. Instead of navigating the web UI or writing complex API scripts, you can simply ask your AI assistant to perform tasks like getting system details, checking for updates, or scheduling maintenance.

Key Capabilities
This server exposes a suite of tools that allow LLMs to:

- Inspect Infrastructure: Retrieve lists of active systems and view system information.
- Manage Updates: Identify systems with pending security updates or CVEs and schedule patch applications.
- Execute Actions: Schedule patches, system updates and reboots.

It is designed to be run as a container remotely (HTTP) or locally (stdio), offering a streamlined way to integrate AI-driven automation into your system administration workflows.

## Table of Contents

- [Tool List](#tool-list)
- [Getting Started](#getting-started)
  - [Configuring the Server](#configuring-the-server)
  - [Running the Server](#running-the-server)
- [Security](#security)
  - [OAuth 2.0](#oauth-20)
  - [Best Practices](#best-practices)
- [Feedback](#feedback)
- [License](#license)
- [Disclaimer](#disclaimer)

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

## Getting Started

To use the Uyuni MCP Server, follow these two main steps:
1.  **Configuring the Server**: Set up the connection details for your Uyuni instance.
2.  **Running the Server**: Choose one of the provided methods to launch the server (e.g., as a container or a local script) and configure your MCP client how to connect to and interact with the server.

### Configuring the Server

Create a file (e.g., `uyuni-config.env`) to store your environment variables. You can place this file anywhere, but you must reference its path when running the server.

```bash
# Required fields
#
# Basic API parameters
UYUNI_SERVER=192.168.1.124:8443
UYUNI_USER=mcp-user
UYUNI_PASS=password

# Optional fields
#
# Set to 'false' to disable SSL certificate verification. Defaults to 'true'.
UYUNI_MCP_SSL_VERIFY=true

# Set to 'true' to enable tools that perform write actions (e.g., POST requests). Defaults to 'false'.
UYUNI_MCP_WRITE_TOOLS_ENABLED=false

# Set the transport protocol. Can be 'stdio' (default) or 'http'.
UYUNI_MCP_TRANSPORT=stdio

# Host and Port when using HTTP transport
UYUNI_MCP_HOST=127.0.0.1
UYUNI_MCP_PORT=8080

# OAuth 2.0 authorization server
UYUNI_AUTH_SERVER=auth.example.com

# Set the path for the server log file. Defaults to logging to the console.
UYUNI_MCP_LOG_FILE_PATH=/var/log/mcp-server-uyuni.log
# Set the logging level. Can be 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'. Defaults to 'INFO'.
UYUNI_MCP_LOG_LEVEL=DEBUG

# Required to bootstrap new systems into Uyuni via the `add_system` tool.
UYUNI_SSH_PRIV_KEY="-----BEGIN OPENSSH PRIVATE KEY-----\n..."
UYUNI_SSH_PRIV_KEY_PASS=""
```

> [!WARNING]
> **Security Note on Write Tools:** Enabling `UYUNI_MCP_WRITE_TOOLS_ENABLED` allows the execution of state-changing and potentially destructive actions (e.g., removing systems, applying updates). When combined with `UYUNI_MCP_TRANSPORT=http`, this risk is amplified, as any client with network access can perform these actions. Only enable write tools in a trusted environment.


> [!WARNING]
> **Security Note on HTTP Transport:** When `UYUNI_MCP_TRANSPORT` is set to `http` but `AUTH_SERVER` is not set, the server runs without authentication. This means any client with network access can execute commands. Only use this mode in a trusted, isolated network environment. For more details, see the Security Policy.


> [!WARNING]
> Note this feature expects OAuth 2.0 to be also supported in Uyuni at the `/manager/api/oicdLogin` endpoint. Otherwise, it will raise an error. See implementation status at [https://github.com/uyuni-project/uyuni/pull/11084](https://github.com/uyuni-project/uyuni/pull/11084). More info on implementation details at the Security Policy.

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

### Running the Server

Choose one of the following methods to run the server.

#### Option A: As a Client-Managed Container (Recommended)

With this method, the MCP client handles the lifecycle of the container. This is the easiest method for deployment, as it isolates the environment and requires no local dependencies other than a container engine (e.g., Docker).

Pre-built container images are available on the GitHub Container Registry. Refer to your MCP client's documentation for specific configuration syntax.

**Client Configuration Examples:**

*   **Using an environment file:**

    Replace `/path/to/uyuni-config.env` with the absolute path to your configuration file. Replace `VERSION` with the desired release tag (e.g., `v0.2.1`) or use `latest`.

    ```json
    {
      "mcpServers": {
        "mcp-server-uyuni": {
          "command": "docker",
          "args": [
            "run", "-i", "--rm",
            "--env-file", "/path/to/uyuni-config.env",
            "ghcr.io/uyuni-project/mcp-server-uyuni:VERSION"
          ]
        }
      }
    }
    ```

*   **Using environment variables:**

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

#### Option B: As a Standalone HTTP Server

This method is ideal for multi-user environments where you need a persistent, network-accessible server with OAuth 2.0 support.

First, ensure the following environment variables are set in your configuration:

```bash
UYUNI_MCP_TRANSPORT=http
UYUNI_MCP_HOST=0.0.0.0 # Or a specific interface
UYUNI_MCP_PORT=8080
UYUNI_AUTH_SERVER=auth.example.com
```

Then, run the container:

```bash
docker run --env-file /path/to/uyuni-config.env -p 8080:8080 ghcr.io/uyuni-project/mcp-server-uyuni:latest
```

Your MCP client can then connect to the server using its URL.

**Client Configuration Example:**
```json
{
  "mcpServers": {
    "mcp-server-uyuni": {
      "url": "http://127.0.0.1:8080/mcp",
      "type": "http"
    }
  }
}
```

> [!NOTE]
> The server runs on plain HTTP. For production environments, it is strongly recommended to use a reverse proxy (e.g., Nginx, Apache) to provide HTTPS encryption (TLS), handle certificates, and enhance security.

> [!WARNING]
> Unsetting `UYUNI_AUTH_SERVER` in HTTP mode bypasses OAuth, enabling any client on the network to access the server. This is only intended for trusted development environments.

#### Option C: Running Locally with `uv` (for development)

If you are developing or prefer running Python directly, you can use `uv`.

**Prerequisites:**

  * Install `uv`: [https://docs.astral.sh/uv](https://docs.astral.sh/uv)
  * Clone this repository
  * Sync dependencies from the root of the repository by running `uv sync`

**Setup and Run:**

To use the server in client-managed stdio mode, use the following configuration example:

```json
{
  "mcpServers": {
    "mcp-server-uyuni": {
      "command": "uv",
      "args": [
        "run",
        "--env-file", "/path/to/uyuni-config.env",
        "--directory", "/path/to/your/mcp-server-uyuni",
        "mcp-server-uyuni"
      ]
    }
  }
}
```

To run the server in standalone HTTP mode, use the following command:

```bash
uv run --env-file /path/to/uyuni-config.env --directory /path/to/your/mcp-server-uyuni mcp-server-uyuni
```


## Security

### OAuth 2.0

When running the server in HTTP mode (`UYUNI_MCP_TRANSPORT=http`), it is strongly recommended to secure it with an authentication layer. The server includes support for OAuth 2.0 to authenticate client requests. To enable it, set the `UYUNI_AUTH_SERVER` environment variable to your identity provider's URL.

#### Configuring an Identity Provider

[TODO]

### Best Practices

Follow these practices to harden your deployment.

#### Principle of Least Privilege
The Uyuni user configured via `UYUNI_USER` should have the minimum set of permissions required to perform its tasks. Avoid using highly privileged accounts like `admin`. See "Role-Based Access Control" in Uyuni documentation to fine-tune permissions.

#### Enable Write Actions Cautiously
Enabling state-changing tools with `UYUNI_MCP_WRITE_TOOLS_ENABLED=true` poses a significant risk. Only enable this in trusted environments and when all other security measures, such as authentication and HTTPS, are in place.

#### Secure Secrets
Avoid hardcoding secrets like passwords (`UYUNI_PASS`) or SSH keys (`UYUNI_SSH_PRIV_KEY`) in your configuration files, especially if they are checked into version control. Use a secrets management system (e.g., HashiCorp Vault, cloud provider secret stores) or inject them as environment variables at runtime. Ensure configuration files containing secrets (like `uyuni-config.env`) are not committed to Git.

### Production Logging
For production environments, configure structured logging to a file for monitoring and auditing:
- Set `UYUNI_MCP_LOG_FILE_PATH` to a secure location (e.g., `/var/log/mcp-server-uyuni.log`).
- Set `UYUNI_MCP_LOG_LEVEL` to `INFO` or `WARNING`.
Regularly review logs for unusual or unauthorized activity.


## Feedback

We would love to hear from you! Any idea you want to discuss or share, please do so at [https://github.com/uyuni-project/uyuni/discussions/10562](https://github.com/uyuni-project/uyuni/discussions/10562)

If you encounter any bug, be so kind to open a new bug report at [https://github.com/uyuni-project/mcp-server-uyuni/issues/new?type=bug](https://github.com/uyuni-project/mcp-server-uyuni/issues/new?type=bug)

Thanks in advance from the Uyuni team!


## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.


## Disclaimer

This is an open-source project provided "AS IS" without any warranty, express or implied. Use at your own risk. For full details, please refer to the [License](#license) section.
