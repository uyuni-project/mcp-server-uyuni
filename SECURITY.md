# Security Policy

This document outlines the security considerations for the MCP Server for Uyuni.

## Credentials Management

Access to the Uyuni server is managed via a config file.

*   **File Name:** `config`
*   **Typical Location:** `.venv/config`

This file contains sensitive information required to authenticate with the Uyuni server API.

```
UYUNI_SERVER=<your_uyuni_server_address>
UYUNI_USER=<your_uyuni_username>
UYUNI_PASS=<your_uyuni_password>
```

*   **Critical:** This `config` file **must not be shared or committed to version control**. It should be treated as highly confidential.
*   **Usage:** The MCP server imports this file as an environment file to obtain the necessary credentials for interacting with the Uyuni server.

## MCP Server Authentication and Authorization

*   **No Authentication:** Currently, the MCP server itself does not implement any form of authentication or authorization.
*   **Access Implication:** Anyone who has access to the environment where the MCP server can be run, can execute any of the tools and actions provided by the MCP server.

### Write Tool Enablement (Default: Disabled)

By default, the server runs in a **read-only** mode for safety. All tools that can change the state of the Uyuni server or the systems it manages (e.g., `remove_system`, `schedule_apply_pending_updates_to_system`) are disabled and not visible to the language model.

To enable these "write tools", you must explicitly set the `UYUNI_MCP_WRITE_TOOLS_ENABLED` environment variable to `true`.

> [!WARNING]
> Enabling write tools is a significant security decision. It grants any client that can connect to the MCP server the ability to perform destructive actions. This risk is amplified when using the `http` transport.

### Transport Layer Implications

The server can be run with two different transport layers, configured via the `UYUNI_MCP_TRANSPORT` environment variable:

*   **`stdio` (default):** In this mode, the server communicates over standard input/output. Access is limited to processes that can execute the server binary directly on the host machine. This is the most secure mode of operation.
*   **`http`:** In this mode, the server runs as an HTTP service. Because there is no authentication layer, **any client with network access to the server's host and port can execute any tool**.

> [!WARNING]
> Running the server with `UYUNI_MCP_TRANSPORT=http` and `UYUNI_MCP_WRITE_TOOLS_ENABLED=true` in an untrusted network environment poses a significant security risk. This combination allows any client with network access to perform destructive actions without authentication. It is strongly recommended to use this configuration only in isolated, trusted networks or to implement network-level controls (e.g., firewall rules) to restrict access to authorized clients only.

## Tool Execution and Confirmation

Tools that perform state-changing or destructive actions (e.g., `remove_system`, `schedule_system_reboot`) are designed with a two-step confirmation flow using a `confirm: bool = False` parameter. By default, the tool returns a confirmation prompt and only performs the action when called a second time with `confirm=True`.

### Risks of Bypassing Confirmation

The confirmation flow using the `confirm` parameter is a **trust-based, stateless pattern**. The server does not maintain any state between the initial call (where `confirm=False`) and the confirmation call (`confirm=True`). It simply trusts that if it receives a request with `confirm=True`, the client has obtained the necessary user consent.

A malicious or non-compliant client can exploit this trust by completely bypassing the user interaction step. Instead of making two calls as intended, it can make a single, direct call to the tool with the `confirm` parameter already set to `True`.

Since the server is stateless and only checks the value of `confirm` in the current request, it has no way to know that the user was never prompted. It will proceed to execute the destructive action immediately, without user consent.

### Elicitation as a More Secure Alternative

The Model Context Protocol (MCP) provides a more secure and robust mechanism for user interaction called **Elicitation**. Unlike the stateless `confirm` parameter, elicitation is a **stateful, protocol-mandated request-response cycle**.

When a tool uses `ctx.elicit()`:
1.  The server sends a formal `elicitation/create` request to the client.
2.  The tool's execution on the server is **paused**, actively awaiting a specific response to that request.
3.  A compliant client is required by the protocol to handle this request and cannot simply ignore it. It must present the prompt to the user and return their action (`accept`, `decline`, or `cancel`).

This stateful pause makes it significantly more difficult for a client to bypass the confirmation step, as it must now participate in a formal protocol exchange rather than simply setting a boolean flag. It is the recommended way to handle user confirmations whenever the client supports it.

### Fallback Mechanism

Since elicitation is a recent addition to the MCP specification, not all clients support it. Therefore, tools in this server **must** implement both mechanisms:
1.  Check if the client supports elicitation. If so, use `ctx.elicit()` for confirmations or to request missing data.
2.  If the client does not support elicitation, fall back to the `confirm: bool` parameter and text-based prompt mechanism.

This dual approach ensures both maximum security with modern clients and graceful degradation for older clients.

## SSH Private Key Management (`add_system` tool)

*   **Context:** The `add_system` tool requires an SSH private key to bootstrap new systems into Uyuni. This key is supplied via the `UYUNI_SSH_PRIV_KEY` environment variable.

*   **Risk of Exposure:** Storing a private key in an environment variable carries inherent risks. An attacker who gains access to the host running the MCP server (e.g., through a different vulnerability) could potentially read the environment variables of the running process and exfiltrate the private key.

*   **Mitigation through Network Isolation:** The primary mitigation for this risk is based on network architecture. The `add_system` tool does not use the key to connect from the MCP server host directly. Instead, it passes the key to the main Uyuni server through an API call. It is the **Uyuni server** that then initiates the SSH connection to the target machine.

    Therefore, you can significantly mitigate the risk by running the MCP server on a host that is in a separate, isolated network from the client machines it will add. If the MCP server host has no network route to the target client systems (e.g., it cannot reach them on the SSH port), the compromised key is of no use to an attacker on that host for direct access. The key's utility is confined to the Uyuni API, which is already protected by the `UYUNI_USER` and `UYUNI_PASS` credentials.

## Impact of Compromised Credentials

If the `config` file is compromised:

*   An attacker would gain access to the Uyuni server API with the privileges of the user defined in the config file.
*   An attacker could potentially also access the Uyuni server web UI using these credentials.

*   **Mitigation:** To limit the potential damage from compromised credentials, it is strongly recommended to use a dedicated Uyuni user account for the MCP server that has the minimum necessary permissions (limited access control) required for its operations. Avoid using highly privileged accounts like `admin` if possible.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it to us by creating a [security advisory[(https://github.com/uyuni-project/mcp-server-uyuni/security/advisories)].
