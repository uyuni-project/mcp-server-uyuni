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

## MCP Server Authentication

*   **No Authentication:** Currently, the MCP server itself does not implement any form of authentication or authorization.
*   **Access Implication:** Anyone who has access to the environment where the MCP server can be run, can execute any of the tools and actions provided by the MCP server.

## Impact of Compromised Credentials

If the `config` file is compromised:

*   An attacker would gain access to the Uyuni server API with the privileges of the user defined in the config file.
*   An attacker could potentially also access the Uyuni server web UI using these credentials.

*   **Mitigation:** To limit the potential damage from compromised credentials, it is strongly recommended to use a dedicated Uyuni user account for the MCP server that has the minimum necessary permissions (limited access control) required for its operations. Avoid using highly privileged accounts like `admin` if possible.

## Reporting a Vulnerability

If you discover a security vulnerability, please report it to us. (TODO: Add contact information or procedure for reporting vulnerabilities).
