# Contributing to MCP Server Uyuni

First off, thank you for considering contributing to MCP Server Uyuni! Your help is appreciated.

## How to Contribute

We welcome contributions in various forms, including:

- Reporting bugs
- Suggesting enhancements
- Submitting pull requests for new features or bug fixes

## Commit Message Guidelines

To ensure a consistent and readable commit history, which helps in generating changelogs and understanding project evolution, we follow the **Conventional Commits** specification.

**Format:**

Each commit message consists of a **header**, a **body**, and a **footer**.

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Type:** Must be one of the following:
  - `feat`: A new feature
  - `fix`: A bug fix
  - `docs`: Documentation only changes
  - `style`: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
  - `refactor`: A code change that neither fixes a bug nor adds a feature
  - `perf`: A code change that improves performance
  - `test`: Adding missing tests or correcting existing tests
  - `build`: Changes that affect the build system or external dependencies (example scopes: gulp, broccoli, npm)
  - `ci`: Changes to our CI configuration files and scripts (example scopes: Travis, Circle, BrowserStack, SauceLabs)
  - `chore`: Other changes that don't modify src or test files

**Scope (Optional):** The scope provides additional contextual information and is contained within parentheses, e.g., `feat(api): add new endpoint`.

**Description:** A short, imperative mood description of the change.

**Body (Optional):** A longer description providing more context.

**Footer (Optional):** Can contain information about breaking changes or issue tracking (e.g., `BREAKING CHANGE: ...` or `Closes #123`).

**Example:**
```
feat(system): add endpoint for listing active systems

This commit introduces a new API endpoint `/systems/active`
that returns a list of all currently active systems managed by Uyuni.
```

For more details, please refer to the [Conventional Commits specification](https://www.conventionalcommits.org/en/v1.0.0/).

### Git Hook

To help you format your commit messages correctly, you can use the provided `prepare-commit-msg.template`.
Copy this file to your local `.git/hooks/prepare-commit-msg` directory and make it executable:

```bash
cp prepare-commit-msg.template .git/hooks/prepare-commit-msg
chmod +x .git/hooks/prepare-commit-msg
```
This hook will prepend a basic template to your commit message editor.

## Learnings and Patterns for MCP Tool Development

When developing tools for an MCP server, the primary consumer is an LLM. This requires a slightly different approach than traditional API design where a human is reading documentation. The following are some best practices and patterns we've learned that help the LLM understand and use the tools more effectively.

### Be Explicit, Verbose, and Redundant

The LLM relies almost entirely on your tool's docstring and the structure of its return data to understand its purpose and how to use it. You need to be overly explicit to bridge the gap between the user's intent and the tool's function.

*   **Docstrings are your API spec for the LLM:** Be verbose. Clearly describe what the tool does, what each parameter means, and what the structure of the returned data will be.
*   **Design for flexible inputs:** A user might ask, "get updates for system 1000010000" or "get updates for system 'buildhost'". The LLM will infer `1000010000` as an integer and `'buildhost'` as a string. Your tool's signature should handle this (e.g., `system_identifier: Union[str, int]`) and your implementation must be robust enough to resolve either type to the correct system. Crucially, **document this flexibility in the docstring** so the LLM knows it's a valid pattern.
*   **Design clear and self-contained outputs:**
    *   **Avoid ambiguous keys:** Instead of a generic `{'id': 123}`, prefer a specific key like `{'system_id': 123}`. An LLM might not correctly infer that `id` in the context of a system list refers to a `system_id`.
    *   **Include input parameters in the output:** If a tool is called with `get_cpu_of_a_system(system_identifier='buildhost')`, the return dictionary should include that identifier, like `{'system_identifier': 'buildhost', 'cores': 8, ...}`. This helps the LLM connect the result back to the original query and prevents it from "forgetting" which system the data belongs to. Without this, the LLM might correctly call the tool but then claim it doesn't have the information it just received.

### Let the Framework Handle Serialization

FastMCP is designed to correctly serialize your Python objects into the JSON and text formats that the MCP client and LLM expect. You should not do this manually.

*   **Return native Python types:** Your tools should return standard Python objects like dictionaries and lists.
*   **Example:** If your tool needs to return a list of systems, it should return a Python `list` of `dict`s. FastMCP will convert this into a proper JSON array of objects. If you were to call `json.dumps()` on the list yourself, you would return a single JSON *string* that contains an array, which is not what the LLM can parse and use effectively.

### Handle State-Changing Actions with a Confirmation Flow

For any tool that modifies state (applies updates, reboots a system, cancels an action), it is critical to prevent the LLM from taking destructive actions without explicit user consent. A reliable pattern for this is to include a confirmation parameter.

*   **Add a `confirm: bool = False` parameter:** Make it default to `False`.
*   **Return a confirmation prompt:** If `confirm` is `False`, the tool should not perform the action. Instead, it should return a clear string asking the user for confirmation.
*   **Instruct the LLM in the docstring:** The parameter's description must explicitly tell the LLM to ask the user for confirmation and only call the tool again with `confirm=True` after the user has agreed.

**Example from `schedule_system_reboot`:**
```python
@mcp.tool()
async def schedule_system_reboot(system_identifier: Union[str, int], confirm: bool = False) -> str:
    """
    ...
    Args:
        ...
        confirm: False by default. Only set confirm to True if the user has explicetely confirmed. Ask the user for confirmation.
    """
    if not confirm:
        return f"CONFIRMATION REQUIRED: This will reboot system {system_identifier}. Do you confirm?"
    # ... proceed with reboot logic ...
```

### Design for Predictable Failure and Composition

*   **Avoid Raising Exceptions:** LLMs do not handle exceptions well. A tool that raises an unhandled exception can break the conversational flow. Instead of raising an error (e.g., for a 404 Not Found), have the tool return a predictable "empty" or "failed" value. For example, return an empty list (`[]`), an empty dictionary (`{}`), or a dictionary that clearly indicates failure, like `{'has_pending_updates': False, 'updates': []}`.
*   **Embrace Tool Composition:** Build more complex tools by having them call simpler, existing tools. This promotes code reuse and modularity. For instance, `check_all_systems_for_updates` works by iterating through all systems and calling `check_system_updates` for each one. This makes the toolset more powerful and easier to maintain.
