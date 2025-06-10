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
