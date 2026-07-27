## 0.6.0 (2026-07-27)

### Security

* **deps:** upgrade `fastmcp` to 3.3.1 to patch CVE-2026-32871, CVE-2026-27124, and CVE-2025-64340
* **deps:** upgrade `lupa` to patch CVE-2026-34444
* **deps:** update `cryptography` to 46.0.7 to resolve Dependabot security alerts (#12, #22)
* **deps:** update `authlib` to 1.6.12 to resolve Dependabot security alerts (#13, #15, #16, #17)
* **deps:** update core Python dependencies (`urllib3`, `aiohttp`, `requests`, `python-multipart`, `idna`, `certifi`) to address indirect security advisories and maintain compatibility

### Features

* **auth:** enable PKCE in Keycloak and harden auth config contract
* **core:** optimize context usage with pagination and update query tools
* **core:** add configurable HTTP timeout
* **core:** share login authentication across concurrent API calls
* **elicitation:** use elicitation mechanisms to confirm write actions
* **proxy:** add DCR sanitizer proxy to support Amazon Quick
* **deploy:** add local Keycloak dev stack, realm import, and deployment stack
* **deploy:** add public Uyuni hostname routing via socat

### Bug Fixes

* **api:** fix scheduling updates for Red Hat-like systems
* **auth:** await FastMCP context `set_state` in middleware
* **logging:** prevent duplicate log entries
* **tools:** remove `union` types from tool signatures
* **docker:** update Uyuni image Dockerfiles to use Python 3.13

### Refactoring & Infrastructure

* **auth:** refactor token extraction and system ID resolution helper methods
* **utils:** split utility modules by domain functionality

### Testing & Quality Assurance

* **e2e:** implement E2E testing framework using DeepEval
* **eval:** improve evaluation agentic loop with multi-turn data accumulation
* **oauth2:** add acceptance tests and headless OIDC flow for CI integration
* **testsuite:** reword prompts to direct instructions and update test configurations

### CI/CD & DevOps

* **ci:** add multi-arch container image builds (`amd64` + `arm64`)
* **ci:** generate container image provenance attestations and SBOMs
* **ci:** pin GitHub Actions to commit SHAs for supply-chain security
* **deps:** add Python dependency monitoring to Dependabot and automate spec file updates

### Documentation

* **docs:** add OAuth2 setup instructions, Keycloak realm details, and architecture diagrams to `deploy/README.md`
* **docs:** explicitly describe confirmation behavior and shorten MCP tool descriptions

## 0.5.2 (2026-02-09)

### Bug Fixes

* **system**: Fix schedule update

## 0.5.1 (2026-02-05)

### Release
 Prepare release in registry.suse.com
 * Review python dependencies
 * Add traceability (last commit id)
 * Add product name
 * Add packaging files for mlm (RPM and container)

### Docs
 * Update README with additional sections

# Development
 * Allow debug level change by setting a new environment variable

## 0.5.0 (2025-12-30)

### Features

* **security:** OAuth support with external idP
* **security:** add write-enable flag to control state-changing tools
* **system group:** add tools to add, list and remove systems from groups 
* **system gorup:** add tool to create system groups
* **errata:** add tool to get unscheduled errata
* **system:** add system search tools
* **system:** add network information to system details tool


### Bug Fixes

* **all:** update to latest fastmcp and review dependencies
* **all:** fix update fastmcp v2 function call
* **security:** use UYUNI_MCP_SSL_VERIFY environment variable instead of "false"
* **all:** standarize tool naming
* **all:** standarize logging and status reporting
* **all:** fix API error handling
* **system:** reorganize system list/detail tools
* **all:** improve confirmation

## 0.4.0 (2025-07-23)

### Features

* **activation_key:** add tool to list activation keys
* **schedule:**: add tool to get unscheduled errata
* **all**: add Streamable HTTP transport
* **all**: add support for server and client logging
* **system:** improve check system updates tool by checking unscheduled updates
* **system:** accept system name as well as ids in our tools
* **system:** add tool to remove system
* **system:** add elicitation into add system tool
* **systems:** add tool to add system with activation key

### Bug Fixes

* **network:** use verified https by default

##  0.3.0 (2025-06-26)

### Features

* **all:** add confirmation for those tools that change the systems
* **schedule:** add tools for canceling an action and listing all
* **all:** add container

## 0.2.1 (2025-06-12)

### Features

* **system:** add tool for scheduling a specific update

## 0.2.0 (2025-06-11)

### Features
* **system:** add tool for scheduling a system update
* **errata:** add a tool to check which systems are affected by a security issue identified by a CVE
* **system:** add a tool to check which systems need a reboot
* **system:** add a tool to schedule a system reboot

## 0.1.0 (2025-06-04)

### Features

* **system:** add tool for listing active systems
* **system:** add tool for getting cpu information of a system
* **system:** add tool for getting all systems cpu information
* **system:** add tool for checking system updates
* **system:** add tool for checking all systems for updates
