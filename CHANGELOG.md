## 0.6.3 (2026-11-10)

### Security

* **deps:** upgrade `multidict` to 6.9.1 to patch CVE-2026-104874 (GHSA-54p9-h82j-f925)
* **deps:** upgrade `authlib` to 1.9.1 to patch CVE-2026-96760, CVE-2026-114614, CVE-2026-114616, CVE-2026-114617, CVE-2026-114618, CVE-2026-114619, CVE-2026-114620, GHSA-c73q-w75p-j82v, and GHSA-7vr2-2fgp-9w7p
* **deps:** upgrade `aiohttp` to 3.14.4 to patch CVE-2026-111064, CVE-2026-111065, CVE-2026-111066, CVE-2026-111749, GHSA-f9xw-jh8m-3mwq, GHSA-pqxq-w44r-73xw, GHSA-5wr8-gcqf-gqf3, and GHSA-2g87-pp6c-29x5
* **deps:** upgrade `pyasn1` to 0.6.5 to patch CVE-2026-119196, CVE-2026-119197, CVE-2026-119195 CVE-2026-119194GHSA-2qm8-x737-gmw5, GHSA-mm57-4v3p-rchx, GHSA-9m75-vc3g-4x39, and GHSA-fm9c-5rcf-2q5p
* **deps:** upgrade `mcp` to 1.30.0 to patch CVE-2026-116685, GHSA-w4fh-qvv9-3v23, GHSA-rwrf-2pqf-9j8j, and GHSA-84m7-p3x7-pcfv
* **deps:** upgrade `joserfc` to 1.7.7 to patch CVE-2026-119283 and CVE-2026-119284 (GHSA-9pg5-8c7x-5hfx, GHSA-jpxq-7h8p-2q76)
* **deps:** upgrade `dnspython` to 2.9.0 to patch CVE-2026-114605 (GHSA-45c3-73f7-pv4m)
* **deps:** upgrade `fastmcp-slim` to 3.4.11 to patch GHSA-7xgj-8392-5q4r (Dependabot alert #114)
* **deps:** upgrade `certifi` to 2026.10.23 to patch GHSA-6q48-6c7w-9gw2 (Dependabot alert #116)
* **deps:** upgrade `opentelemetry-api` to 1.45.1 to patch GHSA-xcq7-p3pf-p88h
* **deps:** upgrade `setuptools` to 84.1.0 to patch GHSA-xmj3-9gf7-h52w

### Packaging

* **packaging:** align openSUSE Factory spec file dependencies (`anyio` 4.15.1, `typing-extensions` 4.16.0)
* **deps:** update `yarl` to 1.25.1 as an indirect dependency required by the `aiohttp` upgrade

## 0.6.2 (2026-10-06)

### Security

* **deps:** upgrade `anyio` to 4.14.2 to patch CVE-2026-63374, CVE-2026-64847
* **deps:** upgrade `PyJWT` to 2.15.1 to patch CVE-2026-102270, CVE-2026-102272,, CVE-2026-102269, CVE-2026-102265, CVE-2026-101918, CVE-2026-101917, CVE-2026-102274, CVE-2026-103001, CVE-2026-102271, CVE-2026-102273, CVE-2026-102266, CVE-2026-102272, CVE-2026-102268 
* **deps:** upgrade `urllib3` to 2.8.0 to patch CVE-2026-97688, CVE-2026-97687, CVE-2026-97689

## 0.6.1 (2026-08-12)

### Security

* **deps:* upgrade `crytopgraphy`to 0.5.0 to patch CVE-2026-69247 - Dependabot securit alert #83

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
