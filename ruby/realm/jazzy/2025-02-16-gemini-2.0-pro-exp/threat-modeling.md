# Threat Model Analysis for realm/jazzy

## Threat: [Source Code Exposure via Included Snippets](./threats/source_code_exposure_via_included_snippets.md)

*   **Threat:** Source Code Exposure via Included Snippets

    *   **Description:** Jazzy is configured to include source code snippets in the generated documentation.  If the source code contains hardcoded secrets (API keys, passwords, database credentials), Jazzy will directly expose this sensitive information in the generated HTML.
    *   **Impact:**
        *   Compromise of accounts and services associated with the exposed credentials.
        *   Unauthorized access to sensitive data.
        *   Reputational damage.
        *   Financial loss.
    *   **Affected Jazzy Component:**
        *   `SourceKitten` (used for parsing source code).
        *   The templating engine (which renders the source code snippets into HTML).
        *   Configuration options related to source code inclusion (`--[no-]hide-source-code`).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Remove Secrets:**  Never hardcode secrets in source code. Use environment variables, configuration files, or secret management services.
        *   **Disable Source Code Inclusion:** Use `--hide-source-code` or set `hide_source_code: true` in `.jazzy.yaml`.
        *   **Code Review:**  Implement a code review process that specifically checks for hardcoded secrets.
        *   **Automated Scanning:** Use tools to automatically scan source code for potential secrets before running Jazzy.

## Threat: [Internal API Exposure](./threats/internal_api_exposure.md)

*   **Threat:** Internal API Exposure

    *   **Description:** Jazzy is configured (or misconfigured) to document internal or private APIs that were not intended for public consumption. This directly exposes the internal structure and potentially vulnerable parts of the codebase.
    *   **Impact:**
        *   Increased attack surface.
        *   Potential for unauthorized access to data or functionality.
        *   Bypass of security controls.
    *   **Affected Jazzy Component:**
        *   `SourceKitten` (parsing of source code).
        *   Configuration options related to access control (`--[no-]skip-undocumented`, `--min-acl`).
        *   Jazzy's handling of access control modifiers (private, fileprivate, internal, public).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Use Access Control Modifiers:**  Consistently use `private`, `fileprivate`, and `internal` (or Objective-C equivalents) to restrict the visibility of APIs.
        *   **`--min-acl` Option:** Use the `--min-acl` option (e.g., `--min-acl internal`) to specify the minimum access level to be included in the documentation.
        *   **`--exclude` Option:**  Use the `--exclude` flag or the `exclude` option in `.jazzy.yaml` to explicitly exclude specific files, directories, or symbols.
        *   **Code Review:** Ensure that access control modifiers are used correctly and consistently.

## Threat: [Configuration File Tampering](./threats/configuration_file_tampering.md)

*   **Threat:** Configuration File Tampering

    *   **Description:** An attacker with access to the build environment modifies the `.jazzy.yaml` file (or command-line arguments *used to invoke Jazzy*) to alter the documentation generation process. They might exclude critical sections, include misleading information, or change settings to expose internal APIs. This directly impacts Jazzy's behavior.
    *   **Impact:**
        *   Incomplete or misleading documentation.
        *   Increased attack surface (if internal APIs are inadvertently exposed).
    *   **Affected Jazzy Component:**
        *   Jazzy's configuration parsing logic.
        *   All other components are indirectly affected by the configuration.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Secure Configuration File:** Store the `.jazzy.yaml` file in a secure location with restricted access (within the development environment).
        *   **Version Control:** Use version control (e.g., Git) to track changes to the configuration file.
        *   **Integrity Checks:** Validate the configuration file's integrity (e.g., using a checksum) before running Jazzy.
        *   **Code Review:** Review any changes to the configuration file as part of the code review process.

