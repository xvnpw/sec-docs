# Attack Surface Analysis for simplecov-ruby/simplecov

## Attack Surface: [1. Information Disclosure via Exposed Reports](./attack_surfaces/1__information_disclosure_via_exposed_reports.md)

*   **Description:**  Leakage of sensitive application information through publicly accessible SimpleCov reports (HTML or data files).
    *   **How SimpleCov Contributes:** SimpleCov generates these reports, which contain detailed information about the application's codebase and execution paths.  This is the *direct* contribution.
    *   **Example:** An attacker accesses `https://example.com/coverage/index.html` and discovers the internal directory structure, class names, and which parts of the code are not covered by tests.
    *   **Impact:**
        *   Provides attackers with a roadmap of the application's internal structure.
        *   Reveals untested code paths, which are more likely to contain vulnerabilities.
        *   Facilitates the creation of targeted exploits.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Never deploy coverage reports to production.** This is the most crucial mitigation.
        *   Restrict access to reports in staging/development using strong authentication (e.g., HTTP Basic Auth, VPN, IP whitelisting).
        *   Store reports in a secure, non-web-accessible directory with appropriate file permissions.
        *   Use random, non-predictable URLs for reports.
        *   Configure web servers to explicitly deny access to the coverage directory.
        *   Use a separate, isolated environment for generating reports.

## Attack Surface: [2. Information Disclosure via Data Files](./attack_surfaces/2__information_disclosure_via_data_files.md)

*   **Description:**  Leakage of sensitive application information through exposed SimpleCov data files (e.g., `.last_run.json`).
    *   **How SimpleCov Contributes:** SimpleCov stores coverage data in these files, which contain similar information to the HTML reports. This is the *direct* contribution.
    *   **Example:** An attacker finds and downloads `https://example.com/.last_run.json` and uses a script to parse the file, extracting information about code coverage and file paths.
    *   **Impact:**  Same as with exposed HTML reports – provides attackers with valuable information for crafting exploits.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**  Identical to those for HTML reports (see above). Treat data files with the same level of security as the HTML reports.

