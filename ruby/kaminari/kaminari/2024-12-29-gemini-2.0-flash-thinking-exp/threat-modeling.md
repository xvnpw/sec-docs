*   **Threat:** Excessive `per_page` Parameter Manipulation
    *   **Description:** An attacker modifies the `per_page` URL parameter to an extremely large value. This forces Kaminari to attempt fetching and potentially rendering a massive number of records.
    *   **Impact:**
        *   **Denial of Service (DoS):** The database server and application server become overloaded, leading to slow response times or complete unavailability for legitimate users.
        *   **Resource Exhaustion:** The application server might run out of memory trying to process and render a huge dataset.
    *   **Affected Kaminari Component:** `Kaminari.paginate_array` or similar pagination methods, which are directly influenced by the `per_page` parameter.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement strict server-side validation and sanitization of the `per_page` parameter *before* it's passed to Kaminari.
        *   Define a reasonable maximum allowed value for `per_page`.
        *   Consider using a whitelist of allowed `per_page` values.

*   **Threat:** Vulnerabilities in Kaminari Gem Itself
    *   **Description:** Kaminari, like any software, might contain undiscovered security vulnerabilities in its code.
    *   **Impact:** Exploiting these vulnerabilities could lead to various security breaches depending on the nature of the flaw, potentially allowing attackers to bypass security measures or gain unauthorized access.
    *   **Affected Kaminari Component:** Potentially any part of the Kaminari codebase.
    *   **Risk Severity:** Varies depending on the specific vulnerability (can be Critical or High).
    *   **Mitigation Strategies:**
        *   Keep Kaminari updated to the latest stable version to benefit from security patches.
        *   Monitor security advisories and changelogs for Kaminari.
        *   Consider using tools like `bundle audit` to check for known vulnerabilities in your dependencies.