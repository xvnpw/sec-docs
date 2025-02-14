# Threat Model Analysis for nikic/fastroute

## Threat: [Threat: Route Information Disclosure via Error Messages](./threats/threat_route_information_disclosure_via_error_messages.md)

*   **Description:** An attacker sends crafted requests that trigger errors *within FastRoute's dispatcher or related components*. The attacker aims to elicit verbose error messages that reveal internal route definitions, parameter names, or dispatcher logic. This is distinct from general application error handling; it focuses on errors *originating from FastRoute itself*.
*   **Impact:**
    *   Exposure of sensitive internal application structure (routes, parameters).
    *   Facilitates further attacks by providing a roadmap of the application's routing.
    *   Potential leakage of FastRoute version information.
*   **FastRoute Component Affected:**
    *   `FastRoute\Dispatcher` (specifically, error handling *within* the dispatcher logic).
    *   Any custom error handlers *directly integrated with FastRoute's internal mechanisms*.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Disable Debug Mode:** Ensure that FastRoute's internal debug mode (if any) is completely disabled in production. This is paramount.
    *   **Generic Error Handling (FastRoute Specific):** Implement custom error handling *within FastRoute's dispatcher* (if extending or modifying it) to ensure that no internal routing details are exposed in error messages.  This might involve catching exceptions within the dispatcher and returning generic responses.
    *   **Log Securely:** Log detailed FastRoute-specific error information to a secure, inaccessible location.

## Threat: [Threat: Unvalidated Route Parameter Injection (Direct FastRoute Handling)](./threats/threat_unvalidated_route_parameter_injection__direct_fastroute_handling_.md)

*   **Description:** While the *vulnerability* is a general injection (SQLi, etc.), this threat focuses on the scenario where FastRoute's handling of parameters *directly contributes* to the vulnerability. This would occur if, for example, a custom dispatcher or route collector were implemented that *directly* used parameters without proper sanitization *before* passing them to application logic.  This is *not* the standard usage, but it's a potential risk if extending FastRoute.
*   **Impact:**
    *   Data breaches (SQLi).
    *   Unauthorized file access (path traversal).
    *   Remote code execution (command injection).
    *   Complete system compromise.
*   **FastRoute Component Affected:**
    *   `FastRoute\Dispatcher` (custom implementations that directly handle parameters unsafely).
    *   `FastRoute\RouteCollector` (custom implementations).
    *   Any custom code that interacts directly with FastRoute's internal data structures.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Sanitize Within Custom Components:** If creating custom dispatchers, route collectors, or other components that interact directly with FastRoute's internal data, *always* sanitize route parameters *before* using them in any sensitive context. This is crucial for any custom FastRoute extensions.
    *   **Follow Secure Coding Practices:** Adhere to secure coding principles when extending or modifying FastRoute.  Assume all data from route parameters is untrusted.
    *   **Code Review:** Thoroughly review any custom FastRoute code for potential injection vulnerabilities.

