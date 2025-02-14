# Attack Surface Analysis for nikic/fastroute

## Attack Surface: [Overly Permissive Routes (Route Parameter Injection/Manipulation)](./attack_surfaces/overly_permissive_routes__route_parameter_injectionmanipulation_.md)

*   **Description:** Attackers can inject malicious input into route parameters if the route definitions are too broad or use insufficiently restrictive regular expressions. This is the most direct and significant FastRoute-related risk.
    *   **How FastRoute Contributes:** FastRoute's core functionality is defining routes and extracting parameters.  The vulnerability stems directly from how developers *configure* routes using FastRoute's API. The library provides the *means* for this vulnerability to exist, even if it's not a flaw in the library itself.
    *   **Example:**
        *   **Vulnerable Route:** `/user/{id:.*}` (allows any character in the `id` parameter)
        *   **Attacker Input:** `/user/../../etc/passwd` (directory traversal attempt)
        *   **Safer Route:** `/user/{id:[0-9]+}` (only allows digits)
    *   **Impact:**  Depends on the handler's logic, but can be severe:
        *   Information Disclosure (e.g., reading arbitrary files)
        *   Code Execution (if the parameter is used unsafely, e.g., in an `eval()`) 
        *   SQL Injection (if the parameter is used in a database query without sanitization)
        *   Denial of Service
    *   **Risk Severity:** High to Critical (depending on the impact)
    *   **Mitigation Strategies:**
        *   **Developer:** Use the *most restrictive* regular expressions possible for route parameters.  Prioritize specific character classes and quantifiers (e.g., `[0-9]+`, `[a-zA-Z0-9_-]{1,32}`).
        *   **Developer:** *Never* assume FastRoute's regex matching provides sufficient security. *Always* validate and sanitize *all* route parameters within the handler function, treating them as untrusted input. This is crucial even if the regex *appears* to be safe.
        *   **Developer:** Avoid using `.*`, `.+`, or overly broad character classes in route parameter regexes.
        *   **Developer:** Favor more specific route definitions over heavy reliance on parameters (e.g., `/products/create` instead of `/products/{action}`).

## Attack Surface: [Regular Expression Denial of Service (ReDoS)](./attack_surfaces/regular_expression_denial_of_service__redos_.md)

*   **Description:**  Attackers can craft malicious input strings that cause computationally expensive regular expression matching, leading to a denial-of-service. This is directly related to how developers use regular expressions *within* FastRoute route definitions.
    *   **How FastRoute Contributes:** FastRoute allows (and often requires) the use of regular expressions for route matching, particularly for route parameters.  The vulnerability arises from using poorly designed or vulnerable regular expressions *within this context*.
    *   **Example:**
        *   **Vulnerable Regex (in route parameter):** `/{id:(a+)+$}/` (nested quantifiers)
        *   **Attacker Input:** A long string of "a" characters followed by a "b" (can cause exponential backtracking)
    *   **Impact:** Denial of Service (the application becomes unresponsive due to excessive CPU usage)
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Developer:** Avoid using complex or nested quantifiers (e.g., `(a+)+$`, `(a*)*`) in regular expressions used in FastRoute route definitions.
        *   **Developer:** Use a regular expression analysis tool (e.g., RegexBuddy, online ReDoS checkers) to identify potentially vulnerable patterns *before* deploying code.
        *   **Developer:** Implement timeouts for regular expression matching (to prevent the engine from running indefinitely). This is a crucial defense-in-depth measure.
        *   **Developer:** Prefer simpler, more specific route definitions over complex regular expressions.  Use character classes and specific quantifiers (e.g., `{1,3}` instead of `+` or `*` when possible).
        * **Developer:** If complex regex are unavoidable, consider using a library or function that provides ReDoS-safe regular expression matching, or pre-compile and test the regex extensively.

