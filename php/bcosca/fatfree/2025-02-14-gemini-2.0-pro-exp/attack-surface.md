# Attack Surface Analysis for bcosca/fatfree

## Attack Surface: [Route Parameter Manipulation](./attack_surfaces/route_parameter_manipulation.md)

*Description:* Attackers exploit vulnerabilities in how F3 handles URL parameters within defined routes.
*How F3 Contributes:* F3's routing system *relies heavily* on URL parameters.  The framework *itself* doesn't enforce strict validation; it's the developer's responsibility.  This reliance on parameters, combined with potential developer oversight, is the core F3-specific risk.
*Example:*
    *   Route: `/product/@id`
    *   Attack: `/product/../../../etc/passwd` (Path Traversal) or `/product/-1` (Invalid Input)
*Impact:*  Information disclosure, unauthorized access to resources, potential code execution (if combined with other vulnerabilities).
*Risk Severity:* High to Critical (depending on the data exposed and the application's logic).
*Mitigation Strategies:*
    *   **Developer:** Use F3's type hinting in route definitions (e.g., `@id:int`).  Implement strict input validation and sanitization for *all* route parameters.  Use regular expressions to enforce expected formats.  Avoid using route parameters directly in file system operations or database queries without proper escaping/parameterization.  Test routes thoroughly, including edge cases and invalid inputs.

## Attack Surface: [Template Injection (via Unsafe Output)](./attack_surfaces/template_injection__via_unsafe_output_.md)

*Description:* Attackers inject malicious code into F3 templates, which is then executed by the server.
*How F3 Contributes:* F3's template engine *provides* escaping mechanisms, but it also *allows* developers to bypass them using `| raw` or disable escaping entirely.  This *framework-provided option* to bypass security is the key F3-specific risk.  The framework *doesn't prevent* unsafe practices.
*Example:*
    *   Template: `<h1>Hello, {{ @name | raw }}</h1>`
    *   Attack: User input for `@name`: `<script>alert('XSS')</script>` or even F3 template syntax or PHP code.
*Impact:*  Cross-Site Scripting (XSS), potential Remote Code Execution (RCE) if the template engine allows PHP code execution, data theft, session hijacking.
*Risk Severity:* Critical
*Mitigation Strategies:*
    *   **Developer:**  *Always* use F3's built-in escaping mechanisms (`{{ @variable }}`).  *Never* use `| raw` with untrusted data.  Understand the context of escaping (HTML, JavaScript, etc.) and use the appropriate escaping function.  Sanitize user input *before* passing it to the template engine, even if escaping is used (defense-in-depth).

## Attack Surface: [Cache Poisoning](./attack_surfaces/cache_poisoning.md)

*Description:* Attackers manipulate cache keys or content to store malicious data in F3's cache, which is then served to other users.
*How F3 Contributes:* F3 *provides* various caching mechanisms (file, memcache, etc.) and the *framework itself* doesn't enforce secure cache key generation.  The responsibility for secure key generation and configuration lies entirely with the developer, making misconfiguration a direct F3-related risk.
*Example:*
    *   Cache key based on a user-supplied `language` parameter: `cache_key = "page_" + $_GET['language']`
    *   Attack: Attacker sets `language` to a malicious value, causing malicious content to be cached and served to users requesting that language.
*Impact:*  Serving malicious content to users, potentially leading to XSS, data theft, or other attacks.
*Risk Severity:* High
*Mitigation Strategies:*
    *   **Developer:**  Generate cache keys based on *trusted* data, *not* directly on user input.  Validate and sanitize any user input used in cache key generation.  Use separate cache namespaces for different types of data.  Implement cache key prefixes or suffixes to prevent collisions.  Regularly monitor cache contents.
    *   **User/Administrator:** Configure cache expiration times appropriately.  Monitor cache size and usage.

## Attack Surface: [SQL Injection (via Raw Queries)](./attack_surfaces/sql_injection__via_raw_queries_.md)

*Description:* Attackers inject malicious SQL code into database queries.
*How F3 Contributes:* While F3's DBAL *encourages* parameterized queries, it *allows* developers to write raw SQL queries. The framework *does not prevent* the use of raw queries, and therefore, the responsibility for secure usage falls entirely on the developer. This allowance is the F3-specific risk.
*Example:*
    *   Code: `$db->exec("SELECT * FROM users WHERE username = '" . $_GET['username'] . "'");`
    *   Attack: User input for `username`: `' OR '1'='1`
*Impact:*  Data theft, data modification, data deletion, potential server compromise.
*Risk Severity:* Critical
*Mitigation Strategies:*
    *   **Developer:**  *Always* use parameterized queries or F3's query builder methods.  *Never* concatenate user input directly into SQL queries.  If raw queries are absolutely necessary, use the database driver's specific escaping functions *correctly*.  Implement strict input validation and sanitization.

## Attack Surface: [Route Hijacking (Dynamic Route Generation)](./attack_surfaces/route_hijacking__dynamic_route_generation_.md)

*Description:* Attackers inject malicious route definitions, overriding existing routes or creating new ones.
*How F3 Contributes:* F3's routing system *allows* for dynamic route generation. If this feature is used with *untrusted* input, the framework's flexibility becomes a vulnerability. The framework *does not inherently protect* against malicious route definitions.
*Example:* An application that allows users to define custom URL aliases without proper sanitization. An attacker could create an alias that conflicts with an existing administrative route.
*Impact:* Unauthorized access to functionality, potential code execution.
*Risk Severity:* High
*Mitigation Strategies:*
        *   **Developer:** *Avoid* dynamically generating routes based on untrusted input. If absolutely necessary, rigorously sanitize and validate any data used to construct routes. Prefer static route definitions. Implement strict access controls on any functionality that allows users to modify routes.

