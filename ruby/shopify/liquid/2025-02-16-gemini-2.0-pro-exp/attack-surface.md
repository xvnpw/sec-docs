# Attack Surface Analysis for shopify/liquid

## Attack Surface: [Loop-Based Denial of Service (DoS)](./attack_surfaces/loop-based_denial_of_service__dos_.md)

*   **Description:** Attackers exploit Liquid's looping constructs (`for`, `tablerow`) to consume excessive server resources (CPU, memory), leading to a denial of service.
*   **Liquid Contribution:** Liquid's looping mechanisms, especially when combined with `limit` and `offset`, provide the direct means for an attacker to trigger excessive iterations.  This is inherent to how Liquid processes loops.
*   **Example:** An attacker provides input that causes a `for` loop to iterate over a seemingly small dataset, but with crafted `limit` and `offset` values that result in a very large number of iterations, each performing a database query.  `{% for i in (1..10) limit: 1000000 offset: 999990 %}{{ i }}{% endfor %}`
*   **Impact:** Service unavailability, degraded performance for legitimate users, potential server crashes.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Iteration Limits:** Enforce hard limits on the maximum number of loop iterations, regardless of user input. Use Shopify's built-in limits and consider even lower, application-specific limits.
    *   **Input Validation:** Validate all user-supplied data that influences loop behavior (e.g., array sizes, `limit`, `offset`).
    *   **Resource Monitoring:** Monitor server resource usage (CPU, memory) during Liquid rendering and set alerts for anomalies.
    *   **Pagination:** Use pagination features to avoid processing large datasets in a single loop.
    *   **Avoid Nested Loops:** Minimize or eliminate nested loops.

## Attack Surface: [Object Depth/Size DoS](./attack_surfaces/object_depthsize_dos.md)

*   **Description:** Attackers provide deeply nested objects or objects with a vast number of properties to Liquid, causing excessive resource consumption during processing.
*   **Liquid Contribution:** Liquid's object handling and property access mechanisms are *directly* involved in processing these objects, making them susceptible to resource exhaustion.  This is a fundamental aspect of how Liquid interacts with data.
*   **Example:** An attacker submits a JSON payload with deeply nested arrays or objects (e.g., 1000 levels deep) that is then passed to Liquid for rendering.
*   **Impact:** Service unavailability, degraded performance, potential server crashes.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Depth Limits:** Impose limits on the maximum allowed depth of object nesting.
    *   **Object Size Validation:** Validate the size and structure of objects before passing them to Liquid.
    *   **Resource Monitoring:** Monitor memory usage during Liquid rendering.

## Attack Surface: [String Manipulation DoS](./attack_surfaces/string_manipulation_dos.md)

*   **Description:** Attackers exploit Liquid's string manipulation filters (e.g., `append`, `prepend`, `replace`) to create extremely large strings, consuming excessive memory.
*   **Liquid Contribution:** Liquid's string filters are the *direct* tools used by attackers to manipulate string sizes, leading to potential memory exhaustion.  This is a core function of these Liquid filters.
*   **Example:** An attacker repeatedly uses the `append` filter in a loop, controlled by user input, to build a string of enormous length.  `{% assign my_string = "a" %}{% for i in (1..1000) %}{% assign my_string = my_string | append: my_string %}{% endfor %}`
*   **Impact:** Service unavailability, degraded performance, potential server crashes.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **String Length Limits:** Enforce strict limits on the maximum length of strings processed by Liquid filters.
    *   **Input Validation:** Validate user-supplied input used in string manipulation filters.
    *   **Avoid Chained Filters:** Minimize the use of chained string filters, especially within loops.
    *   **Resource Monitoring:** Monitor memory usage during Liquid rendering.

## Attack Surface: [Code Injection (via Custom Tags/Filters)](./attack_surfaces/code_injection__via_custom_tagsfilters_.md)

*   **Description:** Attackers exploit vulnerabilities in *custom* Liquid tags or filters (written in Ruby) to execute arbitrary code on the server.
*   **Liquid Contribution:** While Liquid *itself* is designed to prevent direct code injection, it *provides the mechanism* (custom tags/filters) that, if implemented insecurely, creates the vulnerability.  Liquid's extensibility is the direct enabler of this attack.
*   **Example:** A custom filter that uses `eval` on user-supplied input: `def my_filter(input); eval(input); end`. An attacker could then pass Ruby code as input to be executed.
*   **Impact:** Complete server compromise, data theft, arbitrary code execution.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Rigorously validate *all* input to custom tags and filters. Use whitelisting.
    *   **Avoid `eval`:** Never use `eval` or similar functions with user-supplied input.
    *   **Principle of Least Privilege:** Run custom tags/filters with minimal privileges.
    *   **Security Audits:** Conduct regular security audits and code reviews of custom extensions.
    *   **Sandboxing:** Consider sandboxing the execution of custom tag/filter code.
    *   **Dependency Management:** Keep all dependencies of custom tags/filters up-to-date.

