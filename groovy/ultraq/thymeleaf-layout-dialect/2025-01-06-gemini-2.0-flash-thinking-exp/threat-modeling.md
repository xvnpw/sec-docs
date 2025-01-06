# Threat Model Analysis for ultraq/thymeleaf-layout-dialect

## Threat: [Path Traversal in Layout Resolution](./threats/path_traversal_in_layout_resolution.md)

**Description:** An attacker might manipulate the layout name or path provided to the `layout:decorate` attribute (or similar attributes) by injecting directory traversal sequences (e.g., `../`) or absolute paths. This directly exploits the dialect's mechanism for resolving layout template paths, potentially causing the application to load and process arbitrary files from the server's filesystem as layouts, exposing sensitive information or even leading to remote code execution.

**Impact:** Information disclosure (reading configuration files, source code, etc.), potential remote code execution if executable files are accessible and processed.

**Affected Component:** Layout Resolution mechanism, specifically the processing of the `layout:decorate` attribute and how it resolves the layout template path.

**Risk Severity:** High (can be Critical if remote code execution is achievable).

**Mitigation Strategies:**
*   Avoid constructing layout paths directly from user input or external sources.
*   Implement a whitelist of allowed layout names or paths.
*   Sanitize any user input that influences layout path resolution to remove directory traversal sequences.
*   Ensure that the application server's file system permissions restrict access to sensitive files.

## Threat: [Expression Language Injection in Layout/Fragment Selection](./threats/expression_language_injection_in_layoutfragment_selection.md)

**Description:** If the application uses Thymeleaf's expression language (e.g., `${...}`) directly within layout dialect attributes to dynamically determine layout or fragment names based on user input, an attacker could inject malicious expressions. This directly leverages the dialect's integration with Thymeleaf expressions, leading to arbitrary code execution within the Thymeleaf context, potentially allowing access to sensitive data or system resources.

**Impact:** Remote code execution, information disclosure, privilege escalation.

**Affected Component:** Thymeleaf Expression Evaluation within the context of layout attributes like `layout:decorate`, `layout:insert`, etc.

**Risk Severity:** Critical.

**Mitigation Strategies:**
*   **Strongly avoid** using user input directly within Thymeleaf expressions for layout dialect attributes.
*   If dynamic selection is absolutely necessary, implement extremely strict input validation and sanitization. Consider alternative approaches that don't involve dynamic expression evaluation based on user input.

