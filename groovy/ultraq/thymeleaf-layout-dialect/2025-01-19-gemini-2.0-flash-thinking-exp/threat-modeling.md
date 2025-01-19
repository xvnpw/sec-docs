# Threat Model Analysis for ultraq/thymeleaf-layout-dialect

## Threat: [Malicious Layout Path Injection](./threats/malicious_layout_path_injection.md)

**Description:** An attacker manipulates user input or data from untrusted sources that is directly used to set the value of the `layout:decorate` attribute (provided by the layout dialect). By injecting a malicious path, they can force the inclusion of an unintended template. This could be a template hosted on a remote server or a local file they shouldn't have access to.

**Impact:** Remote Code Execution (if the attacker controls the content of the included template), Cross-Site Scripting (if the included template renders attacker-controlled content), Information Disclosure (if the included template exposes sensitive data), or Denial of Service (if the included template is resource-intensive).

**Affected Component:** `layout:decorate` attribute processing (provided by the layout dialect).

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Avoid constructing `layout:decorate` values directly from user input or untrusted sources.**
* **Implement strict input validation and sanitization for any data used in `layout:decorate`, specifically checking for path traversal characters (e.g., `../`).**
* **Use a whitelist of allowed layout template paths.**
* **Consider using an indirect mapping mechanism where user input maps to predefined, safe layout template names.**

## Threat: [Path Traversal through Layout Inclusion](./threats/path_traversal_through_layout_inclusion.md)

**Description:** If the layout dialect does not properly sanitize or validate the paths provided to `layout:decorate` (a feature of the layout dialect), an attacker might be able to use path traversal techniques (e.g., `../../`) to access files outside the intended template directory. This relies on how the layout dialect handles the provided paths.

**Impact:** Information Disclosure (access to sensitive server-side files, configuration files, source code), or potentially Remote Code Execution if the attacker can include executable files.

**Affected Component:** Template resolution mechanism used by `layout:decorate` (provided by the layout dialect).

**Risk Severity:** High

**Mitigation Strategies:**
* **Ensure the Thymeleaf engine is configured to restrict template resolution to specific directories.**
* **The layout dialect should ideally leverage Thymeleaf's secure template resolution mechanisms.**
* **Avoid constructing layout paths dynamically based on user input.**
* **Regularly review and update Thymeleaf and the layout dialect to benefit from security patches.**

## Threat: [Security Misconfiguration Leading to Vulnerabilities](./threats/security_misconfiguration_leading_to_vulnerabilities.md)

**Description:** Incorrect configuration of the layout dialect itself can introduce vulnerabilities. This could involve how the dialect interacts with Thymeleaf's expression evaluation or template resolution.

**Impact:** Depending on the misconfiguration, this could lead to Remote Code Execution, Information Disclosure, or other security breaches.

**Affected Component:** Configuration settings of the layout dialect.

**Risk Severity:** High

**Mitigation Strategies:**
* **Follow the principle of least privilege when configuring the layout dialect.**
* **Disable any unnecessary or potentially dangerous features of the layout dialect.**
* **Regularly review and update the configuration settings based on security best practices and the layout dialect's documentation.**
* **Ensure template resolvers are configured to only access trusted template locations, as this interacts with how the layout dialect finds templates.**

