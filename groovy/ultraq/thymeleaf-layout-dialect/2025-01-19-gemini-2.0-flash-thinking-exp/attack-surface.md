# Attack Surface Analysis for ultraq/thymeleaf-layout-dialect

## Attack Surface: [Layout Template Injection](./attack_surfaces/layout_template_injection.md)

**Description:** An attacker can manipulate the layout template being used by the application, potentially injecting a malicious template.

**How Thymeleaf-Layout-Dialect Contributes:** The `layout:decorate` attribute is the primary mechanism for specifying the layout template. If the value of this attribute is derived from user input without proper sanitization, it becomes a vector for injecting arbitrary template paths.

**Example:** An attacker modifies a URL parameter like `?layout=evil` which is then used in the `layout:decorate` attribute: `<div layout:decorate="~{${layout}}">`. If `evil.html` exists and contains malicious code, it will be executed.

**Impact:** Remote Code Execution (RCE) on the server, leading to complete compromise of the application and potentially the underlying system.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Strict Input Validation:**  Sanitize and validate any user input that influences the layout name. Use a whitelist of allowed layout names instead of a blacklist.
* **Avoid Dynamic Layout Resolution:** If possible, avoid dynamically determining the layout based on user input. Hardcode or use a predefined set of layouts.
* **Secure Template Storage:** Ensure that template files are stored in a secure location with restricted access.

## Attack Surface: [Fragment Injection/Manipulation](./attack_surfaces/fragment_injectionmanipulation.md)

**Description:** An attacker can manipulate the fragments being included in a layout, potentially injecting malicious content or disrupting the intended structure.

**How Thymeleaf-Layout-Dialect Contributes:** The `layout:fragment`, `layout:insert`, and `layout:replace` attributes are used to define and include fragments. If the fragment names used in these attributes are derived from user input, an attacker can inject or manipulate them.

**Example:** An attacker modifies a URL parameter like `?section=maliciousFragment` which is then used in `layout:insert`: `<div layout:insert="~{fragments :: ${section}}">`. If a fragment named `maliciousFragment` exists (or can be crafted), it will be included.

**Impact:** Cross-Site Scripting (XSS) if the injected fragment contains malicious scripts, content injection leading to defacement or misinformation, or denial of service if the injected fragment is resource-intensive.

**Risk Severity:** High

**Mitigation Strategies:**
* **Strict Input Validation:** Sanitize and validate any user input that influences fragment names. Use a whitelist of allowed fragment names.
* **Secure Fragment Management:** Ensure that fragments are stored securely and their content is trusted. Avoid dynamically creating fragments based on untrusted input.
* **Context-Aware Output Encoding:** While Thymeleaf generally provides output encoding, ensure it's applied correctly in all contexts, especially when dealing with dynamically included fragments.

## Attack Surface: [Expression Language Injection via Layout Attributes](./attack_surfaces/expression_language_injection_via_layout_attributes.md)

**Description:** While Thymeleaf itself has mechanisms to prevent expression language injection, the way `thymeleaf-layout-dialect` handles attributes could potentially introduce vulnerabilities if user-controlled data is directly used within layout attributes without proper sanitization.

**How Thymeleaf-Layout-Dialect Contributes:** If custom processors or resolvers are used in conjunction with the dialect, and these processors directly evaluate user-provided data within layout attributes, it could lead to expression language injection.

**Example:** A custom layout dialect processor might directly evaluate a user-provided string used in a custom attribute: `<div my:customAttr="${userInput}">`. If `userInput` contains a malicious expression (e.g., `T(java.lang.Runtime).getRuntime().exec('malicious command')`), it could be executed.

**Impact:** Remote Code Execution (RCE) on the server.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Avoid Direct User Input in Expressions:**  Never directly embed user-provided data within Thymeleaf expressions used in layout attributes without thorough sanitization and validation.
* **Secure Custom Processor Development:** If developing custom layout dialect processors, be extremely cautious about how user input is handled and avoid dynamic expression evaluation.
* **Principle of Least Privilege:** Ensure that the application runs with the minimum necessary permissions to limit the impact of potential RCE.

## Attack Surface: [Path Traversal in Layout/Fragment Resolution](./attack_surfaces/path_traversal_in_layoutfragment_resolution.md)

**Description:** An attacker could potentially use path traversal techniques to access files outside the intended template or fragment directories.

**How Thymeleaf-Layout-Dialect Contributes:** If the logic for resolving layout or fragment paths relies on user-provided input without proper validation, an attacker could use sequences like `../` to navigate the file system.

**Example:** An attacker modifies a URL parameter like `?layout=../../../../etc/passwd` which is then used in `layout:decorate`. If the application doesn't properly sanitize the path, it might attempt to load `/etc/passwd` as a template.

**Impact:** Information Disclosure (access to sensitive files), potential Remote Code Execution if an attacker can access and include executable files.

**Risk Severity:** High

**Mitigation Strategies:**
* **Secure Path Resolution:** Implement robust path resolution logic that prevents traversal outside of allowed directories. Use canonicalization techniques to resolve symbolic links and relative paths.
* **Avoid User Input in Path Construction:** Minimize or eliminate the use of user input in constructing file paths for layouts and fragments.
* **Restrict File System Access:** Configure the application server with appropriate file system permissions to limit access to sensitive areas.

