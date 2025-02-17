# Mitigation Strategies Analysis for krzysztofzablocki/sourcery

## Mitigation Strategy: [Strict Input Validation and Sanitization within Templates](./mitigation_strategies/strict_input_validation_and_sanitization_within_templates.md)

**Description:**

1.  **Identify Template Variables:**  Within each Sourcery template, identify *every* variable that receives external input (e.g., through annotations, configuration files, or other mechanisms).
2.  **Inline Validation:**  Use Sourcery's template language features (e.g., `{% if %}`, `{% for %}`, custom filters/functions) to perform validation *directly within the template*.  This is crucial for early rejection of bad input.
3.  **Whitelist Approach:**  Define allowed values or patterns for each variable *within the template itself*.  Use conditional logic to generate code *only* if the input is valid.
4.  **Custom Filters/Functions (If Needed):**  If the built-in template language features are insufficient, create custom Sourcery filters or functions (written in Swift) to perform more complex validation or sanitization.  These can be called directly from the templates.  Example: `{{ variable | my_custom_sanitizer }}`.
5.  **Fail-Safe Defaults:**  If validation fails, either:
    *   Generate *no* code (preferred).  This prevents any potentially malicious code from being created.
    *   Generate code with a safe, default value.  This is less desirable, but may be necessary in some cases.  *Never* generate code using the invalid input directly.
6.  **Example (in a .stencil template):**
    ```stencil
    {% if type.name|matches:"^[a-zA-Z0-9_]+$" %} // Inline regex validation
    struct {{ type.name }} {
        // ... generated code ...
    }
    {% else %}
    // Type name '{{ type.name }}' is invalid.  Skipping generation.
    {% endif %}
    ```

*   **Threats Mitigated:**
    *   **Template Injection:** (Severity: Critical) - Prevents attackers from injecting malicious code by validating input *before* it's used to generate code.
    *   **Overly Permissive Generated Code:** (Severity: High) - Ensures that only valid input is used, reducing the risk of generating insecure code.

*   **Impact:**
    *   **Template Injection:** Risk reduced from Critical to Low (if validation is comprehensive).
    *   **Overly Permissive Generated Code:** Risk reduced from High to Medium/Low.

*   **Currently Implemented:**
    *   Basic character set validation for type names is present in some templates using `matches` filter.

*   **Missing Implementation:**
    *   Comprehensive validation for *all* template variables is missing.
    *   Custom filters/functions for more complex validation are not used.
    *   Fail-safe defaults are not consistently implemented.

## Mitigation Strategy: [Principle of Least Privilege in Template Design](./mitigation_strategies/principle_of_least_privilege_in_template_design.md)

**Description:**

1.  **Minimize Generated Code:**  Design templates to generate the *absolute minimum* amount of code necessary to achieve the desired functionality.  Avoid generating unnecessary methods, properties, or code blocks.
2.  **Conditional Generation:**  Use Sourcery's conditional logic (`{% if %}`, `{% for %}`) to generate code *only* when it's absolutely required.  Avoid generating code that might be unused or could expose unnecessary functionality.
3.  **Restrict Access Modifiers:**  Use the most restrictive access modifiers (e.g., `private`, `fileprivate`) possible for generated code.  Avoid generating `public` or `open` code unless it's explicitly needed for external access.  Control this *within the template*.
4.  **Avoid Direct Data Access:**  Design templates to *avoid* generating code that directly accesses sensitive data or system resources.  Instead, generate code that calls manually written functions or methods that handle these interactions securely.
5.  **Template-Level Control:** Use template variables and logic to control the "privilege level" of the generated code. For example, you could have a template variable `isSensitiveData` that, when true, causes the template to generate code with more restrictive access controls.

*   **Threats Mitigated:**
    *   **Overly Permissive Generated Code:** (Severity: High) - Prevents the generation of code with excessive privileges.
    *   **Increased Attack Surface:** (Severity: Medium) - Reduces the amount of generated code, minimizing the potential attack surface.

*   **Impact:**
    *   **Overly Permissive Generated Code:** Risk reduced from High to Low.
    *   **Increased Attack Surface:** Risk reduced from Medium to Low.

*   **Currently Implemented:**
    *   Some templates use conditional logic to generate different code based on type properties, but a systematic approach to minimizing privileges is lacking.

*   **Missing Implementation:**
    *   A comprehensive review of all templates to identify and minimize generated code and access modifiers is needed.
    *   Template-level control of privilege levels is not implemented.

## Mitigation Strategy: [Minimize Template Complexity Directly](./mitigation_strategies/minimize_template_complexity_directly.md)

**Description:**

1.  **Simple Logic:**  Keep the logic within Sourcery templates as simple as possible.  Avoid complex nested loops, deeply nested conditional statements, and intricate template expressions.
2.  **Modular Templates:**  Break down large, complex templates into smaller, more manageable partial templates (using Sourcery's `include` or `extends` features).  Each partial template should have a single, well-defined purpose.
3.  **Custom Filters/Functions (for Simplification):**  Use custom Sourcery filters or functions to encapsulate complex logic or data transformations.  This keeps the templates themselves cleaner and easier to understand.  This is different from using them for *validation* (as in Strategy 1); here, they're used for *simplification*.
4.  **Avoid Inline Code Generation:** Minimize the amount of Swift code written *directly* within the template.  Instead, generate calls to well-defined, manually written functions or methods.
5. **Comments within Templates:** Add clear and concise comments *within the templates* to explain the purpose of the generated code and any assumptions made.

*   **Threats Mitigated:**
    *   **Template Injection:** (Severity: Critical) - Simpler templates are less likely to contain hidden injection vulnerabilities.
    *   **Overly Permissive Generated Code:** (Severity: High) - Reduces the chance of generating complex, insecure code.
    *   **Obfuscation of Security Logic:** (Severity: Medium) - Makes the templates easier to understand, improving reviewability.

*   **Impact:**
    *   **Template Injection:** Risk reduced from Critical to Medium.
    *   **Overly Permissive Generated Code:** Risk reduced from High to Medium.
    *   **Obfuscation of Security Logic:** Risk reduced from Medium to Low.

*   **Currently Implemented:**
    *   Some templates are relatively simple, but others are more complex.
    *   Partial templates are used in some cases, but not consistently.

*   **Missing Implementation:**
    *   A systematic review and refactoring of all templates to minimize complexity is needed.
    *   More extensive use of custom filters/functions for simplification could be beneficial.
    * More comments within templates.

## Mitigation Strategy: [Secure Configuration of Sourcery](./mitigation_strategies/secure_configuration_of_sourcery.md)

**Description:**

1.  **`sources`:** Carefully define the `sources` paths in your Sourcery configuration (e.g., `.sourcery.yml` or command-line arguments).  Ensure that Sourcery only reads from the intended source files and directories.  Avoid using overly broad paths (e.g., the project root) that could include unintended files.
2.  **`templates`:**  Similarly, specify the `templates` paths precisely.  Ensure that Sourcery only uses the intended template files.
3.  **`output`:**  Control the `output` path to prevent Sourcery from writing generated code to unintended locations.  Use a dedicated directory for generated code.
4.  **`args` (if used):** If you use the `args` section in your configuration file to pass data to templates, treat these arguments as *untrusted input*.  Apply the same validation and sanitization principles as you would for any other template input.
5. **Disable Unnecessary Features:** If you're not using certain Sourcery features (e.g., custom types, extensions), disable them in the configuration to reduce the potential attack surface.

*   **Threats Mitigated:**
    *   **Template Injection:** (Severity: Critical) - By controlling the input sources and templates, you reduce the risk of an attacker injecting malicious code through unintended files.
    *   **Overly Permissive Generated Code:** (Severity: High) - By controlling the output path, you prevent Sourcery from overwriting critical files or generating code in insecure locations.

*   **Impact:**
    *   **Template Injection:** Risk reduced from Critical to Medium.
    *   **Overly Permissive Generated Code:** Risk reduced from High to Medium.

*   **Currently Implemented:**
    *   `sources`, `templates`, and `output` are defined in `.sourcery.yml`.

*   **Missing Implementation:**
    *   A review of the configuration to ensure that the paths are as restrictive as possible is needed.
    *   Validation of `args` is not explicitly implemented.

