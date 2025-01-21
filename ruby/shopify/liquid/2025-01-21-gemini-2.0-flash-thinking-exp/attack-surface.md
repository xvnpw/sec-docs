# Attack Surface Analysis for shopify/liquid

## Attack Surface: [Server-Side Template Injection (SSTI)](./attack_surfaces/server-side_template_injection__ssti_.md)

* **Attack Surface:** Server-Side Template Injection (SSTI)
    * **Description:**  Attackers inject malicious Liquid code into templates when user-controlled data is not properly sanitized before being embedded.
    * **How Liquid Contributes:** Liquid's syntax allows for code execution within templates through tags and filters. If user input is directly placed within these constructs, it can be interpreted as code.
    * **Example:** A website allows users to customize their profile description, which is then rendered using Liquid: `<h1>{{ user.description }}</h1>`. An attacker could set their description to `{{ 'id' | system }}` (hypothetical malicious filter) to execute the `id` command on the server.
    * **Impact:** Remote Code Execution (RCE), full server compromise, data breaches, denial of service.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **Developers:**  Avoid directly embedding user-controlled data into Liquid templates.
        * **Developers:**  Implement strict input sanitization and validation to remove or escape potentially malicious Liquid syntax.
        * **Developers:**  Utilize context-aware output encoding to prevent the interpretation of user input as code.
        * **Developers:**  Consider using a "safe mode" or restricted execution environment for Liquid if available.

## Attack Surface: [Information Disclosure through Template Logic](./attack_surfaces/information_disclosure_through_template_logic.md)

* **Attack Surface:** Information Disclosure through Template Logic
    * **Description:**  Improperly designed Liquid templates can inadvertently reveal sensitive information based on application state or user input.
    * **How Liquid Contributes:** Liquid's conditional logic (`if`, `else`) and access to application objects can be exploited to expose data that should not be publicly accessible.
    * **Example:** A template displays an error message that includes a database connection string if a specific error code is present: `{% if error.code == 'DB_ERROR_123' %}Database connection failed: {{ error.connection_string }}{% endif %}`.
    * **Impact:** Exposure of API keys, database credentials, internal system details, user data.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Developers:**  Carefully review template logic to ensure it does not expose sensitive information based on error conditions or application state.
        * **Developers:**  Avoid directly embedding sensitive configuration details or credentials within the application state accessible to Liquid.
        * **Developers:**  Implement proper error handling that does not reveal internal system details.

## Attack Surface: [Insecure Use of `include` and `render` Tags](./attack_surfaces/insecure_use_of__include__and__render__tags.md)

* **Attack Surface:** Insecure Use of `include` and `render` Tags
    * **Description:**  If the paths used in `include` or `render` tags are dynamically generated based on user input without proper sanitization, attackers can include arbitrary files.
    * **How Liquid Contributes:** The `include` and `render` tags allow for the inclusion of other template files. If the path is not properly controlled, it can lead to unauthorized file access.
    * **Example:** A template uses `{% include 'partials/' + page_name + '.liquid' %}` where `page_name` is derived from user input. An attacker could manipulate `page_name` to include sensitive files like `/etc/passwd` (if the application has access).
    * **Impact:** Information disclosure, potential for Remote File Inclusion (RFI) if the included file is processed as code.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Developers:**  Avoid dynamically generating paths for `include` and `render` based on user input.
        * **Developers:**  Use a whitelist of allowed template paths for inclusion.
        * **Developers:**  Ensure that the application environment restricts access to sensitive files.

## Attack Surface: [Exposure of Internal Application State through Liquid Objects](./attack_surfaces/exposure_of_internal_application_state_through_liquid_objects.md)

* **Attack Surface:** Exposure of Internal Application State through Liquid Objects
    * **Description:**  Liquid templates have access to objects and variables provided by the application. If these objects expose sensitive internal state or methods, it can be exploited.
    * **How Liquid Contributes:** Liquid's design allows access to data passed from the application context. If this data includes sensitive information or methods that can perform privileged actions, it creates a risk.
    * **Example:** A Liquid object exposes a method to update user roles: `{{ user_management.set_role('admin', user.id) }}`. If this is accessible in a template, it could be abused.
    * **Impact:** Data breaches, privilege escalation, unexpected application behavior.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Developers:**  Apply the principle of least privilege when providing objects to Liquid templates. Only expose the necessary data and methods.
        * **Developers:**  Carefully review the properties and methods of objects accessible within templates to identify potential security risks.
        * **Developers:**  Avoid exposing methods that perform sensitive actions directly to templates.

## Attack Surface: [Bypassing Security Measures through Template Logic](./attack_surfaces/bypassing_security_measures_through_template_logic.md)

* **Attack Surface:** Bypassing Security Measures through Template Logic
    * **Description:**  Security checks implemented in the application logic might be bypassed by manipulating the template rendering process.
    * **How Liquid Contributes:** Liquid's ability to control the flow of execution and data presentation can be exploited to circumvent security controls implemented elsewhere in the application.
    * **Example:** A template might conditionally skip a validation step based on a user-controlled variable: `{% if skip_validation == true %}{{ data }}{% else %}{{ data | validate }}{% endif %}`.
    * **Impact:** Unauthorized access, data manipulation, bypassing intended security controls.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **Developers:**  Ensure that security checks are enforced consistently and cannot be bypassed through template logic.
        * **Developers:**  Avoid relying solely on template logic for security enforcement. Implement security measures in the application's core logic.
        * **Developers:**  Thoroughly review template logic to identify potential bypasses of security controls.

