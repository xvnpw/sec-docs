# Attack Surface Analysis for hanami/hanami

## Attack Surface: [Parameter Handling in Routes (Injection Vulnerabilities)](./attack_surfaces/parameter_handling_in_routes__injection_vulnerabilities_.md)

*   **Description:** Injection vulnerabilities arising from improper handling and validation of parameters extracted from route paths.
*   **Hanami Contribution:** Hanami routes rely on parameters, and the framework does not enforce automatic input validation at the routing level, making it developer's responsibility within actions. This design choice directly contributes to the potential attack surface if developers fail to implement proper validation.
*   **Example:** A route `/users/{id}` where `id` is directly used in a database query within an action without validation can lead to SQL injection if a malicious user provides an input like `' OR 1=1 --`.
*   **Impact:** Data Breach, Data Manipulation, Potential Code Execution (depending on the injection type).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation:** Implement robust input validation and sanitization for all route parameters within Hanami actions.
    *   **Parameterized Queries:** Use parameterized queries or Hanami::Model's query builder to prevent SQL injection when interacting with databases.
    *   **Principle of Least Privilege:** Ensure database users have minimal necessary permissions to limit the impact of SQL injection.

## Attack Surface: [Server-Side Template Injection (SSTI) Risk](./attack_surfaces/server-side_template_injection__ssti__risk.md)

*   **Description:** Vulnerabilities arising from directly embedding user-controlled input into templates without proper escaping, leading to potential code execution on the server.
*   **Hanami Contribution:** Hanami uses ERB or other templating engines for views. The framework relies on developers to manually escape or sanitize user input within templates to prevent SSTI. This direct responsibility placed on developers by Hanami's view layer design contributes to the attack surface.
*   **Example:** A view template directly rendering user input like `<%= params[:name] %>` without escaping could allow an attacker to inject malicious code within `params[:name]` that gets executed by the template engine on the server.
*   **Impact:** Code Execution on the Server, Server Compromise, Data Breach.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Output Escaping:** Always properly escape user-provided data before embedding it in templates. Utilize Hanami's escaping helpers (e.g., `h()`) or equivalent mechanisms provided by the templating engine.
    *   **Avoid Direct Embedding:** Minimize direct embedding of user input in templates. Use view helpers or presenters to handle data formatting and escaping outside of the template itself.
    *   **Templating Engine Security Features:** Utilize security features provided by the templating engine to further mitigate SSTI risks.

## Attack Surface: [Cross-Site Scripting (XSS) via Unescaped Output](./attack_surfaces/cross-site_scripting__xss__via_unescaped_output.md)

*   **Description:** Injecting malicious client-side scripts into web pages due to unescaped output in views, allowing attackers to execute scripts in users' browsers.
*   **Hanami Contribution:** Hanami's view layer design requires developers to be mindful of output escaping to prevent XSS vulnerabilities. The framework does not automatically escape all output, placing the onus on developers and thus contributing to the potential attack surface if developers are not careful.
*   **Example:** Displaying user-generated content in a view using `<%= user.comment %>` without escaping could allow an attacker to inject JavaScript code within `user.comment` that will be executed in other users' browsers viewing the page.
*   **Impact:** Account Takeover, Data Theft, Website Defacement, Malicious Actions on Behalf of Users.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Output Escaping:**  Consistently escape all user-generated content and any data that originates from untrusted sources before rendering it in views. Use Hanami's built-in escaping helpers or equivalent mechanisms.
    *   **Content Security Policy (CSP):** Implement a strong Content Security Policy to restrict the sources from which the browser is allowed to load resources, reducing the impact of XSS attacks.
    *   **Input Sanitization (Defense in Depth):** Sanitize user input on the server-side to remove or neutralize potentially harmful content before it is stored or displayed.

## Attack Surface: [Path Traversal in Asset Serving (If Misconfigured)](./attack_surfaces/path_traversal_in_asset_serving__if_misconfigured_.md)

*   **Description:**  Path traversal vulnerabilities allowing attackers to access files outside of the intended asset directories due to misconfiguration in asset serving.
*   **Hanami Contribution:** Hanami's asset serving configuration, while providing flexibility, can introduce path traversal risks if not properly configured. The framework's design allows for customization of asset paths, and incorrect configuration directly contributes to this attack surface.
*   **Example:** A misconfigured asset serving setup in `config/assets.rb` or web server configuration might allow an attacker to request a URL like `/assets/../../../../etc/passwd`, potentially gaining access to sensitive system files.
*   **Impact:** Information Disclosure, Potential Code Execution (if executable files are accessed).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Secure Asset Path Configuration:** Carefully configure asset paths in `config/assets.rb` and ensure they are properly restricted to the intended asset directories.
    *   **Restrict Asset Serving Directory:** Limit the directory from which assets are served to only the necessary asset files in web server configuration.
    *   **Input Validation for Asset Paths:** If asset paths are dynamically constructed based on user input (which is generally discouraged), rigorously validate and sanitize the input to prevent path traversal.
    *   **Web Server Configuration:** Configure the web server (e.g., Nginx, Apache) to properly handle asset serving and prevent path traversal attempts, independent of Hanami configuration as a defense in depth.

