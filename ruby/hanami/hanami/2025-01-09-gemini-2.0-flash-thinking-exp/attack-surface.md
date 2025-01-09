# Attack Surface Analysis for hanami/hanami

## Attack Surface: [Insecure Route Parameter Handling](./attack_surfaces/insecure_route_parameter_handling.md)

**Description:** Failure to properly sanitize or validate data extracted from route parameters before using it in application logic.

**How Hanami Contributes to the Attack Surface:** Hanami's router allows defining routes with parameters that are directly accessible in actions. If developers don't implement proper validation and sanitization on these parameters, vulnerabilities can arise.

**Example:** A route defined as `/users/:id` where the `id` parameter is directly used in a database query without validation. An attacker could send a request like `/users/1 OR 1=1--` leading to SQL injection if not handled.

**Impact:** SQL injection, command injection, or other injection vulnerabilities depending on how the unsanitized parameter is used.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Input Validation:**  Use Hanami's validation features or custom validation logic within actions to ensure route parameters conform to expected types and formats.
* **Parameterized Queries:** When using route parameters in database queries, always use parameterized queries or prepared statements provided by ROM to prevent SQL injection.
* **Type Casting:** Explicitly cast route parameters to the expected data type (e.g., integer) to prevent unexpected input.

## Attack Surface: [Cross-Site Scripting (XSS) through Unescaped Template Output](./attack_surfaces/cross-site_scripting__xss__through_unescaped_template_output.md)

**Description:** Rendering user-supplied or untrusted data directly in Hanami templates without proper escaping, allowing attackers to inject malicious scripts.

**How Hanami Contributes to the Attack Surface:** Hanami uses ERB by default. While ERB offers escaping mechanisms, developers need to explicitly use them. Forgetting to escape output can lead to XSS vulnerabilities.

**Example:** An action sets `@name = params[:name]`. The template renders this as `<p><%= @name %></p>`. If `params[:name]` contains `<script>alert('XSS')</script>`, this script will execute in the user's browser.

**Impact:** Account takeover, session hijacking, defacement, redirection to malicious sites.

**Risk Severity:** High

**Mitigation Strategies:**
* **Automatic Escaping:** Configure Hanami to automatically escape HTML output by default where possible.
* **Explicit Escaping:** Use Hanami's built-in escaping helpers (e.g., `escape_html()`) or the `= raw()` helper judiciously when you intentionally want to render unescaped HTML.
* **Content Security Policy (CSP):** Implement a strong CSP to mitigate the impact of XSS attacks, even if they occur.

## Attack Surface: [Mass Assignment Vulnerabilities in Actions](./attack_surfaces/mass_assignment_vulnerabilities_in_actions.md)

**Description:** Directly using request parameters to update model attributes without proper whitelisting or sanitization, potentially allowing attackers to modify unintended fields.

**How Hanami Contributes to the Attack Surface:** Hanami actions receive request parameters. If these parameters are directly passed to model update methods without filtering, it creates a mass assignment vulnerability.

**Example:** An action receives `params[:user]` and directly updates a `User` model with it: `UserRepository.new.update(user.id, params[:user])`. If `params[:user]` contains `{ admin: true }`, an attacker could potentially elevate their privileges.

**Impact:** Privilege escalation, data modification, unauthorized access.

**Risk Severity:** High

**Mitigation Strategies:**
* **Strong Parameters (Parameter Filtering):**  Implement strong parameter patterns (similar to Rails' strong parameters) to explicitly define which attributes can be updated through mass assignment.
* **Attribute Whitelisting:**  Explicitly whitelist the allowed attributes when updating models based on request parameters.
* **Use Case Specific Updates:**  Instead of directly using `params`, extract and validate individual parameters relevant to the specific update operation.

## Attack Surface: [Serving Sensitive Files through Misconfigured Assets](./attack_surfaces/serving_sensitive_files_through_misconfigured_assets.md)

**Description:** Accidentally making sensitive files (e.g., configuration files, backups) accessible through the application's asset pipeline or public directory.

**How Hanami Contributes to the Attack Surface:** Hanami serves static assets from the `public` directory by default. If developers place sensitive files in this directory or misconfigure asset paths, they become publicly accessible.

**Example:** Placing a `.env` file containing database credentials in the `public` directory, making it accessible via `/dot_env`.

**Impact:** Exposure of sensitive credentials, API keys, or other confidential information.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Careful File Placement:**  Never place sensitive files within the `public` directory or any directory served as static assets.
* **`.gitignore` and Deployment Practices:**  Use `.gitignore` to prevent sensitive files from being committed to the repository and ensure secure deployment practices.
* **Restrict Asset Access:**  If necessary, configure the web server (e.g., Nginx, Apache) to restrict access to specific asset paths or file types.

