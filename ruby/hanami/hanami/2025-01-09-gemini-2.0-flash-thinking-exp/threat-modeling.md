# Threat Model Analysis for hanami/hanami

## Threat: [Insecure Route Constraint Bypass](./threats/insecure_route_constraint_bypass.md)

**Description:** An attacker crafts a malicious URL that bypasses the intended route constraints defined in the `Hanami::Router`. This could involve exploiting weaknesses in the regular expressions or data type validations used in the constraints.

**Impact:**  Unauthorized access to application functionality or data that was intended to be protected by the route constraints. This could lead to information disclosure, data manipulation, or even privilege escalation if the bypassed route leads to administrative functions.

**Affected Component:** `Hanami::Router` (specifically the route constraint matching logic)

**Risk Severity:** High

**Mitigation Strategies:**
*   Use strong and specific regular expressions for route constraints.
*   Thoroughly test route constraints with various inputs, including edge cases and invalid data.
*   Avoid overly complex or permissive regular expressions in route constraints.
*   Consider using data type constraints where appropriate.

## Threat: [Mass Assignment Vulnerability via Controller Parameters](./threats/mass_assignment_vulnerability_via_controller_parameters.md)

**Description:** An attacker manipulates request parameters to update model attributes that are not intended to be publicly accessible. This occurs if controller actions directly use request parameters (handled by `Hanami::Controller::Params`) to update model attributes without proper filtering or whitelisting.

**Impact:**  Unauthorized modification of sensitive data within the application's models. This could lead to data corruption, privilege escalation (e.g., changing a user's role), or other unintended consequences.

**Affected Component:** `Hanami::Controller::Params` (handling of request parameters) and potentially the specific controller action and model being updated.

**Risk Severity:** High

**Mitigation Strategies:**
*   Avoid directly assigning request parameters to model attributes.
*   Implement strong parameter filtering and whitelisting within controller actions.
*   Use form objects or dedicated parameter validation classes to define allowed attributes.
*   Employ the principle of least privilege when updating model attributes.

## Threat: [Cross-Site Scripting (XSS) through Insecure Template Rendering](./threats/cross-site_scripting__xss__through_insecure_template_rendering.md)

**Description:** An attacker injects malicious scripts into the application's views because user-provided data is not properly escaped or sanitized before being rendered in the HTML. This can happen if developers explicitly disable Hanami's default escaping or use unsafe template helpers incorrectly within Hanami's view layer.

**Impact:**  Execution of arbitrary JavaScript code in the victim's browser when they view the affected page. This can lead to session hijacking, cookie theft, redirection to malicious sites, or defacement of the application.

**Affected Component:**  The specific view template file (e.g., `.erb`, `.haml`) and the template rendering engine used by Hanami.

**Risk Severity:** High

**Mitigation Strategies:**
*   Ensure Hanami's default HTML escaping mechanisms are enabled and used consistently.
*   Be extremely cautious when using `raw` or similar helpers that bypass escaping.
*   Sanitize user-generated content before displaying it in templates, especially if `raw` is necessary.
*   Implement Content Security Policy (CSP) headers to further mitigate XSS risks.

## Threat: [Exposure of Sensitive Configuration Data](./threats/exposure_of_sensitive_configuration_data.md)

**Description:** An attacker gains access to sensitive configuration files (e.g., `.env` files) that contain database credentials, API keys, or other secrets. This could happen due to misconfigured web servers or insecure deployment practices related to how Hanami applications are typically configured.

**Impact:**  Complete compromise of the application and its associated resources. Attackers could gain unauthorized access to the database, external services, or other sensitive systems.

**Affected Component:** Application configuration files and the deployment environment (while not strictly a Hanami component, it's a common area of concern for Hanami deployments).

**Risk Severity:** Critical

**Mitigation Strategies:**
*   Store sensitive configuration data securely, preferably using environment variables or dedicated secrets management solutions.
*   Ensure that configuration files are not accessible through the web server.
*   Avoid committing sensitive information directly to version control.
*   Implement proper access controls on configuration files.

## Threat: [Insecure Handling of File Uploads (if implemented directly)](./threats/insecure_handling_of_file_uploads__if_implemented_directly_.md)

**Description:** If file upload functionality is implemented manually within a Hanami controller action without proper security considerations, an attacker can upload malicious files (e.g., web shells, viruses) that can be executed on the server or used to compromise other users.

**Impact:**  Remote code execution on the server, defacement of the application, or distribution of malware to other users.

**Affected Component:**  Controller actions handling file uploads within the Hanami application.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   Utilize well-vetted file upload libraries or gems.
*   Implement robust file type validation based on content (magic numbers) rather than just extension.
*   Enforce strict file size limits.
*   Store uploaded files in secure locations with appropriate access controls, ideally outside the web server's document root.
*   Sanitize filenames to prevent path traversal vulnerabilities.
*   Consider using a dedicated storage service for uploaded files.

