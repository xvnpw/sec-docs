# Threat Model Analysis for hanami/hanami

## Threat: [Insecure Default Session Configuration](./threats/insecure_default_session_configuration.md)

**Description:** An attacker might exploit weak default session management settings provided by Hanami, such as using insecure cookie attributes (e.g., missing `HttpOnly`, `Secure`, or `SameSite` flags) or predictable session IDs, to hijack user sessions. This could allow them to impersonate users and gain unauthorized access.

**Impact:** Account takeover, unauthorized access to user data and functionalities, potential for data breaches.

**Affected Hanami Component:** `Hanami::Controller::Session`

**Risk Severity:** High

**Mitigation Strategies:**
*   Explicitly configure session settings within your Hanami application to use secure cookie attributes (`HttpOnly`, `Secure`, `SameSite`).
*   Ensure strong and unpredictable session ID generation, potentially by configuring the underlying Rack session middleware.
*   Consider using secure session storage mechanisms if the default is insufficient for your security requirements.
*   Implement session timeouts and regular session rotation.

## Threat: [Vulnerabilities in Hanami Gems and Dependencies](./threats/vulnerabilities_in_hanami_gems_and_dependencies.md)

**Description:** An attacker could exploit known vulnerabilities in the Hanami framework itself or its directly managed dependencies (gems). This could involve sending specially crafted requests that exploit weaknesses in Hanami's routing, controller handling, or other core functionalities, leading to unauthorized access, remote code execution, or denial of service.

**Impact:** Full application compromise, data breaches, denial of service, arbitrary code execution.

**Affected Hanami Component:** Entire framework, including all modules and components.

**Risk Severity:** Critical (depending on the specific vulnerability)

**Mitigation Strategies:**
*   Regularly update the `hanami` gem and all its direct dependencies to the latest versions.
*   Utilize dependency scanning tools (e.g., Bundler Audit, Dependabot) to identify and address known vulnerabilities in your `Gemfile`.
*   Stay informed about security advisories specifically related to the `hanami` gem and its core components.

## Threat: [Mass Assignment Vulnerabilities in Entities](./threats/mass_assignment_vulnerabilities_in_entities.md)

**Description:** If Hanami entities are directly populated from request parameters within actions without explicit filtering or whitelisting, an attacker could send malicious requests with unexpected parameters to modify unintended entity attributes. This is a direct consequence of how Hanami actions can interact with entities.

**Impact:** Data corruption, unauthorized modification of user data or application state, potential for privilege escalation.

**Affected Hanami Component:** `Hanami::Entity`, `Hanami::Action` (parameter handling)

**Risk Severity:** High

**Mitigation Strategies:**
*   Avoid directly assigning request parameters to entity attributes within Hanami actions.
*   Utilize strong parameter filtering and whitelisting within actions to explicitly define which attributes can be updated before interacting with entities.
*   Consider using form objects or input validation libraries in conjunction with Hanami actions to sanitize and validate input before assigning to entities.

## Threat: [Cross-Site Scripting (XSS) through View Rendering](./threats/cross-site_scripting__xss__through_view_rendering.md)

**Description:** If user-provided data is directly embedded into Hanami templates without proper escaping, an attacker can inject malicious scripts into the rendered HTML. This is a direct consequence of how Hanami views render data. When other users view the page, these scripts can execute in their browsers.

**Impact:** Account takeover, data theft, defacement of the application, spreading of malware.

**Affected Hanami Component:** `Hanami::View`, Template engines (e.g., ERB, Haml) as used within Hanami views.

**Risk Severity:** High

**Mitigation Strategies:**
*   Utilize Hanami's built-in escaping mechanisms when rendering user-provided data in views. Be mindful of the context (HTML, JavaScript, CSS) and use appropriate escaping functions provided by the template engine.
*   Consider using Content Security Policy (CSP) to further mitigate XSS risks in conjunction with secure templating practices within Hanami.

