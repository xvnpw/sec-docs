# Attack Surface Analysis for handlebars-lang/handlebars.js

## Attack Surface: [Server-Side Template Injection (SSTI)](./attack_surfaces/server-side_template_injection__ssti_.md)

**Description:** Attackers inject malicious Handlebars expressions into templates, leading to arbitrary code execution on the server.

**How Handlebars.js Contributes:** Handlebars' expression evaluation and helper system allow for dynamic code execution within templates. If user-controlled data is directly embedded into a template without sanitization, attackers can exploit this.

**Example:**  A vulnerable template might look like `<h1>Hello, {{username}}</h1>`. If `username` is directly taken from user input like `{{constructor.constructor('return process')().mainModule.require('child_process').execSync('whoami')}}`, it could execute the `whoami` command on the server.

**Impact:** Complete server compromise, including data breaches, malware installation, and denial of service.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   Never directly embed user-provided data into Handlebars templates without strict sanitization.
*   Use parameterized templates or separate data binding mechanisms.
*   Regularly audit template usage for potential injection points.

## Attack Surface: [Client-Side Cross-Site Scripting (XSS) via Unsafe Output](./attack_surfaces/client-side_cross-site_scripting__xss__via_unsafe_output.md)

**Description:** Attackers inject malicious scripts into data that is then rendered by Handlebars without proper escaping, leading to script execution in the user's browser.

**How Handlebars.js Contributes:** Handlebars provides the `{{{ }}}` syntax for unescaped output. While useful for rendering trusted HTML, it becomes a vulnerability if used with untrusted user data.

**Example:** A template like `<div>{{{userData}}}</div>`. If `userData` contains `<script>alert('XSS')</script>`, this script will execute in the user's browser.

**Impact:**  Stealing user cookies, session hijacking, redirecting users to malicious sites, defacing the website, and other client-side attacks.

**Risk Severity:** High

**Mitigation Strategies:**
*   Always use the default `{{ }}` syntax for escaping HTML entities when rendering user-provided data.
*   Carefully review and justify the use of `{{{ }}}` for unescaped output, ensuring the data source is absolutely trusted.
*   Implement a strong Content Security Policy (CSP) to restrict the sources from which scripts can be loaded and executed.

## Attack Surface: [Abuse of Custom Helpers](./attack_surfaces/abuse_of_custom_helpers.md)

**Description:**  Developers create custom Handlebars helpers that introduce security vulnerabilities due to insecure implementation.

**How Handlebars.js Contributes:** Handlebars allows developers to extend its functionality with custom helpers. If these helpers are not written securely, they can become attack vectors.

**Example:** A custom helper that executes shell commands based on user input: `{{executeCommand userInput}}`. If `userInput` is not sanitized, it could lead to command injection.

**Impact:**  The impact depends on the functionality of the vulnerable helper, ranging from information disclosure to remote code execution.

**Risk Severity:** High to Critical (depending on the helper's function)

**Mitigation Strategies:**
*   Thoroughly review and security-audit all custom Handlebars helpers.
*   Avoid performing dangerous operations (like shell execution or direct database queries) within helpers based on untrusted input.
*   Implement proper input validation and sanitization within the helper logic.
*   Follow the principle of least privilege when designing helper functionality.

## Attack Surface: [Abuse of Partials and Layouts](./attack_surfaces/abuse_of_partials_and_layouts.md)

**Description:** Attackers manipulate the paths or names of partials or layouts to include unintended or malicious files.

**How Handlebars.js Contributes:** Handlebars allows for dynamic inclusion of partials and layouts. If the logic determining which partial or layout to include is based on unsanitized user input, it can be exploited.

**Example:** A template using `{{> (lookup . 'partialName') }}` where `partialName` is derived from user input. An attacker could manipulate this input to include a sensitive file or a malicious partial.

**Impact:** Information disclosure (reading sensitive files), potential for remote code execution if the included file is processed as code.

**Risk Severity:** Medium to High

**Mitigation Strategies:**
*   Avoid using user-provided data to directly determine the paths or names of partials or layouts.
*   Implement a whitelist of allowed partials and layouts and only allow inclusion from this list.
*   Sanitize any user input used in constructing partial or layout paths.

