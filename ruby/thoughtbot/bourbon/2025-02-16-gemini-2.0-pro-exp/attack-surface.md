# Attack Surface Analysis for thoughtbot/bourbon

## Attack Surface: [CSS Injection via Unsanitized Input](./attack_surfaces/css_injection_via_unsanitized_input.md)

*   **Description:** Malicious CSS code is injected into the application's stylesheets, potentially altering the appearance, behavior, or even exfiltrating data.
    *   **Bourbon's Contribution:** Bourbon mixins and functions, *when misused with unsanitized user input provided as Sass variables*, become the direct mechanism for this injection.  The vulnerability isn't in Bourbon itself, but in how it's *used* to process untrusted input.
    *   **Example:**
        ```scss
        // Vulnerable Sass (highly unlikely scenario)
        $user_color: $_POST['color']; // Directly using unsanitized POST data!
        .element {
          background-color: $user_color; // Bourbon mixin or function using the variable
          @include some-bourbon-mixin($user_color); //Another example
        }
        ```
        If `$_POST['color']` contains `red; } body { display: none; } /*`, the malicious CSS would be injected.
    *   **Impact:**
        *   Defacement of the website.
        *   Injection of malicious styles that could phish users.
        *   Limited data exfiltration (using CSS techniques).
        *   Potentially, in very specific and rare cases with older browsers or unusual configurations, a pathway to XSS *might* be created through highly crafted CSS, although this is not a typical CSS injection outcome.
    *   **Risk Severity:** High (conditional on the presence of the architectural flaw allowing unsanitized input into Sass)
    *   **Mitigation Strategies:**
        *   **Strict Input Validation and Sanitization:** *Never* directly incorporate user input into Sass variables.  All user-supplied data must be rigorously validated and sanitized on the server-side *before* being used in any context, including Sass compilation. Employ a whitelist approach (allowing only known-good values) rather than a blacklist.
        *   **Architectural Enforcement:** The application's architecture should *prevent* any direct path from user input to Sass variables. This is a fundamental security design principle.  Sass variables should be derived from trusted, server-side sources.
        *   **Content Security Policy (CSP):** A well-configured CSP can mitigate the impact of CSS injection, even if it occurs, by restricting style sources and potentially disallowing inline styles.

## Attack Surface: [Supply Chain Attack](./attack_surfaces/supply_chain_attack.md)

*   **Description:** A compromised version of the Bourbon library itself is installed, introducing malicious code that executes during the *build* process.
    *   **Bourbon's Contribution:** Bourbon is the direct target of the attack. The attacker compromises the Bourbon package (e.g., on npm) to inject their code.
    *   **Example:** An attacker gains control of the Bourbon package on npm and publishes a malicious version that, during installation or build, steals environment variables or injects malicious JavaScript into the compiled CSS (though the latter is less likely, the build process itself is compromised).
    *   **Impact:**
        *   Compromise of the build environment.
        *   Potential for injection of malicious code into the final application.
        *   Theft of sensitive data (API keys, secrets) accessible during the build.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Package Manager Integrity Checks:** Use `npm` with `package-lock.json` or `yarn` with `yarn.lock`. These files record the exact versions and cryptographic hashes of installed dependencies, ensuring that the same, verified code is installed each time.
        *   **Dependency Auditing:** Regularly audit dependencies for known vulnerabilities. Use tools like `npm audit` or dedicated Software Composition Analysis (SCA) tools.
        *   **Version Pinning:** Pin Bourbon (and other dependencies) to specific versions in your `package.json` to prevent unexpected updates that might introduce malicious code or vulnerabilities.
        *   **Software Composition Analysis (SCA):** Employ SCA tools to continuously monitor and identify vulnerabilities in your dependencies, including Bourbon.
        *   **Vendoring (Optional, High Control):** For the highest level of control, consider vendoring Bourbon (copying its source code directly into your project). This eliminates reliance on external package repositories but requires manual updates.

