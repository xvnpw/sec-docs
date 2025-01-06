# Attack Surface Analysis for angular/angular.js

## Attack Surface: [Client-Side Template Injection (CSTI)](./attack_surfaces/client-side_template_injection__csti_.md)

*   **Attack Surface:** Client-Side Template Injection (CSTI)
    *   **Description:** Attackers inject malicious Angular expressions into the application's templates, leading to arbitrary JavaScript execution in the user's browser.
    *   **How Angular.js Contributes:** Angular.js evaluates expressions within double curly braces `{{ }}`. If user-controlled data is directly placed within these braces without proper sanitization, it can be interpreted as code.
    *   **Example:**  A comment section allows users to input their name. If the template uses `<h1>Hello, {{comment.author}}!</h1>` and a malicious user enters `{{constructor.constructor('alert("XSS")')()}}`, the alert will execute.
    *   **Impact:**  Critical. Attackers can execute arbitrary JavaScript, potentially stealing credentials, redirecting users, or defacing the application.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Avoid directly embedding user input in Angular expressions. Use one-way binding or filters for display purposes.
        *   Utilize the `$sce` (Strict Contextual Escaping) service. Mark data as trusted before rendering it in potentially dangerous contexts.
        *   Employ Content Security Policy (CSP). Restrict the sources from which the browser is allowed to load resources, mitigating the impact of injected scripts.

## Attack Surface: [Cross-Site Scripting (XSS) through Data Binding](./attack_surfaces/cross-site_scripting__xss__through_data_binding.md)

*   **Attack Surface:** Cross-Site Scripting (XSS) through Data Binding
    *   **Description:** Malicious scripts are injected into the application's data model and subsequently rendered into the DOM without proper escaping, leading to script execution in the user's browser.
    *   **How Angular.js Contributes:** Angular.js's two-way data binding automatically updates the view when the model changes. If unsanitized user input containing `<script>` tags or event handlers is bound to a model and rendered, the script will execute.
    *   **Example:** A form field binds user input to `ng-model="user.description"`. If a user enters `<img src="x" onerror="alert('XSS')">`, this image tag with the malicious `onerror` attribute will be rendered and executed.
    *   **Impact:** Critical. Similar to CSTI, attackers can execute arbitrary JavaScript, leading to credential theft, session hijacking, or defacement.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Sanitize user input on the server-side before it reaches the Angular.js application.
        *   Utilize the `ngSanitize` module. This module provides a filter that safely renders HTML by stripping out potentially dangerous elements and attributes.
        *   Avoid using `bypassSecurityTrust...` methods of `$sce` unless absolutely necessary and with extreme caution. These methods can bypass Angular's built-in security.
        *   Implement proper output encoding on the server-side as a defense-in-depth measure.

## Attack Surface: [$eval() and $parse() Function Misuse](./attack_surfaces/$eval___and_$parse___function_misuse.md)

*   **Attack Surface:** `$eval()` and `$parse()` Function Misuse
    *   **Description:** Directly passing user-controlled input to Angular.js's `$eval()` or `$parse()` functions allows attackers to execute arbitrary code within the Angular context.
    *   **How Angular.js Contributes:** These functions are designed to evaluate Angular expressions. If user input is used as the expression string without validation, attackers can inject malicious code.
    *   **Example:**  A poorly designed search feature uses `$scope.$eval(userInput)` to filter results. A malicious user could input code like `constructor.constructor('alert("XSS")')()` to execute JavaScript.
    *   **Impact:** High. Attackers can gain significant control over the application's logic and potentially execute arbitrary JavaScript.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Never directly pass user input to `$eval()` or `$parse()` without rigorous validation and sanitization.
        *   If possible, avoid using these functions with user input altogether. Explore alternative, safer methods for achieving the desired functionality.
        *   Implement strict input validation to ensure the input conforms to expected patterns and does not contain potentially harmful characters or code.

