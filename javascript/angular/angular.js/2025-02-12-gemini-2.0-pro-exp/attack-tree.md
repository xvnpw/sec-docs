# Attack Tree Analysis for angular/angular.js

Objective: Execute Arbitrary JavaScript (AngularJS-Specific) [CRITICAL]

## Attack Tree Visualization

```
                                     [G] Execute Arbitrary JavaScript (AngularJS-Specific) [CRITICAL]
                                                  |
                      -------------------------------------------------
                      |                                               |
             [A] Client-Side Template Injection (CSTI)      [C] Exploiting Known AngularJS Vulnerabilities
                      |                                               |
        --------------                                   ----------------
        |             |                                   |
     [A2] Exploit   [C4] Misuse of
     Expression    AngularJS
     Sandboxes     Directives/Services
     [CRITICAL]    [CRITICAL]
                   (e.g., ng-bind-html
                    without sanitization)

```

## Attack Tree Path: [[G] Execute Arbitrary JavaScript (AngularJS-Specific) [CRITICAL]](./attack_tree_paths/_g__execute_arbitrary_javascript__angularjs-specific___critical_.md)

*   **Description:** This is the ultimate objective of the attacker. By achieving arbitrary JavaScript execution within the context of the AngularJS application, the attacker gains significant control.
*   **Consequences:**
    *   Data Exfiltration: Stealing sensitive user data, session tokens, or application data.
    *   Session Hijacking: Impersonating a legitimate user and performing actions on their behalf.
    *   Defacement: Modifying the application's appearance or functionality.
    *   Client-Side Attacks: Launching attacks against other users of the application (e.g., stored XSS).
    *   Further Exploitation: Using the compromised application as a pivot point to attack other systems.

## Attack Tree Path: [[A] Client-Side Template Injection (CSTI)](./attack_tree_paths/_a__client-side_template_injection__csti_.md)

*   **Description:** CSTI occurs when user-supplied input is directly incorporated into an AngularJS template without proper sanitization or escaping. AngularJS templates are rendered on the client-side, and if an attacker can inject malicious code into the template, it will be executed by the AngularJS framework.
*   **Mechanism:** AngularJS uses double curly braces `{{ }}` for data binding and expression evaluation within templates. If user input is included within these braces, or within directives that evaluate expressions (like `ng-bind-html`), AngularJS will attempt to evaluate it as code.
*   **Example:**
    *   Vulnerable Code: `<div ng-bind-html="userInput"></div>` where `userInput` is directly from a user-controlled source.
    *   Attacker Input: `userInput = "<img src=x onerror=alert(1)>"`
    *   Result: The `onerror` event handler will execute, displaying an alert box (demonstrating arbitrary JavaScript execution).

## Attack Tree Path: [[A2] Exploit Expression Sandboxes [CRITICAL]](./attack_tree_paths/_a2__exploit_expression_sandboxes__critical_.md)

*   **Description:** Older versions of AngularJS used expression sandboxes to try to limit the capabilities of expressions within templates. However, these sandboxes have been repeatedly bypassed and are now considered ineffective. This node represents exploiting those historical sandbox limitations.
*   **Mechanism:** Attackers would craft specific JavaScript expressions designed to escape the sandbox's restrictions, gaining access to global objects and functions that should have been restricted.
*   **Example:** Exploits often involved manipulating the `constructor` property of objects or using specific function calls to break out of the sandbox's context.
*   **Note:** This is primarily relevant to *very old, unpatched* AngularJS applications. Modern versions (1.6+) have removed the sandbox entirely.

## Attack Tree Path: [[C] Exploiting Known AngularJS Vulnerabilities](./attack_tree_paths/_c__exploiting_known_angularjs_vulnerabilities.md)



## Attack Tree Path: [[C4] Misuse of AngularJS Directives/Services [CRITICAL]](./attack_tree_paths/_c4__misuse_of_angularjs_directivesservices__critical_.md)

*   **Description:** This represents vulnerabilities arising from the incorrect or insecure use of built-in AngularJS features, even if there isn't a specific CVE associated with the feature itself. The most common example is using `ng-bind-html` without sanitization.
*   **Mechanism:**
    *   `ng-bind-html`: This directive is designed to render HTML content. If user-provided data is passed to `ng-bind-html` without being properly sanitized, it creates a direct XSS vulnerability. AngularJS will render the HTML, including any malicious scripts embedded within it.
    *   Other Directives: Custom directives that handle user input and manipulate the DOM without proper escaping can also introduce vulnerabilities.
    *   Services: Misusing services like `$http` (e.g., constructing URLs with unsanitized user input) could lead to other vulnerabilities, though these are less directly related to AngularJS-specific code execution.
*   **Example (ng-bind-html):**
    *   Vulnerable Code: `<div ng-bind-html="userComment"></div>` where `userComment` is directly from user input.
    *   Attacker Input: `userComment = "<script>alert('XSS');</script>"`
    *   Result: The injected script will execute, demonstrating XSS.
* **Example (Custom Directive):**
    ```javascript
    app.directive('myDirective', function() {
      return {
        template: '<div>' + /* User input directly concatenated here */ + '</div>'
      };
    });
    ```
    If user input is directly concatenated into the template string without escaping, it creates an XSS vulnerability.

