# Attack Tree Analysis for formatjs/formatjs

Objective: Execute XSS or Manipulate Content via `formatjs`/`react-intl` Vulnerabilities (Focus: Argument Injection)

## Attack Tree Visualization

```
                                     +-------------------------------------------------+
                                     |  Attacker's Goal: Execute XSS or Manipulate    |
                                     |  Content via formatjs/react-intl Vulnerabilities |
                                     +-------------------------------------------------+
                                                        |
                                       +-----------------------------------------+
                                       |  2. Exploit Message Argument Handling   |
                                       |     (e.g., Placeholders)  [HIGH RISK]    |
                                       +-----------------------------------------+
                                                        |
                                       +---------------------+
                                       |  2.a. Unsanitized    |
                                       |      Arguments      |
                                       | [HIGH RISK] [CRITICAL]|                                       +---------------------+
                                                        |
                                       +---------------------+
                                       |  2.a.i. Inject HTML  |
                                       |  tags or event      |
                                       |  handlers (e.g.,   |
                                       |  <img onerror=...>) |
                                       |  into arguments.    |
                                       |  [HIGH RISK]       |
                                       +---------------------+
```

## Attack Tree Path: [2. Exploit Message Argument Handling [HIGH RISK]](./attack_tree_paths/2__exploit_message_argument_handling__high_risk_.md)

*   **Description:** This is the primary attack vector, focusing on how `formatjs` processes arguments (the values inserted into placeholders within formatted messages). The core issue is that `formatjs` itself does *not* automatically sanitize these arguments. It's designed to handle rich text, so it trusts the application to provide safe input.
*   **Why High Risk:**
    *   **High Likelihood:** Developers frequently overlook the need for argument sanitization, making this a very common vulnerability.
    *   **High Impact:** Successful exploitation leads directly to Cross-Site Scripting (XSS), a severe vulnerability.
    *   **Low Effort:** Simple XSS payloads are often effective.
    *   **Relatively Low Skill:** Basic XSS knowledge is sufficient.

## Attack Tree Path: [2.a. Unsanitized Arguments [HIGH RISK] [CRITICAL]](./attack_tree_paths/2_a__unsanitized_arguments__high_risk___critical_.md)

*   **Description:** This is the core vulnerability. If the application doesn't properly sanitize user-provided data before passing it as an argument to `formatjs`, an attacker can inject malicious code.
*   **Why High Risk:** (Same reasons as above - High Likelihood, High Impact, Low Effort, Low Skill)
*   **Why Critical:** This is a *necessary* condition for the most common and dangerous attack. Without unsanitized arguments, the XSS injection (2.a.i) cannot occur. This node is the "gatekeeper" – if it's secured, the attack is blocked.
*   **Example:**
    ```javascript
    // Vulnerable Code:
    const userInput = "<img src=x onerror=alert(1)>";
    const message = intl.formatMessage({ id: 'welcome' }, { name: userInput });
    // The 'welcome' message might be: "Hello, {name}!"
    // Result:  "Hello, <img src=x onerror=alert(1)>!"  (XSS!)

    // Secure Code (using DOMPurify):
    const userInput = "<img src=x onerror=alert(1)>";
    const sanitizedInput = DOMPurify.sanitize(userInput); // Removes the malicious tag
    const message = intl.formatMessage({ id: 'welcome' }, { name: sanitizedInput });
    // Result: "Hello, !" (or whatever DOMPurify leaves after sanitization)
    ```

## Attack Tree Path: [2.a.i. Inject HTML tags or event handlers (e.g., `<img onerror=...>)` into arguments. [HIGH RISK]](./attack_tree_paths/2_a_i__inject_html_tags_or_event_handlers__e_g____img_onerror=______into_arguments___high_risk_.md)

*   **Description:** This is the specific action the attacker takes. They craft a malicious payload (usually containing HTML tags with JavaScript event handlers) and inject it into a user-input field that will be used as an argument in a formatted message.
*   **Why High Risk:**
    *   **High Likelihood:**  Direct consequence of unsanitized arguments.
    *   **High Impact:**  Executes arbitrary JavaScript in the context of the victim's browser, leading to session hijacking, data theft, etc.
    *   **Low Effort:**  Simple payloads are readily available.
    *   **Relatively Low Skill:**  Basic XSS knowledge is sufficient.
*   **Common Payloads:**
    *   `<script>alert(1)</script>` (Simple test payload)
    *   `<img src=x onerror=alert(1)>` (Commonly used to bypass simple filters)
    *   `<iframe onload=alert(1)>`
    *   `<svg onload=alert(1)>`
    *   More complex payloads can steal cookies, redirect users, or modify the page content.
* **Detection:**
    *   **Reflected XSS:** The injected script is immediately reflected back in the server's response. Easier to detect through careful observation of input and output.
    *   **Stored XSS:** The injected script is stored on the server (e.g., in a database) and executed later when another user views the affected page. Harder to detect, requires monitoring stored data and user activity.
    *   **DOM-based XSS:** The vulnerability exists in the client-side JavaScript code. The malicious input modifies the DOM in an unsafe way. Requires analyzing client-side code and its interaction with user input.

