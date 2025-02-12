# Attack Surface Analysis for jquery/jquery

## Attack Surface: [Cross-Site Scripting (XSS) via `$` Function and Untrusted Input](./attack_surfaces/cross-site_scripting__xss__via__$__function_and_untrusted_input.md)

*   **Description:** Exploiting the core jQuery function (`$()`) to inject malicious JavaScript code into the web page by manipulating how it processes untrusted data (e.g., URL parameters, form inputs, data from AJAX calls).
    *   **jQuery Contribution:** jQuery's `$()` function, when used to create or manipulate DOM elements based on unsanitized user input, provides a direct pathway for XSS. Its ease of use can lead developers to inadvertently introduce vulnerabilities.
    *   **Example:**
        ```javascript
        // Vulnerable code:
        $(location.hash); // If the URL is: mypage.html#<img src=x onerror=alert(1)>
        // Or:
        let userInput = "<img src=x onerror=alert('XSS')>";
        $("#someDiv").html(userInput); //Direct injection
        $("#someDiv").append($(userInput)); //Injection via $()
        ```
    *   **Impact:**  Allows attackers to execute arbitrary JavaScript code in the context of the victim's browser.  This can lead to session hijacking, data theft, defacement, phishing, and other malicious actions.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Input Sanitization:**  Always sanitize user-provided data *before* passing it to `$()` or any jQuery method that manipulates the DOM. Use a dedicated HTML sanitization library like DOMPurify.  *Never* attempt to write your own sanitization routines.
        *   **Safe DOM Manipulation:** Prefer jQuery's safer methods for creating and manipulating elements (e.g., `.text()`, `.attr()`, `.prop()`) over directly injecting HTML strings.  Even with these methods, *always* sanitize the input.
        *   **Context-Aware Output Encoding:**  When displaying user-provided data, use appropriate output encoding for the context (e.g., HTML encoding, JavaScript encoding). jQuery's `.text()` method handles HTML encoding automatically.
        *   **Content Security Policy (CSP):** Implement a strong CSP to restrict the execution of inline scripts and limit the sources from which scripts can be loaded. This provides a crucial layer of defense even if an XSS vulnerability exists.

## Attack Surface: [Cross-Site Scripting (XSS) via `$.parseHTML()`](./attack_surfaces/cross-site_scripting__xss__via__$_parsehtml___.md)

*   **Description:**  Exploiting the `$.parseHTML()` function to inject malicious JavaScript by providing it with an unsanitized HTML string containing attacker-controlled code.
    *   **jQuery Contribution:** `$.parseHTML()` is designed to parse HTML strings, and if that string contains malicious script tags or event handlers, they will be parsed and potentially executed when the resulting nodes are added to the DOM.
    *   **Example:**
        ```javascript
        let untrustedHTML = "<img src=x onerror='alert(1)'>";
        let nodes = $.parseHTML(untrustedHTML);
        $("body").append(nodes); // XSS triggered
        ```
    *   **Impact:** Similar to XSS via `$()`, allows attackers to execute arbitrary JavaScript in the victim's browser.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Input Sanitization:**  Always sanitize the HTML string *before* passing it to `$.parseHTML()` using a robust HTML sanitizer like DOMPurify.
        *   **Avoid Unnecessary Use:** If you don't need to parse arbitrary HTML strings, avoid using `$.parseHTML()`. Consider alternative approaches for manipulating the DOM.

## Attack Surface: [Prototype Pollution via `$.extend()` (Primarily Older Versions)](./attack_surfaces/prototype_pollution_via__$_extend_____primarily_older_versions_.md)

*   **Description:**  Attacker modifies the properties of base JavaScript objects (like `Object.prototype`) by exploiting vulnerabilities in how jQuery merges objects, particularly with the `$.extend(true, ...)` (deep copy) functionality.
    *   **jQuery Contribution:** Older versions of jQuery (before 3.4.0) were vulnerable to prototype pollution when using `$.extend()` with recursive merging and attacker-controlled input.  This allowed attackers to inject properties like `__proto__`, potentially altering the behavior of the application.
    *   **Example:**
        ```javascript
        // Vulnerable (older jQuery versions):
        let maliciousInput = JSON.parse('{"__proto__": {"polluted": true}}');
        $.extend(true, {}, maliciousInput); // Pollutes Object.prototype
        if (({}).polluted) {
            console.log("Vulnerable to prototype pollution!");
        }
        ```
    *   **Impact:** Can lead to a variety of issues, including denial of service, arbitrary code execution (in some cases), and unexpected application behavior.  The impact depends on how the application uses object properties.
    *   **Risk Severity:** High (Critical in older, unpatched versions)
    *   **Mitigation Strategies:**
        *   **Upgrade jQuery:**  The primary mitigation is to upgrade to jQuery 3.4.0 or later, which includes fixes for this vulnerability.
        *   **Input Validation:** If using an older version is unavoidable, *strictly* validate and sanitize any input that is used with `$.extend(true, ...)`.  Prevent the injection of `__proto__`, `constructor`, or `prototype` properties.
        *   **Safer Alternatives:** Consider using alternative libraries for deep object merging that are specifically designed to prevent prototype pollution.

