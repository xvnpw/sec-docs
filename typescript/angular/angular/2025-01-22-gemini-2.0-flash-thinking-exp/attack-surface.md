# Attack Surface Analysis for angular/angular

## Attack Surface: [DOM-based Cross-Site Scripting (XSS) via `innerHTML` and similar APIs](./attack_surfaces/dom-based_cross-site_scripting__xss__via__innerhtml__and_similar_apis.md)

**Description:** DOM-based XSS occurs when a web application writes untrusted data directly to the Document Object Model (DOM) without proper sanitization. This allows attackers to inject malicious scripts that execute in the user's browser.

**Angular Contribution:** Angular's data binding and template features, particularly `[innerHTML]` binding and `DomSanitizer.bypassSecurityTrustHtml`, can directly insert HTML into the DOM. If user-controlled data is used in these bindings without sanitization, it creates a direct path for DOM-based XSS.

**Example:**

```html
<div [innerHTML]="userInput"></div>
```

If `userInput` is directly taken from a URL parameter or user input field without sanitization and contains `<img src="x" onerror="alert('XSS')">`, the script will execute when Angular renders the template.

**Impact:** Full compromise of the user's session, including stealing cookies, session tokens, redirecting to malicious sites, defacement, and potentially further attacks against the user's system.

**Risk Severity:** **Critical**

**Mitigation Strategies:**

*   **Avoid `[innerHTML]` and `DomSanitizer.bypassSecurityTrustHtml`:**  Prefer Angular's safe binding mechanisms like text interpolation `{{ }}` and property binding `[property]`.
*   **Sanitize User Input (Server-Side):** If you must use `[innerHTML]` or bypass sanitization (which should be rare), rigorously sanitize user input using a trusted sanitization library *on the server-side* before it reaches the Angular application. Angular's built-in sanitizer is for output, not input validation.
*   **Content Security Policy (CSP):** Implement a strict CSP to limit the sources from which scripts can be loaded and restrict inline script execution. This acts as a defense-in-depth measure.

## Attack Surface: [Client-Side Routing Vulnerabilities - Route Parameter Injection leading to DOM XSS](./attack_surfaces/client-side_routing_vulnerabilities_-_route_parameter_injection_leading_to_dom_xss.md)

**Description:**  Improperly validated or sanitized route parameters can be used to inject malicious data. If these route parameters are directly used to manipulate the DOM without proper encoding or sanitization, it can lead to DOM-based XSS.

**Angular Contribution:** Angular Router allows defining routes with parameters. Components can access these route parameters using `ActivatedRoute`. Unsafe usage of these parameters in DOM manipulation within components creates a vulnerability.

**Example:**

```typescript
constructor(private route: ActivatedRoute, private elementRef: ElementRef) {
  this.route.params.subscribe(params => {
    this.elementRef.nativeElement.innerHTML = `<p>You searched for: ${params['query']}</p>`; // Unsafe use of route parameter
  });
}
```

If the URL is `/search/<img src=x onerror=alert('XSS')>`, the injected script will execute because the `query` route parameter is directly inserted into the DOM via `innerHTML`.

**Impact:** DOM-based XSS, leading to full compromise of the user's session, data theft, and malicious actions on behalf of the user.

**Risk Severity:** **High**

**Mitigation Strategies:**

*   **Sanitize Route Parameters:** Sanitize route parameters before using them to manipulate the DOM. Use Angular's built-in sanitization or a dedicated sanitization library.
*   **Validate Route Parameters:** Validate route parameters to ensure they conform to expected formats and types. Reject invalid parameters.
*   **Use Parameters Safely:** Avoid directly injecting route parameters into HTML using `innerHTML`. Use data binding and Angular's safe rendering mechanisms like text interpolation `{{ }}`.

## Attack Surface: [Server-Side Rendering (SSR) Vulnerabilities leading to Injection (if using Angular Universal)](./attack_surfaces/server-side_rendering__ssr__vulnerabilities_leading_to_injection__if_using_angular_universal_.md)

**Description:** When using Angular Universal for SSR, a Node.js server component is introduced. If data handling in the SSR context is not properly secured, it could be vulnerable to injection attacks. This can manifest as XSS vulnerabilities in the rendered HTML or other server-side injection issues.

**Angular Contribution:** Angular Universal, while providing SSR benefits, introduces a Node.js server layer. Vulnerabilities in how data is handled and rendered server-side within Angular Universal applications can lead to injection flaws.

**Example:** If server-side code directly embeds user-provided data into the rendered HTML without proper escaping, it can lead to XSS. For instance, if a component in SSR uses `innerHTML` with unsanitized data, the vulnerability is present in the server-rendered output.

**Impact:**  XSS vulnerabilities in the server-rendered HTML, potentially leading to full compromise of user sessions. Server-side vulnerabilities could also lead to more severe impacts like server compromise depending on the nature of the injection.

**Risk Severity:** **High** to **Critical** (depending on the specific vulnerability and context)

**Mitigation Strategies:**

*   **Secure Server-Side Code:** Follow secure coding practices in the server-side component of Angular Universal applications.
*   **Input Sanitization and Output Encoding in SSR:** Ensure proper input sanitization and output encoding are applied in the server-side rendering process, especially when handling user-provided data.
*   **Template Security in SSR:** Be mindful of template security in the SSR context and avoid unsafe practices like using `innerHTML` with unsanitized data on the server-side.
*   **Regular Server Security Audits:** Conduct regular security audits and penetration testing of the server-side component of Angular Universal applications.

