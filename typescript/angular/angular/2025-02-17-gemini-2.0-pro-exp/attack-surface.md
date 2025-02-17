# Attack Surface Analysis for angular/angular

## Attack Surface: [Cross-Site Scripting (XSS) via Template Injection](./attack_surfaces/cross-site_scripting__xss__via_template_injection.md)

*   **Description:** Injection of malicious JavaScript code into the application through Angular templates, due to improper handling of user-supplied data within Angular's data binding system.
*   **How Angular Contributes:** Angular's core data binding (`{{ ... }}`, `[property]="value"`, directives like `[innerHTML]`) is the primary vector.  Bypassing or misusing Angular's `DomSanitizer` significantly increases the risk.
*   **Example:**
    ```html
    <!-- Vulnerable if 'userInput' contains malicious script -->
    <div [innerHTML]="userInput"></div>

    <!-- Also vulnerable if userInput contains <script>alert('XSS')</script> -->
    <div>{{userInput}}</div>
    ```
*   **Impact:**
    *   Stealing user cookies and session tokens.
    *   Defacing the website.
    *   Redirecting users to malicious websites.
    *   Performing actions on behalf of the user.
    *   Keylogging and data theft.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Strictly Limit `bypassSecurityTrust...`:**  Avoid `bypassSecurityTrustHtml`, `bypassSecurityTrustScript`, etc., unless absolutely necessary and after thorough security review and server-side sanitization.
    *   **Prefer Safer Bindings:** Use `[textContent]` for plain text, and Angular's property bindings (`[property]="value"`) where possible, as they offer built-in escaping (though not foolproof).
    *   **Minimize `innerHTML`:** Avoid using `innerHTML` with user-supplied data.
    *   **Server-Side Sanitization:**  *Always* sanitize user input on the server-side before it reaches the Angular application. This is the most crucial defense.
    *   **Content Security Policy (CSP):** Implement a strong CSP to limit script execution sources, mitigating XSS impact.
    *   **Regular Angular Updates:** Keep Angular and its dependencies updated to benefit from security patches.

## Attack Surface: [Component Input/Output Misuse (Leading to XSS)](./attack_surfaces/component_inputoutput_misuse__leading_to_xss_.md)

*   **Description:**  Vulnerabilities arising from improper handling of data passed between Angular components, specifically leading to XSS when unsanitized input is rendered in a child component's template.
*   **How Angular Contributes:** Angular's component-based architecture and the `@Input()` decorator are directly involved.  The vulnerability arises when a parent component passes unsanitized data to a child component, and the child component renders it without proper sanitization.
*   **Example:**
    ```typescript
    // Parent Component (Vulnerable)
    @Component({
      selector: 'app-parent',
      template: `<app-child [userInput]="untrustedData"></app-child>`
    })
    export class ParentComponent {
      untrustedData = "<script>alert('XSS')</script>"; // From user input
    }

    // Child Component (Vulnerable if not sanitizing)
    @Component({
      selector: 'app-child',
      template: `<div [innerHTML]="userInput"></div>`  // Or any unsafe binding
    })
    export class ChildComponent {
      @Input() userInput: string;
    }
    ```
*   **Impact:**  Same as standard XSS (cookie theft, defacement, redirection, etc.).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Mandatory Child Component Sanitization:** Child components *must* validate and sanitize all data received via `@Input()` properties, *regardless* of the parent component's supposed trustworthiness.  Treat all inputs as potentially malicious.
    *   **Use `DomSanitizer` (Carefully):**  If absolutely necessary to render HTML in a child component, use `DomSanitizer` *within the child component*, but avoid bypassing security unless strictly required and thoroughly reviewed.
    *   **Strong Typing:** Use TypeScript's strong typing to define the expected types of inputs, reducing the risk of unexpected data.

## Attack Surface: [Route Guard Bypass (Leading to Unauthorized Access)](./attack_surfaces/route_guard_bypass__leading_to_unauthorized_access_.md)

*   **Description:** Circumventing Angular's route guards, allowing unauthorized access to protected routes due to flaws in the guard's implementation.  This is *directly* related to Angular's routing mechanism.
*   **How Angular Contributes:** Angular's router and the `CanActivate`, `CanDeactivate`, etc., interfaces are the core components involved. The vulnerability lies in *incorrectly implemented* guards.
*   **Example:**
    ```typescript
    // Vulnerable Route Guard (simplified - relies on easily manipulated client-side state)
    @Injectable({ providedIn: 'root' })
    export class AuthGuard implements CanActivate {
      canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean {
        // Insecure check - easily bypassed
        if (localStorage.getItem('token')) {
          return true;
        }
        return false;
      }
    }
    ```
*   **Impact:** Unauthorized access to sensitive data or functionality.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Robust Guard Logic:** Implement route guards with robust, server-backed logic that cannot be easily bypassed on the client-side.  Do *not* rely solely on client-side checks (like `localStorage`).
    *   **Server-Side Authorization:** *Always* enforce authorization checks on the server-side, regardless of client-side route guards. Route guards are a *convenience*, not a primary security mechanism.
    *   **Thorough Testing:**  Write comprehensive unit and integration tests for route guards to ensure they handle all edge cases and cannot be bypassed.

## Attack Surface: [Angular Universal (SSR) XSS](./attack_surfaces/angular_universal__ssr__xss.md)

*   **Description:** XSS vulnerabilities that occur specifically during server-side rendering (SSR) with Angular Universal, where unsanitized input is rendered on the server.
*   **How Angular Contributes:** This is *entirely* specific to Angular Universal's server-side rendering process. The vulnerability arises when Angular renders templates on the server without proper sanitization of user-provided data.
*   **Example:** If user input is directly rendered into the HTML template on the server (within an Angular component rendered by Universal) without sanitization, an attacker can inject malicious script.
*   **Impact:** Similar to client-side XSS, but with the added risk of server-side code execution and potential data breaches. The injected script executes *both* on the server and then again on the client.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Server-Side Sanitization (Pre-Rendering):**  *Always* sanitize all user-supplied data *before* it is used in the server-side rendering process. This is the most critical step. Use appropriate sanitization techniques for the type of data.
    *   **Avoid Exposing Sensitive Data in SSR:** Do not include sensitive data (API keys, secrets) in the rendered HTML output.
    *   **Secure Node.js Environment:** Ensure the Node.js environment used for SSR is secure and up-to-date.
    *   **Content Security Policy (CSP):** Use CSP to mitigate the impact of XSS, even during SSR.

