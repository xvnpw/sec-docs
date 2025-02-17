# Mitigation Strategies Analysis for angular/angular

## Mitigation Strategy: [Minimize `DomSanitizer.bypassSecurityTrust*` Usage](./mitigation_strategies/minimize__domsanitizer_bypasssecuritytrust__usage.md)

**Description:**
1.  **Identify all instances:** Search the codebase for `bypassSecurityTrustHtml`, `bypassSecurityTrustScript`, `bypassSecurityTrustStyle`, `bypassSecurityTrustUrl`, and `bypassSecurityTrustResourceUrl`.
2.  **Evaluate Necessity:** Determine if each bypass is *absolutely* necessary. Can Angular's template/property/attribute binding achieve the same result?
3.  **Refactor (if possible):** Use safer alternatives like `[href]="myUrl"` instead of bypassing for an `<a>` tag's `href`.
4.  **Justify and Document (if necessary):** If unavoidable, document *why*, the risks considered, and mitigation steps. Add a code comment.
5.  **Use the Most Restrictive `SafeValue`:** If bypassing, use the *most specific* `SafeValue` (e.g., `bypassSecurityTrustUrl`, not `bypassSecurityTrustHtml`).
6.  **Regular Code Reviews:** Include a check for `DomSanitizer` bypasses in code reviews.

**Threats Mitigated:**
*   **Cross-Site Scripting (XSS):** (Severity: High) - Bypassing allows malicious HTML/JS/CSS/URLs into the DOM, enabling script execution.
*   **Template Injection:** (Severity: High) - Targets Angular templates specifically.

**Impact:**
*   **XSS:** Risk reduction: High. Eliminating bypasses significantly reduces the XSS attack surface.
*   **Template Injection:** Risk reduction: High. Prevents manipulation of Angular template structure/logic.

**Currently Implemented:** (Example - tailor to your project)
*   "Partially implemented.  A review was conducted in Q1 2023, and most instances were refactored. Remaining instances are documented."

**Missing Implementation:** (Example - tailor to your project)
*   "Missing an automated code review process to flag new `DomSanitizer` bypasses in the CI/CD pipeline."

## Mitigation Strategy: [Utilize `ngCspNonce` with Content Security Policy (CSP)](./mitigation_strategies/utilize__ngcspnonce__with_content_security_policy__csp_.md)

**Description:**
1.  **Implement CSP:** Have a strict CSP in place (this is a general web security best practice, but the `ngCspNonce` part is Angular-specific).
2.  **Identify Dynamic Styles:** Locate any components that dynamically generate styles (e.g., using `[style.color]` or similar).
3.  **Add `ngCspNonce`:** In your main application component (usually `AppComponent`), add the `ngCspNonce` attribute to the component's host element: `<app-root ngCspNonce="{{myNonceValue}}"></app-root>`.
4.  **Generate Nonce (Server-Side):**  Your server *must* generate a unique, unpredictable nonce value for each request.  This nonce should be used in both the CSP header (`style-src 'nonce-yourNonceValue'`) and passed to the Angular application (e.g., via a server-rendered variable).
5.  **Angular's Automatic Handling:** Angular will automatically add the `nonce` attribute to any dynamically generated style elements, allowing them to be executed according to the CSP.

**Threats Mitigated:**
*   **Cross-Site Scripting (XSS):** (Severity: High) - Specifically addresses XSS vectors related to dynamically generated styles, ensuring they comply with the CSP.

**Impact:**
*   **XSS:** Risk reduction: High.  Allows safe use of dynamic styles while maintaining a strong CSP.

**Currently Implemented:** (Example)
*   "Not yet implemented.  We have a CSP, but `ngCspNonce` is not used."

**Missing Implementation:** (Example)
*   "Server-side nonce generation and integration with the Angular application are required.  We need to identify all components with dynamic styles."

## Mitigation Strategy: [Use `HttpClient` with Interceptors for CSRF Protection (Angular-Specific Interceptor Focus)](./mitigation_strategies/use__httpclient__with_interceptors_for_csrf_protection__angular-specific_interceptor_focus_.md)

**Description:**
1.  **CSRF Strategy:** Choose a strategy (synchronizer token, double-submit cookie).
2.  **Server-Side Logic:** Server must generate/validate tokens.
3.  **Create an HTTP Interceptor:** This is the Angular-specific part. Create an Angular `HttpInterceptor`.
4.  **Add Token to Requests:** In the interceptor, get the token (cookie, local storage, meta tag) and add it to the request (header, body).
5.  **Exclude Safe Methods:** *Don't* add tokens to GET, HEAD, OPTIONS.
6.  **Register Interceptor:** Register it with Angular's dependency injection.
7.  **Test:** Ensure tokens are added and invalid token requests are rejected.

**Threats Mitigated:**
*   **Cross-Site Request Forgery (CSRF):** (Severity: High)

**Impact:**
*   **CSRF:** Risk reduction: High.

**Currently Implemented:** (Example)
*   "An `HttpInterceptor` (`CsrfInterceptor`) adds a token from a cookie to an `X-CSRF-TOKEN` header for POST/PUT/DELETE. Server-side logic is implemented."

**Missing Implementation:** (Example)
*   "Only protects `HttpClient` requests.  Other methods (e.g., `fetch`) are unprotected."

## Mitigation Strategy: [`OnPush` Change Detection Strategy](./mitigation_strategies/_onpush__change_detection_strategy.md)

**Description:**
1.  **Identify Components:** Find components that update only on input changes or explicit events.
2.  **Set `changeDetection`:** In `@Component`, set `changeDetection: ChangeDetectionStrategy.OnPush`.
3.  **Immutable Data:** Treat input properties as immutable. Create new objects/arrays on updates.
4.  **Manual Change Detection (if needed):** Use `ChangeDetectorRef.markForCheck()` if manual triggering is required.
5.  **Test:** Ensure correct updates after switching to `OnPush`.

**Threats Mitigated:**
*   **Denial of Service (DoS):** (Severity: Medium) - Reduces change detection cycles.
*   **Performance Issues:** (Severity: Low) - Indirectly contributes to DoS.

**Impact:**
*   **DoS:** Risk reduction: Medium.
*   **Performance:** Risk reduction: High.

**Currently Implemented:** (Example)
*   "`OnPush` is used in performance-critical components (large lists, frequent updates)."

**Missing Implementation:** (Example)
*   "A systematic review of all components for `OnPush` candidates hasn't been done."

## Mitigation Strategy: [`trackBy` Function with `*ngFor`](./mitigation_strategies/_trackby__function_with__ngfor_.md)

**Description:**
1.  **Identify `*ngFor` Loops:** Find all `*ngFor` instances.
2.  **Create `trackBy` Function:** Create a function returning a unique identifier for each item (ID, key).
3.  **Bind `trackBy`:** In `*ngFor`, add `trackBy: trackByFn`.
4.  **Test:** Verify correct list updates.

**Threats Mitigated:**
*   **Denial of Service (DoS):** (Severity: Medium) - Prevents unnecessary re-rendering.
*   **Performance Issues:** (Severity: Low)

**Impact:**
*   **DoS:** Risk reduction: Medium.
*   **Performance:** Risk reduction: High.

**Currently Implemented:** (Example)
*   "Consistently used in all components with `*ngFor`. A standard `trackById` function is in a shared utility class."

**Missing Implementation:** (Example)
*   "None. Standard practice."

## Mitigation Strategy: [Custom Error Handler with `ErrorHandler`](./mitigation_strategies/custom_error_handler_with__errorhandler_.md)

**Description:**
1. **Create Custom Error Handler Class:**
   ```typescript
   import { ErrorHandler, Injectable } from '@angular/core';

   @Injectable()
   export class GlobalErrorHandler implements ErrorHandler {
     handleError(error: any): void {
       // 1. Log the error to the server (using a service)
       // 2. Display a generic error message to the user
       console.error('An unexpected error occurred:', error); // Log for debugging
       // Example: this.errorService.logError(error);
       // Example: this.notificationService.showError('An error occurred. Please try again.');
     }
   }
   ```
2. **Provide in AppModule:**
   ```typescript
   import { ErrorHandler } from '@angular/core';
   import { GlobalErrorHandler } from './global-error-handler';

   @NgModule({
     providers: [
       { provide: ErrorHandler, useClass: GlobalErrorHandler }
     ],
     // ...
   })
   export class AppModule { }
   ```
3. **Use a Service for Server-Side Logging:** Create a service to send error details to your backend.
4. **Display Generic User Messages:**  Use a notification service or similar to show user-friendly messages.

**Threats Mitigated:**
*   **Information Disclosure:** (Severity: Medium) - Prevents revealing sensitive details in error messages.

**Impact:**
*   **Information Disclosure:** Risk reduction: High.

**Currently Implemented:** (Example)
*   "A custom `GlobalErrorHandler` is implemented. It logs to the server and shows generic messages."

**Missing Implementation:** (Example)
*   "Older modules have inconsistent error handling; they need refactoring to use the custom handler."

## Mitigation Strategy: [Angular Universal (Server-Side Rendering) Precautions](./mitigation_strategies/angular_universal__server-side_rendering__precautions.md)

**Description:**
1.  **Avoid Direct User Input in SSR:** Never directly embed user-supplied data into the HTML rendered on the server.
2.  **Use `TransferState`:** Use Angular's `TransferState` API to securely transfer data from the server to the client.  This avoids re-fetching data on the client and prevents XSS during hydration.  Example:
    *   **Server:**
        ```typescript
        import { TransferState, makeStateKey } from '@angular/platform-server';
        // ...
        constructor(private transferState: TransferState) {}

        ngOnInit() {
          const DATA_KEY = makeStateKey<any>('myData');
          this.transferState.set(DATA_KEY, myData); // myData is your data
        }
        ```
    *   **Client:**
        ```typescript
        import { TransferState, makeStateKey } from '@angular/platform-browser';
        // ...
        constructor(private transferState: TransferState) {}

        ngOnInit() {
          const DATA_KEY = makeStateKey<any>('myData');
          const data = this.transferState.get(DATA_KEY, null); // Get data, default to null
          if (data) {
            // Use the data
          } else {
            // Fetch the data (it wasn't transferred)
          }
        }
        ```
3.  **Server-Side Sanitization (if necessary):** If you *must* render user data on the server, use a robust HTML sanitizer *on the server* before embedding.  Don't rely on client-side sanitization.

**Threats Mitigated:**
*   **Cross-Site Scripting (XSS):** (Severity: High) - Prevents XSS vulnerabilities introduced by server-side rendering.

**Impact:**
*   **XSS:** Risk reduction: High.

**Currently Implemented:** (Example)
*   "We use `TransferState` to transfer data from server to client.  We avoid rendering user input directly on the server."

**Missing Implementation:** (Example)
*   "We need to implement server-side sanitization for a specific case where user-generated content is displayed in a preview on the server."

## Mitigation Strategy: [AOT Compilation](./mitigation_strategies/aot_compilation.md)

**Description:**
1.  **Enable AOT:** Ensure that your Angular project is configured to use Ahead-of-Time (AOT) compilation for production builds. This is typically the default in modern Angular projects, but it's good to verify. Check your `angular.json` file:
    ```json
    "configurations": {
      "production": {
        "aot": true,
        // ... other production settings
      }
    }
    ```
2.  **Build for Production:** Use the `ng build --configuration production` command (or similar) to build your application with AOT enabled.
3. **Verify:** There is no direct way to verify after deployment, but AOT compilation results in significantly smaller bundle sizes and faster startup times. If you see large bundle sizes or slow initial load, it might indicate AOT is not enabled.

**Threats Mitigated:**
*   **Template Injection:** (Severity: High) - AOT compilation compiles templates during the build process, preventing runtime template injection attacks.
*   **Performance Issues:** (Severity: Low) - Improves startup performance, indirectly reducing the risk of certain DoS attacks.

**Impact:**
*   **Template Injection:** Risk reduction: High.
*   **Performance:** Risk reduction: High.

**Currently Implemented:** (Example)
*   "AOT is enabled for production builds in our `angular.json` configuration."

**Missing Implementation:** (Example)
*   "None. AOT is standard for production."

