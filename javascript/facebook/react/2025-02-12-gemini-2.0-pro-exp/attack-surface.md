# Attack Surface Analysis for facebook/react

## Attack Surface: [Cross-Site Scripting (XSS) via `dangerouslySetInnerHTML`](./attack_surfaces/cross-site_scripting__xss__via__dangerouslysetinnerhtml_.md)

**Description:** Injection of malicious scripts into the application through the misuse of React's `dangerouslySetInnerHTML` property.

**How React Contributes:** React *provides* `dangerouslySetInnerHTML` as a mechanism to directly inject raw HTML, bypassing its standard XSS protection. This is a *deliberate* feature of React, but it creates a direct and easily exploitable XSS vector if the input HTML is not properly sanitized. This is the most direct and React-specific XSS vector.

**Example:**
```javascript
function MyComponent({ userComment }) {
  return <div dangerouslySetInnerHTML={{ __html: userComment }} />;
}
// If userComment contains "<script>alert('XSS!')</script>", the script will execute.
```

**Impact:**
*   Theft of user cookies and session tokens.
*   Redirection to malicious websites.
*   Modification of the page content.
*   Keylogging and data theft.
*   Defacement of the application.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Developers:**
    *   **Avoidance (Preferred):**  Do not use `dangerouslySetInnerHTML` unless absolutely necessary.  Use React's component model and JSX for rendering dynamic content.
    *   **Sanitization (If Unavoidable):** If `dangerouslySetInnerHTML` *must* be used, sanitize the input HTML using a robust, well-maintained HTML sanitization library like DOMPurify *before* passing it to the prop.  Validate the *output* of the sanitizer.  This is *not* optional if using this prop.
    *   **Content Security Policy (CSP):** Implement a strict CSP to limit the sources from which scripts can be executed, providing a defense-in-depth layer even if an XSS vulnerability exists.
*   **Users:** No direct user mitigation; relies entirely on developer implementation.

## Attack Surface: [Cross-Site Scripting (XSS) via Improper JSX Usage](./attack_surfaces/cross-site_scripting__xss__via_improper_jsx_usage.md)

**Description:**  Injection of malicious scripts due to incorrect handling of user input within JSX, even without using `dangerouslySetInnerHTML`. This is more subtle than the previous item, but still directly related to how React handles rendering.

**How React Contributes:** While React *attempts* to automatically escape data bound in JSX, developer errors or misunderstandings of the escaping rules can create vulnerabilities.  This is a direct consequence of React's rendering model and how developers interact with it. The core issue is how React *interprets* and renders the JSX, making it a React-specific concern.

**Example:**
```javascript
function MyComponent({ userLink }) {
  return <a href={userLink}>Click Me</a>;
}
// If userLink is "javascript:alert('XSS!')", the script will execute.
```

**Impact:** (Same as `dangerouslySetInnerHTML` XSS)
*   Theft of user cookies and session tokens.
*   Redirection to malicious websites.
*   Modification of the page content.
*   Keylogging and data theft.
*   Defacement of the application.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Developers:**
    *   **Best Practices:** Follow React's recommended practices for handling user input.  Let React handle escaping whenever possible.  This is the primary defense.
    *   **Attribute Sanitization:** Be extremely cautious when embedding user input directly into attributes, especially `href`, `src`, or event handlers. Validate and sanitize as needed. Use URL encoding where appropriate.  Understand *why* React's default escaping might not be sufficient in these cases.
    *   **Linting:** Use a linter with security rules (e.g., ESLint with `eslint-plugin-react` and security-focused plugins) to automatically detect potential XSS vulnerabilities *specific to React*.
    *   **Code Reviews:** Conduct thorough code reviews, paying close attention to how user input is handled within JSX, specifically looking for deviations from React's intended escaping behavior.
*   **Users:** No direct user mitigation; relies entirely on developer implementation.

