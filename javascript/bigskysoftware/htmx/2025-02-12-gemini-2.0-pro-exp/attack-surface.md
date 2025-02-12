# Attack Surface Analysis for bigskysoftware/htmx

## Attack Surface: [Cross-Site Scripting (XSS)](./attack_surfaces/cross-site_scripting__xss_.md)

*   **Description:** Injection of malicious JavaScript into the web application, executed in the context of other users' browsers.
*   **How HTMX Contributes:** HTMX's core mechanism of injecting server-rendered HTML fragments directly into the DOM *significantly* increases XSS risk if server responses are not meticulously sanitized. The persistent nature of htmx updates (vs. full-page reloads) makes stored XSS more likely and impactful.  `hx-swap`, especially with `innerHTML`, is a key factor. `hx-on` attribute can be used to inject malicious javascript code.
*   **Example:**
    *   User input `<script>alert('XSS')</script>` into a comment field.
    *   Server fails to sanitize.
    *   HTMX fetches the comment list (with the script) via `hx-get` and injects it using `hx-swap="innerHTML"`.
    *   The script executes in other users' browsers.
*   **Impact:**
    *   Theft of cookies/session tokens.
    *   Redirection to malicious sites.
    *   Defacement.
    *   Arbitrary code execution in the user's browser.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Server-Side Output Encoding (Primary):** Use a robust HTML templating engine with *automatic, contextual escaping* (e.g., Jinja2, ERB with proper escaping).  *Never* construct HTML responses via string concatenation. This is the single most important defense.
    *   **Content Security Policy (CSP):** Implement a *strict* CSP, focusing on the `script-src` directive.  Avoid `unsafe-inline` if at all possible; use nonces or hashes if necessary.  Ensure `unsafe-eval` is *not* enabled unless absolutely required by a specific, trusted htmx extension.
    *   **Input Validation (Secondary):** Validate and sanitize all user input *before* server-side use, but rely *primarily* on output encoding.
    *   **Safer `hx-swap` Options:** If possible, use safer `hx-swap` alternatives to `innerHTML` (e.g., `outerHTML`, `beforebegin`, `afterend`) with carefully structured HTML. This reduces, but does not eliminate, the risk.

## Attack Surface: [Cross-Site Request Forgery (CSRF)](./attack_surfaces/cross-site_request_forgery__csrf_.md)

*   **Description:** Tricking a user's browser into making unintended, authenticated requests.
*   **How HTMX Contributes:** HTMX makes requests via JavaScript.  Standard form-based CSRF tokens might *not* be automatically included.  Developers *must* explicitly handle CSRF for htmx-initiated requests (using `hx-post`, `hx-put`, `hx-patch`, `hx-delete`).
*   **Example:**
    *   Attacker crafts a malicious site with a hidden form or JS that makes a `POST` to `/delete-account`.
    *   A logged-in user visits the attacker's site.
    *   The browser sends the request to `/delete-account` with the user's cookies.
    *   Without proper CSRF protection *specifically for htmx requests*, the account is deleted.
*   **Impact:**
    *   Unauthorized actions on behalf of the user (data deletion, setting changes, purchases).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Request Headers (Recommended):** Include the CSRF token in a request header (e.g., `X-CSRF-Token`). Configure htmx to automatically include this header (using the `htmx:configRequest` event listener or the `hx-headers` attribute).
    *   **Server-Side Validation:** The server *must* validate the CSRF token for *all* state-changing requests, regardless of origin (htmx or otherwise).

## Attack Surface: [Sensitive Data Exposure](./attack_surfaces/sensitive_data_exposure.md)

*   **Description:** Unintentional disclosure of sensitive information.
*   **How HTMX Contributes:** HTMX fetches HTML fragments. If these fragments contain sensitive data that shouldn't be exposed, it creates a vulnerability. Developers might be less careful with partial responses. All `hx-` attributes that trigger server requests are relevant.
*   **Example:**
    *   An htmx request to update a profile section fetches the *entire* user object, including the hashed password, even though only the username is displayed.
    *   An attacker inspects the network response and sees the sensitive data.
*   **Impact:**
    *   Exposure of passwords (even hashed), API keys, internal IDs, etc.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Minimal Response Data:** *Only* include the absolutely necessary data in the HTML fragments. Avoid returning entire model objects.
    *   **Dedicated API Endpoints:** Use separate API endpoints specifically for htmx requests, returning *only* the data needed for the partial update.
    *   **Server-Side Templating:** Use server-side templating to selectively render *only* the required data fields.

## Attack Surface: [Request Forgery](./attack_surfaces/request_forgery.md)

*   **Description:** Crafting unauthorized requests by manipulating request parameters, headers, or the target URL on the client-side.
*   **How HTMX Contributes:** HTMX allows dynamic modification of request details (using attributes like `hx-vals`, `hx-headers`, and dynamically generated URLs in `hx-get`, `hx-post`, etc.), making it easier for an attacker to tamper with requests if client-side JavaScript is compromised.
*   **Example:**
    *   An attacker uses a browser extension or compromised JS to modify `hx-vals`, adding a hidden parameter that grants them admin privileges.
*   **Impact:**
    *   Unauthorized access to data/functionality.
    *   Bypassing security controls.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Server-Side Validation (Paramount):** *Always* validate *all* request parameters and headers on the server-side, *regardless* of their origin. Do *not* trust client-side data.
    *   **Input Sanitization:** Sanitize any user input used in request parameters or headers.
    *   **Minimize Client-Side Manipulation:** Avoid relying on client-side JS to dynamically modify request details based on user input.

