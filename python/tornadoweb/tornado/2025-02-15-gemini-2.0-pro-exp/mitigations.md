# Mitigation Strategies Analysis for tornadoweb/tornado

## Mitigation Strategy: [Template Autoescaping and Context-Aware Escaping](./mitigation_strategies/template_autoescaping_and_context-aware_escaping.md)

**Mitigation Strategy:** Enforce Autoescaping and Use Tornado's Context-Aware Escaping Functions.

**Description:**
1.  **`autoescape=True`:** In your Tornado `Application` settings, *ensure* `autoescape=True` is set. This is the foundation of Tornado's template-based XSS defense.
2.  **Minimize `{% raw %}`:**  Avoid using `{% raw %}` in your Tornado templates. If unavoidable, *absolutely* ensure any user data within `{% raw %}` is meticulously sanitized *before* being passed to the template.
3.  **Tornado's Escaping Modules:** Use Tornado's built-in escaping functions within your templates, *specifically*:
    *   `{% module escape(variable) %}`: For general HTML escaping (use when autoescaping is off or for extra assurance).
    *   `{% module json_encode(variable) %}`: *Mandatory* for embedding data within JavaScript `<script>` tags. This is a Tornado-provided function specifically designed for this context.
    *   `{% module url_escape(variable) %}`: For escaping URL parameters.
4.  **UI Modules:** If you use Tornado's `UIModule` feature, ensure that the `render` method of *every* UI Module correctly escapes any user-provided data using the appropriate Tornado escaping functions.

**Threats Mitigated:**
*   **Cross-Site Scripting (XSS) (Severity: High):**  Directly leverages Tornado's template engine features to prevent injection of malicious scripts.
*   **Template Injection (Severity: High):** While not a complete solution, proper use of Tornado's escaping functions reduces the attack surface for template injection.

**Impact:**
*   **XSS:**  When used correctly, Tornado's escaping mechanisms significantly reduce XSS risk.
*   **Template Injection:** Reduces the risk, but other server-side controls are also needed.

**Currently Implemented:**
*   Check `Application` settings for `autoescape=True`.
*   Inspect templates for correct use of `escape`, `json_encode`, and `url_escape`.
*   Review `UIModule` `render` methods.

**Missing Implementation:**
*   Missing `autoescape=True`.
*   Incorrect or missing use of Tornado's escaping functions in templates.
*   `UIModule`s not escaping user data.

## Mitigation Strategy: [CSRF Protection (Tornado's Built-in Mechanism)](./mitigation_strategies/csrf_protection__tornado's_built-in_mechanism_.md)

**Mitigation Strategy:** Utilize Tornado's `xsrf_cookies` and `xsrf_form_html()` Features.

**Description:**
1.  **`xsrf_cookies=True`:** In your Tornado `Application` settings, *must* have `xsrf_cookies=True`. This enables Tornado's built-in CSRF protection.
2.  **`{% module xsrf_form_html() %}`:**  Within *every* HTML form rendered by Tornado, include `{% module xsrf_form_html() %}`. This is a Tornado-specific template directive that inserts the hidden CSRF token.
3.  **AJAX with `X-XSRFToken`:** For AJAX requests, retrieve the `_xsrf` cookie (set by Tornado) and include it in the `X-XSRFToken` header. This is how Tornado validates AJAX requests against CSRF.
4.  **`xsrf_cookie_kwargs`:** Use the `xsrf_cookie_kwargs` setting in your `Application` to configure the security attributes of the `_xsrf` cookie:
    ```python
    xsrf_cookie_kwargs = {"secure": True, "samesite": "Strict"} # Or "Lax"
    ```
    This is crucial for making the cookie secure.

**Threats Mitigated:**
*   **Cross-Site Request Forgery (CSRF) (Severity: High):**  Directly leverages Tornado's built-in CSRF protection mechanism.

**Impact:**
*   **CSRF:**  Effectively eliminates CSRF risk when implemented correctly using Tornado's features.

**Currently Implemented:**
*   Check `Application` settings for `xsrf_cookies=True` and `xsrf_cookie_kwargs`.
*   Inspect HTML forms for `{% module xsrf_form_html() %}`.
*   Check AJAX code for `X-XSRFToken` header usage.

**Missing Implementation:**
*   Missing `xsrf_cookies=True`.
*   Missing `{% module xsrf_form_html() %}` in forms.
*   AJAX requests not sending the `X-XSRFToken` header.
*   Incorrect or missing `xsrf_cookie_kwargs`.

## Mitigation Strategy: [HTTP Parameter Pollution (HPP) - Tornado's `get_arguments`](./mitigation_strategies/http_parameter_pollution__hpp__-_tornado's__get_arguments_.md)

**Mitigation Strategy:** Use Tornado's `get_arguments` Method Correctly.

**Description:**
1.  **Avoid `get_argument` (for potential pollution):**  Do *not* rely on Tornado's `get_argument` method's default behavior (returning the last value) when dealing with parameters that might be subject to HPP.
2.  **Use `get_arguments`:** Instead, use Tornado's `get_arguments(name, strip=True)` method. This returns a *list* of all values provided for the parameter `name`.
3.  **Explicit Handling:**  Implement explicit logic to handle the list returned by `get_arguments`.  This might involve:
    *   Rejecting the request if multiple values are unexpected.
    *   Selecting a specific value (first, last, or based on validation).
    *   Safely concatenating values (if appropriate).

**Threats Mitigated:**
*   **HTTP Parameter Pollution (HPP) (Severity: Medium):**  Addresses how Tornado specifically handles multiple parameters with the same name.
*   **Input Validation Bypass (Severity: Medium to High):**  Reduces the risk of HPP being used to bypass input validation.

**Impact:**
*   **HPP:**  Significantly reduces the risk by forcing explicit handling of multiple parameter values.
*   **Input Validation Bypass:** Reduces the risk, but general input validation is still essential.

**Currently Implemented:**
*   Check code for uses of `get_argument` vs. `get_arguments`.
*   Verify logic for handling the list returned by `get_arguments`.

**Missing Implementation:**
*   Reliance on `get_argument`'s default behavior without considering multiple values.
*   Missing or incorrect handling of the list from `get_arguments`.

## Mitigation Strategy: [Denial of Service (DoS) - Tornado's Asynchronous Handling](./mitigation_strategies/denial_of_service__dos__-_tornado's_asynchronous_handling.md)

**Mitigation Strategy:** Use Tornado's `run_on_executor` and Timeouts for Asynchronous Operations.

**Description:**
1.  **Identify Blocking Operations:** Analyze your Tornado request handlers for any operations that could block the IOLoop (database calls, external API requests, etc.).
2.  **`tornado.concurrent.run_on_executor`:** Use Tornado's `run_on_executor` decorator to offload *blocking* operations to a thread pool. This is a *core* Tornado feature for maintaining responsiveness.
    ```python
    from tornado.concurrent import run_on_executor
    from concurrent.futures import ThreadPoolExecutor

    class MyHandler(tornado.web.RequestHandler):
        executor = ThreadPoolExecutor(max_workers=4)

        @run_on_executor
        def _blocking_method(self):
            # ... blocking code here ...
    ```
3.  **Timeouts:**  Utilize Tornado's mechanisms for setting timeouts on asynchronous operations:
    *   `AsyncHTTPClient`: Use the `timeout` parameter when making requests.
    *   `IOLoop.call_later`:  Use this for custom timeout logic.
    This prevents a single slow operation from stalling the entire Tornado application.

**Threats Mitigated:**
*   **Denial of Service (DoS) (Severity: High):**  Specifically addresses DoS vulnerabilities arising from Tornado's asynchronous nature.

**Impact:**
*   **DoS:**  Significantly reduces DoS risk by preventing blocking operations from tying up the IOLoop and by enforcing timeouts.

**Currently Implemented:**
*   Check for uses of `run_on_executor`.
*   Check for `timeout` parameters in `AsyncHTTPClient` calls.
*   Look for uses of `IOLoop.call_later` for timeout handling.

**Missing Implementation:**
*   Blocking operations within request handlers without `run_on_executor`.
*   Missing timeouts on asynchronous operations.

## Mitigation Strategy: [WebSocket Security - Tornado's `WebSocketHandler`](./mitigation_strategies/websocket_security_-_tornado's__websockethandler_.md)

**Mitigation Strategy:** Utilize Tornado's `WebSocketHandler` Features for Security.

**Description:**
1.  **`check_origin`:**  *Override* and *implement* the `check_origin(self, origin)` method in your `WebSocketHandler` subclasses. This is a *Tornado-specific* method for validating the `Origin` header, crucial for preventing Cross-Site WebSocket Hijacking (CSWSH).
    ```python
    class MyWebSocketHandler(tornado.websocket.WebSocketHandler):
        def check_origin(self, origin):
            allowed_origins = ["https://example.com", "https://www.example.com"]
            return origin in allowed_origins
    ```
2.  **CSRF (Handshake):** While less common, consider using Tornado's CSRF protection (described earlier) for the *initial* WebSocket handshake, as it's a standard HTTP request.
3. **Subprotocol:** Use Tornado's support for WebSocket subprotocols.

**Threats Mitigated:**
*   **Cross-Site WebSocket Hijacking (CSWSH) (Severity: High):**  `check_origin` is Tornado's primary defense against CSWSH.
*   **Unauthorized Access (Severity: High):** Authentication is a general practice, but using it within a `WebSocketHandler` is Tornado-specific.

**Impact:**
*   **CSWSH:**  `check_origin` is highly effective when implemented correctly.
*   **Unauthorized Access:** Authentication prevents unauthorized connections.

**Currently Implemented:**
*   Check `WebSocketHandler` subclasses for `check_origin` implementation.
*   Check if CSRF protection is applied to the handshake.

**Missing Implementation:**
*   Missing or incorrect `check_origin` implementation.
*   Lack of CSRF protection on the handshake (optional but recommended).

## Mitigation Strategy: [Asynchronous Error Handling - Tornado Specifics](./mitigation_strategies/asynchronous_error_handling_-_tornado_specifics.md)

**Mitigation Strategy:** Proper Exception Handling in Tornado Coroutines and Futures.

**Description:**
1.  **`try...except` in Coroutines:** Within your `@tornado.gen.coroutine` (or `async def`) methods, use standard Python `try...except` blocks to catch and handle exceptions that might arise from asynchronous operations. This is standard Python, but its *application within Tornado coroutines* is key.
2.  **`Future.set_exception`:** If you interact directly with Tornado's `Future` objects, ensure you call `set_exception` on the `Future` if an error occurs within the asynchronous task. This propagates the exception correctly.
3.  **`RequestHandler.write_error`:** Override Tornado's `RequestHandler.write_error` method to create a global exception handler. This is a *Tornado-specific* way to catch any unhandled exceptions that bubble up, allowing for logging and a controlled error response.

**Threats Mitigated:**
*   **Uncaught Exceptions (Severity: Medium to High):** Prevents Tornado-specific issues with exceptions in asynchronous code.
*   **Information Leakage (Severity: Low to Medium):** `write_error` allows you to control error responses, preventing sensitive data leaks.

**Impact:**
*   **Uncaught Exceptions:** Improves stability and debuggability of Tornado applications.
*   **Information Leakage:** Reduces the risk of leaking sensitive information.

**Currently Implemented:**
*   Check coroutines for `try...except` blocks.
*   Check `Future` usage for `set_exception` calls.
*   Check for overridden `RequestHandler.write_error`.

**Missing Implementation:**
*   Missing `try...except` in coroutines.
*   Incorrect `Future` exception handling.
*   No global exception handler via `write_error`.

