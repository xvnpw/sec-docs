# Threat Model Analysis for tokio-rs/axum

## Threat: [Unbounded Request Body Consumption (Axum Extractors)](./threats/unbounded_request_body_consumption__axum_extractors_.md)

*   **Description:** An attacker sends a crafted HTTP request with a very large body.  An Axum extractor (e.g., `Json`, `Form`, `Bytes`, or a custom extractor) attempts to deserialize or process the entire body *without* checking its size, leading to excessive memory allocation. This is a direct misuse of Axum's extractor mechanism.
*   **Impact:**  Causes the application to consume excessive memory, leading to a Denial of Service (DoS) due to resource exhaustion. The application may crash or become unresponsive.
*   **Axum Component Affected:**  `axum::extract::Json`, `axum::extract::Form`, `axum::extract::Bytes`, and any *custom* extractors implemented by the developer that do not enforce size limits. The core issue is the lack of size validation *within* the extractor's `from_request` (or equivalent) implementation.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Mandatory:** Use `axum::extract::ContentLengthLimit` middleware. This provides a global limit, but it's crucial to understand that it's applied *before* the extractor runs.
    *   **Mandatory:** Within *every* custom extractor, implement explicit size checks *before* allocating memory or processing the request body.  Do *not* rely solely on `ContentLengthLimit`.  This is the most direct Axum-specific mitigation.
    *   **Recommended:** If possible, process the request body as a stream using `axum::body::Body::into_data_stream()` *within* the handler or extractor, avoiding loading the entire body into memory at once.

## Threat: [Panic-Induced Denial of Service (Axum Handlers/Middleware)](./threats/panic-induced_denial_of_service__axum_handlersmiddleware_.md)

*   **Description:** An attacker sends a request that triggers an unhandled panic *within* an Axum handler function or middleware.  Axum, by default, does not catch panics within handlers. This panic unwinds the stack, potentially terminating the Tokio worker thread.
*   **Impact:**  Loss of a worker thread.  Repeated attacks can lead to a Denial of Service (DoS) as the application loses the ability to handle requests.
*   **Axum Component Affected:** Any `async fn` used as an Axum handler (`axum::routing::get`, `post`, etc.) or any middleware (`axum::middleware::from_fn`, `axum::Layer`) that contains code capable of panicking without proper error handling (e.g., `unwrap()`, array out-of-bounds access).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Mandatory:**  Within all Axum handlers and middleware, use `Result` and `Option` extensively to handle errors gracefully.  Avoid `unwrap()` and `expect()` on operations that might fail.  Propagate errors using `?`. This is the core Axum-specific mitigation.
    *   **Mandatory:** Implement robust error handling middleware using `axum::middleware::from_fn` or `axum::Layer`. This middleware should catch errors (potentially converted from panics) and return appropriate HTTP error responses (e.g., 500 Internal Server Error). This prevents the panic from reaching the top level and crashing the worker.
    *   **Advanced (Use with Extreme Caution):** A custom panic handler *could* be used, but it's generally *not* recommended for Axum applications due to the asynchronous nature and potential for inconsistent state after a panic. Letting the worker restart is usually safer.

## Threat: [Middleware Ordering Issues (Bypassing Security Checks)](./threats/middleware_ordering_issues__bypassing_security_checks_.md)

*   **Description:**  An attacker exploits the incorrect ordering of Axum middleware.  For example, authentication middleware placed *after* logging middleware could log sensitive data even for unauthenticated requests.  This is a direct consequence of how Axum's middleware system is used.
*   **Impact:**  Can lead to various security vulnerabilities, including information disclosure (sensitive data logged), authentication bypass, authorization bypass, or even denial of service (if rate limiting is misconfigured).
*   **Axum Component Affected:**  The `axum::Router` and its `layer()` method, which is used to define the order in which middleware is applied to requests. The specific middleware involved in the misconfiguration are also directly affected.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Mandatory:** Carefully design the middleware stack.  Security-related middleware (authentication, authorization, rate limiting, input validation) *must* be placed *before* any middleware that accesses sensitive data, logs request details, or performs potentially expensive operations. This is a direct Axum usage issue.
    *   **Mandatory:** Thoroughly test the application with various request scenarios to ensure that the middleware stack behaves as expected and that security checks are not bypassed.

## Threat: [Insecure Deserialization in Extractors (Axum + Deserialization Library)](./threats/insecure_deserialization_in_extractors__axum_+_deserialization_library_.md)

*   **Description:** An attacker sends a crafted request body designed to exploit vulnerabilities in the deserialization process *within* an Axum extractor. While the vulnerability might be in the underlying deserialization library (e.g., Serde), the *use* of the extractor in Axum is what exposes the application.
*   **Impact:**  Can range from Denial of Service (DoS) if the deserialization process consumes excessive resources to Remote Code Execution (RCE) if the deserialization library has vulnerabilities or if custom deserialization logic is flawed.
*   **Axum Component Affected:** Axum extractors that perform deserialization, most commonly `axum::extract::Json`, but also any custom extractors that use Serde or other deserialization libraries. The vulnerability is triggered through the extractor's `from_request` implementation.
*   **Risk Severity:** High to Critical
*   **Mitigation Strategies:**
    *   **Mandatory:** Keep the deserialization library (e.g., Serde) updated to the latest version to patch any known vulnerabilities.
    *   **Mandatory:** If using custom data types with `#[derive(Deserialize)]`, carefully review the generated deserialization code (using `cargo expand`) for potential issues. This is especially important for complex or nested data structures.
    *   **Highly Recommended:** Avoid deserializing complex, deeply nested, or untrusted data structures directly within Axum extractors. Prefer simpler, well-defined data formats.
    *   **Recommended:** Implement strict validation of the deserialized data *after* it has been extracted, as an extra layer of defense. This validation should be performed within the handler or a dedicated validation function.

