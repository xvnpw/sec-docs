# Mitigation Strategies Analysis for actix/actix-web

## Mitigation Strategy: [Denial of Service (DoS) Protection using Actix-Web Features](./mitigation_strategies/denial_of_service__dos__protection_using_actix-web_features.md)

**Description:**
1.  **Request Timeouts:**
    *   **Server Timeouts:** Configure global server timeouts using `HttpServer::bind` in combination with `.keep_alive` and `.client_timeout`. This sets timeouts for the entire server. Example:
        ```rust
        HttpServer::new(|| App::new())
            .bind("127.0.0.1:8080")?
            .keep_alive(75) // Keep-alive timeout (seconds)
            .client_timeout(5000) // Client timeout (milliseconds)
            .run()
            .await
        ```
    *   **Middleware Timeouts:** Use `actix_web::middleware::Timeout` for *route-specific* timeouts. This allows finer-grained control. Example:
        ```rust
        use actix_web::middleware::Timeout;
        use std::time::Duration;

        App::new()
            .wrap(Timeout::new(Duration::from_secs(5))) // 5-second timeout for all routes
            .service(
                web::resource("/slow")
                    .wrap(Timeout::new(Duration::from_secs(1))) // 1-second timeout for this specific route
                    .route(web::get().to(handler))
            )
        ```
2.  **Connection Limits:** Limit the maximum number of concurrent connections using `HttpServer::workers` and `.max_connections`.  `workers` controls the number of OS threads, and `.max_connections` sets the overall connection limit. Example:
    ```rust
    HttpServer::new(|| App::new())
        .workers(4) // Use 4 worker threads
        .max_connections(1024) // Limit to 1024 concurrent connections
        .bind("127.0.0.1:8080")?
        .run()
        .await
    ```
3.  **Request Body Size Limits:**
    *   **Global Limit (Middleware):** Use `actix_web::middleware::BodyLimit` to set a global limit on request body sizes. This applies to all requests. Example:
        ```rust
        use actix_web::middleware::BodyLimit;

        App::new()
            .wrap(BodyLimit::new(1024 * 1024)) // 1MB global limit
        ```
    *   **Extractor Limits:** Configure limits *directly on extractors* like `web::Json` and `web::Form`. This provides the most granular control. Example:
        ```rust
        async fn handler(item: web::Json<MyData>) -> HttpResponse { /* ... */ }

        App::new().service(
            web::resource("/data")
                .app_data(web::Json::<MyData>::configure(|cfg| {
                    cfg.limit(4096); // 4KB limit for this specific JSON extractor
                }))
                .route(web::post().to(handler)),
        )
        ```
4.  **Rate Limiting (using Actix-Web compatible middleware):** While not *built-in* to Actix-Web, use a compatible rate-limiting middleware crate like `actix-web-rate-limit`.  This is crucial for preventing various DoS attacks.  The setup depends on the chosen crate, but generally involves wrapping your application or specific routes with the rate-limiting middleware.

**Threats Mitigated:**
*   **Slowloris Attacks (Severity: Medium to High):** Attackers hold connections open by sending data very slowly.  Actix-Web timeouts directly counter this.
*   **Resource Exhaustion (Severity: High):** Attackers send large requests or many requests to consume server resources.  Connection limits, body size limits, and timeouts mitigate this.
*   **Application-Layer DoS (Severity: Medium to High):**  While some application-layer DoS attacks require application-specific logic, rate limiting (via middleware) and timeouts can help mitigate many cases.

**Impact:**
*   **Slowloris Attacks:**  Timeouts and connection limits are highly effective (80-90% risk reduction).
*   **Resource Exhaustion:**  Body size limits, connection limits, and timeouts significantly reduce the risk (70-80%).
*   **Application-Layer DoS:**  Impact varies, but rate limiting and timeouts are important components of a defense-in-depth strategy.

**Currently Implemented:**
*   Server and client timeouts are configured on `HttpServer`.
*   `BodyLimit` middleware is used globally.
*   JSON payload size limits are configured on relevant routes using `web::Json::configure`.

**Missing Implementation:**
*   Rate limiting middleware (`actix-web-rate-limit` or similar) is *not* implemented.
*   Connection limits are *not* explicitly configured (relying on Actix-Web's defaults).  This should be explicitly set.
*   Route-specific timeouts using `middleware::Timeout` are not used consistently.

## Mitigation Strategy: [Secure WebSocket Handling (using `actix-web-actors`)](./mitigation_strategies/secure_websocket_handling__using__actix-web-actors__.md)

**Description:**
1.  **Origin Validation:**  Within your WebSocket actor's `ws::start` handler (or equivalent if using a different WebSocket library with Actix-Web), *strictly validate the `Origin` header* against a whitelist of allowed origins.  Reject connections from unknown or untrusted origins.  This is *crucial* for preventing Cross-Site WebSocket Hijacking (CSWSH). Example:
    ```rust
    use actix_web::{HttpRequest, HttpResponse, web};
    use actix_web_actors::ws;

    async fn ws_index(req: HttpRequest, stream: web::Payload) -> Result<HttpResponse, actix_web::Error> {
        let allowed_origins = vec!["https://yourdomain.com", "https://www.yourdomain.com"];
        let origin_valid = req.headers().get("Origin").map_or(false, |origin| {
            origin.to_str().map_or(false, |origin_str| {
                allowed_origins.contains(&origin_str)
            })
        });

        if !origin_valid {
            return Ok(HttpResponse::Forbidden().body("Invalid Origin"));
        }

        let resp = ws::start(MyWebSocketActor::new(), &req, stream);
        resp
    }
    ```
2.  **Secure Protocol (wss://):**  Ensure your WebSocket connections use the `wss://` protocol (WebSocket Secure).  This requires configuring TLS/SSL certificates for your Actix-Web server, which is typically done through your server configuration (e.g., using a reverse proxy like Nginx or configuring TLS directly in Actix-Web, though this is less common for production).
3.  **Input Validation (within the Actor):**  Inside your WebSocket actor's message handling logic (e.g., the `handle` method for `actix-web-actors`), treat *all received messages as untrusted input*.  Validate and sanitize the data thoroughly before processing it.  This is the same principle as with HTTP requests, but applied to WebSocket messages.
4. **Rate Limiting (WebSocket-Specific, within the Actor):** Implement rate limiting *within your WebSocket actor* to control the rate of incoming messages from each client. This can be done using a simple counter and timer within the actor, or by integrating a more sophisticated rate-limiting library. This prevents a single client from flooding your server with WebSocket messages.

**Threats Mitigated:**
*   **Cross-Site WebSocket Hijacking (CSWSH) (Severity: High):**  Origin validation is the *primary defense* against CSWSH.
*   **WebSocket Data Injection (Severity: Medium to High):**  Input validation within the actor prevents attackers from injecting malicious data.
*   **WebSocket DoS (Severity: Medium to High):**  Rate limiting within the actor prevents message flooding.

**Impact:**
*   **CSWSH:**  Proper Origin validation effectively eliminates this risk (near 100%).
*   **WebSocket Data Injection:**  Thorough input validation significantly reduces the risk (80-90%).
*   **WebSocket DoS:**  Rate limiting within the actor is highly effective (70-80%).

**Currently Implemented:**
*   The application uses `wss://` (TLS is configured via a reverse proxy).
*   Basic input validation is performed on WebSocket messages within the actor.

**Missing Implementation:**
*   **Strict `Origin` header validation is MISSING.** This is a critical vulnerability. The example code above needs to be implemented.
*   WebSocket-specific rate limiting within the actor is *not* implemented.

## Mitigation Strategy: [Asynchronous Operation Handling within Actix-Web Context](./mitigation_strategies/asynchronous_operation_handling_within_actix-web_context.md)

**Description:**
1.  **Correct `await` Usage:** Ensure that `.await` is used correctly on all futures within your request handlers and other asynchronous code. Avoid blocking the main thread.
2.  **`web::block` for Blocking Operations:** Use `actix_web::web::block` to offload *any* blocking I/O operations (database queries, file system access, external API calls that don't use async clients) to a dedicated thread pool. This prevents blocking the Actix-Web worker threads, which are responsible for handling incoming requests. Example:
    ```rust
    use actix_web::{web, HttpResponse, Error};

    async fn my_handler() -> Result<HttpResponse, Error> {
        let result = web::block(|| {
            // Perform a blocking operation here (e.g., a database query)
            // This code runs on a separate thread pool.
            std::thread::sleep(std::time::Duration::from_secs(2)); // Simulate a long operation
            Ok::<String, MyCustomError>("Operation completed".to_string()) // Replace with your error type
        }).await?; // .await the result of web::block

        Ok(HttpResponse::Ok().body(result))
    }
    ```
3.  **Error Handling in Asynchronous Contexts:** Implement robust error handling for *all* asynchronous operations within your Actix-Web handlers. Use `?` (the try operator) or `match` statements to handle potential errors and return appropriate HTTP responses (e.g., `HttpResponse::InternalServerError`).  Unhandled errors can lead to crashes or unexpected behavior.
4. **Asynchronous Testing:** Use `#[actix_rt::test]` for asynchronous tests.

**Threats Mitigated:**
*   **Resource Leaks (Severity: Medium):**  Improperly handled futures can lead to resource leaks.
*   **Deadlocks (Severity: High):** Incorrect use of asynchronous primitives, especially without `web::block`, can cause deadlocks.
*   **Application Instability (Severity: Medium to High):** Unhandled errors in asynchronous code can lead to crashes or unpredictable behavior, potentially impacting availability.
*  **Reduced Responsiveness (Severity: Medium):** Blocking the main event loop makes the application less responsive.

**Impact:**
*   **Resource Leaks:** Correct `await` usage and resource management significantly reduce the risk (70-80%).
*   **Deadlocks:**  Proper use of `web::block` is *essential* and greatly reduces the risk (60-70%).
*   **Application Instability:** Robust error handling is crucial (80-90% risk reduction).
* **Reduced Responsiveness:** Using `web::block` prevents blocking main event loop.

**Currently Implemented:**
*   `web::block` is used for database operations (which are blocking).
*   Basic error handling is implemented in most request handlers.

**Missing Implementation:**
*   Comprehensive asynchronous testing using `#[actix_rt::test]` is *lacking*. Many asynchronous code paths are not adequately tested.
*   More rigorous review of *all* `await` usage is needed to ensure correctness and prevent potential issues.  A code review checklist should include this.

