# Attack Surface Analysis for fastapi/fastapi

## Attack Surface: [1. Insufficient Path/Query Parameter Validation](./attack_surfaces/1__insufficient_pathquery_parameter_validation.md)

*   **Description:** While FastAPI handles type conversion for path and query parameters, relying solely on this without further application-level validation can lead to injection vulnerabilities.  FastAPI's design encourages using type hints for parameters, but this *does not* replace proper input validation.
*   **How FastAPI Contributes:** FastAPI's convenient parameter handling, using type hints and automatic conversion, can create a false sense of security.  Developers might assume that because FastAPI converts a path parameter to an `int`, it's safe to use directly in a database query. This is the *direct* contribution: the framework's ease of use can lead to overlooking crucial validation.
*   **Example:** A path parameter `/users/{user_id}` is defined as `user_id: int`. An attacker provides `/users/1;DROP%20TABLE%20users` (URL-encoded). FastAPI converts this to the string "1;DROP TABLE users", and if the application uses this directly in a raw SQL query, it leads to SQL injection.
*   **Impact:** SQL injection, path traversal, command injection, denial of service.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   Always validate path and query parameters *after* FastAPI's type conversion, treating them as untrusted input.
    *   Use Pydantic's `Field` constraints within parameter definitions (e.g., `Path(..., ge=1, le=1000)`, `Query(..., regex="^[a-zA-Z0-9]+$")`).  This leverages FastAPI's features for mitigation.
    *   Use parameterized queries or ORMs for database interactions (this is a general best practice, but *especially* important given FastAPI's parameter handling).
    *   Sanitize parameters before using them in file system operations or shell commands.
    *   Implement input validation libraries for complex validation rules, integrating them with FastAPI's dependency injection.

## Attack Surface: [2. Request Body Resource Exhaustion](./attack_surfaces/2__request_body_resource_exhaustion.md)

*   **Description:** Attackers can send excessively large or deeply nested request bodies to consume server resources, leading to denial of service.
*   **How FastAPI Contributes:** FastAPI *automatically* parses request bodies (JSON, form data, multipart) based on Pydantic models. This automatic parsing, while convenient, is the direct link to the vulnerability.  Without explicit limits, FastAPI will attempt to parse arbitrarily large requests.
*   **Example:** An attacker sends a JSON payload with millions of nested objects or a multi-gigabyte string in a single field, targeting an endpoint that expects a Pydantic model. FastAPI attempts to parse this, consuming excessive memory or CPU.
*   **Impact:** Denial of service (DoS), server crashes, resource exhaustion.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Set reasonable limits on request body sizes using server configuration (e.g., Uvicorn's `--limit-request-body` option). This is *external* to FastAPI, but necessary.
    *   Use Pydantic's `max_length` constraint for string fields and similar constraints (e.g., `max_items` for lists) for other types within your Pydantic models. This is a *direct* use of FastAPI's features to mitigate the risk.
    *   Implement middleware to reject requests exceeding size limits *before* they reach FastAPI's parsing logic. This can be done using Starlette's middleware capabilities, which FastAPI exposes.
    *   Monitor server resource usage and implement alerting for unusual spikes.

## Attack Surface: [3. Overly Permissive Pydantic Models](./attack_surfaces/3__overly_permissive_pydantic_models.md)

* **Description:** Pydantic models that don't strictly define allowed fields or use overly broad types can lead to unexpected data being accepted and potentially used in vulnerable ways.
    * **How FastAPI Contributes:** FastAPI's core design relies on Pydantic for data validation and serialization. The framework's ease of use and the central role of Pydantic models make this a *direct* and significant concern.
    * **Example:** A model accepts a `user_data` field of type `dict` without specifying the allowed keys. An attacker sends `{"username": "victim", "is_admin": true}`, and the application logic later uses this `is_admin` flag without further checks, granting administrative privileges.
    * **Impact:** Data integrity violations, privilege escalation, bypass of security controls.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        *   Use `extra = "forbid"` in the Pydantic model's `Config` class to raise an error if unexpected fields are present in the request. This is a *direct* use of Pydantic, as facilitated by FastAPI.
        *   Use specific Pydantic types (e.g., `EmailStr`, `ConstrainedStr`, `PositiveInt`) instead of generic types like `str`, `int`, or `Any` whenever possible.
        *   Employ comprehensive `Field` constraints (e.g., `min_length`, `max_length`, `regex`, `gt`, `lt`) to restrict the allowed values for each field.
        *   Explicitly filter data obtained from `model.dict()` or similar methods before passing it to other systems, ensuring that only expected fields are used.
        *   Implement custom validators using Pydantic's `@validator` decorator for complex validation logic that cannot be expressed with built-in constraints.

## Attack Surface: [4. WebSocket Vulnerabilities (via Starlette)](./attack_surfaces/4__websocket_vulnerabilities__via_starlette_.md)

*   **Description:** WebSockets introduce persistent connections, requiring specific security considerations like CSWSH protection and DoS prevention.
*   **How FastAPI Contributes:** FastAPI directly uses Starlette for WebSocket support, and Starlette's WebSocket implementation is exposed through FastAPI. This is a direct inheritance of functionality and, therefore, potential vulnerabilities.
*   **Example:** An attacker opens numerous WebSocket connections to a FastAPI endpoint, exhausting server resources. Or, an attacker crafts a malicious webpage that, when visited by an authenticated user, establishes a WebSocket connection to the FastAPI server and sends unauthorized commands, exploiting a missing origin check (CSWSH).
*   **Impact:** Denial of service, session hijacking, data leakage/manipulation.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement rate limiting and connection limits for WebSocket connections. This can be done using custom middleware in FastAPI that interacts with Starlette's request/response cycle.
    *   Use secure WebSockets (WSS) with TLS. This is a general best practice, but FastAPI's reliance on Starlette makes it directly relevant.
    *   Implement robust authentication and authorization for WebSocket connections *at the connection establishment*. This often involves validating tokens or session cookies within FastAPI's dependency injection system or a custom middleware.
    *   Validate all data received over WebSockets, treating it as untrusted input, using Pydantic models where appropriate.
    *   Use Starlette's `allowed_origins` setting (accessible through FastAPI) to explicitly control which origins are allowed to establish WebSocket connections, preventing Cross-Site WebSocket Hijacking. This is a *direct* use of a Starlette feature exposed by FastAPI.

