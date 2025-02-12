# Threat Model Analysis for expressjs/body-parser

## Threat: [Denial of Service (DoS) via Excessive Payload Size](./threats/denial_of_service__dos__via_excessive_payload_size.md)

*   **Threat:** Denial of Service (DoS) via Excessive Payload Size

    *   **Description:** An attacker sends a crafted HTTP request with an extremely large body (e.g., gigabytes of data). The attacker's goal is to overwhelm the server's resources (memory, CPU, disk I/O) by forcing `body-parser` to attempt to process this massive payload.  `body-parser`'s default behavior, without explicit limits, is to attempt to buffer the entire request body.
    *   **Impact:** The application becomes unresponsive, potentially crashing the server or making it unavailable to legitimate users. This results in a denial of service.
    *   **Affected Component:** All `body-parser` modules that handle request bodies: `json()`, `urlencoded()`, `raw()`, `text()`. The core issue is the handling of the request stream and buffering of data *without sufficient limits*.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Set `limit` option:**  This is the *primary* mitigation. Configure the `limit` option for each parser (e.g., `bodyParser.json({ limit: '100kb' })`) to a reasonable maximum size based on expected valid input.  Use units like 'kb', 'mb', or 'gb'.  This directly controls `body-parser`'s behavior.
        *   **Monitor Request Sizes:** Implement monitoring to track request body sizes and alert on unusually large requests.
        *   **Web Application Firewall (WAF):** Use a WAF to enforce request size limits at the network edge, providing an additional layer of defense (though this is less *direct*).

## Threat: [Denial of Service (DoS) via Content-Type Spoofing](./threats/denial_of_service__dos__via_content-type_spoofing.md)

*   **Threat:** Denial of Service (DoS) via Content-Type Spoofing

    *   **Description:** An attacker sends a request with a large body and a deliberately incorrect `Content-Type` header.  For instance, they might send a large text file but claim it's `application/json`.  The attacker aims to force `body-parser` to attempt parsing the data using an inappropriate parser, leading to excessive resource consumption or unexpected errors. `body-parser` relies on the `Content-Type` header to determine which parsing logic to apply.
    *   **Impact:** Similar to the excessive payload size DoS, this can lead to resource exhaustion and application unavailability. It can also cause unexpected application behavior due to parsing errors.
    *   **Affected Component:** All `body-parser` modules: `json()`, `urlencoded()`, `raw()`, `text()`. The vulnerability lies in the reliance on the `Content-Type` header for parser selection *without sufficient validation*.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Specify `type` option:** Use the `type` option to explicitly define which content types each parser should handle (e.g., `bodyParser.json({ type: 'application/json' })`). This *directly* controls which requests `body-parser` will process, preventing it from attempting to parse unexpected content types.
        *   **Validate `Content-Type`:** Implement custom middleware *before* `body-parser` to validate the `Content-Type` header against a whitelist of allowed types if more complex logic is required (this is slightly less direct, but a good practice).

## Threat: [Denial of Service (DoS) via Slowloris (with `raw` parser)](./threats/denial_of_service__dos__via_slowloris__with__raw__parser_.md)

*   **Threat:** Denial of Service (DoS) via Slowloris (with `raw` parser)

    *   **Description:** An attacker sends data very slowly, keeping the connection open for an extended period.  This is particularly effective with the `raw` parser if no size limit is set. The attacker's goal is to tie up server resources (connections, threads) by maintaining many slow, incomplete requests. `body-parser`'s `raw` parser, without a limit, will continue to buffer the incoming data, even if it arrives very slowly.
    *   **Impact:** The server becomes unable to handle legitimate requests due to resource exhaustion (connection limits, thread pool depletion). This results in a denial of service.
    *   **Affected Component:** Primarily the `raw()` parser, especially when used without a `limit`.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Mandatory `limit` for `raw()`:** Always set a reasonable `limit` on the `raw` parser (e.g., `bodyParser.raw({ limit: '1mb' })`). This *directly* limits the amount of data `body-parser` will buffer.
        *   **Connection Timeouts:** Configure server-level connection timeouts (e.g., in Node.js's HTTP server or a reverse proxy like Nginx) to automatically close connections that are idle or sending data too slowly (less direct, but important).
        *   **Reverse Proxy/Load Balancer:** Use a reverse proxy or load balancer that has built-in protection against Slowloris attacks (less direct).

## Threat: [Prototype Pollution (via `urlencoded` parser with `extended: true`)](./threats/prototype_pollution__via__urlencoded__parser_with__extended_true__.md)

*   **Threat:** Prototype Pollution (via `urlencoded` parser with `extended: true`)

    *   **Description:** An attacker crafts a malicious URL-encoded payload that exploits vulnerabilities in the `qs` library (or similar libraries used for extended parsing) to inject properties into the `Object.prototype`. The attacker's goal is to modify the behavior of the application. This is a *direct* threat because `body-parser`'s `urlencoded` parser, when configured with `extended: true`, *directly* uses a vulnerable library (historically `qs`, though it may be a different library now). The vulnerability is in the dependency, but the choice to use `extended: true` enables it.
    *   **Impact:**
        *   Denial of Service: By modifying core object behavior.
        *   Data Tampering: By altering expected values.
        *   Potential Remote Code Execution (RCE): In some cases.
    *   **Affected Component:** The `urlencoded()` parser when used with the `extended: true` option.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Update Dependencies:** Ensure `body-parser` and its dependencies are up-to-date. This is the *most direct* way to address vulnerabilities in the underlying parsing library.
        *   **Use `extended: false`:** If nested object parsing is *not* required, use `extended: false` (e.g., `bodyParser.urlencoded({ extended: false })`). This *directly* avoids using the potentially vulnerable extended parsing library.
        *   **Prototype Pollution Protection Libraries:** Consider using libraries specifically designed to mitigate prototype pollution (less direct, but a good defense-in-depth measure).
        * Freeze Object Prototypes: Use `Object.freeze(Object.prototype)` to prevent modifications to the Object prototype.


