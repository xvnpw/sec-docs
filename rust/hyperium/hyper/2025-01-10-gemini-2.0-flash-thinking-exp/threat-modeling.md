# Threat Model Analysis for hyperium/hyper

## Threat: [Malformed Request Handling (Server)](./threats/malformed_request_handling__server_.md)

* **Description:** An attacker sends a crafted HTTP request with oversized headers, an extremely large body, or invalid syntax. This can cause `hyper`'s request parsing logic to consume excessive resources (CPU, memory), potentially leading to a denial-of-service (DoS).
    * **Impact:** Server becomes unresponsive or crashes, impacting availability for legitimate users.
    * **Affected Component:** `hyper::server::conn::Http` (responsible for handling incoming connections and parsing requests), `hyper::http::request::Parts` (representation of the parsed request).
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Configure `hyper::server::conn::Http` with appropriate limits for header sizes (using methods like `max_headers_size`), body sizes (using methods like `max_buf_size`), and the number of headers.
        * Implement timeouts for request processing within `hyper`'s connection handling to prevent indefinite resource consumption.

## Threat: [Connection Exhaustion (Server)](./threats/connection_exhaustion__server_.md)

* **Description:** An attacker opens a large number of connections to the server without sending valid requests or by sending requests very slowly. This can exhaust `hyper`'s ability to handle new connections, as well as the underlying `tokio` runtime's resources, preventing legitimate users from establishing new connections.
    * **Impact:** Denial of service.
    * **Affected Component:** `hyper::server::conn::Http` (manages individual connections), the underlying `tokio` runtime (handles asynchronous I/O on which `hyper` is built).
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Configure connection limits within the application logic that uses `hyper` or at the operating system level.
        * Implement timeouts for idle connections handled by `hyper`.
        * Consider using a reverse proxy or load balancer that can handle connection limiting and request buffering before reaching the `hyper` server.

## Threat: [Slowloris Attack (Server)](./threats/slowloris_attack__server_.md)

* **Description:** An attacker sends partial HTTP requests slowly, never completing them. This keeps connections open within `hyper` for an extended period, tying up server resources and potentially leading to connection exhaustion.
    * **Impact:** Denial of service.
    * **Affected Component:** `hyper::server::conn::Http` (manages connection state and timeouts for individual connections).
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Configure aggressive timeouts for incomplete requests within `hyper::server::conn::Http` (e.g., using `http1::Builder::keep_alive_timeout`).
        * Implement connection limits and rate limiting on the application level using `hyper`'s building blocks or with external tools.
        * Use a reverse proxy with buffering capabilities to absorb slow requests before they reach the `hyper` server.

## Threat: [HTTP/2 Specific Vulnerabilities (Server/Client)](./threats/http2_specific_vulnerabilities__serverclient_.md)

* **Description:** `hyper` supports HTTP/2. There are vulnerabilities specific to the HTTP/2 protocol implementation within `hyper`, such as stream multiplexing issues, rapid reset attacks, or excessive resource consumption related to stream management. An attacker could exploit these vulnerabilities by sending malicious HTTP/2 frames.
    * **Impact:** Denial of service, resource exhaustion within the `hyper` application, unexpected behavior in connection handling.
    * **Affected Component:** `hyper::server::conn::Http` and `hyper::client::conn::Http` when handling HTTP/2 connections, specifically the parts dealing with stream management and frame processing (e.g., within the `proto::h2` module).
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Keep `hyper` updated to the latest version to benefit from fixes for known HTTP/2 vulnerabilities.
        * Configure limits for the number of concurrent streams and other HTTP/2 parameters offered by `hyper`'s configuration options.
        * Consider disabling HTTP/2 if the application doesn't strictly require its features and the risk is deemed too high (though this limits functionality).

## Threat: [HTTP/3 (QUIC) Specific Vulnerabilities (Server/Client)](./threats/http3__quic__specific_vulnerabilities__serverclient_.md)

* **Description:** If using `hyper`'s HTTP/3 support (which is currently a feature behind a flag), there are potential vulnerabilities specific to the QUIC protocol implementation within `hyper`. These could involve issues with connection establishment, flow control, or congestion control.
    * **Impact:** Denial of service, resource exhaustion within the `hyper` application, potential for data manipulation or unexpected connection behavior.
    * **Affected Component:** `hyper::server::conn::quic` and `hyper::client::conn::quic`, and the underlying QUIC implementation integrated with `hyper`.
    * **Risk Severity:** High (due to the relative novelty and complexity of QUIC, and the feature flag status suggesting ongoing development and potential for undiscovered issues).
    * **Mitigation Strategies:**
        * Be extremely cautious when enabling and using experimental features like HTTP/3.
        * Keep `hyper` updated to the latest versions, as updates will likely include fixes for discovered QUIC vulnerabilities.
        * Carefully review the security considerations and best practices for QUIC protocol implementation.
        * Consider the maturity and security audit status of the specific QUIC implementation used by `hyper`.

