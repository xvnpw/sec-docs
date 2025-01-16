# Attack Surface Analysis for arut/nginx-rtmp-module

## Attack Surface: [Malicious RTMP Handshake](./attack_surfaces/malicious_rtmp_handshake.md)

*   **Description:** An attacker sends specially crafted or oversized RTMP handshake packets to the server.
    *   **How nginx-rtmp-module Contributes:** The module is responsible for parsing and processing the initial RTMP handshake to establish a connection. Vulnerabilities in this parsing logic can be exploited.
    *   **Example:** Sending an extremely large or malformed `C0`, `C1`, or `C2` packet that causes a buffer overflow or crashes the module.
    *   **Impact:** Denial of Service (DoS) by crashing the Nginx worker process handling RTMP connections. Potential for remote code execution if a buffer overflow vulnerability is present and exploitable.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Ensure the `nginx-rtmp-module` is updated to the latest version with known handshake parsing vulnerabilities patched.
        *   Implement input validation and size limits on incoming handshake packets within the module's code (if developing custom patches).
        *   Consider using network-level filtering or firewalls to block abnormally large or malformed packets before they reach the Nginx server.

## Attack Surface: [Malicious RTMP Message Injection (Publishing)](./attack_surfaces/malicious_rtmp_message_injection__publishing_.md)

*   **Description:** An attacker publishing a stream sends crafted RTMP messages containing unexpected data types, sizes, or malicious payloads.
    *   **How nginx-rtmp-module Contributes:** The module parses and processes incoming RTMP messages from publishers. Insufficient validation can lead to vulnerabilities.
    *   **Example:** Injecting excessively large metadata, malformed audio/video data, or control messages that exploit parsing flaws.
    *   **Impact:** Denial of Service (DoS) by crashing the module or Nginx worker process. Potential for remote code execution if vulnerabilities in message processing are exploitable. Could also lead to data corruption or unexpected behavior in downstream processes.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement strict input validation on all incoming RTMP messages, checking data types, sizes, and formats.
        *   Sanitize or reject messages containing unexpected or malicious content.
        *   Update the `nginx-rtmp-module` to the latest version with known message parsing vulnerabilities addressed.
        *   Consider implementing rate limiting on publishing streams to mitigate resource exhaustion.

## Attack Surface: [Unauthorized Access via HTTP Control Interface](./attack_surfaces/unauthorized_access_via_http_control_interface.md)

*   **Description:** If the HTTP control interface of the `nginx-rtmp-module` is enabled without proper authentication or authorization, attackers can gain unauthorized control.
    *   **How nginx-rtmp-module Contributes:** The module provides HTTP endpoints for managing streams, viewing statistics, and other control functions. Lack of security on these endpoints is a direct contribution.
    *   **Example:** An attacker accessing `/control/drop/publisher?app=live&name=mystream` without authentication to forcibly disconnect a legitimate publisher.
    *   **Impact:**  Unauthorized control over the RTMP server, including disconnecting publishers/players, manipulating stream recordings, and potentially gaining access to sensitive information.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Require authentication for all HTTP control interface endpoints.** Use strong authentication mechanisms (e.g., HTTP Basic Auth, API keys).
        *   Implement authorization checks to ensure only authorized users can perform specific actions.
        *   If the HTTP control interface is not needed, disable it entirely in the `nginx.conf` file.
        *   Restrict access to the control interface to specific IP addresses or networks using firewall rules.

## Attack Surface: [Command Injection via `exec` Directive](./attack_surfaces/command_injection_via__exec__directive.md)

*   **Description:** If the `exec` directive is used within the `nginx-rtmp-module` configuration to execute external commands based on user-provided data (e.g., stream names), it can lead to command injection vulnerabilities.
    *   **How nginx-rtmp-module Contributes:** The module allows executing arbitrary system commands based on events like publishing or playing, making it a conduit for command injection if not used carefully.
    *   **Example:** A publisher using a stream name like `test; rm -rf /` which, if passed unsanitized to an `exec` directive, could execute a dangerous command on the server.
    *   **Impact:** Full compromise of the server by executing arbitrary commands with the privileges of the Nginx worker process.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Avoid using the `exec` directive if possible.** Explore alternative methods for achieving the desired functionality.
        *   **If `exec` is necessary, strictly sanitize all user-provided data before passing it to the command.** Use whitelisting and escape special characters.
        *   Run the Nginx worker process with the least privileges necessary to minimize the impact of a successful command injection.

## Attack Surface: [SSRF via `on_publish`/`on_play` Hooks](./attack_surfaces/ssrf_via__on_publish__on_play__hooks.md)

*   **Description:** If the `on_publish` or `on_play` directives are used to make HTTP requests to external servers based on user-provided data, it can create a Server-Side Request Forgery (SSRF) vulnerability.
    *   **How nginx-rtmp-module Contributes:** The module facilitates making outbound HTTP requests based on events, making it a potential vector for SSRF if the target URL is not carefully controlled.
    *   **Example:** A publisher providing a malicious URL in their stream name that is then used by the `on_publish` hook to make a request to an internal service or an external attacker-controlled server.
    *   **Impact:**  Ability to make requests to internal services that are not directly accessible from the outside, potentially leading to information disclosure or further exploitation. Can also be used to scan internal networks or launch attacks against other systems.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid using user-provided data directly in the URLs for `on_publish` or `on_play` hooks.**
        *   If external requests are necessary, use a whitelist of allowed destination URLs or domains.
        *   Implement proper input validation and sanitization of any user-provided data used in the URLs.

