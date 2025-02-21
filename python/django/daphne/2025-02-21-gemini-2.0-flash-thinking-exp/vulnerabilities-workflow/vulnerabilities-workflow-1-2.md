- **Vulnerability Name**: Trusting Unvalidated Proxy Headers Leading to IP Spoofing
  - **Description**:
    When the server is started with the “proxy headers” feature enabled (for example, via the “--proxy-headers” command‐line flag), it calls the `parse_x_forwarded_for` function to determine the client’s IP address and port. This function simply takes the contents of headers such as “X-Forwarded-For” and “X-Forwarded-Port”, splits the “X-Forwarded-For” value on commas, and returns the left-most element without any further validation. An external attacker who is able to connect directly to the Daphne server (i.e. outside of a trusted proxy network) can easily inject arbitrary header values into their HTTP or WebSocket request. As a result, the server mistakenly believes the connection originates from the spoofed IP and port.
    - **Step by step how an attacker might trigger this vulnerability**:
      1. Deploy Daphne in a publicly accessible environment with proxy header processing enabled (for example, by starting the server with the “--proxy-headers” flag).
      2. An attacker directly makes an HTTP request (or opens a WebSocket connection) to the server while including custom headers such as:
         - `X-Forwarded-For: 192.0.2.1`
         - `X-Forwarded-Port: 8080`
      3. The server’s `parse_x_forwarded_for` routine (located in `daphne/utils.py`) processes these headers, picks the attacker‑supplied IP “192.0.2.1” (and port 8080) as the client address, and uses them in the request scope as well as access logging.
      4. Thus, any logic (for example, IP‑based access controls or rate limiters) that depends on the reported client address is deceived into trusting the attacker’s spoofed values.

  - **Impact**:
    An attacker can impersonate an arbitrary IP address, potentially bypassing IP‑based restrictions, rate‐limiting measures, or logging/auditing controls. This misattribution may lead to unauthorized access or abuse of backend resources.

  - **Vulnerability Rank**: High

  - **Currently Implemented Mitigations**:
    - The `parse_x_forwarded_for` function merely splits the header value (at commas) and uses the first IP, which is a standard (but minimal) approach when processing “X-Forwarded-For”.
    - Proxy header processing is enabled only if the server has been explicitly configured (via CLI options such as “--proxy-headers”).

  - **Missing Mitigations**:
    - No verification is made that the incoming “X-Forwarded-For” header originates from a trusted proxy.
    - There is no mechanism (e.g., an IP whitelist) to ensure that only proxy headers from known, secure intermediary addresses are honored.
    - Additional validation should be implemented so that if proxy header processing is enabled, the server accepts those headers only from a trusted source.

  - **Preconditions**:
    - The Daphne server must be started with proxy header processing enabled (e.g. using “--proxy-headers”).
    - The attacker must be able to send requests directly to the server (i.e. no trusted upstream proxy is present to strip or re‑format these headers).

  - **Source Code Analysis**:
    - In **`daphne/utils.py` → `parse_x_forwarded_for`**:
      - The function checks if the configured address header (default “X-Forwarded-For”) is present.
      - It converts all header names to lower-case and, if multiple IPs are found (separated by commas), selects the first element (without validating its origin).
      - No cross-check is performed to confirm that the request is arriving from a known proxy IP.
    - In **`daphne/ws_protocol.py` (in `WebSocketProtocol.onConnect`)** and **`daphne/http_protocol.py` (in `WebRequest.process`)**:
      - The function is called to override the client address with the value derived from the proxy headers—even for connections coming directly from an attacker’s host.

  - **Security Test Case**:
    1. Start the Daphne server with the proxy header option enabled (e.g. run:
       `daphne --proxy-headers …`).
    2. Using a tool such as curl, send an HTTP GET request directly to the server with custom headers:
       - `X-Forwarded-For: 192.0.2.1`
       - `X-Forwarded-Port: 8080`
    3. Observe the server’s access logs or the request scope (if accessible via an application endpoint) and verify that the reported client address is “192.0.2.1” on port 8080 instead of the actual IP address.
    4. This confirms that the server trusts unvalidated proxy header values, enabling an attacker to spoof their IP address.

- **Vulnerability Name**: Lack of WebSocket Origin Validation
  - **Description**:
    During the WebSocket handshake, the Daphne server (in its WebSocket protocol implementation) accepts connection requests with any “Origin” header value. In the `WebSocketProtocol.onConnect` method (found in `daphne/ws_protocol.py`), while the server sanitizes header names by encoding them and filtering for specific headers (for example, “daphne-root-path”), it does not perform any checks against the “Origin” header. Consequently, an attacker can supply a malicious “Origin” header without triggering any rejection logic.
    - **Step by step how an attacker might trigger this vulnerability**:
      1. An attacker initiates a WebSocket handshake to the Daphne server and deliberately sets the “Origin” header to an untrusted value (for example, “http://malicious.example”).
      2. During the connection process in the `onConnect` method, all request headers (including “Origin”) are read and normalized but not verified or compared against a whitelist of allowed origins.
      3. The handshake completes successfully regardless of the value of “Origin”.
      4. As a result, any backend application relying on the same-origin policy for security is exposed to cross-origin WebSocket connections.

  - **Impact**:
    - Attackers may hijack or abuse WebSocket connections from unauthorized origins.
    - This flaw can undermine same-origin policy assumptions in a web application, potentially enabling cross-site WebSocket attacks that could exfiltrate or manipulate sensitive data.

  - **Vulnerability Rank**: High

  - **Currently Implemented Mitigations**:
    - Header names are normalized and nonessential headers (like those with underscores) are dropped.
    - The server does extract and pass along the “Origin” header as part of the connection scope, but it does no further validation.

  - **Missing Mitigations**:
    - There is no mechanism to validate the “Origin” header against a list of trusted or allowed origins.
    - The server lacks configuration options to enforce an origin check during the WebSocket handshake.
    - Implementing an origin whitelisting check would help ensure that only requests from authorized origins are accepted.

  - **Preconditions**:
    - The server must be running in a mode where WebSocket connections are accepted (i.e. deployed publicly without an intervening proxy that performs the origin check).
    - The application or infrastructure does not already enforce strict origin validation.

  - **Source Code Analysis**:
    - In **`daphne/ws_protocol.py` → `WebSocketProtocol.onConnect`**:
      - The method iterates over all headers in the incoming WebSocket request and encodes them (e.g. using `name.encode("ascii")`).
      - For headers that match “daphne-root-path” the value is used to set the request’s root path; however, no similar check is performed for the “Origin” header.
      - As a consequence, any “Origin” header provided by the client (including one set to an attacker‑controlled value) is ignored from a security validation standpoint and does not lead to connection rejection.

  - **Security Test Case**:
    1. Deploy the Daphne server in an environment where WebSocket connections are allowed.
    2. Use a WebSocket testing tool (such as “wscat”) or a custom script to initiate a WebSocket handshake; explicitly set the “Origin” header to a malicious value (e.g. “http://malicious.example”).
    3. Verify that the handshake completes successfully (i.e. the server responds with a 101 Switching Protocols status code).
    4. Confirm (via logs or application response inspection) that the connection is treated as acceptable despite the untrusted “Origin” value.
    5. This proves that the server does not validate WebSocket origins, leaving the connection open to cross-origin abuse.