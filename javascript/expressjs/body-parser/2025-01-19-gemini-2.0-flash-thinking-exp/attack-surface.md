# Attack Surface Analysis for expressjs/body-parser

## Attack Surface: [Prototype Pollution (JSON & URL-encoded)](./attack_surfaces/prototype_pollution__json_&_url-encoded_.md)

* **Description:** Attackers can manipulate the prototype of JavaScript objects by injecting properties like `__proto__` or `constructor.prototype` in the request body. This can lead to denial-of-service or unexpected behavior across the application.
    * **How `body-parser` Contributes:** `bodyParser.json()` and `bodyParser.urlencoded()` by default parse the request body and create JavaScript objects. If not configured carefully, they can allow the injection of these prototype-modifying properties.
    * **Example:** Sending a JSON payload like `{"__proto__": {"isAdmin": true}}` or URL-encoded data like `__proto__[isAdmin]=true`. This could potentially add an `isAdmin` property to all objects in the application.
    * **Impact:** Denial of service, arbitrary code execution (in some scenarios or older JavaScript engines), security bypasses.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * **`bodyParser.json({ strict: true })`:** Enable the `strict` option for `bodyParser.json()`. This prevents the parser from accepting non-object/array top-level primitives, reducing the risk of prototype pollution via JSON.
        * **Input Sanitization:** Sanitize or filter request body data to remove potentially malicious properties like `__proto__` and `constructor`.
        * **Object Creation without Prototypes:** When processing data from `req.body`, create objects without a prototype using `Object.create(null)` if possible, to avoid inheriting potentially polluted prototypes.
        * **Framework/Library Updates:** Keep your Express.js and `body-parser` versions up-to-date, as security patches often address prototype pollution vulnerabilities.

## Attack Surface: [Resource Exhaustion (Denial of Service via Large Payloads)](./attack_surfaces/resource_exhaustion__denial_of_service_via_large_payloads_.md)

* **Description:** Attackers send excessively large request bodies, consuming significant server resources (CPU, memory), leading to performance degradation or denial of service.
    * **How `body-parser` Contributes:** `body-parser` reads and parses the entire request body into memory. Without proper limits, it will attempt to process arbitrarily large payloads.
    * **Example:** Sending a multi-gigabyte JSON or URL-encoded payload.
    * **Impact:** Service disruption, server crashes, increased infrastructure costs.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * **`limit` Option:** Use the `limit` option in `bodyParser.json()` and `bodyParser.urlencoded()` to restrict the maximum size of the request body that will be parsed. Choose a reasonable limit based on your application's needs.
        * **Web Server Limits:** Configure your web server (e.g., Nginx, Apache) to also enforce limits on request body sizes. This acts as a first line of defense.
        * **Rate Limiting:** Implement rate limiting to restrict the number of requests from a single IP address within a given time frame, mitigating attempts to flood the server with large requests.

