# Threat Model Analysis for openresty/lua-nginx-module

## Threat: [Lua Code Injection](./threats/lua_code_injection.md)

**Description:** An attacker crafts malicious input (e.g., through request parameters, headers, or upstream responses) that is not properly sanitized and is then interpreted as executable Lua code by the `lua-nginx-module`. This allows the attacker to execute arbitrary code within the Nginx worker process.

**Impact:** Full compromise of the Nginx worker process, leading to potential data breaches, server takeover, denial of service, and the ability to pivot to other internal systems.

**Affected Component:** `content_by_lua_block`, `access_by_lua_block`, `header_filter_by_lua_block` directives; `ngx.req.get_uri_args()`, `ngx.var`, and any Lua code processing external input *through the module's interfaces*.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Implement strict input validation using Lua pattern matching or dedicated validation libraries *within the Lua code executed by the module*.
* Sanitize input to remove potentially harmful characters or escape them appropriately *before processing in Lua*.
* Avoid using `loadstring` or similar functions with untrusted input *within the Lua code*.
* Follow secure coding practices in Lua, treating all external input as potentially malicious.

## Threat: [Access to Sensitive Nginx Internals](./threats/access_to_sensitive_nginx_internals.md)

**Description:** Malicious or poorly written Lua code leverages the `lua-nginx-module`'s access to Nginx's internal APIs and data structures to expose sensitive information like request headers, server variables, or even internal configurations. An attacker might exploit this to gain insights into the application's architecture or security mechanisms.

**Impact:** Disclosure of sensitive information, potentially aiding further attacks. This could include API keys, internal hostnames, or details about upstream services.

**Affected Component:** `ngx.var`, `ngx.req.get_headers()`, `ngx.config`, `ngx.shared.DICT`, and other Nginx API functions directly accessible through the `lua-nginx-module`.

**Risk Severity:** High

**Mitigation Strategies:**
* Adhere to the principle of least privilege in Lua code. Only access necessary Nginx APIs and variables.
* Carefully review the documentation for each Nginx API used to understand its security implications.
* Avoid logging sensitive information directly from Lua *using the module's logging capabilities*.
* Implement access controls within Lua to restrict which scripts can access sensitive Nginx data.

## Threat: [Server-Side Request Forgery (SSRF) via Lua](./threats/server-side_request_forgery_(ssrf)_via_lua.md)

**Description:** Lua code, executed by the `lua-nginx-module`, is used to make requests to internal or external resources based on user-controlled input without proper validation. An attacker could manipulate this to make the server send requests to unintended destinations, potentially accessing internal services or performing actions on their behalf.

**Impact:** Access to internal resources, potential data breaches, and the ability to abuse internal services.

**Affected Component:** `ngx.location.capture`, `ngx.socket.tcp`, `resty.http` library *when used within the context of the module's execution*.

**Risk Severity:** High

**Mitigation Strategies:**
* Implement strict validation of URLs and hostnames used in Lua requests.
* Use allow lists instead of deny lists for allowed destinations.
* Avoid directly using user input to construct URLs *within the Lua code*.
* Consider using network segmentation to restrict the server's access to internal resources.

