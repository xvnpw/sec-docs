- **Vulnerability Name:** Debug Toolbar Information Disclosure
  - **Description:**
    If the Django Debug Toolbar is inadvertently left enabled on a publicly accessible production instance, an external attacker can send a specially crafted GET request (for example, to `/__debug__/render_panel/`) with valid query parameters (e.g. a valid `store_id` and panel identifier) that bypasses the intended internal IP and debug‑mode checks. When the middleware’s check (using `show_toolbar()`) erroneously accepts an external request (possibly owing to misconfigured `INTERNAL_IPS` or a fallback “Docker hack”), an attacker can retrieve detailed internal debug data such as SQL queries, stack traces, and application state.
  - **Impact:**
    An attacker could harvest sensitive information about the internal workings of the application—including database query patterns, configuration settings, and possible implementation logic—to facilitate further targeted attacks.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    - The middleware’s `show_toolbar()` function restricts activation of the toolbar to cases when `DEBUG=True` and the request is from an IP address in the `INTERNAL_IPS` list.
    - Debug endpoints are decorated with access‑limiting decorators (such as `require_show_toolbar` and `login_not_required`) so that in a correctly configured development environment only trusted/local requests may access them.
  - **Missing Mitigations:**
    - There is no guarantee that the Debug Toolbar is completely disabled in production. A misconfiguration (for example, leaving `DEBUG=True` or misconfiguring `INTERNAL_IPS`) immediately exposes all debug endpoints.
    - No additional authentication is applied beyond the internal IP and debug‑mode checks.
  - **Preconditions:**
    - The application is deployed with `DEBUG=True` (or with an overly permissive `INTERNAL_IPS` setting) so that non‑internal requests trigger the debug toolbar.
    - An attacker is able to enumerate or guess debug endpoint URL patterns (for example, `/__debug__/render_panel/`).
  - **Source Code Analysis:**
    - In **`debug_toolbar/middleware.py`** (not shown in full here), the function `show_toolbar(request)` checks that the request’s IP matches `INTERNAL_IPS` (or uses a fallback “Docker hack”), and in **`debug_toolbar/views.py`** the `render_panel` view (decorated with `require_show_toolbar`) immediately returns the internal debug panel content (including sensitive data) in a JSON response when called with valid GET parameters.
  - **Security Test Case:**
    1. **Setup:** Configure the application with `DEBUG=True` (or misconfigure `INTERNAL_IPS`) so that the debug toolbar is active for external IPs.
    2. **Request:** From an external host, send a GET request to
       ```
       http://<target-domain>/__debug__/render_panel/?store_id=<valid_uuid>&panel_id=SQLPanel
       ```
       using a tool such as curl or Postman.
    3. **Observation:** Examine the JSON response. If the response includes keys such as `"content"` displaying SQL queries, stack traces, or other internal data, then the vulnerability is confirmed.
    4. **Confirmation:** If sensitive internal debug information is disclosed to an unauthenticated, external client, the vulnerability is validated.

- **Vulnerability Name:** SQL Debug Endpoint Forgery
  - **Description:**
    The debug toolbar exposes several SQL endpoints (such as `/__debug__/sql_select/`, `/__debug__/sql_explain/`, and `/__debug__/sql_profile/`) that process a signed payload containing SQL query details. The signing mechanism (using Django’s signing module) relies on the application’s `SECRET_KEY`.
    An attacker who is aware of—or can guess—the application’s default or weak `SECRET_KEY` (for example, as seen in the example settings) can create a forged payload that passes the signature verification. The steps to trigger the attack are:
    1. The attacker constructs a payload containing a valid SQL query (limited to `SELECT` statements by validation in `SQLSelectForm`), along with parameters such as `raw_sql`, `sql`, `params` (JSON‑encoded), `alias` (e.g., `"default"`), and a `duration` value.
    2. Using the known weak `SECRET_KEY`, the attacker signs the payload to generate a valid signature.
    3. The attacker sends an HTTP GET request to one of the SQL endpoints (for example, `/__debug__/sql_select/`) with the forged signed payload as query parameters.
    4. Upon successful signature verification, the endpoint executes the provided SQL and returns the results in a JSON response.
  - **Impact:**
    By executing arbitrary `SELECT` queries through the debug SQL endpoints, an attacker may access sensitive information from the database (such as user details, configuration parameters, or internal schema information). Such disclosure could facilitate additional attacks or further data exfiltration.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    - All SQL endpoints are decorated with `@require_show_toolbar` so that under normal development conditions only internal requests gain access.
    - The SQL form (`SQLSelectForm`) enforces that only `SELECT` queries are executed.
    - The payload must be signed; an unsigned or invalid payload is rejected.
  - **Missing Mitigations:**
    - No additional authentication (beyond the debug toolbar checks) is applied to the SQL endpoints.
    - If the application uses a weak or default `SECRET_KEY` (as in the provided settings), an attacker can forge valid signed payloads.
    - There is no rate limiting or audit logging on these endpoints to track abuse.
  - **Preconditions:**
    - The application is deployed with the debug toolbar active (i.e. `DEBUG=True`) and is accessible from the external network.
    - The `SECRET_KEY` in use is weak, default, or otherwise compromised.
    - The `INTERNAL_IPS` setting is misconfigured or otherwise allows external access.
  - **Source Code Analysis:**
    - In **`/code/debug_toolbar/panels/sql/views.py`**, the helper function `get_signed_data(request)` creates a signed data form from the incoming GET/POST parameters and calls its `is_valid()` method.
    - If valid, the payload is passed to `SQLSelectForm` (defined in **`/code/debug_toolbar/panels/sql/forms.py`**) where `clean_raw_sql` ensures the query is a `SELECT` only.
    - The signing (using Django’s `signing.loads`) derives its security from the global `SECRET_KEY` as configured (in this project, the default insecure string is visible in `/code/example/settings.py`).
  - **Security Test Case:**
    1. **Setup:** Confirm that the application is running with `DEBUG=True` and that the `SECRET_KEY` is set to a default or weak value.
    2. **Payload Forging:** Using Django’s signing module (or a custom script), generate a valid signed payload for a `SELECT` query (for example, use `"SELECT sqlite_version();"` as both `raw_sql` and `sql`). Encode empty parameters (e.g. an empty JSON array) for `params`, set `"alias": "default"`, and include a dummy `duration`.
    3. **Request:** Send an HTTP GET request to
       ```
       http://<target-domain>/__debug__/sql_select/?<signed_payload_parameters>
       ```
       using curl or a similar tool.
    4. **Observation:** If the response status is 200 and the JSON output includes a `"content"` key showing the result of the provided SQL (for instance, the SQLite version), the exploitation is confirmed.
    5. **Confirmation:** Successful execution and return of the result indicate that an attacker can abuse the SQL debug endpoint to query sensitive database information.

- **Vulnerability Name:** Template Source Disclosure via Forged Signed Parameter
  - **Description:**
    The debug toolbar includes a template source view (`template_source`) that returns the source code of a template after syntax highlighting. This view expects a GET parameter named `template_origin` that is signed using Django’s signing module.
    An attacker who knows or can guess the application’s weak or default `SECRET_KEY` can forge a valid signature for a chosen template filename. By submitting this forged signature along with a `template` parameter (if desired), an attacker can force the debug toolbar to load and return the template’s source code.
  - **Impact:**
    Disclosure of template source code can reveal sensitive internal logic, configuration hints, and even business rules. Such details may assist an attacker in crafting further targeted attacks, bypassing client‑side validation, or exploiting other weaknesses in the application.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    - The view is protected by the `@require_show_toolbar` decorator (and `@login_not_required`), which normally restricts access to trusted environments when debugging.
    - The use of a signed `template_origin` parameter attempts to ensure that only template sources approved during a debug session are revealed.
  - **Missing Mitigations:**
    - No additional authorization or authentication is applied beyond the debug toolbar’s internal checks.
    - If the application is misconfigured in production or uses a weak/default `SECRET_KEY`, an attacker can forge a valid signed parameter.
    - Input validation is limited to deserialization via `signing.loads`, without further restrictions to restrict retrieval to only expected templates.
  - **Preconditions:**
    - The debug toolbar is enabled in the deployed instance (e.g. `DEBUG=True`).
    - The application uses a weak or default `SECRET_KEY` that enables signature forgery.
    - The `INTERNAL_IPS` or similar access controls are misconfigured or bypassable by an external attacker.
  - **Source Code Analysis:**
    - In **`/code/debug_toolbar/panels/templates/views.py`**, the view `template_source` retrieves the GET parameter `template_origin` and attempts to deserialize it using `signing.loads()`.
    - On successful deserialization, the view uses the resulting string to create an `Origin` object and iterate through the active template loaders (using methods like `loader.get_contents(origin)`) until the template source is found.
    - The resulting content is then syntax‑highlighted (using Pygments, if available) and returned in a JSON response.
    - The signing mechanism hinges on the security of the application’s `SECRET_KEY` (as seen in `/code/example/settings.py`), which—in case of a weak value—allows an attacker to generate valid signed parameters.
  - **Security Test Case:**
    1. **Setup:** Verify that the application is running with debug toolbar enabled (i.e. `DEBUG=True`) and note the `SECRET_KEY` (if it is a known default or weak string).
    2. **Forge a Signature:** Using Django’s signing tools, create a valid signed string for a known template file’s origin (for example, the path or name of a template present in the application).
    3. **Request:** Send an HTTP GET request to
       ```
       http://<target-domain>/__debug__/template_source/?template_origin=<forged_value>&template=<expected_template_name>
       ```
       through a browser or a tool like curl.
    4. **Observation:** If the response is HTTP 200 and the returned JSON contains the HTML‑formatted source code of the template, the vulnerability is confirmed.
    5. **Confirmation:** The successful retrieval of template source indicates that an attacker can abuse the signing mechanism to expose sensitive template code.