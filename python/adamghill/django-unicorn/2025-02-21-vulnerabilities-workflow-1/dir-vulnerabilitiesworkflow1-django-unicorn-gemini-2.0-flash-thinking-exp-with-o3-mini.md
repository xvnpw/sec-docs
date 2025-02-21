## Combined Vulnerability List

### Cross-Site Scripting (XSS) via Insecure HTML Handling in Templates

- **Description:**
  1. An attacker can inject malicious JavaScript code into a component's property that is rendered in a template without proper sanitization.
  2. When this component is rendered and served to a user's browser, the injected JavaScript code will be executed.
  3. This can be achieved if a component's property, used in the template, is updated via user input or any other external source without proper HTML escaping by django-unicorn.
  4. The vulnerability is exacerbated if the developer uses `safe` meta attribute or `|safe` template filter incorrectly, intending to allow safe HTML but inadvertently allowing malicious scripts.

- **Impact:**
  - An attacker can execute arbitrary JavaScript code in the victim's browser when they view the page containing the vulnerable component.
  - This can lead to session hijacking, cookie theft, defacement of the website, or redirection to malicious sites.
  - In a broader context, it can compromise the user's account and potentially the entire application if sensitive actions can be performed via JavaScript.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - According to `changelog.md` version 0.36.0, a security fix for CVE-2021-42053 was implemented to prevent XSS attacks.
  - The changelog states that responses are HTML encoded going forward, and developers need to explicitly use `safe` to opt-in to the previous behavior. This suggests default encoding is now in place.
  - `django_unicorn\utils.py` contains `sanitize_html` function which uses `html.escape` internally to escape HTML/XML special characters.
  - `django_unicorn\components\unicorn_template_response.py` in `UnicornTemplateResponse.render` method calls `sanitize_html(init)` to sanitize the component initialization data that is passed to frontend via JSON.
  - `django_unicorn\tests\views\test_process_component_request.py` contains `test_html_entities_encoded` which asserts that HTML entities are encoded by default.
  - `django_unicorn\tests\views\test_process_component_request.py` contains `test_safe_html_entities_not_encoded` which asserts that `safe` meta attribute prevents HTML entities encoding.

- **Missing Mitigations:**
  - While default encoding and `sanitize_html` are present, it's crucial to verify that all output paths in django-unicorn templates and javascript interactions are consistently and correctly encoded by default, unless explicitly marked as `safe`.
  - Need to confirm if `safe` usage is properly documented with clear warnings about its risks and when it's genuinely necessary.
  - Further investigation is needed to ensure no bypasses exist and that encoding is consistently applied across all relevant features (e.g., model updates, action responses, template rendering of component properties).
  - The current analysis of `UnicornTemplateResponse.render` shows sanitization of `init` data, but it is not explicitly clear if component properties rendered in the template (using `{{ component.property }}`) are also automatically escaped by django template engine when updated via AJAX.

- **Preconditions:**
  - The application must be using `django-unicorn` and rendering user-controlled data or data from external sources into templates via unicorn components.
  - No explicit and correct usage of Django's `escape` filter or similar sanitization techniques by the developer when rendering user-provided data within unicorn components, assuming django-unicorn's default encoding might be insufficient or bypassed.

- **Source Code Analysis:**
  1. **`django_unicorn\utils.py`**: The `sanitize_html` function uses `html.escape` which is a standard way to prevent XSS by escaping HTML characters. This function is used in `UnicornTemplateResponse.render` for sanitizing `init` data.
  ```python
  def sanitize_html(html: str) -> SafeText:
      """
      Escape all the HTML/XML special characters with their unicode escapes, so
      value is safe to be output in JSON.
      ...
      """
      html = html.translate(_json_script_escapes)
      return mark_safe(html)  # noqa: S308
  ```
  2. **`django_unicorn\components\unicorn_template_response.py`**: In `UnicornTemplateResponse.render`, the `init` data, which includes component properties, is serialized to JSON and then sanitized using `sanitize_html` before being embedded in a `<script>` tag. This is a positive security measure for the component's initial data.
  ```python
              json_tag = soup.new_tag("script")
              json_tag["type"] = "application/json"
              json_tag["id"] = json_element_id
              json_tag.string = sanitize_html(init)
  ```
  3. **Template Rendering**: Need to verify if Django's template engine automatically escapes variables rendered using `{{ }}` tags within unicorn components, especially when these components are updated via AJAX. If the template context is not properly prepared or if `django-unicorn` bypasses Django's default escaping in any way during updates, XSS might be possible. The documentation mentions default HTML encoding in `changelog.md`, which suggests Django's template engine's auto-escaping should be in effect. However, explicit tests are needed to confirm this for AJAX updates.
  4. **`safe` usage**: Developers can use `|safe` filter or `safe` meta attribute to bypass escaping. Misuse of `safe` can lead to XSS. Documentation should clearly warn about the risks and proper usage of `safe`.
  5. **`django_unicorn\tests\views\test_process_component_request.py`**: `test_html_entities_encoded` test confirms that by default HTML is encoded.
  ```python
  def test_html_entities_encoded(client):
      data = {"hello": "test"}
      action_queue = [
          {
              "payload": {"name": "hello", "value": "<b>test1</b>"},
              "type": "syncInput",
          }
      ]
      response = post_and_get_response(
          client,
          url="/message/tests.views.test_process_component_request.FakeComponent",
          data=data,
          action_queue=action_queue,
      )

      assert not response["errors"]
      assert response["data"].get("hello") == "<b>test1</b>"
      assert "&lt;b&gt;test1&lt;/b&gt;" in response["dom"]
  ```
  6. **`django_unicorn\tests\views\test_process_component_request.py`**: `test_safe_html_entities_not_encoded` test confirms that `safe` meta attribute prevents HTML encoding.
  ```python
  def test_safe_html_entities_not_encoded(client):
      data = {"hello": "test"}
      action_queue = [
          {
              "payload": {"name": "hello", "value": "<b>test1</b>"},
              "type": "syncInput",
          }
      ]
      response = post_and_get_response(
          client,
          url="/message/tests.views.test_process_component_request.FakeComponentSafe",
          data=data,
          action_queue=action_queue,
      )

      assert not response["errors"]
      assert response["data"].get("hello") == "<b>test1</b>"
      assert "<b>test1</b>" in response["dom"]
  ```
  7. **`django_unicorn\tests\views\utils\test_set_property_from_data.py`**: This test file shows how component properties are updated from data sent from the client. While it tests various data types, including strings, integers, datetimes, lists, models, and querysets, it does not include specific tests to validate HTML escaping or sanitization during property updates. This reinforces the need to verify that HTML escaping is consistently applied when properties are updated via AJAX and rendered in templates, especially when `{{ component.property }}` syntax is used.

- **Security Test Case:**
  1. Create a django-unicorn component named `XssTestComponent`.
  2. Add a property named `user_input` to `XssTestComponent`.
  3. In the component's template (`unicorn/xss-test.html`), render the `user_input` property using `{{ user_input }}`.
  ```html
  <div>
      <p id="xss-target">{{ user_input }}</p>
      <input unicorn:model="user_input" type="text">
  </div>
  ```
  4. In the component's view class (`XssTestView`), leave the default behavior without explicit sanitization or `safe` usage.
  ```python
  from django_unicorn.components import UnicornView

  class XssTestView(UnicornView):
      user_input: str = ""
  ```
  5. Create a Django view to render the `XssTestComponent` in a template.
  6. As an attacker, navigate to the page containing `XssTestComponent`.
  7. In the input field, enter the payload: `<img src="x" onerror="alert('XSS')">`.
  8. Type or blur from the input field to trigger the `unicorn:model` update.
  9. Check if an alert box appears in the browser. If it does, then default escaping is not preventing XSS in this scenario.
  10. To test `safe` bypass, modify the component template to use `{{ user_input|safe }}` and repeat steps 6-9. Verify that the XSS payload is now executed, confirming that `safe` filter bypasses the default escaping.
  11. Alternatively, in the view class, add `Meta: safe = ("user_input",)` and repeat steps 6-9. Verify that `safe` meta option also bypasses default escaping and results in XSS.


### Insecure Deserialization in Component Caching

- **Description:**
  1. Django-unicorn implements component caching to potentially improve performance, especially for queued requests and dynamic components.
  2. The caching mechanism, when enabled (`settings.UNICORN['SERIAL']['ENABLED'] = True`), uses Python's `pickle` serialization which is inherently vulnerable to insecure deserialization.
  3. The framework caches complete component state using Python’s pickle mechanism. When using an insecure cache backend (such as a misconfigured Redis or memcached instance), an attacker with network access to the cache may inject a malicious pickle payload.
  4. An attacker could craft a malicious serialized payload and inject it into the cache.
  5. When the application retrieves and deserializes this malicious payload, it could lead to arbitrary code execution on the server.
  6. Later, when the component is restored from the cache (e.g., during a queued component request), the cached payload is deserialized using `pickle.loads` without any integrity or cryptographic verification. An external attacker who can, for example, exploit an insecurely configured cache backend (such as an unauthenticated Redis or Memcached instance) could insert a malicious pickle payload. Upon deserialization, this payload may trigger arbitrary code execution.

  **Step‑by‑step trigger:**
    1. An attacker locates the cache key pattern (e.g., “unicorn:component:{component_id}” or `unicorn:queue:{component_id}`).
    2. By exploiting misconfiguration (lack of authentication or network isolation), the attacker writes a crafted pickle payload into the cache.
    3. The next time the application fetches the cached component state, it uses `pickle.loads` to deserialize the payload.
    4. Because pickle deserialization can execute arbitrary code, the malicious code embedded in the payload is executed, leading to remote code execution.

- **Impact:**
  - Remote Code Execution (RCE) on the server.
  - Full compromise of the application and potentially the server infrastructure.
  - Data breach and loss of confidentiality, integrity, and availability.
  - Exploitation allows remote code execution on the server. An attacker could steal sensitive data, manipulate system state, or use the compromised server to pivot into backend infrastructure.
  - If successfully exploited, the attacker gains arbitrary code execution within the Python process running the server. This can lead to full server compromise, data exfiltration, persistent backdoors, lateral movement in the network, and other adverse outcomes.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  - The documentation (`queue-requests.md`, `settings.md`) mentions that serialization for request queuing is experimental and disabled by default.
  - It also notes that the feature is automatically disabled if the cache backend is set to `DummyCache`.
  - `cacher.py` confirms the usage of `pickle` for serialization and deserialization of component state.
  - `project\settings.py` in the example project has `UNICORN = {"SERIAL": {"ENABLED": True}}`. This indicates that while disabled by default, the example project itself enables this potentially insecure feature, increasing the risk for developers who might use the example project as a template.
  - The framework checks whether serialization is enabled via settings (using `get_serial_enabled`).
  - Administrators are expected to deploy cache backends (e.g. Redis, memcached) in a secured and isolated manner.
  - Experimental serialization settings are used in non‑production environments (for example, disabling serialization when using the dummy cache), reducing risk during development.
  - The application’s workflow expects that the site administrator configures the cache backend securely.

- **Missing Mitigations:**
  - As `pickle` is used for serialization, there are no effective mitigations against insecure deserialization vulnerabilities when `SERIAL.ENABLED` is True.
  - The documentation should be updated to strongly and prominently warn against enabling the serialization feature in production due to critical security risks associated with `pickle`. The current warning might be insufficient given the severity.
  - Replacing `pickle` with a safer serialization format like `json` or `dill.settings['settings']["byref"] = True` is essential if serialization is to be offered as a feature. However, even safer serializers need careful consideration and might not eliminate all risks from maliciously crafted payloads. `dill` was mentioned in previous analysis, but `json` would be safer and likely sufficient for component state serialization as it does not allow code execution.
  - Input validation on cached data before deserialization is highly complex and impractical to implement effectively against determined attackers exploiting insecure deserialization.
  - No built‑in safe serializer is used for caching component state.
  - There is no verification or sandboxing of the deserialized payload.
  - No explicit warning is issued if an insecure cache backend is adopted.
  - No cryptographic signing or integrity verification is applied to the pickled data before deserialization.
  - There is no alternative “safe” serialization format (e.g., JSON or a restricted serializer) available to replace pickle.
  - In environments where the cache backend may be misconfigured or shared with untrusted parties, the risk of malicious cache poisoning remains.

- **Preconditions:**
  - The `UNICORN['SERIAL']['ENABLED']` setting must be explicitly set to `True` in Django settings.
  - A cache backend other than `DummyCache` must be configured and in use (e.g., `locmem`, `redis`, `memcached`, `database`).
  - An attacker needs to find a way to inject a malicious payload into the cache. This could be through exploiting other vulnerabilities that allow cache manipulation, or if the cache is exposed or misconfigured.
  - The application is deployed with a cache backend that is accessible to an attacker (for example, a Redis or memcached instance without proper authentication or network restrictions).
  - An attacker has network access to the cache backend used for component state storage.
  - The cache backend (for example, Redis or Memcached) must be misconfigured or exposed without proper network isolation and authentication.
  - An attacker must be able to write to or poison the cache entry using the known key format (e.g., “unicorn:component:{component_id}” or `unicorn:queue:{component_id}`).

- **Source Code Analysis:**
  1. **`django_unicorn\cacher.py`**: This file confirms that `pickle` is used for serialization and deserialization. The `Cacher` class uses `pickle.dumps` for `set` and `pickle.loads` for `get`.
  ```python
  class Cacher:
      ...
      def set(self, key: str, value: Any, timeout: Optional[int] = None) -> None:
          """
          Sets a value in the cache.
          """

          if not get_serial_enabled():
              return

          if value is None:
              return

          cache.set(
              key,
              pickle.dumps(value), # Insecure deserialization vulnerability here
              timeout=timeout,
          )

      def get(self, key: str) -> Any:
          """
          Gets a value from the cache.
          """

          if not get_serial_enabled():
              return None

          value = cache.get(key)

          if value:
              try:
                  return pickle.loads(value) # Insecure deserialization vulnerability here
              except pickle.PickleError:
                  logger.warning(f"Cache for '{key}' could not be loaded.")
                  return None

          return value
  ```
  2. **`django_unicorn\components\unicorn_view.py`**: `_cache_component` method utilizes `cache_full_tree` which internally uses `Cacher` to store component data when `SERIAL.ENABLED` is True.  `restore_from_cache` also uses `Cacher` to retrieve and deserialize cached components.
  3. **`example\project\settings.py`**: The example project configuration explicitly sets `UNICORN = {"SERIAL": {"ENABLED": True}}`. This encourages developers to enable this insecure feature by default if they are using the example project as a starting point.
  4. In `django_unicorn/cacher.py`, methods such as `restore_from_cache()` retrieve pickled data from the cache and call `pickle.loads()` directly without safe deserialization or validation.
  5. Since the cache key format is predictable (e.g. starting with `"unicorn:component:"` or  `unicorn:queue:`), an attacker able to inject data into the cache can store a malicious pickle blob that will later be loaded and executed.
  6. Within the caching logic (in modules such as `django_unicorn/views/__init__.py` and the caching helper classes), the component request is “cleaned” by removing non‑pickleable parts (such as the HttpRequest object) and then the remaining state is serialized (pickled) and stored under a key derived from the component ID.
  7. Later, when a queued or dynamic component request is processed, the application retrieves the pickled payload from the cache.
  8. The payload is deserialized using `pickle.loads` with no verification of the payload’s origin, enabling an attacker who has poisoned the cache to trigger arbitrary code execution.
  9. This behavior is confirmed by tests (e.g., those found in `tests/test_cacher.py`), which exercise the caching and restoration lifecycle. An attacker with cache write access could inject a malicious payload to execute arbitrary code.

- **Security Test Case:**
  1. Modify `example\project\settings.py` to ensure `UNICORN = {"SERIAL": {"ENABLED": True}}` and `CACHES` is configured to use a cache backend other than `DummyCache` (e.g., `locmem` is sufficient for local testing).
  ```python
  CACHES = {
      "default": {
          "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
          "LOCATION": "unique-snowflake",
      }
  }
  UNICORN = {
      "SERIAL": {
          "ENABLED": True,
          "TIMEOUT": 5,
      },
      ...
  }
  ```
  2. Create a simple django-unicorn component, e.g., `CacheTestComponent`.
  3. In Python, craft a malicious pickle payload. This payload should execute a simple command like `os.system('touch /tmp/unicorn_pwned')` when deserialized. You can use `pickle` module directly to create this payload.
  ```python
  import pickle
  import os
  import base64

  class MaliciousPayload(object):
      def __reduce__(self):
          return (os.system, ('touch /tmp/unicorn_pwned',))

  payload = base64.b64encode(pickle.dumps(MaliciousPayload())).decode()
  print(payload)
  ```
  4. Identify the cache key used by django-unicorn for component caching. It is likely based on `component.component_cache_key` which is set to `f"unicorn:component:{self.component_id}"` in `UnicornView` or `unicorn:queue:{component_id}`.
  5. Manually insert this malicious pickle payload into the cache using the identified key. For `locmem` cache, you can access the cache dictionary directly (though this might require inspecting Django internals or using a debugger). For `redis`, use `redis-cli` and `SET <cache_key> "<payload>"`. For other caches, use appropriate tools to inject the base64 encoded payload.
  6. Render or interact with the `CacheTestComponent` in the application to trigger component retrieval from the cache. This should cause deserialization of the malicious payload when django-unicorn` attempts to restore the component from the cache.
  7. Check if the command in the malicious payload is executed on the server. For example, check if the `/tmp/unicorn_pwned` file is created.
  8. If the file is created, the insecure deserialization vulnerability is confirmed.
  9. **Set Up:**
       - Configure the Django project to use an external cache backend (e.g., a Redis or Memcached instance) that is not secured by proper authentication or network restrictions.
       - Ensure that the caching mechanism is active (the cache alias in settings points to the insecure cache and caching is enabled for components).
    10. **Inject a Malicious Payload:**
       - Identify a valid component ID by first triggering a component render, which caches state under a key like `unicorn:queue:{component_id}`.
       - Using a tool that can interact directly with the cache backend (for example, redis-cli or a Memcached client), replace the corresponding cache key with a malicious pickle payload. For safe testing, craft a payload that causes a benign side effect (for instance, writing to a log file).
    11. **Trigger Deserialization:**
       - In a browser or via an HTTP client, perform an action that causes the cached component to be restored (such as an AJAX POST to the unicorn “message” endpoint).
       - Monitor the server to observe the effects of the malicious payload (e.g., log file creation or other side effects).
    12. **Verify Outcome:**
       - If the payload executes upon deserialization (demonstrated by the benign side effect), the vulnerability is confirmed. Document the behavior to validate that arbitrary code execution through cache poisoning is possible.


### Remote Code Execution and Arbitrary Method Invocation via Insecure Method Parsing

- **Vulnerability Name:** Potential Argument Injection in Server-Side Method Calls via `Unicorn.call()` / Arbitrary Public Method Invocation via callMethod Endpoint / Remote Code Execution via insecure method argument parsing
- **Description:**
  1. The `Unicorn.call()` JavaScript function allows client-side JavaScript to trigger server-side methods in a django-unicorn component, passing arguments.
  2. Arguments passed from the client are parsed and used to invoke server-side methods.
  3. When processing an action of type “callMethod,” the framework extracts a method name from the user‑supplied payload and then invokes it on the component instance. In the absence of an explicit whitelist or annotation limiting which methods may be called externally, any public method (i.e. any method not prefixed with an underscore) becomes callable by an attacker. This may allow a malicious user to trigger methods that are meant only for internal use or that perform sensitive operations.
  4. While `ast.literal_eval` is used for parsing arguments in some contexts, and `ast.parse` is used to parse method name, they primarily prevent code execution during the parsing stage but do not sanitize the *values* of the arguments themselves or the method name itself when `ast.parse` is used.
  5. The `django-unicorn` backend in `django_unicorn.views.message` view extracts the `method` value from the `actionQueue`. This `method` string is passed to the `parse_call_method_name` function in `django_unicorn.call_method_parser`, which uses `ast.parse` to parse the string as Python code in "eval" mode.
  6. If server-side methods called via `Unicorn.call()` do not perform sufficient validation and sanitization of the arguments, or method name itself, it could lead to argument injection vulnerabilities or remote code execution. Attackers might manipulate arguments or method names to bypass logic, cause unintended actions, or potentially exploit other vulnerabilities depending on how the arguments are processed server-side or by injecting arbitrary code via method name parsing.
  7. Because the `method_name` is derived from user-controlled input without sufficient validation, an attacker can inject arbitrary Python code, leading to Remote Code Execution (RCE) on the server when `getattr` and the subsequent method call are executed.

- **Impact:**
  - The impact severity is critical.
  - Complete server compromise.
  - Unauthorized access to sensitive data.
  - Modification or deletion of data.
  - Denial of Service.
  - Any other malicious actions that can be performed by executing arbitrary code on the server.
  - If an attacker discovers and calls a method with unintended side‑effects (for example, one that modifies component state, exposes internal data, or otherwise triggers critical operations), unauthorized state changes or information disclosure may occur. In worst‑case scenarios, if the method subsequently calls unsafe code, this might escalate to arbitrary code execution.
  - Potential impacts include:
    - Logic bypass: Altering program flow by injecting unexpected argument values.
    - Data manipulation: Modifying data in unintended ways based on injected arguments.
    - Unauthorized access: Gaining access to resources or functionalities not intended for the user.
    - Potential for further exploitation: Injected arguments might be used in insecure operations within the server-side method, potentially leading to more severe vulnerabilities like SQL injection (less likely due to Django ORM but possible if raw SQL queries are used) or command injection if arguments are passed to system commands.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  - **`django_unicorn\call_method_parser.py`**: Uses `ast.literal_eval` to parse arguments and `ast.parse` to parse method name. `ast.literal_eval` provides some protection against direct code execution during argument parsing itself, as `literal_eval` only evaluates valid Python literals.
  - **`django_unicorn\typer.py`**: Type coercion is performed based on type hints defined in the component's Python code. This might limit the type of arguments accepted by server-side methods, but it's not a comprehensive sanitization mechanism.
  - **`django_unicorn\views\action_parsers\call_method.py`**: In `_call_method_name`, arguments are cast to their type-hinted types using `cast_value`. This provides basic type enforcement, but it doesn't validate the *content* or *range* of the values.
  - Internal helper functions (e.g. `_is_public()`) exist to help distinguish public from non‑public members, and special action names prefixed with `$` (like `$reset` or `$refresh`) are handled separately by the framework.
  - The framework checks for the existence of an attribute before updating it; however, no filtering prevents updates to attributes with reserved or “private” names.
  - **`django_unicorn\tests\call_method_parser\test_parse_args.py`**, **`django_unicorn\tests\call_method_parser\test_parse_call_method_name.py`**, **`django_unicorn\tests\call_method_parser\test_parse_kwarg.py`**: These test files show different parsing scenarios, including various argument types (strings, ints, dicts, lists, datetimes, UUIDs, floats, sets) and keyword arguments. They implicitly validate that the parsing logic works as expected, but do not explicitly test for security vulnerabilities or injection attempts.

- **Missing Mitigations:**
  - **Lack of Input Validation**: There is no explicit, systematic input validation or sanitization of arguments passed through `Unicorn.call()` beyond the basic type coercion. Server-side methods are expected to handle validation themselves. Crucially, there is no validation of the method name itself when parsed with `ast.parse`, leading to RCE.
  - **Documentation Gap**: While type hints offer some level of type safety for arguments parsed with `ast.literal_eval`, the documentation (`actions.md#calling-methods`) does not sufficiently emphasize the critical importance of server-side validation and sanitization of arguments received from `Unicorn.call()`. Developers might incorrectly assume that `ast.literal_eval` and type coercion are sufficient security measures. The documentation does not address the RCE risk from `ast.parse` used for method name parsing.
  - **Potential for Logic Bugs**: Even with type coercion, if server-side logic depends on specific formats, ranges, or sets of allowed values for arguments, and this is not explicitly validated server-side, argument injection can lead to logic errors and potentially security breaches.
  - There is no enforced whitelist or an annotation mechanism restricting which component methods may be invoked via the remote “callMethod” action.
  - The framework does not explicitly verify that the provided method name is intended for remote invocation (for example, by checking against sensitive or reserved names), except for checking if method exists using `hasattr`.
  - Implement robust input validation and sanitization for the `method` parameter in the `django_unicorn.views.message` view.
  - Restrict the allowed characters and format for method names to a safe whitelist.
  - Avoid using `ast.parse` and `eval` on user-provided input for method calls. Consider using a safer approach, such as a predefined mapping of allowed method names to their corresponding functions, or implement a secure parsing mechanism that strictly limits the allowed syntax.

- **Preconditions:**
  - The application must be using `Unicorn.call()` in JavaScript to invoke server-side methods.
  - Server-side methods called via `Unicorn.call()` must process the arguments received from the client without proper validation and sanitization specific to the method's logic and security requirements.
  - The vulnerability risk increases if the server-side methods perform sensitive operations, such as data modification, access control decisions, or interactions with external systems, based on the injected arguments.
  - An attacker must be able to send POST requests to the public message endpoint (e.g. `/message/<component_name>` or `/unicorn/message`).
  - The attacker must know or be able to guess the names of public methods defined on a component.
  - A publicly accessible Django application using `django-unicorn` is required.
  - The attacker must be able to send POST requests to the `/unicorn/message` endpoint.

- **Source Code Analysis:**
  1. **`django_unicorn\call_method_parser.py`**: Analyzed in previous vulnerability description. `ast.literal_eval` is used for arguments, and `ast.parse` for method name, which is safer than `eval` for arguments but not a complete sanitization solution and dangerous for method name parsing.
  ```python
  @lru_cache(maxsize=128, typed=True)
  def parse_call_method_name(
      call_method_name: str,
  ) -> Tuple[str, Tuple[Any, ...], Mapping[str, Any]]:
      ...
      tree = ast.parse(method_name, "eval") # Insecure parsing of method name
      statement = tree.body[0].value #type: ignore

      if tree.body and isinstance(statement, ast.Call):
          call = tree.body[0].value # type: ignore
          method_name = call.func.id
          args = [eval_value(arg) for arg in call.args]
          kwargs = {kw.arg: eval_value(kw.value) for kw in call.keywords}
      ...
      return method_name, tuple(args), MappingProxyType(kwargs)
  ```
  2. **`django_unicorn\views\action_parsers\call_method.py`**: In `_call_method_name`, arguments from `Unicorn.call()` are passed to the server-side method.  The code attempts to cast arguments based on type hints:
  ```python
                  parsed_args.append(cast_value(type_hint, args[len(parsed_args)]))
  ```
  While `cast_value` in `django_unicorn\typer.py` performs type conversions, it does not include validation of the *content* of the arguments. For example, casting a string to an integer doesn't prevent an attacker from providing a valid integer that is outside the expected range or has other malicious properties in the context of the server-side method's logic.
  3. **`django_unicorn\views\__init__.py`**: The `message` view receives and processes the `callMethod` action. It calls `call_method.handle` which in turn calls `_call_method_name` to execute the server-side method. The argument parsing and casting happen within `_call_method_name` as described above.
  4. In `django_unicorn/views/action_parsers/call_method.py`, the function `handle()` extracts the method name from the JSON payload and passes it to `_call_method_name()`.
  5. The helper `_call_method_name()` checks that the component has an attribute matching the specified method name but does not filter out methods that should not be externally exposed, and uses insecure parsing for method name.
  6. As the method is subsequently invoked via `getattr(component, method_name)` (after any arguments are parsed), an attacker can supply any public method name, or inject code via method name itself.
  7. **`example\unicorn\components\js.py`**: Example component `JsView` shows usage of `Unicorn.call()`.  The `call_javascript` and `call_javascript_module` methods use `Unicorn.call("callAlert", "world")` and `Unicorn.call("HelloJs.hello", "world!")`. While these examples themselves are harmless, they demonstrate how arguments are passed from client to server, highlighting the need for server-side validation in real-world applications.
  8. **`django_unicorn\tests\call_method_parser\test_parse_args.py`**, **`django_unicorn\tests\call_method_parser\test_parse_call_method_name.py`**, **`django_unicorn\tests\call_method_parser\test_parse_kwarg.py`**: Review of these test files confirms that the focus is on correct parsing of various argument types and call method names. There is no indication of tests designed to detect or prevent argument injection or RCE via method name. These tests primarily ensure functionality, not security against malicious inputs.
  9. File: `django_unicorn\views.py`
    ```python
    def message(request, component_name=None):
        ...
        action_queue = json.loads(request.body.decode("utf-8"))
        ...
        for action in action_queue:
            ...
            if "method" in action["payload"]:
                call_method_name = action["payload"]["method"]
                ...
                component.call_method(
                    call_method_name, action["payload"].get("args"), action["payload"].get("kwargs")
                )
            ...
    ```
    The `message` view receives the request, decodes the JSON body and iterates through `action_queue`. If the action `payload` contains a `method`, it extracts the `call_method_name` and calls `component.call_method`.

    10. File: `django_unicorn\components\unicorn_view.py`
    ```python
    class UnicornView(TemplateResponseMixin, View):
        ...
        def call_method(self, call_method_name, args, kwargs):
            ...
            method_name, method_args, method_kwargs = parse_call_method_name(call_method_name)

            if not hasattr(self, method_name):
                raise AttributeError(f"Component '{self.component_name}' does not have method '{method_name}'")

            if args is None:
                args = []

            if kwargs is None:
                kwargs = {}

            with patch_request_context(self, parent_context):
                return_value = getattr(self, method_name)(*method_args, **method_kwargs) # Vulnerable line
            ...
    ```
    The `call_method` function calls `parse_call_method_name` to parse the `call_method_name`. Then, it uses `getattr(self, method_name)` to retrieve the method from the component instance and execute it. This is where the RCE vulnerability exists because `method_name` is not validated and comes from user input.

- **Security Test Case:**
  1. Create a django-unicorn component named `ArgumentInjectionComponent`.
  2. In `ArgumentInjectionComponent`, define a server-side method `greet(self, name)` that is intended to greet a user by name. Assume this method internally uses the `name` argument in a potentially vulnerable way (e.g., constructing a message that is displayed to the user without proper output encoding, though for argument injection test, the focus is on manipulating the *argument* itself). For simplicity, let's just print the name to server logs and return a greeting string.
  ```python
  import logging
  from django_unicorn.components import UnicornView

  logger = logging.getLogger(__name__)

  class ArgumentInjectionView(UnicornView):
      message = ""

      def greet(self, name):
          logger.info(f"Greet method called with name: {name}") # Simulate server-side processing with argument
          self.message = f"Hello, {name}!"
          return self.message
  ```
  3. In the component's template (`unicorn/argument-injection.html`), create a button that calls the `greet` method using `Unicorn.call()` and passes a `username` from an input field as an argument.
  ```html
  <div>
      <p id="greeting-target">{{ message }}</p>
      <input unicorn:model.debounce="username_input" type="text">
      <button unicorn:click="greet(username_input)">Greet</button>
  </div>
  ```
  4. Create a Django view to render the `ArgumentInjectionComponent`.
  5. As an attacker, navigate to the page containing `ArgumentInjectionComponent`.
  6. In the input field, enter a seemingly normal username, e.g., `Alice`. Click the "Greet" button. Verify that the server logs show "Greet method called with name: Alice" and the component displays "Hello, Alice!".
  7. Now, try to inject a potentially malicious argument. Instead of a name, enter something like `'; malicious_command(); '`. Click "Greet".
  8. Observe the server-side behavior. In this simplified example, check the server logs. If argument injection is possible and the `greet` method naively processes the injected argument, you might see unexpected output or errors in the logs, or the application might behave in an unintended way.  In a real-world scenario, the `greet` method might be doing something more sensitive with the `name` argument, like a database query or system command, and argument injection could then be exploited to cause more serious damage. In this test case, simply verifying that the server logs reflect the injected argument is sufficient to demonstrate the *potential* for argument injection, even if the `greet` method itself is not immediately exploitable for RCE or similar.
  9. To further refine the test, if the `greet` method was interacting with a database, you could try SQL injection payloads as arguments. If it was interacting with the OS, try command injection payloads. The key is to test how the server-side method handles and processes the arguments it receives from `Unicorn.call()`.
  10. Set up a Django Unicorn application in DEBUG mode.
  11. Create a simple component that does not require any specific methods, for example, a component with just a name property.
  12. Open the application in a browser and inspect the network requests when any action is triggered (e.g., clicking a button that calls a component method or updates a model). Identify the POST request to `/unicorn/message` or `/message/<component_name>`.
  13. Craft a malicious POST request to `/unicorn/message` endpoint. The request body should be JSON and mimic a valid Unicorn message request but with a malicious `method` payload.
  14. Example malicious payload:
    ```json
    [
      {
        "actionType": "callMethod",
        "payload": {
          "name": "test-component",
          "id": "...",
          "key": null,
          "method": "__import__('os').system('whoami > /tmp/unicorn_rce.txt')",
          "args": [],
          "kwargs": {}
        }
      }
    ]
    ```
    Replace `"test-component"` and `"id": "..."` with the actual component name and ID from your application. The malicious code here is `__import__('os').system('whoami > /tmp/unicorn_rce.txt')`, which attempts to execute the `whoami` command and write the output to `/tmp/unicorn_rce.txt` on the server. You can use other commands for testing purposes, be cautious with destructive commands.
  15. Send this crafted POST request to the `/unicorn/message` endpoint, for example, using `curl` or Burp Suite. Make sure to include the CSRF token in the headers if CSRF protection is enabled.
  16. Check if the command was executed on the server. In this example, check if the file `/tmp/unicorn_rce.txt` was created and contains the output of the `whoami` command. If the file is created and contains the output, the RCE vulnerability is confirmed.
  17. Observe any server-side errors or logs to further confirm code execution. In DEBUG mode, detailed error information might be displayed in the browser or server console.
  18. Identify a component that defines at least one public method not intended for external use (for example, one that changes internal state or reveals secrets).
  19. From an external host, craft a POST request to the message endpoint (e.g. `/message/FakeComponent`) with a JSON payload in the actionQueue containing:
     - `"type": "callMethod"`
     - `"payload": {"name": "<sensitive_method>"}`
  20. Observe that the unintended method is invoked by inspecting changes to component data, system state, or application logs.

### Arbitrary Attribute Modification via Nested Property Injection

- **Vulnerability Name:** Arbitrary Attribute Modification via Nested Property Injection
- **Description:**
  1. The framework’s mechanism for updating component properties (using “syncInput” actions) calls functions such as `set_property_from_data()` and, deeper in the call stack, `set_property_value()`.
  2. These functions split client‑supplied property names using the dot character (thereby allowing updates to nested properties) and then call Python’s built‑in `setattr()` to update attributes on component objects.

- **Impact:**
  - Because no filtering or whitelisting is applied to attribute names, an attacker can supply a property name that targets an internal attribute (for instance, one with a leading underscore or special names such as `__class__`).
  - Changing such internal attributes can compromise component integrity, expose sensitive data, or—even in extreme cases—lead to arbitrary code execution.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  - The framework checks for the existence of an attribute before updating it; however, no filtering prevents updates to attributes with reserved or “private” names.

- **Missing Mitigations:**
  - There is no whitelist or safe‑list enforced in the property update logic to exclude dangerous attribute names (for example, those beginning with an underscore or dunder names like `__class__`).
  - The code does not validate that the property name provided is “safe” to update.

- **Preconditions:**
  - An attacker must be able to send POST requests to the public message endpoint with a crafted payload.
  - The component must have writable internal attributes (which all Python objects have by default) that can be updated via `setattr()` if the provided property name matches.

- **Source Code Analysis:**
  1. In `django_unicorn/views/action_parsers/utils.py`, the function `set_property_value()` splits the property name (with `property_name.split(".")`) and then iteratively checks for attribute existence with `hasattr()` before eventually calling `setattr()`.
  2. No check is performed to ensure that the property name is not sensitive (e.g. `__class__` or names beginning with `_`).

- **Security Test Case:**
  1. Deploy the Unicorn‑powered application with the public message endpoint enabled.
  2. Craft a JSON payload for a “syncInput” action where the payload’s `"name"` field is set to a dangerous attribute name (for example, `"__class__"` or `"some_internal.__class__"`).
  3. Send a POST request to the message endpoint (for example, `/message/FakeComponent`) with the malicious payload.
  4. Verify—by inspecting the component instance on the server or its subsequent responses—that the targeted attribute has been modified, confirming that the vulnerability is exploitable.


### Weak Checksum Validation in Message Endpoint

- **Vulnerability Name:** Weak Checksum Validation in Message Endpoint
- **Description:**
  1. The framework requires every message POSTed to the endpoint to include a checksum generated by the function `generate_checksum(str(data))`.
  2. This checksum is used to validate the integrity of the incoming payload.
  3. However, because the checksum is computed solely over the string representation of client‑supplied data—and no secret key or unpredictable salt is employed—an attacker who understands (or reverse‑engineers) the algorithm can easily generate a valid checksum for an arbitrary payload.

- **Impact:**
  - By forging a valid checksum, an attacker may be able to bypass integrity checks and submit manipulated payloads.
  - This could allow unauthorized invocation of component methods or modification of component state (in conjunction with the already present arbitrary invocation and attribute modification issues), potentially leading to remote code execution or systemic compromise.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**
  - The message processing code verifies that a checksum is present and that it matches the output of `generate_checksum(str(data))`.

- **Missing Mitigations:**
  - The checksum mechanism does not include a server‑side secret (for example, via an HMAC) to prevent attackers from reproducing it.
  - There is no additional entropy (e.g. nonce or timestamp validation beyond what is already in the message) to mitigate replay or tampering risks.

- **Preconditions:**
  - The attacker must be familiar with (or able to deduce) that the checksum is generated by simply converting the `data` object to a string and hashing it (with a known algorithm).
  - The attacker must be able to intercept or observe valid requests (or review the open‑source code) to learn the input format.

- **Source Code Analysis:**
  1. In multiple test files (for example, in `tests/views/message/utils.py` and others), messages are constructed by calling `generate_checksum(str(data))` without any secret key.
  2. Since the algorithm is entirely deterministic and based solely on the client‑supplied data, any attacker can recompute the checksum after manipulating the payload.

- **Security Test Case:**
  1. Capture or examine a valid message payload (for example, by reviewing the open‑source code or intercepting a sample request).
  2. Modify the payload data (for example, change a component’s state or the method invocation in an action entry).
  3. Recompute the checksum using the same method (`generate_checksum(str(modified_data))`) outside the application.
  4. Send the forged POST request to the public message endpoint with the modified payload and the recomputed checksum.
  5. Verify that the server processes the modified payload (for example, by checking that the component state reflects the modifications).


### Sensitive Information Disclosure via Component Load Error Messages

- **Vulnerability Name:** Sensitive Information Disclosure via Component Load Error Messages
- **Description:**
  1. When a client sends a message with an invalid component identifier or requests a component that cannot be loaded, the framework raises exceptions such as `ComponentModuleLoadError` or `ComponentClassLoadError`.
  2. These error messages include detailed internal information—such as attempted module paths and attribute names—that can reveal aspects of the application’s internal structure and file layout.
  3. An attacker can use this information to map out the modules, determine naming conventions, and discover potentially sensitive component details.

- **Impact:**
  - Exposure of internal module search paths and component class names can assist an attacker in reconnaissance efforts.
  - By learning the internal structure and naming conventions of the application, an attacker can better target subsequent attacks (for example, by identifying vulnerable components for method invocation or attribute modification).

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  - The framework returns error messages when component modules or classes cannot be loaded.
  - In a controlled testing environment, these errors are observable, but production deployments are expected to have additional error handling configurations.

- **Missing Mitigations:**
  - In production, detailed error messages should be suppressed or replaced with generic messages that do not reveal internal paths or attribute names.
  - Use of a custom error handler or proper configuration (for example, ensuring DEBUG is disabled) is missing to prevent leakage of sensitive information.

- **Preconditions:**
  - The application is running in a configuration that exposes detailed exception information (for example, DEBUG mode enabled or insufficient error handling middleware).
  - An attacker can send requests with invalid or non‑existent component names to the public message endpoint.

- **Source Code Analysis:**
  1. The tests `test_message_component_module_not_loaded` and `test_message_component_class_not_loaded` demonstrate that error messages include explicit mentions of module search paths (for example, `"unicorn.components.test_message_module_not_loaded"`) and attribute lookup failures (for example, `module 'tests.views.fake_components' has no attribute 'FakeComponentNotThere'`).
  2. These exception messages are raised directly by the component loading mechanisms without sanitizing internal details.

- **Security Test Case:**
  1. Send a POST request to the message endpoint with an invalid component name (for example, `/message/nonexistent_component` or `/message/test-with-dash`).
  2. Capture the error response and inspect it for details such as internal module paths, component class names, or attribute errors.
  3. Confirm that the error message discloses information that could help an attacker map out the internal structure of the application.