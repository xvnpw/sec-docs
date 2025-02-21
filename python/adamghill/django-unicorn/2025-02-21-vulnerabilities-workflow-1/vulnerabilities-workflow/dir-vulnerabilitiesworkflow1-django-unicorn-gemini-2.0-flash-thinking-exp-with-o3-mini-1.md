### Vulnerability List:

- Vulnerability Name: Cross-Site Scripting (XSS) via Insecure HTML Handling in Templates

- Description:
  1. An attacker can inject malicious JavaScript code into a component's property that is rendered in a template without proper sanitization.
  2. When this component is rendered and served to a user's browser, the injected JavaScript code will be executed.
  3. This can be achieved if a component's property, used in the template, is updated via user input or any other external source without proper HTML escaping by django-unicorn.
  4. The vulnerability is exacerbated if the developer uses `safe` meta attribute or `|safe` template filter incorrectly, intending to allow safe HTML but inadvertently allowing malicious scripts.

- Impact:
  - An attacker can execute arbitrary JavaScript code in the victim's browser when they view the page containing the vulnerable component.
  - This can lead to session hijacking, cookie theft, defacement of the website, or redirection to malicious sites.
  - In a broader context, it can compromise the user's account and potentially the entire application if sensitive actions can be performed via JavaScript.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - According to `changelog.md` version 0.36.0, a security fix for CVE-2021-42053 was implemented to prevent XSS attacks.
  - The changelog states that responses are HTML encoded going forward, and developers need to explicitly use `safe` to opt-in to the previous behavior. This suggests default encoding is now in place.
  - `django_unicorn\utils.py` contains `sanitize_html` function which uses `html.escape` internally to escape HTML/XML special characters.
  - `django_unicorn\components\unicorn_template_response.py` in `UnicornTemplateResponse.render` method calls `sanitize_html(init)` to sanitize the component initialization data that is passed to frontend via JSON.
  - `django_unicorn\tests\views\test_process_component_request.py` contains `test_html_entities_encoded` which asserts that HTML entities are encoded by default.
  - `django_unicorn\tests\views\test_process_component_request.py` contains `test_safe_html_entities_not_encoded` which asserts that `safe` meta attribute prevents HTML entities encoding.

- Missing Mitigations:
  - While default encoding and `sanitize_html` are present, it's crucial to verify that all output paths in django-unicorn templates and javascript interactions are consistently and correctly encoded by default, unless explicitly marked as `safe`.
  - Need to confirm if `safe` usage is properly documented with clear warnings about its risks and when it's genuinely necessary.
  - Further investigation is needed to ensure no bypasses exist and that encoding is consistently applied across all relevant features (e.g., model updates, action responses, template rendering of component properties).
  - The current analysis of `UnicornTemplateResponse.render` shows sanitization of `init` data, but it is not explicitly clear if component properties rendered in the template (using `{{ component.property }}`) are also automatically escaped by django template engine when updated via AJAX.

- Preconditions:
  - The application must be using `django-unicorn` and rendering user-controlled data or data from external sources into templates via unicorn components.
  - No explicit and correct usage of Django's `escape` filter or similar sanitization techniques by the developer when rendering user-provided data within unicorn components, assuming django-unicorn's default encoding might be insufficient or bypassed.

- Source Code Analysis:
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

- Security Test Case:
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

- Vulnerability Name: Insecure Deserialization in Component Caching

- Description:
  1. Django-unicorn implements component caching to potentially improve performance, especially for queued requests.
  2. The caching mechanism, when enabled (`settings.UNICORN['SERIAL']['ENABLED'] = True`), uses Python's `pickle` serialization which is inherently vulnerable to insecure deserialization.
  3. An attacker could craft a malicious serialized payload and inject it into the cache.
  4. When the application retrieves and deserializes this malicious payload, it could lead to arbitrary code execution on the server.

- Impact:
  - Remote Code Execution (RCE) on the server.
  - Full compromise of the application and potentially the server infrastructure.
  - Data breach and loss of confidentiality, integrity, and availability.

- Vulnerability Rank: Critical

- Currently Implemented Mitigations:
  - The documentation (`queue-requests.md`, `settings.md`) mentions that serialization for request queuing is experimental and disabled by default.
  - It also notes that the feature is automatically disabled if the cache backend is set to `DummyCache`.
  - `cacher.py` confirms the usage of `pickle` for serialization and deserialization of component state.
  - `project\settings.py` in the example project has `UNICORN = {"SERIAL": {"ENABLED": True}}`. This indicates that while disabled by default, the example project itself enables this potentially insecure feature, increasing the risk for developers who might use the example project as a template.

- Missing Mitigations:
  - As `pickle` is used for serialization, there are no effective mitigations against insecure deserialization vulnerabilities when `SERIAL.ENABLED` is True.
  - The documentation should be updated to strongly and prominently warn against enabling the serialization feature in production due to critical security risks associated with `pickle`. The current warning might be insufficient given the severity.
  - Replacing `pickle` with a safer serialization format like `json` or `dill.settings['settings']["byref"] = True` is essential if serialization is to be offered as a feature. However, even safer serializers need careful consideration and might not eliminate all risks from maliciously crafted payloads. `dill` was mentioned in previous analysis, but `json` would be safer and likely sufficient for component state serialization as it does not allow code execution.
  - Input validation on cached data before deserialization is highly complex and impractical to implement effectively against determined attackers exploiting insecure deserialization.

- Preconditions:
  - The `UNICORN['SERIAL']['ENABLED']` setting must be explicitly set to `True` in Django settings.
  - A cache backend other than `DummyCache` must be configured and in use (e.g., `locmem`, `redis`, `memcached`, `database`).
  - An attacker needs to find a way to inject a malicious payload into the cache. This could be through exploiting other vulnerabilities that allow cache manipulation, or if the cache is exposed or misconfigured.

- Source Code Analysis:
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

- Security Test Case:
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
  4. Identify the cache key used by django-unicorn for component caching. It is likely based on `component.component_cache_key` which is set to `f"unicorn:component:{self.component_id}"` in `UnicornView`.
  5. Manually insert this malicious pickle payload into the cache using the identified key. For `locmem` cache, you can access the cache dictionary directly (though this might require inspecting Django internals or using a debugger). For `redis`, use `redis-cli` and `SET <cache_key> "<payload>"`. For other caches, use appropriate tools to inject the base64 encoded payload.
  6. Render or interact with the `CacheTestComponent` in the application to trigger component retrieval from the cache. This should cause deserialization of the malicious payload when django-unicorn` attempts to restore the component from the cache.
  7. Check if the command in the malicious payload is executed on the server. For example, check if the `/tmp/unicorn_pwned` file is created.
  8. If the file is created, the insecure deserialization vulnerability is confirmed.

- Vulnerability Name: Potential Argument Injection in Server-Side Method Calls via `Unicorn.call()`

- Description:
  1. The `Unicorn.call()` JavaScript function allows client-side JavaScript to trigger server-side methods in a django-unicorn component, passing arguments.
  2. Arguments passed from the client are parsed and used to invoke server-side methods.
  3. While `ast.literal_eval` is used for parsing, it primarily prevents code execution during the parsing stage but does not sanitize the *values* of the arguments themselves.
  4. If server-side methods called via `Unicorn.call()` do not perform sufficient validation and sanitization of the arguments, it could lead to argument injection vulnerabilities. Attackers might manipulate arguments to bypass logic, cause unintended actions, or potentially exploit other vulnerabilities depending on how the arguments are processed server-side.

- Impact:
  - The impact severity is medium to high, depending on the specific server-side methods that are vulnerable and the actions they perform.
  - Potential impacts include:
    - Logic bypass: Altering program flow by injecting unexpected argument values.
    - Data manipulation: Modifying data in unintended ways based on injected arguments.
    - Unauthorized access: Gaining access to resources or functionalities not intended for the user.
    - Potential for further exploitation: Injected arguments might be used in insecure operations within the server-side method, potentially leading to more severe vulnerabilities like SQL injection (less likely due to Django ORM but possible if raw SQL queries are used) or command injection if arguments are passed to system commands.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
  - **`django_unicorn\call_method_parser.py`**: Uses `ast.literal_eval` to parse arguments. This provides some protection against direct code execution during argument parsing itself, as `literal_eval` only evaluates valid Python literals.
  - **`django_unicorn\typer.py`**: Type coercion is performed based on type hints defined in the component's Python code. This might limit the type of arguments accepted by server-side methods, but it's not a comprehensive sanitization mechanism.
  - **`django_unicorn\views\action_parsers\call_method.py`**: In `_call_method_name`, arguments are cast to their type-hinted types using `cast_value`. This provides basic type enforcement, but it doesn't validate the *content* or *range* of the values.
  - **`django_unicorn\tests\call_method_parser\test_parse_args.py`**, **`django_unicorn\tests\call_method_parser\test_parse_call_method_name.py`**, **`django_unicorn\tests\call_method_parser\test_parse_kwarg.py`**: These test files show different parsing scenarios, including various argument types (strings, ints, dicts, lists, datetimes, UUIDs, floats, sets) and keyword arguments. They implicitly validate that the parsing logic works as expected, but do not explicitly test for security vulnerabilities or injection attempts.

- Missing Mitigations:
  - **Lack of Input Validation**: There is no explicit, systematic input validation or sanitization of arguments passed through `Unicorn.call()` beyond the basic type coercion. Server-side methods are expected to handle validation themselves.
  - **Documentation Gap**: While type hints offer some level of type safety, the documentation (`actions.md#calling-methods`) does not sufficiently emphasize the critical importance of server-side validation and sanitization of arguments received from `Unicorn.call()`. Developers might incorrectly assume that `ast.literal_eval` and type coercion are sufficient security measures.
  - **Potential for Logic Bugs**: Even with type coercion, if server-side logic depends on specific formats, ranges, or sets of allowed values for arguments, and this is not explicitly validated server-side, argument injection can lead to logic errors and potentially security breaches.

- Preconditions:
  - The application must be using `Unicorn.call()` in JavaScript to invoke server-side methods.
  - Server-side methods called via `Unicorn.call()` must process the arguments received from the client without proper validation and sanitization specific to the method's logic and security requirements.
  - The vulnerability risk increases if the server-side methods perform sensitive operations, such as data modification, access control decisions, or interactions with external systems, based on the injected arguments.

- Source Code Analysis:
  1. **`django_unicorn\call_method_parser.py`**: Analyzed in previous vulnerability description. `ast.literal_eval` is used, which is safer than `eval` but not a complete sanitization solution.
  2. **`django_unicorn\views\action_parsers\call_method.py`**: In `_call_method_name`, arguments from `Unicorn.call()` are passed to the server-side method.  The code attempts to cast arguments based on type hints:
  ```python
                  parsed_args.append(cast_value(type_hint, args[len(parsed_args)]))
  ```
  While `cast_value` in `django_unicorn\typer.py` performs type conversions, it does not include validation of the *content* of the arguments. For example, casting a string to an integer doesn't prevent an attacker from providing a valid integer that is outside the expected range or has other malicious properties in the context of the server-side method's logic.
  3. **`django_unicorn\views\__init__.py`**: The `message` view receives and processes the `callMethod` action. It calls `call_method.handle` which in turn calls `_call_method_name` to execute the server-side method. The argument parsing and casting happen within `_call_method_name` as described above.
  4. **`example\unicorn\components\js.py`**: Example component `JsView` shows usage of `Unicorn.call()`.  The `call_javascript` and `call_javascript_module` methods use `Unicorn.call("callAlert", "world")` and `Unicorn.call("HelloJs.hello", "world!")`. While these examples themselves are harmless, they demonstrate how arguments are passed from client to server, highlighting the need for server-side validation in real-world applications.
  5. **`django_unicorn\tests\call_method_parser\test_parse_args.py`**, **`django_unicorn\tests\call_method_parser\test_parse_call_method_name.py`**, **`django_unicorn\tests\call_method_parser\test_parse_kwarg.py`**: Review of these test files confirms that the focus is on correct parsing of various argument types and call method names. There is no indication of tests designed to detect or prevent argument injection. These tests primarily ensure functionality, not security against malicious inputs.

- Security Test Case:
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