- Vulnerability name: Remote Code Execution via insecure method argument parsing
- Description:
    1. An attacker can send a crafted POST request to the `/unicorn/message` endpoint.
    2. In the request payload, the attacker manipulates the `actionQueue` parameter, specifically the `payload.method` value.
    3. The `django-unicorn` backend in `django_unicorn.views.message` view extracts the `method` value from the `actionQueue`.
    4. This `method` string is passed to the `parse_call_method_name` function in `django_unicorn.call_method_parser`, which uses `ast.parse` to parse the string as Python code in "eval" mode.
    5. The parsed method name is then used in `getattr(component, method_name)` within the `call_method` function of the `UnicornView` class in `django_unicorn.components.unicorn_view`.
    6. Because the `method_name` is derived from user-controlled input without sufficient validation, an attacker can inject arbitrary Python code, leading to Remote Code Execution (RCE) on the server when `getattr` and the subsequent method call are executed.
- Impact:
    - Complete server compromise.
    - Unauthorized access to sensitive data.
    - Modification or deletion of data.
    - Denial of Service.
    - Any other malicious actions that can be performed by executing arbitrary code on the server.
- Vulnerability rank: Critical
- Currently implemented mitigations:
    - None. The project does not implement any input validation or sanitization for the `method` parameter in the AJAX requests.
- Missing mitigations:
    - Implement robust input validation and sanitization for the `method` parameter in the `django_unicorn.views.message` view.
    - Restrict the allowed characters and format for method names to a safe whitelist.
    - Avoid using `ast.parse` and `eval` on user-provided input for method calls. Consider using a safer approach, such as a predefined mapping of allowed method names to their corresponding functions, or implement a secure parsing mechanism that strictly limits the allowed syntax.
- Preconditions:
    - A publicly accessible Django application using `django-unicorn` is required.
    - The attacker must be able to send POST requests to the `/unicorn/message` endpoint.
- Source code analysis:
    1. File: `django_unicorn\views.py`
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

    2. File: `django_unicorn\components\unicorn_view.py`
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

    3. File: `django_unicorn\call_method_parser.py`
    ```python
    @lru_cache(maxsize=128, typed=True)
    def parse_call_method_name(
        call_method_name: str,
    ) -> Tuple[str, Tuple[Any, ...], Mapping[str, Any]]:
        ...
        tree = ast.parse(method_name, "eval") # Insecure parsing
        statement = tree.body[0].value #type: ignore

        if tree.body and isinstance(statement, ast.Call):
            call = tree.body[0].value # type: ignore
            method_name = call.func.id
            args = [eval_value(arg) for arg in call.args]
            kwargs = {kw.arg: eval_value(kw.value) for kw in call.keywords}
        ...
        return method_name, tuple(args), MappingProxyType(kwargs)
    ```
    The `parse_call_method_name` function uses `ast.parse(method_name, "eval")` which is inherently unsafe when `method_name` is not strictly controlled, as it allows parsing and evaluation of arbitrary Python expressions. The files in `django_unicorn\tests\call_method_parser\` demonstrate various test cases for parsing method names and arguments, further highlighting the functionality and potential attack surface of this insecure parsing mechanism.

- Security test case:
    1. Set up a Django Unicorn application in DEBUG mode.
    2. Create a simple component that does not require any specific methods, for example, a component with just a name property.
    3. Open the application in a browser and inspect the network requests when any action is triggered (e.g., clicking a button that calls a component method or updates a model). Identify the POST request to `/unicorn/message`.
    4. Craft a malicious POST request to `/unicorn/message` endpoint. The request body should be JSON and mimic a valid Unicorn message request but with a malicious `method` payload.
    5. Example malicious payload:
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
    6. Send this crafted POST request to the `/unicorn/message` endpoint, for example, using `curl` or Burp Suite. Make sure to include the CSRF token in the headers if CSRF protection is enabled.
    7. Check if the command was executed on the server. In this example, check if the file `/tmp/unicorn_rce.txt` was created and contains the output of the `whoami` command. If the file is created and contains the output, the RCE vulnerability is confirmed.
    8. Observe any server-side errors or logs to further confirm code execution. In DEBUG mode, detailed error information might be displayed in the browser or server console.

This test case demonstrates how an attacker can execute arbitrary commands on the server by crafting a malicious `method` payload, confirming the Remote Code Execution vulnerability.