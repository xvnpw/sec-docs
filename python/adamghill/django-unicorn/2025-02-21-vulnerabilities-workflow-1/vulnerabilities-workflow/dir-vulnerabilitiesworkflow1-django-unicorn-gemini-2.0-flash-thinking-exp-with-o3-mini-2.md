- **Vulnerability Name:** Insecure Deserialization via Pickle in Component Caching  
  **Description:**  
  The framework caches complete component state using Python’s pickle mechanism. When using an insecure cache backend (such as a misconfigured Redis or memcached instance), an attacker with network access to the cache may inject a malicious pickle payload. When a normal request later restores the component state by unpickling data, the attacker’s payload may execute arbitrary code on the server.  
  **Impact:**  
  Exploitation allows remote code execution on the server. An attacker could steal sensitive data, manipulate system state, or use the compromised server to pivot into backend infrastructure.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  – The framework checks whether serialization is enabled via settings (using `get_serial_enabled`).  
  – Administrators are expected to deploy cache backends (e.g. Redis, memcached) in a secured and isolated manner.  
  **Missing Mitigations:**  
  – No built‑in safe serializer is used for caching component state.  
  – There is no verification or sandboxing of the deserialized payload.  
  – No explicit warning is issued if an insecure cache backend is adopted.  
  **Preconditions:**  
  – The application is deployed with a cache backend that is accessible to an attacker (for example, a Redis or memcached instance without proper authentication or network restrictions).  
  – An attacker has network access to the cache backend used for component state storage.  
  **Source Code Analysis:**  
  – In `django_unicorn/cacher.py`, methods such as `restore_from_cache()` retrieve pickled data from the cache and call `pickle.loads()` directly without safe deserialization or validation.  
  – Since the cache key format is predictable (e.g. starting with `"unicorn:component:"`), an attacker able to inject data into the cache can store a malicious pickle blob that will later be loaded and executed.  
  **Security Test Case:**  
  1. Deploy the application with a vulnerable cache backend (for example, a Redis instance lacking authentication and network isolation).  
  2. From an external host with network access to the cache backend, inject a malicious pickle payload under a cache key such as `"unicorn:component:XYZ"`.  
  3. Cause a normal user request that triggers restoration of a component stored under that key (for example, by triggering a UI action).  
  4. Verify that the malicious payload executes on the server (for example, by observing system changes or a reverse shell).

- **Vulnerability Name:** Arbitrary Public Method Invocation via callMethod Endpoint  
  **Description:**  
  When processing an action of type “callMethod,” the framework extracts a method name from the user‑supplied payload and then invokes it on the component instance. In the absence of an explicit whitelist or annotation limiting which methods may be called externally, any public method (i.e. any method not prefixed with an underscore) becomes callable by an attacker. This may allow a malicious user to trigger methods that are meant only for internal use or that perform sensitive operations.  
  **Impact:**  
  If an attacker discovers and calls a method with unintended side‑effects (for example, one that modifies component state, exposes internal data, or otherwise triggers critical operations), unauthorized state changes or information disclosure may occur. In worst‑case scenarios, if the method subsequently calls unsafe code, this might escalate to arbitrary code execution.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  – Internal helper functions (e.g. `_is_public()`) exist to help distinguish public from non‑public members, and special action names prefixed with `$` (like `$reset` or `$refresh`) are handled separately by the framework.  
  **Missing Mitigations:**  
  – There is no enforced whitelist or an annotation mechanism restricting which component methods may be invoked via the remote “callMethod” action.  
  – The framework does not explicitly verify that the provided method name is intended for remote invocation (for example, by checking against sensitive or reserved names).  
  **Preconditions:**  
  – An attacker must be able to send POST requests to the public message endpoint (e.g. `/message/<component_name>`).  
  – The attacker must know or be able to guess the names of public methods defined on a component.  
  **Source Code Analysis:**  
  – In `django_unicorn/views/action_parsers/call_method.py`, the function `handle()` extracts the method name from the JSON payload and passes it to `_call_method_name()`.  
  – The helper `_call_method_name()` checks that the component has an attribute matching the specified method name but does not filter out methods that should not be externally exposed.  
  – As the method is subsequently invoked via `getattr(component, method_name)` (after any arguments are parsed), an attacker can supply any public method name.  
  **Security Test Case:**  
  1. Identify a component that defines at least one public method not intended for external use (for example, one that changes internal state or reveals secrets).  
  2. From an external host, craft a POST request to the message endpoint (e.g. `/message/FakeComponent`) with a JSON payload in the actionQueue containing:  
     - `"type": "callMethod"`  
     - `"payload": {"name": "<sensitive_method>"}`  
  3. Observe that the unintended method is invoked by inspecting changes to component data, system state, or application logs.

- **Vulnerability Name:** Arbitrary Attribute Modification via Nested Property Injection  
  **Description:**  
  The framework’s mechanism for updating component properties (using “syncInput” actions) calls functions such as `set_property_from_data()` and, deeper in the call stack, `set_property_value()`. These functions split client‑supplied property names using the dot character (thereby allowing updates to nested properties) and then call Python’s built‑in `setattr()` to update attributes on component objects.  
  **Impact:**  
  Because no filtering or whitelisting is applied to attribute names, an attacker can supply a property name that targets an internal attribute (for instance, one with a leading underscore or special names such as `__class__`). Changing such internal attributes can compromise component integrity, expose sensitive data, or—even in extreme cases—lead to arbitrary code execution.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  – The framework checks for the existence of an attribute before updating it; however, no filtering prevents updates to attributes with reserved or “private” names.  
  **Missing Mitigations:**  
  – There is no whitelist or safe‑list enforced in the property update logic to exclude dangerous attribute names (for example, those beginning with an underscore or dunder names like `__class__`).  
  – The code does not validate that the property name provided is “safe” to update.  
  **Preconditions:**  
  – An attacker must be able to send POST requests to the public message endpoint with a crafted payload.  
  – The component must have writable internal attributes (which all Python objects have by default) that can be updated via `setattr()` if the provided property name matches.  
  **Source Code Analysis:**  
  – In `django_unicorn/views/action_parsers/utils.py`, the function `set_property_value()` splits the property name (with `property_name.split(".")`) and then iteratively checks for attribute existence with `hasattr()` before eventually calling `setattr()`.  
  – No check is performed to ensure that the property name is not sensitive (e.g. `__class__` or names beginning with `_`).  
  **Security Test Case:**  
  1. Deploy the Unicorn‑powered application with the public message endpoint enabled.  
  2. Craft a JSON payload for a “syncInput” action where the payload’s `"name"` field is set to a dangerous attribute name (for example, `"__class__"` or `"some_internal.__class__"`).  
  3. Send a POST request to the message endpoint (for example, `/message/FakeComponent`) with the malicious payload.  
  4. Verify—by inspecting the component instance on the server or its subsequent responses—that the targeted attribute has been modified, confirming that the vulnerability is exploitable.

- **Vulnerability Name:** Weak Checksum Validation in Message Endpoint  
  **Description:**  
  The framework requires every message POSTed to the endpoint to include a checksum generated by the function `generate_checksum(str(data))`. This checksum is used to validate the integrity of the incoming payload. However, because the checksum is computed solely over the string representation of client‑supplied data—and no secret key or unpredictable salt is employed—an attacker who understands (or reverse‑engineers) the algorithm can easily generate a valid checksum for an arbitrary payload.  
  **Impact:**  
  By forging a valid checksum, an attacker may be able to bypass integrity checks and submit manipulated payloads. This could allow unauthorized invocation of component methods or modification of component state (in conjunction with the already present arbitrary invocation and attribute modification issues), potentially leading to remote code execution or systemic compromise.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  – The message processing code verifies that a checksum is present and that it matches the output of `generate_checksum(str(data))`.  
  **Missing Mitigations:**  
  – The checksum mechanism does not include a server‑side secret (for example, via an HMAC) to prevent attackers from reproducing it.  
  – There is no additional entropy (e.g. nonce or timestamp validation beyond what is already in the message) to mitigate replay or tampering risks.  
  **Preconditions:**  
  – The attacker must be familiar with (or able to deduce) that the checksum is generated by simply converting the `data` object to a string and hashing it (with a known algorithm).  
  – The attacker must be able to intercept or observe valid requests (or review the open‑source code) to learn the input format.  
  **Source Code Analysis:**  
  – In multiple test files (for example, in `tests/views/message/utils.py` and others), messages are constructed by calling `generate_checksum(str(data))` without any secret key.  
  – Since the algorithm is entirely deterministic and based solely on the client‑supplied data, any attacker can recompute the checksum after manipulating the payload.  
  **Security Test Case:**  
  1. Capture or examine a valid message payload (for example, by reviewing the open‑source code or intercepting a sample request).  
  2. Modify the payload data (for example, change a component’s state or the method invocation in an action entry).  
  3. Recompute the checksum using the same method (`generate_checksum(str(modified_data))`) outside the application.  
  4. Send the forged POST request to the public message endpoint with the modified payload and the recomputed checksum.  
  5. Verify that the server processes the modified payload (for example, by checking that the component state reflects the modifications).

- **Vulnerability Name:** Sensitive Information Disclosure via Component Load Error Messages  
  **Description:**  
  When a client sends a message with an invalid component identifier or requests a component that cannot be loaded, the framework raises exceptions such as `ComponentModuleLoadError` or `ComponentClassLoadError`. These error messages include detailed internal information—such as attempted module paths and attribute names—that can reveal aspects of the application’s internal structure and file layout. An attacker can use this information to map out the modules, determine naming conventions, and discover potentially sensitive component details.  
  **Impact:**  
  Exposure of internal module search paths and component class names can assist an attacker in reconnaissance efforts. By learning the internal structure and naming conventions of the application, an attacker can better target subsequent attacks (for example, by identifying vulnerable components for method invocation or attribute modification).  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  – The framework returns error messages when component modules or classes cannot be loaded.  
  – In a controlled testing environment, these errors are observable, but production deployments are expected to have additional error handling configurations.  
  **Missing Mitigations:**  
  – In production, detailed error messages should be suppressed or replaced with generic messages that do not reveal internal paths or attribute names.  
  – Use of a custom error handler or proper configuration (for example, ensuring DEBUG is disabled) is missing to prevent leakage of sensitive information.  
  **Preconditions:**  
  – The application is running in a configuration that exposes detailed exception information (for example, DEBUG mode enabled or insufficient error handling middleware).  
  – An attacker can send requests with invalid or non‑existent component names to the public message endpoint.  
  **Source Code Analysis:**  
  – The tests `test_message_component_module_not_loaded` and `test_message_component_class_not_loaded` demonstrate that error messages include explicit mentions of module search paths (for example, `"unicorn.components.test_message_module_not_loaded"`) and attribute lookup failures (for example, `module 'tests.views.fake_components' has no attribute 'FakeComponentNotThere'`).  
  – These exception messages are raised directly by the component loading mechanisms without sanitizing internal details.  
  **Security Test Case:**  
  1. Send a POST request to the message endpoint with an invalid component name (for example, `/message/nonexistent_component` or `/message/test-with-dash`).  
  2. Capture the error response and inspect it for details such as internal module paths, component class names, or attribute errors.  
  3. Confirm that the error message discloses information that could help an attacker map out the internal structure of the application.