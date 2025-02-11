# Threat Model Analysis for alibaba/fastjson2

## Threat: [Remote Code Execution (RCE) via AutoType Bypass or Deserialization Gadgets](./threats/remote_code_execution__rce__via_autotype_bypass_or_deserialization_gadgets.md)

**Description:** An attacker crafts a malicious JSON payload that bypasses Fastjson2's AutoType restrictions (even when supposedly disabled or using a whitelist) or exploits vulnerabilities in the deserialization process of specific classes. The attacker leverages known or newly discovered gadgets (classes with specific methods that can be chained together) to execute arbitrary code on the server.  They might exploit vulnerabilities in how Fastjson2 handles class loading, reflection, or specific deserialization logic, even without relying on AutoType. The key is that the vulnerability lies *within Fastjson2's handling of the JSON data*, not in the application's subsequent use of the deserialized objects.

**Impact:** Complete system compromise. The attacker gains the ability to execute arbitrary commands with the privileges of the application, potentially leading to data theft, system modification, or lateral movement within the network.

**Affected Fastjson2 Component:** `JSON.parseObject()`, `JSON.parse()`, AutoType mechanism (even when disabled, bypasses are possible), Class Deserialization logic, Reflection handling, specific vulnerable classes and their deserialization routines. The core issue is in how Fastjson2 instantiates and populates objects based on the JSON input.

**Risk Severity:** Critical

**Mitigation Strategies:**

*   **Completely Disable AutoType:** Ensure AutoType is fully disabled. Do not rely on whitelists alone, as they can be bypassed. This is the *most important* mitigation, but not a guarantee.
*   **Use `expectClass`:** *Always* use `JSON.parseObject(String text, Type type, JSONReader.Feature... features)` and explicitly specify the expected class or interface. Avoid using methods that automatically infer the type from the JSON. This is crucial.
*   **Regularly Update Fastjson2:** Stay up-to-date with the latest version of Fastjson2 to receive security patches. Monitor security advisories *very* closely. This is a continuous process.
*   **Input Validation (Defense in Depth):** Validate the structure and content of the JSON input *before* deserialization. While not a primary defense against sophisticated exploits, this can help prevent some malformed or obviously malicious payloads.
*   **Least Privilege:** Run the application with the lowest necessary privileges to limit the impact of a successful RCE. This is a general security best practice, but particularly important here.
*   **Consider a Deserialization Firewall:** Use a third-party library or tool designed to intercept and analyze JSON payloads for malicious content *before* they reach Fastjson2. This adds a layer of defense.
*   **Use Value Filters**: Use `ContextValueFilter` to filter values during deserialization.

## Threat: [Type Confusion Leading to Security Bypass (High-Risk Variant)](./threats/type_confusion_leading_to_security_bypass__high-risk_variant_.md)

**Description:**  While not full RCE, a carefully crafted JSON payload can cause Fastjson2 to create an object of an *unexpected but related* type, or to populate an object with unexpected values in a way that *directly bypasses a security check*.  This differs from the "Medium" risk version in that the attacker achieves a specific, security-relevant outcome.  For example, if the application uses a custom class `User` with a field `isAdmin`, and a *different* class `AdminUser` also exists, the attacker might trick Fastjson2 into creating an `AdminUser` instance when a `User` instance was expected, potentially granting elevated privileges *due to Fastjson2's behavior*. The vulnerability is in how Fastjson2 handles type resolution and property mapping, *leading directly to a security bypass*.

**Impact:** Bypass of security checks, potentially leading to unauthorized access or privilege escalation.  The impact is less than full RCE, but still significant in terms of security.

**Affected Fastjson2 Component:** `JSON.parseObject()`, `JSON.parse()`, Deserialization logic, Type handling, Setter methods, Class hierarchy resolution. The core issue is in how Fastjson2 maps JSON data to object properties and handles type ambiguities.

**Risk Severity:** High

**Mitigation Strategies:**

*   **Use `expectClass`:** *Always* use `JSON.parseObject(String text, Type type, JSONReader.Feature... features)` and explicitly specify the expected class. This is the primary defense against type confusion.
*   **Input Validation:**  Rigorously validate the *values* of all properties within the JSON payload, *especially* those related to security decisions (e.g., roles, permissions).  Don't just validate the structure; validate the *semantics*.
*   **Defensive Programming:** Write code that is robust against unexpected property values and performs explicit checks *before* making security-critical decisions based on deserialized data.  Assume the data *could* be malicious.
*   **Avoid Ambiguous Class Hierarchies:** Design your class hierarchies carefully to minimize the possibility of type confusion.  Avoid having classes with similar property names that could be misinterpreted by Fastjson2.
*   **Use Value Filters**: Use `ContextValueFilter` to filter values during deserialization.

