# Threat Model Analysis for square/moshi

## Threat: [Malicious JSON Payload Causing Denial of Service (DoS) via Deeply Nested Objects](./threats/malicious_json_payload_causing_denial_of_service__dos__via_deeply_nested_objects.md)

**Threat:** Malicious JSON Payload Causing Denial of Service (DoS) via Deeply Nested Objects

**Description:** An attacker crafts a malicious JSON payload with an excessively deep level of nesting. When the application attempts to deserialize this payload using Moshi, it can lead to stack overflow errors or excessive memory consumption, ultimately crashing the application or making it unresponsive. This directly exploits Moshi's recursive deserialization process.

**Impact:** Application becomes unavailable, impacting users and potentially leading to financial loss or reputational damage.

**Affected Moshi Component:** Moshi's `fromJson()` function and the recursive nature of its deserialization process for complex objects.

**Risk Severity:** High

**Mitigation Strategies:**
* Implement limits on the maximum depth of JSON structures accepted by the application before attempting deserialization.
* Set timeouts for deserialization operations to prevent indefinite processing of malicious payloads.
* Consider using iterative deserialization techniques if dealing with potentially deep structures, although this might require custom `JsonAdapter` implementations.

## Threat: [Exploiting Polymorphic Deserialization to Instantiate Unexpected Classes](./threats/exploiting_polymorphic_deserialization_to_instantiate_unexpected_classes.md)

**Threat:** Exploiting Polymorphic Deserialization to Instantiate Unexpected Classes

**Description:** When using Moshi's polymorphic deserialization features (e.g., with `@JsonClass(generateAdapter = true, polymorphic = true)`), an attacker might craft a JSON payload with a type discriminator that forces Moshi to instantiate an unexpected class. If this unexpected class has unintended side effects in its constructor or methods, it could lead to security vulnerabilities, including potential code execution in some scenarios. This directly targets Moshi's polymorphic deserialization logic.

**Impact:** Potential for arbitrary code execution (in specific, vulnerable scenarios), unexpected application behavior, or denial of service depending on the instantiated class.

**Affected Moshi Component:** Moshi's polymorphic deserialization logic, specifically the handling of `@JsonClassDiscriminator` and `@JsonClassLabel`.

**Risk Severity:** High

**Mitigation Strategies:**
* Explicitly register all allowed subtypes using `@JsonClassDiscriminator` and `@JsonClassLabel`. Avoid relying on default or automatic subtype discovery.
* Thoroughly review the constructors and methods of all registered subtypes for potential security vulnerabilities.
* If possible, limit the number of allowed subtypes to only those strictly necessary.
* Consider alternative approaches to handling different data structures if the risk of exploiting polymorphism is deemed too high.

## Threat: [Exploiting Vulnerabilities in Custom `JsonAdapter` Implementations](./threats/exploiting_vulnerabilities_in_custom__jsonadapter__implementations.md)

**Threat:** Exploiting Vulnerabilities in Custom `JsonAdapter` Implementations

**Description:** If developers create custom `JsonAdapter` classes for serialization or deserialization, these adapters might contain vulnerabilities due to coding errors or lack of proper input validation. An attacker could exploit these vulnerabilities by sending crafted JSON payloads or by manipulating data that is processed by the custom adapter. This directly involves the custom components interacting with Moshi's core functionality.

**Impact:** The impact depends on the specific vulnerability in the custom adapter, potentially leading to data corruption, denial of service, or even code execution if the adapter interacts with other vulnerable parts of the application.

**Affected Moshi Component:** Custom `JsonAdapter` classes implemented by developers.

**Risk Severity:** High

**Mitigation Strategies:**
* Follow secure coding practices when implementing custom `JsonAdapter` classes.
* Thoroughly test custom adapters with various valid and invalid inputs, including potentially malicious ones.
* Consider using existing Moshi features or community-provided adapters before implementing custom ones.
* Conduct code reviews of custom adapter implementations to identify potential vulnerabilities.

