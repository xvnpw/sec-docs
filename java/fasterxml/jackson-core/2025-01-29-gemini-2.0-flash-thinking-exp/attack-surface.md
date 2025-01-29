# Attack Surface Analysis for fasterxml/jackson-core

## Attack Surface: [Polymorphic Deserialization with Unsafe Default Typing](./attack_surfaces/polymorphic_deserialization_with_unsafe_default_typing.md)

*   **Description:** Exploiting Jackson's polymorphic deserialization when default typing is enabled insecurely. Attackers inject malicious class names in JSON to force deserialization of arbitrary classes, leading to severe consequences.
*   **Jackson-core Contribution:** Jackson-core provides the core deserialization engine and the configuration options for default typing. Insecure default typing configuration directly enables this attack vector.
*   **Example:** An application uses `ObjectMapper` with default typing enabled. An attacker sends JSON like `{"@class":"java.net.URL", "val":"http://malicious.site"}`. Jackson-core, due to default typing, attempts to deserialize this into a `java.net.URL` object. This can lead to SSRF if the application processes the URL. More critically, gadget chains like `org.springframework.context.support.ClassPathXmlApplicationContext` can be triggered for RCE.
*   **Impact:** Remote Code Execution (RCE), Arbitrary File System Access, Server-Side Request Forgery (SSRF).
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Disable Default Typing:**  Completely disable default typing using `ObjectMapper.setDefaultTyping(null)`. This is the most effective mitigation.
    *   **Restrict Default Typing (with extreme caution):** If absolutely necessary, restrict default typing to a very limited whitelist of safe classes using a secure `PolymorphicTypeValidator`. Avoid using `LaissezFaireSubTypeValidator` as it is insecure.
    *   **Explicit Type Information:** Design APIs to include explicit type information in JSON using Jackson annotations like `@JsonTypeInfo` and `@JsonSubTypes`, avoiding reliance on default typing.

## Attack Surface: [Deserialization Gadget Chains](./attack_surfaces/deserialization_gadget_chains.md)

*   **Description:** Exploiting existing classes (gadgets) in the application's classpath (or dependencies) to achieve malicious outcomes through Jackson's deserialization process, even without default typing. Jackson-core's deserialization triggers these chains.
*   **Jackson-core Contribution:** Jackson-core's deserialization engine is the direct mechanism that processes JSON and instantiates objects, triggering method calls within gadget classes when processing crafted JSON payloads.
*   **Example:** An application includes vulnerable libraries like older versions of Apache Commons Collections or Spring. Attackers craft JSON that, when deserialized by Jackson-core into seemingly harmless application classes, triggers a sequence of method calls within these libraries (the gadget chain) leading to RCE. Gadgets like `org.apache.commons.collections.functors.InvokerTransformer` are commonly used.
*   **Impact:** Remote Code Execution (RCE), Arbitrary File System Access.
*   **Risk Severity:** **High** to **Critical** (depending on the specific gadget chain and application context)
*   **Mitigation Strategies:**
    *   **Dependency Management and Updates:** Regularly audit and update all dependencies to patch known gadget chain vulnerabilities in libraries used alongside Jackson-core.
    *   **Minimize Dependencies:** Reduce the number of dependencies to minimize the potential surface for gadget chains.
    *   **Code Audits for Gadget Classes:** Conduct security-focused code audits to identify potential classes within the application or its dependencies that could be exploited as gadgets.
    *   **Runtime Application Self-Protection (RASP):** Consider RASP solutions to detect and block deserialization exploits at runtime.

## Attack Surface: [Denial of Service (DoS) via Large or Nested JSON Payloads](./attack_surfaces/denial_of_service__dos__via_large_or_nested_json_payloads.md)

*   **Description:** Causing a Denial of Service by sending excessively large or deeply nested JSON payloads that overwhelm Jackson-core's parsing process, consuming excessive server resources (CPU, memory).
*   **Jackson-core Contribution:** Jackson-core is the library responsible for parsing the incoming JSON. Its parsing process, while generally efficient, can be resource-intensive when handling extremely large or complex JSON structures.
*   **Example:** An attacker sends a JSON payload with extreme nesting depth (e.g., hundreds of levels of nested arrays or objects) or an extremely large JSON document exceeding available memory. Jackson-core attempts to parse this, leading to excessive CPU and memory consumption, potentially crashing the application or making it unresponsive.
*   **Impact:** Denial of Service (DoS), Application Unavailability.
*   **Risk Severity:** **High** (in scenarios where DoS has significant impact on availability and business operations)
*   **Mitigation Strategies:**
    *   **Input Size Limits:** Implement strict limits on the maximum size of incoming JSON payloads at the application level, before Jackson-core parsing.
    *   **Jackson Parser Configuration Limits:** Configure Jackson-core's `JsonFactory` to enforce limits on nesting depth and string lengths using builder methods like `JsonFactory.builder().maxDepth(int)` and `JsonFactory.builder().maxStringLength(int)`.
    *   **Resource Monitoring and Throttling:** Monitor server resource usage and implement request throttling to limit the rate of incoming requests, especially from suspicious sources.

## Attack Surface: [Use of Outdated Jackson-core Versions](./attack_surfaces/use_of_outdated_jackson-core_versions.md)

*   **Description:** Using older versions of `jackson-core` that contain known, publicly disclosed security vulnerabilities.
*   **Jackson-core Contribution:** Outdated versions of Jackson-core directly contain exploitable vulnerabilities within their code.
*   **Example:** An application uses an old version of `jackson-core` with a known deserialization vulnerability (e.g., CVE-2019-12384). Attackers exploit this vulnerability by sending malicious JSON payloads, potentially achieving RCE. Upgrading to a patched version of Jackson-core would eliminate this vulnerability.
*   **Impact:** Exposure to known vulnerabilities, potentially leading to RCE, data breaches, or DoS, depending on the specific vulnerability.
*   **Risk Severity:** **High** to **Critical** (depending on the specific vulnerability in the outdated version)
*   **Mitigation Strategies:**
    *   **Regularly Update Dependencies:** Implement a robust process for regularly updating all dependencies, including `jackson-core`, to the latest stable versions.
    *   **Dependency Scanning Tools:** Utilize dependency scanning tools (like OWASP Dependency-Check, Snyk, or GitHub Dependency Scanning) to automatically identify outdated dependencies with known vulnerabilities.
    *   **Automated Dependency Updates:** Consider using automated dependency update tools to streamline the update process and ensure timely patching of vulnerabilities.

