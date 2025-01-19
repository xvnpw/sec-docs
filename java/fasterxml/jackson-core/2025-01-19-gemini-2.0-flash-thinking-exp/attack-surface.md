# Attack Surface Analysis for fasterxml/jackson-core

## Attack Surface: [Denial of Service (DoS) through Resource Exhaustion (Large Payloads)](./attack_surfaces/denial_of_service__dos__through_resource_exhaustion__large_payloads_.md)

**Description:** `jackson-core` needs to parse the entire JSON structure. Sending extremely large JSON payloads can consume excessive memory or CPU resources directly within the `jackson-core` parsing process, potentially leading to a denial of service.

**How Jackson-core Contributes:** `jackson-core` is responsible for reading and processing the entire input stream. The larger the input, the more resources it consumes *during its own parsing operations*.

**Example:** An attacker sends a JSON payload containing millions of nested objects or extremely long strings. `jackson-core` attempts to parse this massive structure, leading to excessive memory allocation or CPU usage, making the application unresponsive.

**Impact:** Application becomes unavailable, impacting legitimate users.

**Risk Severity:** High

**Mitigation Strategies:**
* Implement limits on the maximum size of incoming JSON payloads *before* they are processed by `jackson-core`.
* Utilize Jackson's streaming parsing APIs when dealing with potentially large inputs to avoid loading the entire payload into memory at once.
* Implement timeouts for parsing operations to prevent indefinite resource consumption.

## Attack Surface: [Denial of Service (DoS) through Resource Exhaustion (Deeply Nested Payloads)](./attack_surfaces/denial_of_service__dos__through_resource_exhaustion__deeply_nested_payloads_.md)

**Description:** JSON payloads with excessive nesting can lead to stack overflow errors or excessive memory consumption *within the `jackson-core` parsing logic*.

**How Jackson-core Contributes:** The recursive nature of parsing nested JSON structures can lead to deep call stacks and increased memory usage *within `jackson-core` itself* for tracking the parsing state.

**Example:** An attacker sends a JSON payload with hundreds or thousands of nested objects or arrays. `jackson-core`'s parsing process recurses deeply, potentially exceeding stack limits or consuming excessive memory to track the nesting levels.

**Impact:** Application crashes or becomes unresponsive, leading to service disruption.

**Risk Severity:** High

**Mitigation Strategies:**
* Configure limits on the maximum nesting depth allowed during parsing within `jackson-core` (if such configuration is available, otherwise handle this at a higher level).
* Implement timeouts for parsing operations.

