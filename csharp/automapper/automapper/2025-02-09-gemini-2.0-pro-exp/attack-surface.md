# Attack Surface Analysis for automapper/automapper

## Attack Surface: [Over-Mapping / Unintended Property Exposure](./attack_surfaces/over-mapping__unintended_property_exposure.md)

*   **Description:** Sensitive data from the source object is unintentionally mapped to the destination object due to AutoMapper's default behavior or overly permissive configurations, leading to data exposure.
*   **How AutoMapper Contributes:** AutoMapper's core functionality is mapping; if not configured carefully, it *will* copy properties that should remain private. This is the *primary* risk of using AutoMapper.
*   **Example:** A `User` entity with `PasswordHash` is mapped to a `UserPublicDto` without explicitly excluding `PasswordHash`.
*   **Impact:** Information disclosure, potential privilege escalation, violation of data privacy regulations.
*   **Risk Severity:** **High** (Potentially Critical if highly sensitive data is exposed)
*   **Mitigation Strategies:**
    *   **Explicit Mapping:** Use `CreateMap<Source, Destination>().ForMember(...)` to define *only* the properties to be mapped.  This is the most crucial mitigation.
    *   **Avoid `ForAllMembers` (with many ignores):**  Explicit inclusion is safer than exclusion.
    *   **`AssertConfigurationIsValid()`:** Use during startup/testing to catch misconfigurations.
    *   **`ProjectTo` (with `IQueryable`):** For database queries, prevent loading unnecessary data in the first place.

## Attack Surface: [Custom Resolver / Value Injector Exploitation](./attack_surfaces/custom_resolver__value_injector_exploitation.md)

*   **Description:** Vulnerabilities in custom code executed within AutoMapper's resolvers (`ResolveUsing`) or value injectors can be exploited. This is a direct consequence of using these AutoMapper features.
*   **How AutoMapper Contributes:** AutoMapper provides the *mechanism* (resolvers/injectors) for running custom code during the mapping process. The vulnerability is in the *custom* code, but AutoMapper is the *enabler*.
*   **Example:** A custom resolver that constructs a file path using unsanitized data from the source object (path traversal). Or, a resolver making an external API call with unvalidated data (SSRF).
*   **Impact:** Wide range: code execution, data breaches, denial of service, system compromise – directly tied to the vulnerability within the custom code.
*   **Risk Severity:** **High** (Potentially Critical, depending on the vulnerability in the custom code)
*   **Mitigation Strategies:**
    *   **Secure Coding Practices:** Treat custom resolvers as security-critical code. Apply all relevant secure coding principles.
    *   **Minimize Complexity:** Prefer simpler, declarative mappings whenever possible. Avoid resolvers if a standard mapping will suffice.
    *   **Input Sanitization (within Resolver):** Sanitize any data from the source object *within the resolver itself* before using it in sensitive operations.
    *   **Thorough Testing:** Rigorously test custom resolvers with a wide range of inputs, including malicious ones.

