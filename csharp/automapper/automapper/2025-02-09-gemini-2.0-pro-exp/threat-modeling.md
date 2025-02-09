# Threat Model Analysis for automapper/automapper

## Threat: [Property Injection via Unintended Mapping](./threats/property_injection_via_unintended_mapping.md)

**Description:** An attacker sends a crafted HTTP request containing extra properties in the DTO.  AutoMapper, if configured to automatically map properties based on name matching (without explicit `ForMember` configurations or with incorrect `ForAllMembers` conditions), maps these extra properties to sensitive fields in the domain model.  For example, adding an `IsAdmin` property to a user registration DTO that gets mapped to a corresponding property in the `User` domain model.

**Impact:** Unauthorized data modification, privilege escalation (e.g., granting administrative rights), data corruption.

**Affected Component:** `Mapper.Map<TSource, TDestination>(TSource source)`, `Mapper.Map(object source, Type sourceType, Type destinationType)`, implicit mapping based on naming conventions, `ProjectTo<TDestination>(...)` without explicit `Select` clauses, incorrect use of `ForAllMembers` with conditions.

**Risk Severity:** Critical (if it leads to privilege escalation or sensitive data modification) or High (for other unauthorized data changes).

**Mitigation Strategies:**
    *   **Explicit `CreateMap` and `ForMember`:**  Define explicit mappings using `CreateMap`. Use `ForMember` to specify *exactly* which properties should be mapped.  Crucially, use `ForMember(dest => dest.SensitiveProperty, opt => opt.Ignore())` to explicitly *prevent* mapping to sensitive properties.
    *   **`ForAllMembers` with Strict `Condition`:** If using `ForAllMembers`, use a very strict `Condition` to allow only specific, known properties.  Avoid broad conditions that might inadvertently allow unintended mappings.
    *   **Avoid `DynamicMap`:** Do not use `DynamicMap` or `Map` with `object` as the source type. These bypass type safety.

## Threat: [Data Exposure via Over-Mapping](./threats/data_exposure_via_over-mapping.md)

**Description:** An attacker requests data. AutoMapper maps a domain model to a DTO, but the mapping configuration inadvertently includes sensitive properties that should not be exposed. This happens if the DTO is too closely aligned with the domain model or if `ForMember` with `Ignore` is not used correctly.

**Impact:** Information disclosure, leakage of sensitive data (e.g., internal IDs, passwords, PII).

**Affected Component:** `Mapper.Map<TSource, TDestination>(TSource source)`, `ProjectTo<TDestination>(...)` without explicit `Select` clauses, flattening operations.

**Risk Severity:** High (depending on the sensitivity of the exposed data).

**Mitigation Strategies:**
    *   **Explicit `ForMember` with `Ignore`:**  Use `ForMember(dest => dest.SensitiveProperty, opt => opt.Ignore())` to *explicitly exclude* sensitive properties from the mapping. This is the most reliable defense.
    *   **`ProjectTo` with `Select`:** When using `ProjectTo` with `IQueryable`, use a `Select` clause in your LINQ query to explicitly specify the properties to be included.
    *   **Review Flattening:** Carefully review any use of AutoMapper's flattening feature. Ensure it doesn't expose sensitive data from nested objects.

## Threat: [Code Injection via Custom Resolvers/Converters](./threats/code_injection_via_custom_resolversconverters.md)

**Description:** An attacker exploits a vulnerability in a *custom* `IValueResolver`, `ITypeConverter`, or `IMemberValueResolver` implementation. If these resolvers execute arbitrary code based on (potentially manipulated) user input without proper sanitization, it could lead to code injection.

**Impact:** Remote code execution, complete system compromise.

**Affected Component:** Custom `IValueResolver`, `ITypeConverter`, or `IMemberValueResolver` implementations.

**Risk Severity:** Critical.

**Mitigation Strategies:**
    *   **Secure Coding Practices:** Follow secure coding practices *within* the custom resolver. Avoid executing code based on untrusted input. Sanitize and validate all input used within the resolver.
    *   **Input Validation (Within Resolver):** Perform strict input validation *within* the custom resolver itself, ensuring only expected values are processed. This is *in addition to* any pre-mapping validation.
    *   **Avoid Dynamic Code Generation:** Avoid dynamic code generation or evaluation within resolvers, especially based on user input.
    *   **Code Reviews:** Thoroughly review *all* custom resolver implementations for security vulnerabilities.

