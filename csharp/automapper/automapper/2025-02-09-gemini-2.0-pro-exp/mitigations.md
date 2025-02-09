# Mitigation Strategies Analysis for automapper/automapper

## Mitigation Strategy: [Explicit Configuration over Convention](./mitigation_strategies/explicit_configuration_over_convention.md)

**Mitigation Strategy:** Explicit Configuration over Convention

    *   **Description:**
        1.  **Identify all mapping needs:** Before writing any code, list all instances where data needs to be transformed between objects.
        2.  **Create AutoMapper Profiles:** Organize mappings into logical groups using AutoMapper Profiles (`Profile` class).
        3.  **Define `CreateMap`:** Within each profile, use `CreateMap<SourceType, DestinationType>()` for *every* mapping.  Do *not* rely on automatic discovery.
        4.  **Use `ForMember` for Explicit Mapping:** For *each* property that needs to be mapped, use `.ForMember(dest => dest.PropertyName, opt => opt.MapFrom(src => src.SourcePropertyName))`. This explicitly defines the source and destination properties.
        5.  **Use `ForMember` to Ignore:** For *each* property that should *never* be mapped, use `.ForMember(dest => dest.SensitiveProperty, opt => opt.Ignore())`. This explicitly prevents mapping.
        6.  **Use `ProjectTo` for Database Queries:** When querying a database using an ORM, use `ProjectTo<DestinationType>(mapper.ConfigurationProvider)` on the `IQueryable` to optimize database queries.

    *   **Threats Mitigated:**
        *   **Unintended Data Exposure (High Severity):** Prevents sensitive data from being accidentally exposed.
        *   **Over-Posting/Mass Assignment (High Severity):** Reduces the risk (though DTOs are the primary defense).
        *   **Information Disclosure (Medium Severity):** Limits data returned from database queries via `ProjectTo`.

    *   **Impact:**
        *   **Unintended Data Exposure:** Risk reduced significantly (High to Low).
        *   **Over-Posting/Mass Assignment:** Risk reduced (High to Medium/Low, further reduced with DTOs).
        *   **Information Disclosure:** Risk reduced moderately (Medium to Low).

    *   **Currently Implemented:**
        *   Implemented in `UserProfile` and `ProductProfile`.
        *   `ProjectTo` used in `ProductService`.

    *   **Missing Implementation:**
        *   Missing in `OrderProfile`.

## Mitigation Strategy: [Input Validation and Sanitization (Custom Logic)](./mitigation_strategies/input_validation_and_sanitization__custom_logic_.md)

**Mitigation Strategy:** Input Validation and Sanitization (Custom Logic)

    *   **Description:**
        1.  **Identify Custom Logic:** Locate all instances of custom value resolvers (`ConvertUsing`, `MapFrom`) and type converters.
        2.  **Analyze Input:** Identify the source of the input data for each custom resolver/converter.
        3.  **Implement Validation:** Add validation logic *within* the resolver/converter, at the beginning.
        4.  **Implement Sanitization:** Sanitize data *within* the resolver/converter if it will be used in contexts like HTML or SQL.
        5.  **Error Handling:** Handle validation failures appropriately *within* the resolver/converter.
        6.  **Unit Tests:** Write unit tests specifically for your custom resolvers and type converters.

    *   **Threats Mitigated:**
        *   **SQL Injection (High Severity):** Prevents injection through resolvers interacting with databases.
        *   **Cross-Site Scripting (XSS) (High Severity):** Prevents injection through resolvers handling data for web pages.
        *   **Code Injection (High Severity):** Prevents arbitrary code execution.
        *   **Data Corruption (Medium Severity):** Prevents invalid data from being mapped.

    *   **Impact:**
        *   **SQL Injection, XSS, Code Injection:** Risk reduced significantly (High to Low).
        *   **Data Corruption:** Risk reduced moderately (Medium to Low).

    *   **Currently Implemented:**
        *   Implemented in `UserDisplayNameResolver` and `ProductUrlResolver`.

    *   **Missing Implementation:**
        *   Missing in `OrderTotalResolver`.

## Mitigation Strategy: [Preventing Over-Posting/Mass Assignment (Using DTOs in conjunction with AutoMapper)](./mitigation_strategies/preventing_over-postingmass_assignment__using_dtos_in_conjunction_with_automapper_.md)

**Mitigation Strategy:** Preventing Over-Posting/Mass Assignment (Using DTOs in conjunction with AutoMapper)

    *   **Description:**
        1.  **Identify Controller Actions:** Locate actions accepting user input.
        2.  **Create DTOs:** Create DTOs containing *only* the properties users can modify.
        3.  **Map to DTO:** Map incoming request data to the DTO.
        4.  **Validate DTO:** Validate the DTO.
        5.  **Map from DTO to Entity:** If valid, use AutoMapper to map *from* the DTO *to* the domain entity.
        6.  **Never Map Directly:** *Never* map directly from request data to the domain entity.

    *   **Threats Mitigated:**
        *   **Over-Posting/Mass Assignment (High Severity):** This is the primary threat.

    *   **Impact:**
        *   **Over-Posting/Mass Assignment:** Risk reduced significantly (High to Low).

    *   **Currently Implemented:**
        *   Implemented for `CreateUser`, `UpdateUser`, and `CreateProduct` actions.

    *   **Missing Implementation:**
        *   Missing for `UpdateOrder` action.

## Mitigation Strategy: [Profile Validation and Testing (AutoMapper-Specific)](./mitigation_strategies/profile_validation_and_testing__automapper-specific_.md)

**Mitigation Strategy:** Profile Validation and Testing (AutoMapper-Specific)

    *   **Description:**
        1.  **Centralized Test:** Create a unit/integration test that runs during startup or CI/CD.
        2.  **Call `AssertConfigurationIsValid()`:** Call `mapper.ConfigurationProvider.AssertConfigurationIsValid()`.
        3.  **Write Mapping Tests:** Create unit tests for *each* mapping:
            *   Create a source object.
            *   Map to the destination object.
            *   Assert expected values.
            *   Test edge cases.
        4.  **Test Custom Logic:** Include tests specifically for custom resolvers/converters.

    *   **Threats Mitigated:**
        *   **Runtime Errors (Medium Severity):** Due to incorrect configurations.
        *   **Unexpected Behavior (Medium Severity):** From incorrect mappings.
        *   **Data Loss (Medium Severity):** Due to incorrect mappings.
        *   **Indirectly supports other mitigations.**

    *   **Impact:**
        *   **Runtime Errors, Unexpected Behavior, Data Loss:** Risk reduced significantly (Medium to Low).

    *   **Currently Implemented:**
        *   `AssertConfigurationIsValid()` is called.
        *   Basic tests for `UserProfile` and `ProductProfile`.

    *   **Missing Implementation:**
        *   Missing comprehensive tests for `OrderProfile`, `OrderTotalResolver`, and `UserDisplayNameResolver`.

