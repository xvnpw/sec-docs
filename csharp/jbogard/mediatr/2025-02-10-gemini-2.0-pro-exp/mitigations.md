# Mitigation Strategies Analysis for jbogard/mediatr

## Mitigation Strategy: [Input Validation and Sanitization (Per Request Type)](./mitigation_strategies/input_validation_and_sanitization__per_request_type_.md)

*   **Description:**
    1.  **Identify all Request Objects:** List all classes implementing `IRequest` or `IRequest<TResponse>` (your commands and queries within MediatR).
    2.  **Define Validation Rules:** For *each* MediatR request object, create a corresponding validator (e.g., using FluentValidation). Within the validator:
        *   Define rules for *every* property.
        *   Use appropriate validation rules (e.g., `NotEmpty()`, `MaximumLength()`, `GreaterThan()`, `EmailAddress()`, regex).
        *   Consider custom validation for complex business rules.
    3.  **Register Validators:** Register all validators with your dependency injection container.
    4.  **Implement Validation Behavior:** Use a MediatR *pipeline behavior* (e.g., a custom `ValidationBehavior<TRequest, TResponse>`) to automatically apply validation to *all* MediatR requests. This behavior should:
        *   Retrieve validators for the current request type.
        *   Execute the validators.
        *   If validation fails, throw a `ValidationException` (or custom type) *before* the MediatR handler executes.
    5.  **Sanitization (If Necessary):** If sanitization is *required*, do it *before* validation, using a trusted library. Prioritize validation.
    6.  **Test Thoroughly:** Write unit tests for each validator.

*   **Threats Mitigated:**
    *   **Malicious Input:** Attackers send crafted MediatR requests with invalid data to exploit handler vulnerabilities (e.g., SQL injection, buffer overflows, XSS). **Severity: High**
    *   **Data Corruption:** Invalid data can corrupt data stores. **Severity: Medium**
    *   **Unexpected Behavior:** Handlers behave unpredictably with unexpected input. **Severity: Medium**
    *   **Denial of Service (DoS):** Large/complex input could overwhelm the system via MediatR. **Severity: High**

*   **Impact:**
    *   **Malicious Input:** Reduces exploitation risk by rejecting invalid MediatR requests before handler execution.
    *   **Data Corruption:** Prevents invalid data persistence.
    *   **Unexpected Behavior:** Ensures MediatR handlers receive only valid input.
    *   **Denial of Service (DoS):** Mitigates some DoS attacks by limiting input size/complexity *within the MediatR pipeline*.

*   **Currently Implemented:** [Placeholder: e.g., "Implemented for `CreateProductCommand` and `UpdateProductCommand` using FluentValidation and a custom MediatR `ValidationBehavior`."]

*   **Missing Implementation:** [Placeholder: e.g., "Missing for `DeleteProductCommand`, `GetAllProductsQuery`, and all other MediatR request types. Need validators and registration."]

## Mitigation Strategy: [Secure Pipeline Behaviors (MediatR-Specific)](./mitigation_strategies/secure_pipeline_behaviors__mediatr-specific_.md)

*   **Description:**
    1.  **Review Existing Behaviors:** Examine all *custom* MediatR pipeline behaviors.
    2.  **Minimize Behavior Logic:** Keep MediatR behaviors simple and focused. Avoid complex logic or state.
    3.  **Secure Behavior Order:** Ensure MediatR behaviors for security checks (validation, authorization) are registered *early* in the MediatR pipeline.
    4.  **Avoid Sensitive Data in Context:** Do not store sensitive data in the MediatR pipeline context.
    5.  **Thorough Testing:** Write comprehensive unit/integration tests for all custom MediatR behaviors, focusing on security.
    6.  **Prefer Built-in Behaviors:** Use well-tested, built-in MediatR behaviors (or from trusted libraries) instead of custom ones when possible.

*   **Threats Mitigated:**
    *   **Security Bypass:** Malicious/poorly designed MediatR behaviors could bypass security checks in handlers or other behaviors. **Severity: High**
    *   **Code Injection:** Attackers might inject malicious code into the MediatR pipeline via custom behaviors. **Severity: High**
    *   **Data Tampering:** MediatR Behaviors could modify request/response data. **Severity: High**
    *   **Denial of Service (DoS):** Inefficient MediatR behaviors could cause performance issues or DoS. **Severity: Medium**

*   **Impact:**
    *   **Security Bypass:** Ensures security checks are consistently applied within the MediatR pipeline.
    *   **Code Injection:** Reduces code injection risk by limiting the attack surface within MediatR.
    *   **Data Tampering:** Protects MediatR request/response data integrity.
    *   **Denial of Service (DoS):** Improves performance/resilience via efficient MediatR behaviors.

*   **Currently Implemented:** [Placeholder: e.g., "Only a custom MediatR `ValidationBehavior` is implemented. It's reviewed and tested."]

*   **Missing Implementation:** [Placeholder: e.g., "Review the need for other custom MediatR behaviors. New behaviors require audit and testing."]

## Mitigation Strategy: [Avoid Command/Query Object Overloading (MediatR Context)](./mitigation_strategies/avoid_commandquery_object_overloading__mediatr_context_.md)

*   **Description:**
    1.  **One Command/Query Per Operation:** Create a *separate* MediatR command/query object for *each* operation.
    2.  **Clear Naming:** Use descriptive names for MediatR command/query objects (e.g., `CreateUserCommand`, `GetUserByIdQuery`).
    3.  **Specific Validation:** Implement validation *specifically* for each MediatR command/query object.
    4.  **Avoid Shared Properties (When Unrelated):** If operations share properties but have different validation/authorization, create separate MediatR objects.

*   **Threats Mitigated:**
    *   **Logic Errors:** Reduces risk of using the wrong MediatR object or applying incorrect validation/authorization. **Severity: Medium**
    *   **Security Bypass:** Prevents exploiting overloaded MediatR objects to bypass checks. **Severity: Medium**

*   **Impact:**
    *   **Logic Errors:** Improves code clarity/maintainability, reducing errors.
    *   **Security Bypass:** Makes it harder to exploit ambiguities in MediatR object usage.

*   **Currently Implemented:** [Placeholder: e.g., "Most operations have dedicated MediatR objects, but some older code might reuse objects."]

*   **Missing Implementation:** [Placeholder: e.g., "Review all MediatR command/query objects and refactor any overloaded ones."]

