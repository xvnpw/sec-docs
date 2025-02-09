# Mitigation Strategies Analysis for dotnet/aspnetcore

## Mitigation Strategy: [Use ViewModels/DTOs and `[Bind]` Attribute](./mitigation_strategies/use_viewmodelsdtos_and___bind___attribute.md)

**1. Mitigation Strategy: Use ViewModels/DTOs and `[Bind]` Attribute**

*   **Description:**
    1.  **Create ViewModels/DTOs:** For each controller action that accepts user input, create a dedicated class (ViewModel or DTO) that contains *only* the properties expected from the client.  Do *not* use your domain/entity models directly for data binding. This is a core ASP.NET Core MVC pattern.
    2.  **Use `[Bind]` (Optional but Recommended):** In your controller action, use the `[Bind]` attribute on the ViewModel/DTO parameter to explicitly specify which properties are allowed to be bound.  Example: `public IActionResult Create([Bind("Name,Email")] ProductViewModel model)`. This is an ASP.NET Core-specific attribute.
    3.  **Use `[BindNever]`:** On properties within your models (even ViewModels) that should *never* be populated from user input (e.g., `Id`, `IsAdmin`, `CreationDate`), apply the `[BindNever]` attribute. Example: `[BindNever] public int Id { get; set; }`. This is an ASP.NET Core-specific attribute.
    4.  **Controller Action Logic:** In your controller action, receive the ViewModel/DTO as a parameter.  After model validation, map the data from the ViewModel/DTO to your domain/entity model *manually*.

*   **List of Threats Mitigated:**
    *   **Over-Posting/Mass Assignment (High Severity):** Attackers can add extra properties to the request payload. ASP.NET Core's model binding, if misused, can be vulnerable.
    *   **Type Mismatches (Medium Severity):** Exploiting ASP.NET Core's model binding with unexpected types.

*   **Impact:**
    *   **Over-Posting/Mass Assignment:** Risk reduced from High to Low.
    *   **Type Mismatches:** Risk reduced from Medium to Low.

*   **Currently Implemented:** *[Placeholder]*

*   **Missing Implementation:** *[Placeholder]*

## Mitigation Strategy: [Validate Model State and Use Data Annotations](./mitigation_strategies/validate_model_state_and_use_data_annotations.md)

**2. Mitigation Strategy: Validate Model State and Use Data Annotations**

*   **Description:**
    1.  **Data Annotations:** Use ASP.NET Core's data annotations (e.g., `[Required]`, `[StringLength]`, `[EmailAddress]`, `[Range]`, `[RegularExpression]`) on the properties of your ViewModels/DTOs. These are part of the `System.ComponentModel.DataAnnotations` namespace, deeply integrated with ASP.NET Core.
    2.  **`ModelState.IsValid`:** In *every* controller action, *always* check the `ModelState.IsValid` property (an ASP.NET Core MVC feature) *before* processing data.
    3.  **Return Errors:** If `ModelState.IsValid` is `false`, return the validation errors to the client using ASP.NET Core's built-in mechanisms.
    4.  **Custom Validation (if needed):** Implement the `IValidatableObject` interface (part of ASP.NET Core's validation system) on your ViewModel/DTO for complex rules.

*   **List of Threats Mitigated:**
    *   **Under-Posting (Medium Severity):** Attackers omitting required fields, bypassing checks that rely on ASP.NET Core's model binding.
    *   **Invalid Input (Medium to High Severity):** Data violating rules defined via ASP.NET Core's data annotations.
    *   **Bypassing Business Logic (Medium to High Severity):** Circumventing client-side validation, relying on ASP.NET Core's *server-side* validation.

*   **Impact:**
    *   **Under-Posting:** Risk reduced from Medium to Low.
    *   **Invalid Input:** Risk reduced from Medium/High to Low.
    *   **Bypassing Business Logic:** Risk reduced from Medium/High to Low.

*   **Currently Implemented:** *[Placeholder]*

*   **Missing Implementation:** *[Placeholder]*

## Mitigation Strategy: [Use Attribute Routing and Route Constraints](./mitigation_strategies/use_attribute_routing_and_route_constraints.md)

**3. Mitigation Strategy: Use Attribute Routing and Route Constraints**

*   **Description:**
    1.  **Attribute Routing:** Use ASP.NET Core's attribute routing (`[Route]`, `[HttpGet]`, `[HttpPost]`, etc.) on controller actions. This is the recommended routing mechanism in ASP.NET Core.
    2.  **Specific Route Templates:** Define precise route templates.
    3.  **Route Constraints:** Use ASP.NET Core's route constraints (e.g., `[HttpGet("users/{id:int}")]`) to restrict parameter types. This is a built-in ASP.NET Core feature.
    4.  **Route Parameter Validation (in Action):** Validate route parameters within your controller actions.

*   **List of Threats Mitigated:**
    *   **Ambiguous Routes (Medium Severity):** Poorly defined routes leading to incorrect action execution, specific to ASP.NET Core's routing system.
    *   **Route Parameter Tampering (Medium to High Severity):** Manipulating route parameters, exploiting weaknesses in ASP.NET Core's routing if not properly secured.

*   **Impact:**
    *   **Ambiguous Routes:** Risk reduced from Medium to Low.
    *   **Route Parameter Tampering:** Risk reduced from Medium/High to Low.

*   **Currently Implemented:** *[Placeholder]*

*   **Missing Implementation:** *[Placeholder]*

## Mitigation Strategy: [Auto-Validate Anti-Forgery Tokens Globally](./mitigation_strategies/auto-validate_anti-forgery_tokens_globally.md)

**4. Mitigation Strategy: Auto-Validate Anti-Forgery Tokens Globally**

*   **Description:**
    1.  **Global Validation:** In `Program.cs` (or `Startup.cs`), add the `AutoValidateAntiforgeryTokenAttribute` (an ASP.NET Core-specific attribute) to the global filter collection. This leverages ASP.NET Core's built-in anti-CSRF protection.
    2.  **Include Token in Forms:** Use `@Html.AntiForgeryToken()` (an ASP.NET Core Razor helper) in forms.
    3.  **Include Token in AJAX Requests:** Use ASP.NET Core's JavaScript helpers to include the token in AJAX request headers.

*   **List of Threats Mitigated:**
    *   **Cross-Site Request Forgery (CSRF) (High Severity):** Directly mitigated by ASP.NET Core's anti-forgery token mechanism.

*   **Impact:**
    *   **CSRF:** Risk reduced from High to Low.

*   **Currently Implemented:** *[Placeholder]*

*   **Missing Implementation:** *[Placeholder]*

## Mitigation Strategy: [Use `[Authorize]` Attribute and Role/Claims-Based Authorization](./mitigation_strategies/use___authorize___attribute_and_roleclaims-based_authorization.md)

**5. Mitigation Strategy: Use `[Authorize]` Attribute and Role/Claims-Based Authorization**

*   **Description:**
    1.  **Authentication:** Use an ASP.NET Core authentication mechanism (e.g., Identity, JWT Bearer).
    2.  **`[Authorize]` Attribute:** Apply the `[Authorize]` attribute (an ASP.NET Core attribute) to controllers/actions.
    3.  **Role-Based Authorization:** Use `[Authorize(Roles = "Admin")]` (ASP.NET Core feature).
    4.  **Claims-Based Authorization:** Use ASP.NET Core's claims-based authorization and policies.
    5. **Policy-Based Authorization:** Define authorization policies using ASP.NET Core's authorization services.

*   **List of Threats Mitigated:**
    *   **Unauthenticated Access (High Severity):** Prevented by ASP.NET Core's authentication and `[Authorize]` attribute.
    *   **Unauthorized Access (High Severity):** Prevented by ASP.NET Core's role/claims-based authorization.
    *   **Privilege Escalation (High Severity):** Mitigated by proper use of ASP.NET Core's authorization features.

*   **Impact:**
    *   **Unauthenticated Access:** Risk reduced from High to Low.
    *   **Unauthorized Access:** Risk reduced from High to Low.
    *   **Privilege Escalation:** Risk reduced from High to Low.

*   **Currently Implemented:** *[Placeholder]*

*   **Missing Implementation:** *[Placeholder]*

## Mitigation Strategy: [Secure Key Storage and Data Protection API](./mitigation_strategies/secure_key_storage_and_data_protection_api.md)

**6. Mitigation Strategy: Secure Key Storage and Data Protection API**

*   **Description:**
    1.  **Identify Sensitive Data:** Determine data needing protection.
    2.  **Data Protection API:** Use the *ASP.NET Core Data Protection API* to encrypt and decrypt. This is a core ASP.NET Core feature.
    3.  **Secure Key Storage:** Use a secure key storage provider, integrating with ASP.NET Core's configuration system.
    4.  **Key Rotation:** Configure automatic key rotation within the ASP.NET Core Data Protection system.
    5. **Configuration:** Use `IConfiguration` to load secrets.

*   **List of Threats Mitigated:**
    *   **Data Breach (High Severity):** Mitigated by using ASP.NET Core's Data Protection API for encryption.
    *   **Key Compromise (High Severity):** Addressed by key rotation within the ASP.NET Core Data Protection framework.

*   **Impact:**
    *   **Data Breach:** Risk reduced from High to Medium/Low.
    *   **Key Compromise:** Risk reduced from High to Medium.

*   **Currently Implemented:** *[Placeholder]*

*   **Missing Implementation:** *[Placeholder]*

## Mitigation Strategy: [Set Request Size Limits](./mitigation_strategies/set_request_size_limits.md)

**7. Mitigation Strategy: Set Request Size Limits**

* **Description:**
    1. **Global Configuration:** Configure `MaxRequestBodySize` in your `Program.cs` or `Startup.cs` using Kestrel server options. This is an ASP.NET Core-specific configuration.
    2. **Per-Action/Controller Configuration:** Use the `[RequestSizeLimit]` attribute (an ASP.NET Core attribute) on specific actions or controllers.
    3. **Disable Request Size Limit (Rarely Needed):** Use the `[DisableRequestSizeLimit]` attribute (an ASP.NET Core attribute).
    4. **Handle Large Requests:** ASP.NET Core will return a `413 Payload Too Large` status code.

* **List of Threats Mitigated:**
    * **Denial of Service (DoS) (High Severity):** Mitigated by configuring request size limits within ASP.NET Core.
    * **Resource Exhaustion (Medium Severity):** Addressed by limiting request sizes in ASP.NET Core.

* **Impact:**
    * **DoS:** Risk reduced from High to Medium/Low.
    * **Resource Exhaustion:** Risk reduced from Medium to Low.

* **Currently Implemented:** *[Placeholder]*

* **Missing Implementation:** *[Placeholder]*

