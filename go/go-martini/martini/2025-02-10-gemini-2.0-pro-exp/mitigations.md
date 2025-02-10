# Mitigation Strategies Analysis for go-martini/martini

## Mitigation Strategy: [Explicit Middleware Configuration (Martini-Specific)](./mitigation_strategies/explicit_middleware_configuration__martini-specific_.md)

**Description:**
1.  **Avoid `martini.Classic()`:**  Do *not* use `martini.Classic()`. This is the core Martini-specific action.
2.  **Create `martini.Martini`:** Instantiate a `martini.Martini` object directly: `m := martini.New()`. This is the fundamental alternative to `Classic()`.
3.  **Add Middleware Selectively:**  Use `m.Use()` to add *only* the middleware you absolutely need.  This is about *how* you use the Martini API.  The *choice* of middleware is less Martini-specific.
    ```go
    m.Use(martini.Logger()) // Example: Using Martini's logger (if you must)
    m.Use(myCustomRecoveryMiddleware) // Replacing a Martini default
    // ... other middleware added via m.Use() ...
    ```
4.  **Configure Martini Middleware:** If using any built-in Martini middleware (like `martini.Logger` or `martini.Static`), configure them through their Martini-provided options. This is interacting directly with Martini's API.
5.  **Custom Recovery (Replacing Martini's Default):** Create a custom recovery middleware to *replace* `martini.Recovery`. This is a direct interaction with Martini's middleware system.

**Threats Mitigated:**
*   **Information Disclosure (Severity: Medium to High):**  Directly addresses the potential for `martini.Recovery` to expose sensitive information.
*   **Insecure Defaults (Severity: Variable):** Avoids using potentially insecure default configurations of Martini's built-in middleware.
*   **Directory Traversal (Severity: High):** Addresses potential issues with `martini.Static` *if* you choose to use it (though a separate web server is strongly recommended). This is about *how* you configure `martini.Static`, a Martini component.

**Impact:**
*   **Information Disclosure:** Significantly reduces risk by replacing the default recovery handler.
*   **Insecure Defaults:** Eliminates the risk of using Martini's potentially insecure defaults.
*   **Directory Traversal:** Reduces risk *if* `martini.Static` is used and configured correctly (via Martini's API).

**Currently Implemented:**
*   Example: "The application uses `martini.Martini` and explicitly adds middleware via `m.Use()`. A custom recovery middleware replaces `martini.Recovery` (in `middleware/recovery.go`). `martini.Static` is *not* used."
*   *Replace this with your project's details.*

**Missing Implementation:**
*   Example: "The application still uses `martini.Classic()` in some parts of the codebase.  These instances need to be refactored to use `martini.Martini` and explicit middleware."
*   *Replace this with your project's details.*

## Mitigation Strategy: [Strict Handler Signatures and Controlled Injection (Martini's Dependency Injection)](./mitigation_strategies/strict_handler_signatures_and_controlled_injection__martini's_dependency_injection_.md)

**Description:**
1.  **Precise Types in Handlers:** In your Martini handler functions, use the most specific Go types possible for parameters.  This directly interacts with how Martini's dependency injection works. Avoid `interface{}`.
2.  **Review `m.Map()` and `m.MapTo()`:** Carefully examine all uses of Martini's `m.Map()` and `m.MapTo()` functions. These are the core of Martini's injection mechanism. Understand precisely what is being injected and where.
3.  **Code Reviews (Martini Focus):** During code reviews, pay *extra* attention to any code that uses `m.Map()`, `m.MapTo()`, or defines Martini handler function signatures. This is about scrutinizing Martini-specific code.
4.  **Limit Injection Scope (Martini's `m.Use()`):** If possible, use Martini's routing features (e.g., route groups) to limit the scope of injected dependencies. Inject dependencies at the most specific level needed, rather than globally using `m.Map()` at the top level. This leverages Martini's routing to control injection.

**Threats Mitigated:**
*   **Type Confusion (Severity: Medium to High):**  Addresses potential issues arising from Martini's reflection-based injection and imprecise type usage.
*   **Injection of Untrusted Objects (Severity: High):**  Mitigates the risk of malicious objects being injected via Martini's `m.Map()` or `m.MapTo()`.

**Impact:**
*   **Type Confusion:** Reduces risk by making Martini's injection behavior more predictable.
*   **Injection of Untrusted Objects:** Reduces risk by ensuring careful control over what is injected via Martini's mechanisms.

**Currently Implemented:**
*   Example: "Handler functions generally use specific types. Code reviews include a checklist item specifically for reviewing Martini's `m.Map()` and `m.MapTo()` calls."
*   *Replace this with your project's details.*

**Missing Implementation:**
*   Example: "Some older handlers still use `interface{}` for parameters, bypassing Martini's type checking. A comprehensive review of all `m.Map()` and `m.MapTo()` calls is needed."
*   *Replace this with your project's details.*

## Mitigation Strategy: [Secure Routing (Martini's Route Definitions)](./mitigation_strategies/secure_routing__martini's_route_definitions_.md)

**Description:**
1.  **Specific Route Patterns:** When defining routes using Martini's `m.Get()`, `m.Post()`, `m.Put()`, `m.Delete()`, etc., use the most precise route patterns possible. Avoid overly broad patterns with excessive wildcards. This is about *how* you define routes *within* Martini.
2. **Avoid using `Params` directly:** Instead of using `Params` directly, use a dedicated validation library.

**Threats Mitigated:**
*   **Unexpected Handler Execution (Severity: Variable):**  Reduces the risk of unintended Martini handlers being executed due to overly broad route matching. This is specific to how Martini handles routes.
*   **Broken Access Control (Severity: Medium to High):** Precise routes can contribute to a more robust access control system, especially when combined with authentication and authorization middleware (though those are less Martini-specific).

**Impact:**
*   **Unexpected Handler Execution:** Improves the predictability of Martini's routing.
*   **Broken Access Control:** Contributes to a more secure application, though it's not a complete solution on its own.

**Currently Implemented:**
*   Example: "Routes are generally well-defined in `routes.go`, using specific patterns. A review was conducted to eliminate overly broad wildcards."
*   *Replace this with your project's details.*

**Missing Implementation:**
*   Example: "Some older routes still use broad patterns. A thorough review of all route definitions is needed to ensure they are as specific as possible, minimizing the use of wildcards."
*   *Replace this with your project's details.*

