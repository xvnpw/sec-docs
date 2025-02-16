# Attack Surface Analysis for yewstack/yew

## Attack Surface: [Uncontrolled Props and State](./attack_surfaces/uncontrolled_props_and_state.md)

*   **Description:**  Vulnerabilities arising from insufficient validation or sanitization of data passed as props to components or used in component state.  This is a *core* aspect of Yew's component model.
*   **Yew Contribution:** Yew's component-based architecture relies *entirely* on props and state for data flow. The framework provides the *mechanism* (props and state), but the *responsibility for validation and sanitization rests entirely with the developer*.
*   **Example:**
    *   A component accepts a `String` prop intended for display as text. An attacker provides a string containing `<script>alert('XSS')</script>`, which is directly rendered into the DOM *because the component doesn't use Yew's escaping features correctly*.
    *   A component uses a numeric prop as an array index without bounds checking, leading to a panic (DoS). This is a direct consequence of how Yew handles data within components.
*   **Impact:** Client-side XSS, Denial of Service (DoS), application logic errors, unexpected behavior.
*   **Risk Severity:** High to Critical (depending on the specific usage and impact).
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Strict Prop Validation:** Implement robust validation for *all* props, using Rust's type system and custom validation logic. This is *essential* in Yew.
        *   **Sanitization:** Sanitize any prop data used in HTML rendering, even if it *appears* safe. While Yew's `html!` macro *generally* handles escaping, be extra cautious with `innerHTML` or similar attributes, or when constructing HTML strings manually.  A dedicated HTML sanitization library might be necessary in complex cases.  *Understand how Yew handles escaping and where it might not be sufficient*.
        *   **Defensive State Updates:** Ensure state updates are triggered only by validated input and handle potential errors gracefully. Avoid directly modifying state based on raw user input. *This is crucial for preventing logic flaws within Yew's state management*.
        *   **Input validation:** Validate all data that is coming from user.

## Attack Surface: [Improper `unsafe` Code Usage](./attack_surfaces/improper__unsafe__code_usage.md)

*   **Description:** Memory safety vulnerabilities introduced by incorrect use of `unsafe` blocks, primarily when interacting with JavaScript APIs or low-level WebAssembly operations. This is directly related to how Yew interacts with the browser.
*   **Yew Contribution:** Yew *requires* `unsafe` for certain operations, particularly when interfacing with the browser's DOM and other JavaScript APIs through `web-sys` and `js-sys`.  The framework *necessitates* the use of `unsafe` in these cases.
*   **Example:**
    *   Incorrect pointer arithmetic within an `unsafe` block when manipulating DOM elements (accessed via `web-sys`, which Yew uses), leading to a memory access violation (crash).
    *   Failing to properly release resources allocated within an `unsafe` block (again, likely related to `web-sys` interaction), causing a memory leak.
*   **Impact:** Application crashes (DoS), *potential* for arbitrary code execution (though less likely in a browser context compared to native Rust, but still a high-severity risk), memory leaks.
*   **Risk Severity:** High to Critical.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Minimize `unsafe`:** Use Yew's abstractions (e.g., `html!`, component lifecycle methods, `Scope`) whenever possible to avoid direct `unsafe` code. *This is the primary defense*.
        *   **Isolate `unsafe`:** If `unsafe` is unavoidable (and it often is with Yew and `web-sys`), keep the `unsafe` blocks as small and self-contained as possible.
        *   **Thorough Review:** Carefully review *all* `unsafe` code for potential memory safety issues, pointer arithmetic errors, and resource leaks.
        *   **Use Safe Wrappers:** Prefer well-vetted libraries (like `web-sys` and `js-sys`) that provide safe wrappers around JavaScript APIs, but *understand that even these require careful usage*.  Don't assume they are inherently safe.
        *   **Testing:** Use tools like Miri to detect undefined behavior in `unsafe` code during testing.

## Attack Surface: [Insecure `web-sys` and `js-sys` Usage](./attack_surfaces/insecure__web-sys__and__js-sys__usage.md)

*   **Description:**  Vulnerabilities introduced by incorrect or insecure use of the `web-sys` and `js-sys` crates. This is *directly* tied to Yew's interaction with the browser.
*   **Yew Contribution:** Yew *relies heavily* on `web-sys` and `js-sys` for interacting with the browser.  These crates are *fundamental* to how Yew operates.
*   **Example:**
    *   Using `web-sys` to directly set `innerHTML` with unsanitized user input, leading to XSS. *This is a common pitfall when developers bypass Yew's `html!` macro*.
    *   Calling a JavaScript function through `js-sys` that is vulnerable to injection attacks (e.g., passing unsanitized data to `eval`).
*   **Impact:** XSS, manipulation of the DOM, potential for other JavaScript-based attacks.
*   **Risk Severity:** High.
*   **Mitigation Strategies:**
    *   **Developers:**
        *   **Prefer Yew Abstractions:** Use Yew's higher-level abstractions (e.g., `html!`, event handling) whenever possible, *instead of directly using `web-sys`*. This is the *most important mitigation*.
        *   **Sanitize Data:** Carefully sanitize *any* data passed to `web-sys` or `js-sys` functions, especially when dealing with user input or data from external sources.
        *   **Avoid `eval`:** Do not use `eval` or similar functions that execute arbitrary JavaScript code.
        *   **Understand API Security:** Be aware of the security implications of the specific `web-sys` and `js-sys` functions you are using. Consult the documentation and security best practices for those APIs. *Don't assume these crates are inherently safe*.

