# Threat Model Analysis for iced-rs/iced

## Threat: [Threat 1: Input Validation Bypass (Numeric Overflow/Underflow)](./threats/threat_1_input_validation_bypass__numeric_overflowunderflow_.md)

*   **Description:** An attacker provides an extremely large or small number to a `TextInput` field intended for numeric input, exceeding the expected range or causing an integer overflow/underflow in the application's logic *after* the value is parsed. This is *not* a memory safety issue (Rust prevents that), but a logical error.  The attacker exploits the lack of proper range checking *after* the string-to-number conversion within the Iced application's `update` function.
    *   **Impact:**
        *   Incorrect calculations.
        *   Unexpected application behavior.
        *   Potential denial of service (if the large number is used to allocate memory, for example).
        *   Data corruption (if the incorrect value is stored).
    *   **Iced Component Affected:**
        *   `iced::widget::TextInput` (and any custom widgets that handle numeric input).
        *   The application's `update` function, where the input is processed.
    *   **Risk Severity:** High (can lead to significant logic errors and potentially DoS).
    *   **Mitigation Strategies:**
        *   **Pre-Parse Validation:** Use `TextInput::on_input` to filter characters *as they are typed*, preventing non-numeric characters from being entered.
        *   **Post-Parse Validation:** In the `update` function, *after* parsing the string to a number (e.g., using `parse::<i32>()`), check if the resulting number is within the acceptable range.  Return an error or clamp the value if it's out of range.
        *   **Use Bounded Numeric Types:** If possible, use Rust's bounded numeric types (e.g., `u8`, `i32`, etc.) that match the expected range of the input.  This provides some compile-time protection, but *still requires runtime validation*.
        *   **Error Handling:** Provide clear error messages to the user if the input is invalid.

## Threat: [Threat 2: Event Loop Starvation (Blocking Operations)](./threats/threat_2_event_loop_starvation__blocking_operations_.md)

*   **Description:** The application performs a long-running, blocking operation (e.g., a network request, a large file read, a complex calculation) *within* the Iced `update` or `view` functions.  This directly violates Iced's architectural model, blocking the main event loop and making the UI unresponsive. The attacker triggers this by providing input that causes the application to execute this blocking code path.
    *   **Impact:**
        *   Application freeze (UI becomes unresponsive).
        *   Denial of service.
        *   Poor user experience.
    *   **Iced Component Affected:**
        *   The application's `update` and `view` functions.
        *   The entire Iced event loop (`iced::Application::run`).
    *   **Risk Severity:** High (directly impacts application usability).
    *   **Mitigation Strategies:**
        *   **Asynchronous Tasks:** Use Rust's `async`/`await` features and a suitable runtime (like `tokio`) to perform long-running operations in the background.
        *   **`Command::perform`:** Use `Command::perform` to spawn asynchronous tasks from the `update` function. This allows you to return a `Command` that represents the asynchronous operation, and Iced will handle it appropriately.
        *   **`Subscription`:** Use `Subscription` to listen for events from background tasks or external sources (e.g., network events).
        *   **Non-Blocking I/O:** Use non-blocking I/O operations whenever possible.
        *   **Progress Indicators:** If a long-running operation is unavoidable, display a progress indicator to the user to show that the application is still working.

## Threat: [Threat 3: Logic Error in Message Handling](./threats/threat_3_logic_error_in_message_handling.md)

* **Description:** The application's `update` function, a core part of the Iced architecture, incorrectly handles a specific message, leading to an unexpected state transition or incorrect behavior. The attacker might craft specific input sequences to trigger this incorrect message handling. This is a direct flaw in how the application uses Iced's message-passing system.
    * **Impact:**
        *   Incorrect application state.
        *   Unexpected UI behavior.
        *   Data corruption (if the incorrect state is persisted).
        *   Potential security vulnerabilities (if the incorrect state leads to a bypass of security checks).
    * **Iced Component Affected:**
        * The application's `update` function.
        * The message type definition.
    * **Risk Severity:** High (depending on the specific logic error, could lead to significant application misbehavior).
    * **Mitigation Strategies:**
        *   **Thorough Testing:** Write unit tests to cover all possible message types and state transitions.
        *   **Code Review:** Carefully review the `update` function logic, paying attention to message handling.
        *   **State Machine Design:** Consider using a formal state machine to manage complex state transitions.
        *   **Type Safety:** Use Rust's type system to enforce constraints on message types and data.

