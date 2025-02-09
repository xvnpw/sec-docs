# Attack Surface Analysis for fmtlib/fmt

## Attack Surface: [Uncontrolled Format String](./attack_surfaces/uncontrolled_format_string.md)

An attacker can control the format string passed to a `fmt` formatting function. This is the most dangerous vulnerability associated with format string handling.

*   **How fmt Contributes:** `fmtlib/fmt` provides the mechanism for interpreting format strings. The vulnerability arises from *misuse* of this mechanism, by allowing user input to dictate the format string.
*   **Example:**
    ```c++
    std::string userInput = get_user_input(); // Assume this gets "%p %p %p %p"
    fmt::print(userInput, 1, 2, 3); // Vulnerable! User controls the format string.
    ```
*   **Impact:**
    *   Information Disclosure (leaking memory addresses, stack contents)
    *   Denial of Service (crashing the application)
    *   Arbitrary Code Execution (extremely unlikely with default `fmtlib/fmt` settings, but theoretically possible with misconfiguration and combined with other vulnerabilities)
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Never use user input directly as the format string.** This is the paramount rule.
    *   **Use static, predefined format strings:** `fmt::print("Value: {}\n", user_input);` (Safe)
    *   **Leverage compile-time checking:** Use `fmt::format` with string literals to enable compile-time verification of format specifiers and arguments. This is a *major* security benefit of `fmtlib/fmt`.
    *   **Input Validation:** Even when using user input as *arguments*, validate and sanitize it.

## Attack Surface: [Indirect Format String Control](./attack_surfaces/indirect_format_string_control.md)

The attacker doesn't directly provide the format string, but they can influence which pre-existing format string is chosen.

*   **How fmt Contributes:** `fmtlib/fmt` provides the formatting functionality. The vulnerability lies in how the application selects the format string based on (potentially malicious) user input.
*   **Example:**
    ```c++
    std::map<std::string, std::string> formatStrings = {
        {"normal", "Value: {}}",
        {"debug", "Value: {}, Address: %p"} // Potentially dangerous
    };
    std::string userInput = get_user_input(); // Assume this gets "debug"
    if (formatStrings.count(userInput)) {
        fmt::print(formatStrings[userInput], someValue); // Vulnerable if userInput is attacker-controlled
    }
    ```
*   **Impact:** Same as Uncontrolled Format String (Information Disclosure, DoS, potentially ACE in extreme cases).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Whitelisting:** If format strings must be selected dynamically, use a *very* strict whitelist of known-safe format strings. Do *not* allow arbitrary keys in the lookup table.
    *   **Avoid Dynamic Selection:** Prefer static format strings whenever possible. If dynamic selection is unavoidable, derive the selection from a trusted source, *not* directly from user input.
    *   **Input Validation:** Rigorously validate any input that influences the choice of format string.

