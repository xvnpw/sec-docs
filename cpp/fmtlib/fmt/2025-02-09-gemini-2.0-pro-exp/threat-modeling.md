# Threat Model Analysis for fmtlib/fmt

## Threat: [Format String Injection (Information Disclosure)](./threats/format_string_injection__information_disclosure_.md)

*   **Threat:** Format String Injection (Information Disclosure)

    *   **Description:** An attacker provides a crafted format string as input to the application.  Instead of treating it as literal text, the application passes this attacker-controlled string to a `fmtlib/fmt` formatting function (e.g., `fmt::format`, `fmt::print`, `fmt::sprintf`). The attacker uses format specifiers like `%p`, `%x`, `%s`, `%n` (extremely dangerous), etc., to read data from the application's memory (stack, heap, or other locations).
    *   **Impact:**
        *   **Information Disclosure:** Leakage of sensitive data, including passwords, API keys, internal application state, memory addresses, and potentially the contents of arbitrary memory locations.
        *   **Potential for Code Execution (Rare, but possible):** In some, very specific, and complex scenarios, using `%n` (which writes to memory) *might* be leveraged to overwrite critical data structures and eventually gain code execution, although this is significantly harder to achieve than information disclosure.
    *   **Affected Component:**
        *   `fmt::format`
        *   `fmt::print`
        *   `fmt::fprintf`
        *   `fmt::sprintf`
        *   `fmt::vformat`
        *   `fmt::vprint`
        *   `fmt::vfprintf`
        *   `fmt::vsprintf`
        *   Any function that accepts a format string as an argument.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Primary Mitigation:** *Never* allow user-supplied input to directly or indirectly control the format string. Format strings *must* be hardcoded constants.
        *   **Input Validation (Secondary):** Even if user input is used as an *argument* to a format string (which is the safe way), rigorously validate and sanitize that input to prevent other types of attacks (e.g., XSS if the output is displayed in a web page).
        *   **Compiler Warnings:** Enable and treat as errors all compiler warnings related to format string vulnerabilities (e.g., `-Wformat-security` in GCC/Clang).
        *   **Static Analysis:** Use static analysis tools (e.g., linters, code scanners) that can detect format string vulnerabilities.
        *   **Code Review:**  Manually review code for any instances where user input might influence a format string.

## Threat: [Format String Injection (Denial of Service)](./threats/format_string_injection__denial_of_service_.md)

*   **Threat:** Format String Injection (Denial of Service)

    *   **Description:** An attacker provides a format string with excessively large field width or precision specifiers (e.g., `%1000000s`, `%.1000000f`).  The `fmtlib/fmt` library attempts to allocate memory to accommodate these specifications, potentially leading to excessive memory consumption or CPU usage.
    *   **Impact:**
        *   **Denial of Service:** The application becomes unresponsive or crashes due to resource exhaustion (memory or CPU).
    *   **Affected Component:**
        *   `fmt::format`
        *   `fmt::print`
        *   `fmt::fprintf`
        *   `fmt::sprintf`
        *   `fmt::vformat`
        *   `fmt::vprint`
        *   `fmt::vfprintf`
        *   `fmt::vsprintf`
        *   Any function that accepts a format string as an argument.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Primary Mitigation:** *Never* allow user-supplied input to directly or indirectly control the format string.
        *   **Input Validation (Secondary):** If user input is used as an *argument*, validate its length and content to prevent excessively large values.
        *   **Resource Limits:** Implement resource limits (e.g., memory limits) on the application to prevent it from consuming excessive resources.
        *   **Testing:** Perform stress testing with large field widths and precisions to identify potential vulnerabilities.

