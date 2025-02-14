# Threat Model Analysis for briannesbitt/carbon

## Threat: [System Time Manipulation via `setTestNow()`](./threats/system_time_manipulation_via__settestnow___.md)

*   **Threat:** System Time Manipulation via `setTestNow()`

    *   **Description:** An attacker provides crafted input (e.g., through a hidden form field, URL parameter, or manipulated API request) that is ultimately used, directly or indirectly, to call `Carbon::setTestNow()` with a malicious date/time value.  This changes the application's perception of "now" for all subsequent Carbon operations.  This is a *direct* misuse of a Carbon function.
    *   **Impact:**
        *   Bypass time-based access controls (e.g., accessing content outside of allowed hours).
        *   Trigger premature or delayed execution of scheduled tasks.
        *   Corrupt data integrity by recording incorrect timestamps.
        *   Manipulate financial transactions or reporting based on time.
    *   **Carbon Component Affected:** `Carbon::setTestNow()` function, and any functionality relying on the current time (`Carbon::now()`, `Carbon::today()`, etc.).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strictly prohibit** the use of `Carbon::setTestNow()` in production code based on *any* user-supplied input.  This function should be *exclusively* for testing.
        *   Implement robust input validation and sanitization to prevent any user-controlled data from influencing the system's time.
        *   If a "testing mode" is absolutely required in a production-like environment, use a highly restricted, authenticated, and auditable mechanism *completely separate* from normal user input channels.

## Threat: [Timezone Manipulation via User Input](./threats/timezone_manipulation_via_user_input.md)

*   **Threat:** Timezone Manipulation via User Input

    *   **Description:** An attacker provides a malicious or unexpected timezone string (e.g., "Evil/Timezone", or a timezone with extreme offsets) through a form field, API parameter, or other input vector. This timezone is then used in Carbon operations like `Carbon::parse()`, `Carbon::createFromFormat()`, or when setting the timezone on a Carbon instance. This directly impacts how Carbon interprets and processes date/time data.
    *   **Impact:**
        *   Incorrect date/time calculations, leading to data corruption or logic errors.
        *   Circumventing time-based restrictions by shifting the perceived time.
        *   Potential denial-of-service if an extremely complex or invalid timezone is processed (though this is less likely to be *directly* exploitable through Carbon alone, it's a consequence of using the input with Carbon).
        *   Information disclosure if timezone handling reveals server location or configuration (again, less direct, but a consequence of the misuse).
    *   **Carbon Component Affected:**  `Carbon::parse()`, `Carbon::createFromFormat()`, `setTimezone()` method, and any functions that accept a timezone argument.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strictly validate** user-provided timezone input against a whitelist of known, safe timezone identifiers (IANA timezone database names, e.g., "America/Los_Angeles").  *Never* allow arbitrary strings.
        *   Use a configuration setting to define the application's default timezone, and avoid relying on the server's default timezone.
        *   Store user timezones in a validated, secure format (e.g., database field with a limited set of allowed values).
        *   Convert all dates and times to UTC for internal storage and calculations, converting to user-specific timezones only for display.

## Threat: [Malformed Date String Parsing (DoS)](./threats/malformed_date_string_parsing__dos_.md)

*   **Threat:** Malformed Date String Parsing (DoS)

    *   **Description:** An attacker submits an extremely long, complex, or intentionally malformed date/time string to a function like `Carbon::parse()` or `Carbon::createFromFormat()`. This causes excessive CPU and memory consumption within the Carbon library, potentially leading to a denial-of-service. This is a direct attack on Carbon's parsing capabilities.
    *   **Impact:**
        *   Application becomes unresponsive or crashes.
        *   Other users are unable to access the application.
        *   Potential resource exhaustion on the server.
    *   **Carbon Component Affected:** `Carbon::parse()`, `Carbon::createFromFormat()`, and other parsing functions.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement **strict input validation** to limit the length and allowed characters of date/time strings *before* passing them to Carbon.  Use regular expressions to enforce expected formats.
        *   Set a **timeout** on Carbon parsing operations to prevent them from running indefinitely.
        *   Implement **rate limiting** to prevent an attacker from submitting a large number of malformed date strings in a short period.
        *   Use a well-defined date/time format (e.g., ISO 8601) whenever possible, and avoid relying on Carbon's "fuzzy" parsing capabilities for user-supplied input.

## Threat: [Unsafe usage of `createFromFormat`](./threats/unsafe_usage_of__createfromformat_.md)

* **Threat:** Unsafe usage of `createFromFormat`

    *   **Description:** An attacker can control the format string passed to `createFromFormat`, potentially leading to unexpected behavior or vulnerabilities. If the attacker can inject format specifiers, they might be able to influence the parsing process in unintended ways.
    *   **Impact:**
        *   Unexpected date/time interpretation.
        *   Potential for format string vulnerabilities if the format string is used in other contexts (although less likely directly within Carbon, the misuse creates the vulnerability).
    *   **Carbon Component Affected:** `Carbon::createFromFormat()`
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Never** allow user input to directly control the format string passed to `createFromFormat`. Use predefined, static format strings.
        *   If the format needs to be dynamic, generate it programmatically based on a strictly controlled set of options, and thoroughly validate the generated format string before using it.  Ensure no user-supplied data can influence the format specifiers.

