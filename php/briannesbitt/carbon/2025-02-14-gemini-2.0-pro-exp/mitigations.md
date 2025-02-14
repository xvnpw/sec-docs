# Mitigation Strategies Analysis for briannesbitt/carbon

## Mitigation Strategy: [Strict Input Validation and Sanitization (Carbon-Specific)](./mitigation_strategies/strict_input_validation_and_sanitization__carbon-specific_.md)

*   **Description:**
    1.  **Identify Carbon Input Points:** Locate all instances where data is passed to Carbon's parsing functions: `Parse`, `CreateFromFormat`, `ParseFromLocale`, etc.
    2.  **Prioritize `CreateFromFormat`:** Replace `carbon.Parse(input)` with `carbon.CreateFromFormat("specific_format", input)`. Use the *most restrictive* format string possible.  Example: `"2006-01-02 15:04:05"` for a full date and time.  If multiple formats are unavoidable, use separate `CreateFromFormat` calls, trying the most restrictive first.
    3.  **Length Limits (Pre-Carbon):** *Before* calling any Carbon function, check the input string's length. Set a reasonable maximum based on the expected format.  Example: `if len(input) > 25 { return error("Input too long") }`.
    4.  **Whitelist Characters (Pre-Carbon, Optional):** If the format is highly constrained, use a regular expression *before* calling Carbon to ensure only allowed characters are present. Example (YYYY-MM-DD): `if !regexp.MustCompile(`^[0-9\-]+$`).MatchString(input) { return error("Invalid characters") }`.
    5.  **Carbon Error Handling:** *Always* check the error returned by Carbon's parsing functions (e.g., `_, err := carbon.CreateFromFormat(...)`).  Handle errors:
        *   Log the error (including the input).
        *   Return a user-friendly error.
        *   *Never* use the `Carbon` object if an error occurred. Use a default or fallback.
    6.  **Post-Carbon Validation:** After successful parsing by Carbon, if the date/time is used in a security-sensitive context, perform additional validation:
        *   Check for reasonable date ranges.
        *   Ensure logical consistency within the application.

*   **List of Threats Mitigated:**
    *   **Denial of Service (DoS) via Carbon Panic (Severity: Medium):** Malformed input could cause Carbon's parsing to panic. Strict format and length limits prevent this.
    *   **Unexpected Behavior/Logic Errors (Severity: Low to Medium):** Lenient parsing could lead to misinterpretations. Strict format enforcement ensures consistency.
    *   **Potential Code Injection (Severity: Very Low, Indirect):** While unlikely, if the *output* of Carbon is used unsafely (e.g., in a SQL query without escaping – a separate vulnerability), strict input validation provides a defense-in-depth layer.

*   **Impact:**
    *   **DoS via Panic:** Risk significantly reduced.
    *   **Unexpected Behavior:** Risk significantly reduced.
    *   **Potential Code Injection:** Risk remains very low, but slightly reduced.

*   **Currently Implemented:**
    *   Example: `controllers/user.go` uses `CreateFromFormat` and length limits for user registration dates.

*   **Missing Implementation:**
    *   Example: `/admin/reports` uses `Parse` and lacks length limits. Needs `CreateFromFormat` and validation.
    *   Example: Date parsing from `config/settings.yaml` uses `Parse`; change to `CreateFromFormat`.

## Mitigation Strategy: [Explicit and Consistent Timezone Handling (Carbon-Specific)](./mitigation_strategies/explicit_and_consistent_timezone_handling__carbon-specific_.md)

*   **Description:**
    1.  **Identify Carbon Timezone Usage:** Find all code using Carbon, especially `Parse`, `Now`, `Create`, and timezone methods.
    2.  **UTC Internally:** Store dates/times in the database and perform internal calculations in UTC. Use `carbon.UTC`.
    3.  **Explicit Timezone on Input (with Carbon):** When parsing with Carbon, *always* specify the timezone:
        *   If the user provides a timezone, validate it against IANA timezone identifiers (e.g., "America/Los_Angeles").
        *   If no user timezone, use a documented default or require the user to provide one.
        *   Use `carbon.Parse(input, userTimezone)` or `carbon.CreateFromFormat(format, input, userTimezone)`, where `userTimezone` is validated.
    4.  **Explicit Timezone on Output (with Carbon):** When displaying dates/times, convert from UTC to the user's timezone (or a default display timezone) using `carbon.Timezone(userTimezone)`.
    5.  **Carbon Default Timezone:** Set a default application timezone using `carbon.SetTimezone("UTC")` (or another appropriate default) at application startup. This ensures consistent behavior if no timezone is explicitly provided in other parts of the code.

*   **List of Threats Mitigated:**
    *   **Data Corruption/Inconsistency (Severity: Medium):** Inconsistent timezones lead to incorrect data.
    *   **Logic Errors (Severity: Medium):** Incorrect timezone conversions cause errors in calculations.
    *   **Information Disclosure (Severity: Low):** Displaying incorrect timezones can reveal server location or user timezone.
    * **Timezone Confusion Attacks (Severity: Low to Medium):** If user is allowed to provide timezone, and it is not validated, attacker can provide invalid timezone.

*   **Impact:**
    *   **Data Corruption/Inconsistency:** Risk significantly reduced.
    *   **Logic Errors:** Risk significantly reduced.
    *   **Information Disclosure:** Risk reduced.
    * **Timezone Confusion Attacks:** Risk is eliminated.

*   **Currently Implemented:**
    *   Example: Database uses UTC timestamps.
    *   Example: User profiles validate timezone selections.

*   **Missing Implementation:**
    *   Example: `/api/schedule` doesn't explicitly handle timezones on input.
    *   Example: Some logs use the server's default timezone instead of UTC.

## Mitigation Strategy: [Safe Time-Based Calculations (Carbon-Specific)](./mitigation_strategies/safe_time-based_calculations__carbon-specific_.md)

*   **Description:**
    1.  **Identify Calculations:** Find all code performing time calculations.
    2.  **Use Carbon's Methods Exclusively:** Replace manual calculations with Carbon's methods:
        *   `Add...` (e.g., `AddDay`, `AddHours`).
        *   `Sub...` (e.g., `SubDay`, `SubHours`).
        *   `Diff...` (e.g., `DiffInDays`, `DiffForHumans`).
    3.  **DST Awareness (with Carbon):** Be mindful of DST transitions. Use Carbon's `IsDST()` to check. Test around DST boundaries.
    4.  **Carbon Comparison Methods:** Use Carbon's comparison methods: `IsBefore`, `IsAfter`, `EqualTo`. Avoid direct comparisons like `timestamp1 < timestamp2`.
    5. **Leap Second Consideration (with Carbon):** If high precision is needed, be aware of leap seconds. Carbon handles them, but synchronization with external systems might require extra logic.

*   **List of Threats Mitigated:**
    *   **Logic Errors (Severity: Medium):** Incorrect calculations due to mishandling DST, leap seconds, or anomalies.
    *   **Off-by-One Errors (Severity: Low to Medium):** Incorrect durations or intervals.

*   **Impact:**
    *   **Logic Errors:** Risk significantly reduced.
    *   **Off-by-One Errors:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Example: `utils/time.go` uses `AddDays` in `calculateExpirationDate`.

*   **Missing Implementation:**
    *   Example: `/admin/suspend` calculates duration manually; use Carbon methods.
    *   Example: Some unit tests lack DST transition coverage.

## Mitigation Strategy: [Consistent Localization (Carbon-Specific)](./mitigation_strategies/consistent_localization__carbon-specific_.md)

*   **Description:**
    1.  **Identify Localization Points:** Find all code displaying dates/times to users.
    2.  **Use Carbon's Localization:** Use `carbon.SetLocale()` and `carbon.Translate()` (or the `FormatLocalized` method) to display dates/times in the user's locale.
    3.  **Locale Input Validation:** If users select their locale, validate against supported locales.
    4.  **Consistent Formatting (with Carbon):** Use consistent formats throughout the application. Define a default display format using a configuration setting, and use Carbon's formatting methods (e.g., `Format`, `To...String`) consistently.

*   **List of Threats Mitigated:**
    *   **Data Entry Errors (Severity: Low):** Incorrectly formatted dates can lead to user confusion and errors.
    *   **Usability Issues (Severity: Low):** Inconsistent localization makes the application harder to use.

*   **Impact:**
    *   **Data Entry Errors:** Risk reduced.
    *   **Usability Issues:** Improved user experience.

*   **Currently Implemented:**
    *   Example: User profile page uses localized date displays.

*   **Missing Implementation:**
    *   Example: Error messages with dates are not localized.
    *   Example: Admin dashboard uses a hardcoded format.

