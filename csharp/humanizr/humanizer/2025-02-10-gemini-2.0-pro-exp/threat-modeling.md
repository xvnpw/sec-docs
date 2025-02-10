# Threat Model Analysis for humanizr/humanizer

## Threat: [Culture Manipulation Leading to Misleading Dates](./threats/culture_manipulation_leading_to_misleading_dates.md)

*   **Threat:** Culture Manipulation Leading to Misleading Dates

    *   **Description:** An attacker manipulates the application's culture settings (e.g., through a crafted request or by exploiting a configuration vulnerability) to change the expected date format.  For example, they switch from `MM/DD/YYYY` to `DD/MM/YYYY`, causing users to misinterpret dates.
    *   **Impact:** Users make incorrect decisions based on misinterpreted dates, potentially leading to financial errors, scheduling conflicts, or other business-related problems.
    *   **Affected Component:** `DateTimeHumanizeExtensions.Humanize()`, `DateTimeOffsetHumanizeExtensions.Humanize()`, and any other date/time formatting methods that rely on the current culture.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Culture Control:** Do not allow user input to directly set the application's culture. Use a whitelist of allowed cultures.
        *   **Validation:** If user-specific cultures are necessary, validate them against a known-good list and sanitize them before use.
        *   **Default Culture:** Use a safe, default culture as a fallback.
        *   **Logging:** Log any changes to the application's culture settings.

## Threat: [Culture Manipulation Leading to Misleading Numbers](./threats/culture_manipulation_leading_to_misleading_numbers.md)

*   **Threat:** Culture Manipulation Leading to Misleading Numbers

    *   **Description:** An attacker manipulates the culture settings to change the decimal or thousands separator.  For example, they switch the decimal separator from `.` to `,`, causing users to misinterpret numeric values (e.g., 1.234 becoming 1,234).
    *   **Impact:** Users make incorrect calculations or decisions based on misinterpreted numbers, potentially leading to financial errors or data corruption.
    *   **Affected Component:** `NumberHumanizeExtensions.ToWords()`, `NumberHumanizeExtensions.Ordinalize()`, `NumberHumanizeExtensions.Format()`, and any other number formatting methods that rely on the current culture.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Culture Control:** Do not allow user input to directly set the application's culture. Use a whitelist of allowed cultures.
        *   **Validation:** If user-specific cultures are necessary, validate them against a known-good list and sanitize them before use.
        *   **Default Culture:** Use a safe, default culture as a fallback.
        *   **Logging:** Log any changes to the application's culture settings.

