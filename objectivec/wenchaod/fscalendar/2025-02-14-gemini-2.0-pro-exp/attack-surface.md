# Attack Surface Analysis for wenchaod/fscalendar

## Attack Surface: [Cross-Site Scripting (XSS) via Event Data](./attack_surfaces/cross-site_scripting__xss__via_event_data.md)

*   **Description:**  Injection of malicious JavaScript code into event data (titles, descriptions) displayed on the calendar.
*   **FSCalendar Contribution:** `FSCalendar` provides the *display mechanism* for event data.  While it doesn't directly handle the *content*, its role in displaying the data makes it a crucial part of the attack vector if the application fails to sanitize the input.
*   **Example:** An attacker creates an event with the title: `<script>alert('XSS');</script>`. If this title is displayed without escaping, the JavaScript will execute when another user views the calendar, facilitated by `FSCalendar`'s rendering.
*   **Impact:**  Compromise of user accounts, session hijacking, data theft, website defacement, phishing attacks.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Developer:** Implement robust HTML sanitization on *all* event data *before* it is used by `FSCalendar`. Use a well-vetted sanitization library (e.g., DOMPurify). *Never* trust user-supplied data.
    *   **Developer:** Implement a strong Content Security Policy (CSP) to restrict script execution.

## Attack Surface: [Denial of Service (DoS) via Delegate/DataSource Overload](./attack_surfaces/denial_of_service__dos__via_delegatedatasource_overload.md)

*   **Description:**  Overwhelming the application by triggering excessive calls to `FSCalendar`'s delegate or data source methods, or by providing large amounts of data to these methods.
*   **FSCalendar Contribution:** `FSCalendar` *directly* relies on delegate and data source methods for its functionality and customization.  The design of these methods and how the application implements them directly impacts the vulnerability.
*   **Example:**  If a `FSCalendar` delegate method performs a database query every time a date is selected, an attacker could rapidly select many dates, causing numerous database queries and potentially overwhelming the server.
*   **Impact:**  Application slowdown, unresponsiveness, or complete unavailability.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:**  Optimize `FSCalendar` delegate and data source methods for performance. Avoid expensive operations within these methods. Implement caching.
    *   **Developer:**  Implement rate limiting to restrict the frequency of calls to `FSCalendar`'s delegate/data source methods.
    *   **Developer:** Implement input validation on data passed to `FSCalendar`'s delegate/data source methods.

