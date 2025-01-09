# Attack Surface Analysis for kaminari/kaminari

## Attack Surface: [Unvalidated `per_page` Parameter (if enabled)](./attack_surfaces/unvalidated__per_page__parameter__if_enabled_.md)

* **Description:** If the application allows users to control the number of items displayed per page via a `per_page` parameter, lack of validation can lead to abuse.
* **How Kaminari Contributes:** Kaminari uses the `params[:per_page]` value (or a configured parameter name) to determine the `LIMIT` clause in database queries.
* **Example:** An attacker sends a request with `?per_page=9999`.
* **Impact:**
    * **Denial of Service (DoS):** Requesting an extremely large number of items can overload the database and the application server, potentially causing crashes or slowdowns for all users.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * **Input Validation:** Implement strict validation on the `per_page` parameter, ensuring it's a positive integer within a predefined, reasonable range.
    * **Whitelist Allowed Values:** Instead of arbitrary input, offer a dropdown or a limited set of predefined `per_page` options.
    * **Set Maximum Limit:** Enforce a hard maximum limit for the number of items per page on the server-side, regardless of user input.

## Attack Surface: [Insecure Link Generation leading to Client-Side Vulnerabilities](./attack_surfaces/insecure_link_generation_leading_to_client-side_vulnerabilities.md)

* **Description:** While Kaminari generates pagination links, vulnerabilities can arise if the application doesn't properly handle or sanitize data used in these links, potentially leading to client-side attacks.
* **How Kaminari Contributes:** Kaminari generates URLs with the `page` parameter (and potentially `per_page`), and the application's view layer uses this to create HTML links. If other parameters are included in the pagination links without proper encoding, it can be exploited.
* **Example:** An attacker manipulates other parameters in the URL (not directly the `page` parameter itself, but parameters that are part of the pagination link generation) that are then used unsafely in JavaScript or HTML on the page. For instance, if a `sort` parameter is reflected without encoding: `<a href="/items?page=2&sort=<script>alert('XSS')</script>">Next</a>`.
* **Impact:**
    * **Cross-Site Scripting (XSS):** Malicious scripts can be injected into the page, potentially stealing user credentials or performing other malicious actions.
* **Risk Severity:** High
* **Mitigation Strategies:**
    * **Proper Output Encoding/Escaping:** Ensure all data used in generating pagination links, including parameter values, is properly encoded or escaped in the view layer before being rendered in HTML to prevent XSS. Use framework-provided helpers for this (e.g., `h` in Rails).
    * **Content Security Policy (CSP):** Implement a strong CSP to mitigate the impact of potential XSS vulnerabilities.

