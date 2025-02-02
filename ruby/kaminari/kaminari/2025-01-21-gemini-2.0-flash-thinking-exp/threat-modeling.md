# Threat Model Analysis for kaminari/kaminari

## Threat: [Malicious Per-Page Input](./threats/malicious_per-page_input.md)

**Description:** An attacker manipulates the `per_page` parameter in the URL, providing non-integer values, negative numbers, zero, or excessively large numbers. This directly impacts Kaminari's query generation and pagination logic.

**Impact:**
*   Application errors or exceptions due to Kaminari attempting to process invalid input.
*   Excessive database load caused by Kaminari generating queries to retrieve a very large number of records.
*   Memory exhaustion on the server if Kaminari or the application attempts to process and render an extremely large number of items.

**Affected Kaminari Component:**
*   `Kaminari::Helpers::Paginator#page_tag` (indirectly, as it uses the `per_page` parameter).
*   `Kaminari::ActionViewExtension#paginate` (indirectly, as it relies on the `per_page` parameter).
*   The underlying database adapter's query building logic *as invoked by Kaminari*.

**Risk Severity:** High

**Mitigation Strategies:**
*   **Server-side Input Validation:** Implement strict validation on the `per_page` parameter in the controller *before* it is passed to Kaminari, ensuring it is a positive integer within an acceptable and predefined range.
*   **Whitelist Allowed Values:** Define a set of allowed `per_page` values and only accept those, preventing Kaminari from processing unexpected values.
*   **Set Maximum Limit:** Configure Kaminari with a reasonable maximum value for `per_page` using `Kaminari.config.max_per_page = ...`.

## Threat: [Tampering with Pagination Links](./threats/tampering_with_pagination_links.md)

**Description:** An attacker modifies the `page` or `per_page` parameters within the HTML pagination links generated by Kaminari. This directly targets the parameters Kaminari uses for pagination.

**Impact:**
*   Unauthorized access to data on different pages if the application relies solely on these parameters without server-side verification.
*   Potential for triggering application errors or unexpected behavior if Kaminari receives manipulated values.

**Affected Kaminari Component:**
*   `Kaminari::Helpers::Paginator#page_tag` (generates the links).
*   `Kaminari::ActionViewExtension#paginate` (uses the paginator to generate links).

**Risk Severity:** Medium *(While the impact can be high, the direct involvement of Kaminari is in generating the links, the vulnerability lies in the application's reliance on them. However, to meet the criteria of *directly involving* Kaminari, and considering potential for high impact if not handled, we'll keep it)*

**Mitigation Strategies:**
*   **Server-side Validation:** Always validate the `page` and `per_page` parameters on the server-side *after* they are received from the request, regardless of the values in the links generated by Kaminari.
*   **Signed Pagination Links:** Consider using signed or encrypted parameters in the pagination links generated by Kaminari. This can be implemented by extending Kaminari's link generation or using a separate helper.

## Threat: [Improper Integration with Authorization](./threats/improper_integration_with_authorization.md)

**Description:** Pagination is implemented without proper consideration for authorization. An attacker might be able to bypass access controls by manipulating the `page` parameter, which Kaminari uses to determine the data to retrieve. While the authorization flaw isn't in Kaminari itself, the way Kaminari facilitates data retrieval across pages makes it a key component in this attack vector.

**Impact:**
*   Unauthorized access to sensitive data that should not be accessible to the user on certain pages.
*   Circumvention of intended access controls by navigating through paginated data.

**Affected Kaminari Component:**
*   The core pagination logic within Kaminari that determines which records to fetch based on the `page` parameter.
*   Indirectly, `Kaminari::Helpers::Paginator` and `Kaminari::ActionViewExtension` as they facilitate navigation.

**Risk Severity:** Critical

**Mitigation Strategies:**
*   **Enforce Authorization on Each Page Request:** Ensure that authorization checks are performed *before* Kaminari fetches data for a specific page, verifying that the user has permission to access the data on that page.
*   **Filter Data Before Pagination:** Apply authorization filters to the dataset *before* passing it to Kaminari for pagination, ensuring that only authorized data is considered for pagination.

