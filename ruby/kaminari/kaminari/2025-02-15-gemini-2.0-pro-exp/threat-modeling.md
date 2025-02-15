# Threat Model Analysis for kaminari/kaminari

## Threat: [Parameter Manipulation - `per_page` Overflow](./threats/parameter_manipulation_-__per_page__overflow.md)

*   **Threat 1: Parameter Manipulation - `per_page` Overflow**

    *   **Description:** An attacker modifies the `per_page` parameter in the URL to a very large number (e.g., `per_page=1000000`). The goal is to force the application to retrieve a massive number of records from the database in a single request, overwhelming the server.
    *   **Impact:**
        *   Severe performance degradation or denial-of-service (DoS) due to excessive database load.
        *   Potential memory exhaustion on the server.
    *   **Kaminari Component Affected:**
        *   `Kaminari::PageScopeMethods#per`: This method determines the number of records per page and is directly influenced by the user-supplied `per_page` parameter.
        *   `Kaminari::Configuration`: The default `per_page` value and any configured maximum `per_page` limit are relevant, but the vulnerability exists because Kaminari *accepts* the parameter without inherent validation.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict Input Validation:** Validate the `per_page` parameter in the controller to ensure it's a positive integer and within a strict, pre-defined limit (e.g., 100 or 200).  Reject any values exceeding this limit.  Do *not* rely solely on Kaminari's configuration.
        *   **Configuration:** Set a reasonable default `per_page` value (e.g., 25) and a hard maximum `per_page` limit in the Kaminari configuration (`config.max_per_page = 100`). This provides a fallback, but controller-level validation is crucial.
        *   **Rate Limiting (Additional Layer):** Consider implementing rate limiting at the application or infrastructure level to prevent abuse of pagination parameters, even if validation is in place.

## Threat: [Parameter Manipulation - Page Number Overflow (DoS Potential)](./threats/parameter_manipulation_-_page_number_overflow__dos_potential_.md)

*   **Threat 2: Parameter Manipulation - Page Number Overflow (DoS Potential)**

    *   **Description:** An attacker modifies the `page` parameter in the URL to an extremely large number (e.g., `page=999999999`). While Kaminari might handle this internally to some extent (by returning an empty result set), the underlying database query *could* still be executed, potentially leading to performance issues if the query is not optimized.
    *   **Impact:**
        *   Potential denial-of-service (DoS) if the application attempts to process an excessively large page number, especially if the underlying database query is inefficient.  This is less severe than the `per_page` overflow, but still a concern.
        *   Exposure of internal error messages (less likely with proper error handling, but still a possibility).
    *   **Kaminari Component Affected:**
        *   `Kaminari::PageScopeMethods#page`: This method is responsible for retrieving the requested page of records. It relies on the `page` parameter. Kaminari's internal handling might mitigate *some* impact, but the underlying query is still triggered.
        *   `Kaminari::Configuration`: The default configuration might not have limits on the maximum page number.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Input Validation:** In the controller, validate that the `page` parameter is a positive integer and within a reasonable range (e.g., less than 1000, or a value based on the expected maximum number of pages). This is crucial to prevent excessively large page numbers.
        *   **Default Value:** Ensure a default `page` value of 1 is used if no `page` parameter is provided or if it's invalid.
        *   **Error Handling:** Implement robust error handling to gracefully handle invalid `page` values. Return a 400 Bad Request or redirect to the first page instead of crashing or revealing internal errors.
        * **Query Optimization:** Ensure that the database queries used for pagination are optimized to handle large page numbers efficiently, even if they result in empty result sets. This might involve using appropriate indexes and avoiding unnecessary calculations.

