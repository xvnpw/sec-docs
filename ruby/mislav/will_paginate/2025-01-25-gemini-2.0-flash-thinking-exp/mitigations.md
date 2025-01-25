# Mitigation Strategies Analysis for mislav/will_paginate

## Mitigation Strategy: [Whitelist Allowed `per_page` Values](./mitigation_strategies/whitelist_allowed__per_page__values.md)

*   **Description:**
    1.  **Identify acceptable `per_page` values:** Determine a set of reasonable values for the number of items displayed per page based on UI design and performance considerations (e.g., 10, 20, 50, 100). These are the only `per_page` values your application will accept.
    2.  **Implement validation in the controller:** In your Rails controller action that uses `will_paginate`, add a validation step for the `params[:per_page]` value *before* passing it to `will_paginate`.
    3.  **Check against the whitelist:**  Compare the received `params[:per_page]` value against the predefined whitelist of allowed values.
    4.  **Reject invalid values:** If `params[:per_page]` is not in the whitelist, return an error (e.g., a `400 Bad Request` response) or default to a safe, predefined `per_page` value.  Do not pass the invalid value to `will_paginate`.
    5.  **Use validated value with `will_paginate`:** Only use the validated `per_page` value when calling `will_paginate` on your ActiveRecord relation.

*   **List of Threats Mitigated:**
    *   **DoS via Excessive `per_page` (High Severity):** Attackers attempting to overload the server by manipulating the `per_page` parameter to request an extremely large number of items per page, leading to resource exhaustion when `will_paginate` executes the query.

*   **Impact:**
    *   **DoS via Excessive `per_page`:** High reduction. This strategy directly prevents `will_paginate` from being used with excessively large `per_page` values, significantly mitigating the DoS threat.

*   **Currently Implemented:**
    *   Implemented in `app/controllers/products_controller.rb` in the `index` action.  The code checks if `params[:per_page]` is within `[10, 20, 50]` and defaults to `20` if invalid before using it with `will_paginate`.

*   **Missing Implementation:**
    *   Not yet implemented in `app/controllers/users_controller.rb` and `app/controllers/orders_controller.rb` index actions, which also use `will_paginate` and are vulnerable if they directly use unvalidated `params[:per_page]`.

## Mitigation Strategy: [Set a Maximum `per_page` Limit](./mitigation_strategies/set_a_maximum__per_page__limit.md)

*   **Description:**
    1.  **Define a maximum `per_page` value:** Determine the absolute maximum number of items that your application can reasonably handle per page without performance degradation. This limit will be enforced regardless of user input.
    2.  **Implement a check in the controller:** In your controller action, retrieve the `params[:per_page]` value.
    3.  **Compare with the maximum limit:** Check if the received `params[:per_page]` exceeds the defined maximum limit.
    4.  **Enforce the limit:** If `params[:per_page]` is greater than the maximum, either:
        *   Set `params[:per_page]` to the maximum limit *before* passing it to `will_paginate`.
        *   Return an error (e.g., `400 Bad Request`) indicating the limit has been exceeded and prevent the `will_paginate` call.
    5.  **Use the adjusted/validated value with `will_paginate`:** Proceed with pagination using the enforced `per_page` value in your `will_paginate` call.

*   **List of Threats Mitigated:**
    *   **DoS via Excessive `per_page` (High Severity):** Similar to whitelisting, this prevents excessively large page size requests from being processed by `will_paginate`.

*   **Impact:**
    *   **DoS via Excessive `per_page`:** High reduction.  Effectively limits the resource consumption when `will_paginate` is used, by preventing it from processing requests with large `per_page` values.

*   **Currently Implemented:**
    *   Implemented as a global application setting in `config/initializers/will_paginate.rb`.  A constant `MAX_PER_PAGE = 100` is defined, and controllers are *intended* to use this constant to limit `per_page` before using `will_paginate`.

*   **Missing Implementation:**
    *   While a global limit is set, individual controllers are not explicitly checking and enforcing this limit in their code *before* calling `will_paginate`. Reliance on developer discipline is weak. Explicit checks in each controller action *before* using `will_paginate` are needed for robust enforcement.

## Mitigation Strategy: [Sanitize and Validate `per_page` Input Type](./mitigation_strategies/sanitize_and_validate__per_page__input_type.md)

*   **Description:**
    1.  **Retrieve `per_page` parameter:** Get the `params[:per_page]` value in your controller.
    2.  **Sanitize input:** Remove any non-numeric characters from the input string *before* any further processing.
    3.  **Validate as integer:** Attempt to convert the sanitized input to an integer.
    4.  **Handle invalid input:** If the conversion to integer fails (e.g., input is still not a number after sanitization), treat it as invalid.  Default to a safe `per_page` value or return an error. Do not pass invalid types to `will_paginate`.
    5.  **Use validated integer with `will_paginate`:** Use the validated integer value for `per_page` when calling `will_paginate`.

*   **List of Threats Mitigated:**
    *   **DoS via Malformed `per_page` (Medium Severity):**  Attackers sending non-integer or malformed values for `per_page` that could potentially cause errors or unexpected behavior when `will_paginate` or the underlying database query processes it.

*   **Impact:**
    *   **DoS via Malformed `per_page`:** Medium reduction. Prevents errors caused by invalid input types being passed to `will_paginate` and potentially the database.

*   **Currently Implemented:**
    *   Implemented using Rails strong parameters in each controller action.  For example, `params.permit(:page, :per_page).tap { |p| p[:per_page] = p[:per_page].to_i if p[:per_page].present? }`. This attempts to convert `per_page` to integer before it's used with `will_paginate`.

*   **Missing Implementation:**
    *   The current implementation relies on `to_i`, which defaults to `0` if conversion fails. While technically safe for `will_paginate`, it might be better to explicitly check if the conversion was successful and handle non-numeric input more explicitly (e.g., return an error message or log the invalid input) *before* using it with `will_paginate`.

## Mitigation Strategy: [Validate `page` Input Type and Range](./mitigation_strategies/validate__page__input_type_and_range.md)

*   **Description:**
    1.  **Retrieve `page` parameter:** Get the `params[:page]` value in your controller.
    2.  **Sanitize input:** Remove any non-numeric characters.
    3.  **Validate as positive integer:** Convert to integer and ensure it is a positive integer (greater than 0).
    4.  **Handle invalid input:** If not a positive integer, default to page 1 or return an error. Do not pass invalid page numbers to `will_paginate`.
    5.  **Use validated integer with `will_paginate`:** Use the validated `page` value when calling `will_paginate`.
    6.  **(Optional) Implement upper bound check:**  If feasible, calculate or estimate a reasonable maximum page number based on data size.  Reject requests for excessively high page numbers *before* `will_paginate` attempts to process them.

*   **List of Threats Mitigated:**
    *   **DoS via Excessive `page` (Low to Medium Severity):**  Requesting extremely high page numbers can cause unnecessary database processing when `will_paginate` calculates pagination, even if the resulting page is empty.

*   **Impact:**
    *   **DoS via Excessive `page`:** Low to Medium reduction. Reduces unnecessary database load from very high page requests processed by `will_paginate`.

*   **Currently Implemented:**
    *   Partially implemented.  Rails strong parameters are used to permit `page` and `to_i` is used for conversion, similar to `per_page`.  However, there is no explicit check to ensure `page` is positive or to enforce an upper bound *before* using it with `will_paginate`.

*   **Missing Implementation:**
    *   Explicitly check if `page` is a positive integer after conversion and *before* passing it to `will_paginate`.
    *   Consider implementing a dynamic or static upper bound check for the `page` parameter, especially for very large datasets where extremely high page numbers are unlikely to be valid, and prevent `will_paginate` from processing such requests.

