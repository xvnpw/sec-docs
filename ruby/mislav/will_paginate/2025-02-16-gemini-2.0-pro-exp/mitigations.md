# Mitigation Strategies Analysis for mislav/will_paginate

## Mitigation Strategy: [Limit Maximum Page Number](./mitigation_strategies/limit_maximum_page_number.md)

*   **Description:**
    1.  **Identify Pagination Controllers:** Locate all controller actions that use `will_paginate` to display paginated results (search for `.paginate`).
    2.  **Define a Constant:** Create a constant (e.g., `MAX_PAGE`) to store the maximum allowed page number.
    3.  **Implement the Check:** Before calling `.paginate`, retrieve and convert the `page` parameter (`params[:page]`) to an integer.
    4.  **Enforce the Limit:**
        *   If `page <= 0`, set `page = 1`.
        *   If `page > MAX_PAGE`, set `page = MAX_PAGE`.
    5.  **Pass the Sanitized Value:** Pass the sanitized `page` value to the `.paginate` method.
    6.  **Test:** Test with edge cases (page 0, 1, `MAX_PAGE`, `MAX_PAGE + 1`).

*   **Threats Mitigated:**
    *   **Excessive Page Number Requests (Denial of Service / Performance Degradation):** Severity: High.
    *   **Information Disclosure (Leaking Total Count - Indirectly):** Severity: Low.

*   **Impact:**
    *   **Excessive Page Number Requests:** Risk significantly reduced.
    *   **Information Disclosure:** Risk slightly reduced.

*   **Currently Implemented:**
    *   Example: Implemented in `app/controllers/products_controller.rb` (`index` action). `MAX_PAGE` in `app/controllers/application_controller.rb`.

*   **Missing Implementation:**
    *   Example: Missing in `app/controllers/admin/users_controller.rb` (`index` action).

## Mitigation Strategy: [Validate `per_page` Parameter](./mitigation_strategies/validate__per_page__parameter.md)

*   **Description:**
    1.  **Identify Pagination Controllers:** Locate controller actions using `.paginate`.
    2.  **Define a Constant:** Create a constant (e.g., `MAX_PER_PAGE`).
    3.  **Implement the Check:** Before calling `.paginate`, retrieve and convert `params[:per_page]` to an integer.
    4.  **Enforce the Limit:**
        *   If `per_page <= 0`, set `per_page` to a default (e.g., 20).
        *   If `per_page > MAX_PER_PAGE`, set `per_page = MAX_PER_PAGE`.
    5.  **Pass the Sanitized Value:** Pass the sanitized `per_page` to `.paginate`.
    6.  **Test:** Test with various `per_page` values, including edge cases.

*   **Threats Mitigated:**
    *   **Excessive Data Retrieval (Denial of Service / Performance Degradation):** Severity: High.

*   **Impact:**
    *   **Excessive Data Retrieval:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Example: Implemented in `app/controllers/products_controller.rb` and `app/controllers/articles_controller.rb`. `MAX_PER_PAGE` in `config/initializers/pagination.rb`.

*   **Missing Implementation:**
    *   Example: Missing in `app/controllers/search_controller.rb`.

## Mitigation Strategy: [Disable Total Count Calculation (if not needed)](./mitigation_strategies/disable_total_count_calculation__if_not_needed_.md)

*   **Description:**
    1.  **Identify Pagination Views:** Locate views where `will_paginate`'s helper is used.
    2.  **Analyze UI Requirements:** Determine if the exact total count is *essential*.
    3.  **Customize the Renderer:** Create a custom renderer for `will_paginate` that *doesn't* include the total count.  Inherit from `WillPaginate::ActionView::LinkRenderer` and override methods like `total_pages` and `html_container`.
    4.  **Configure `will_paginate`:** In your view, use the `:renderer` option with the `will_paginate` helper to specify your custom renderer.
    5.  **Test:** Verify pagination links display correctly *without* the total count.

*   **Threats Mitigated:**
    *   **Information Disclosure (Leaking Total Count):** Severity: Medium.

*   **Impact:**
    *   **Information Disclosure:** Risk eliminated (if the total count is not needed). Performance improvement.

*   **Currently Implemented:**
    *   Example: Implemented for the "Recent Activity" feed (`app/views/dashboard/index.html.erb`). Custom renderer: `app/helpers/custom_pagination_renderer.rb`.

*   **Missing Implementation:**
    *   Example: Missing in `app/views/products/index.html.erb`.

## Mitigation Strategy: [Provide a Custom `count` Option (for complex queries)](./mitigation_strategies/provide_a_custom__count__option__for_complex_queries_.md)

*   **Description:**
    1.  **Identify Complex Queries:** Identify controller actions using `will_paginate` with complex ActiveRecord queries.
    2.  **Analyze Query Performance:** Use database profiling tools to examine the performance of the `COUNT(*)` query.
    3.  **Implement Custom Count Logic:** If the default `COUNT(*)` is inefficient, create a custom method (model or helper) for a more efficient count.  This might involve:
        *   Optimized SQL.
        *   Cached count (if appropriate).
        *   Different counting technique.
    4.  **Pass the `count` Option:** In the `paginate` method call, use the `:count` option:
        *   String with custom SQL.
        *   Symbol of the custom method.
    5.  **Test:** Test pagination with the custom count logic.

*   **Threats Mitigated:**
    *   **Unexpected Behavior with Complex Queries (Incorrect Pagination / Errors):** Severity: Medium.
    *   **Performance Issues with Complex Queries (Denial of Service - Indirectly):** Severity: Low.

*   **Impact:**
    *   **Unexpected Behavior:** Risk significantly reduced.
    *   **Performance Issues:** Risk reduced.

*   **Currently Implemented:**
    *   Example: Implemented in `app/controllers/reports_controller.rb` (`sales_report` action). Custom method: `Report.sales_report_count`.

*   **Missing Implementation:**
    *   Example: Potentially needed in `app/controllers/admin/audit_logs_controller.rb`. Needs investigation.

