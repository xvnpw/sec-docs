### Combined Vulnerability List

This document consolidates vulnerabilities from multiple lists into a single, de-duplicated list.

#### Information Disclosure via OrderableListMixin

* **Vulnerability Name:** Information Disclosure via OrderableListMixin

* **Description:**
    1. An attacker accesses a publicly available list view that uses `OrderableListMixin`.
    2. The attacker inspects the HTML source or available documentation to identify the `orderable_columns` defined in the view.
    3. The attacker crafts a malicious URL by appending the `order_by` query parameter with a sensitive column name from `orderable_columns`, and `ordering` parameter to specify the order (asc or desc).
    4. The server processes the request and orders the list of objects based on the attacker-specified sensitive column.
    5. Although the sensitive column's data may not be directly displayed, the attacker can infer information about the data by observing the order of the list. For example, if ordering by a column like `is_staff` changes the order of displayed items, the attacker can deduce which items correspond to staff users.

* **Impact:**
    - Information Disclosure: Attackers can potentially infer sensitive information about the data being listed, such as internal statuses, flags, or timestamps, even if these details are not directly displayed in the list view. This can aid in further targeted attacks or profiling of the system's data.

* **Vulnerability Rank:** High

* **Currently Implemented Mitigations:**
    - None in the `OrderableListMixin` itself. The mixin relies on developers to define a safe list of `orderable_columns`.

* **Missing Mitigations:**
    - Documentation should be improved to explicitly warn developers about the security implications of including sensitive column names in `orderable_columns`.
    - Input validation within `OrderableListMixin` to allow developers to define a safe-list or block-list of columns, and enforce it to prevent ordering by unintended columns.
    - A mechanism to sanitize or transform the `orderable_columns` list to ensure only safe, display-relevant columns are used for ordering.

* **Preconditions:**
    - A Django application uses `django-braces` library.
    - A ListView in the application is implemented using `OrderableListMixin`.
    - The developer has mistakenly included sensitive internal database column names in the `orderable_columns` attribute of the view.
    - The ListView is publicly accessible without strict authorization controls.

* **Source Code Analysis:**
    1. File: `/code/braces/views/_queries.py`
    2. Class: `OrderableListMixin`
    3. Method: `get_ordered_queryset(self, queryset=None)`
    ```python
    def get_ordered_queryset(self, queryset=None):
        """
        Augments ``QuerySet`` with order_by statement if possible

        :param QuerySet queryset: ``QuerySet`` to ``order_by``
        :return: QuerySet
        """
        get_order_by = self.request.GET.get("order_by")

        if get_order_by in self.get_orderable_columns(): # [!] Vulnerability Point: Checks if user-provided order_by is in developer-defined orderable_columns
            order_by = get_order_by
        else:
            order_by = self.get_orderable_columns_default()

        self.order_by = order_by
        self.ordering = self.get_ordering_default()

        if all([order_by,
            self.request.GET.get("ordering", self.ordering) == "desc"
        ]):
            order_by = f"-{order_by}"
        self.ordering = self.request.GET.get("ordering", self.ordering)

        return queryset.order_by(order_by) # [!] Vulnerability Point: Directly applies user-influenced order_by to queryset
    ```
    - The `get_ordered_queryset` method retrieves the `order_by` parameter from the GET request.
    - It checks if this parameter is present in the `orderable_columns` list defined by the developer in the view.
    - **Vulnerability**: If the `order_by` parameter is in `orderable_columns`, it is directly used in `queryset.order_by(order_by)`. If `orderable_columns` contains sensitive column names, an attacker can control the ordering and infer information.
    - There is no sanitization or validation of the column names beyond checking inclusion in the `orderable_columns` list.

* **Security Test Case:**
    1. Setup:
        - Create a Django model `SensitiveData` with fields `title` (CharField) and `internal_status` (CharField, choices=['VIP', 'Normal']).
        - Create a ListView `SensitiveDataListView` using `OrderableListMixin` to display `SensitiveData` objects.
        - In `SensitiveDataListView`, set `model = SensitiveData`, `template_name = 'sensitive_list.html'`, and crucially, `orderable_columns = ('title', 'internal_status')`.
        - Create a template `sensitive_list.html` that only displays the `title` of each `SensitiveData` object in a list.
        - Populate the database with `SensitiveData` objects having different `internal_status` values ('VIP', 'Normal').
    2. Test Steps:
        - Access the `SensitiveDataListView` in a browser using a GET request without any query parameters (e.g., `/sensitive_data_list/`). Observe the default order of the list.
        - Craft a URL with the query parameter to order by the sensitive column: `/sensitive_data_list/?order_by=internal_status&ordering=asc`.
        - Reload the page with the crafted URL.
        - Observe if the order of the displayed titles in the list changes compared to the default order.
        - Repeat step 2 and 3 with `/sensitive_data_list/?order_by=internal_status&ordering=desc`.
        - Compare the order of items in the list for default, `asc`, and `desc` ordering by `internal_status`.
    3. Expected Result:
        - If the order of titles in the list changes predictably when ordering by `internal_status` (e.g., 'Normal' status items appear before 'VIP' status items in 'asc' order), it confirms the information disclosure vulnerability. An attacker can infer the `internal_status` of items by manipulating the `order_by` parameter, even though the `internal_status` itself is not directly displayed.