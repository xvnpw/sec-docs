## Combined Vulnerability List for django-extra-views

This document consolidates identified vulnerabilities from the provided lists, removing duplicates and presenting them in a structured markdown format.

### 1. Uncontrolled Query Parameter in `SearchableListMixin` leading to potential SQL Injection

- **Vulnerability Name:** Uncontrolled Query Parameter in `SearchableListMixin` leading to potential SQL Injection
- **Description:**
    1. The `SearchableListMixin` is designed to filter querysets based on user-provided search terms.
    2. The mixin iterates through `search_fields` and `search_date_fields` to construct queryset filters.
    3. The vulnerability lies in how the `word` variable, derived directly from user input (`request.GET.get("q", "").strip()`), is incorporated into the `Q` object without sufficient sanitization.
    4. Specifically, in `SearchableListMixin.get_queryset`, the code constructs filters like `Q(**{"%s__%s" % (pair[0], pair[1]): word})`. If `pair[1]` is maliciously crafted by manipulating `search_fields` (although directly manipulating `search_fields` is not an external attacker scenario based on prompt, assuming configuration is fixed), or if the `word` contains SQL injection payloads, it could lead to unintended SQL execution.
    5. Although the default lookups are limited to string lookups like `icontains`, a developer could potentially configure the `search_fields` with less safe lookups or if a vulnerability exists allowing modification of `search_fields` this could be exploited. Even with `icontains` and similar lookups, depending on the database backend and sanitization, there's a theoretical risk of injection if the input is not properly handled by the ORM backend, though Django ORM is generally good at preventing SQL injection in standard cases. However, the risk is elevated if custom lookups are used or if future updates introduce vulnerabilities in Django ORM itself.
    6. For example, if a malicious user provides a crafted string as 'q' parameter, and if `search_fields` is configured in a way that is vulnerable (e.g. using a raw SQL lookup, or if a weakness exists in the ORM layer for certain lookups), this could potentially lead to SQL injection.
- **Impact:** Potential SQL Injection. Depending on the database and application setup, a successful SQL injection could lead to unauthorized data access, modification, or deletion. In the worst case, it could allow for complete database takeover.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:** None in the `SearchableListMixin` itself. Django ORM provides some level of protection against SQL injection, but reliance on ORM alone is not a complete mitigation, especially if complex or custom lookups are involved or if vulnerabilities are found in Django ORM in the future.
- **Missing Mitigations:**
    - Input sanitization of the `word` variable before constructing the `Q` object.
    - Restricting the allowed lookups in `search_fields` to a safe whitelist and validating the lookup type.
    - Consider using Django's built-in search functionalities or more robust input validation libraries.
- **Preconditions:**
    - A view is using `SearchableListMixin`.
    - The application is deployed publicly and accessible to external attackers.
    - An attacker can control the `q` GET parameter.
    - While not directly exploitable with default safe lookups like `icontains` in many database setups, the risk exists due to the lack of explicit sanitization and potential for misconfiguration or future ORM vulnerabilities.
- **Source Code Analysis:**
    ```python
    File: /code/extra_views/contrib/mixins.py
    ...
    class SearchableListMixin(object):
        ...
        def get_queryset(self):
            qs = super(SearchableListMixin, self).get_queryset()
            query = self.get_search_query() # User controlled input from request.GET.get("q", "").strip()
            if query:
                w_qs = []
                search_pairs = self.get_search_fields_with_filters()
                for word in self.get_words(query): # word is derived from user input
                    filters = [
                        Q(**{"%s__%s" % (pair[0], pair[1]): word}) for pair in search_pairs # Constructing Q object with user input 'word' without sanitization
                    ]
                    ...
                    w_qs.append(functools.reduce(operator.or_, filters))
                qs = qs.filter(functools.reduce(operator.and_, w_qs))
                qs = qs.distinct()
            return qs
    ```
    The code directly uses the `word` variable, which comes from the user-controlled `q` parameter, in the `Q` object construction without any sanitization. While Django ORM offers protection in many cases, this pattern is not ideal and can be risky, especially if developers use custom lookups or if ORM vulnerabilities are discovered.
- **Security Test Case:**
    1. Deploy an application using `django-extra-views` with a `SearchableListMixin` view (e.g., `SearchableItemListView` from `extra_views_tests/views.py` and `extra_views_tests/urls.py`). Ensure the view is publicly accessible.
    2. Identify the URL for the searchable list view (e.g., `/searchable/`).
    3. Craft a malicious payload to be used as the `q` parameter in the GET request. For example, try a simple SQL injection payload like `test' OR '1'='1`.
    4. Send a GET request to the searchable list view URL with the crafted `q` parameter: `GET /searchable/?q=test' OR '1'='1`.
    5. Analyze the server-side logs or database query logs to check if the crafted SQL payload is being executed or causing any errors.
    6. While a direct, easily exploitable SQL injection might be difficult to achieve with default settings and safe lookups due to Django ORM's protections, monitoring for errors and unusual database behavior is crucial. For more advanced testing, try payloads specific to the database backend in use and explore edge cases in Django ORM's lookup handling. If custom lookups are implemented in a derived class, test payloads relevant to those lookups.

### 2. HTTP Response Splitting in Custom Redirect Handling

- **Vulnerability Name:** HTTP Response Splitting in Custom Redirect Handling
- **Description:**
  In the file `/code/extra_views_tests/views.py`, the `OrderCreateView` class overrides its `form_valid` method to modify the redirect response as follows:
  ```python
  def form_valid(self, form):
      response = super().form_valid(form)
      response["Location"] += "?form_valid_called=1"
      return response
  ```
  Here, the `get_success_url()` (called by the parent method) falls back to using `self.request.get_full_path()` when no explicit `success_url` is defined. Because the full request path (including query string) is derived from external user input, an attacker could supply malicious characters (for example, CRLF sequences) in the URL. These characters would then be concatenated directly into the `Location` header, possibly allowing header injection or HTTP response splitting. The exploitation steps might be:
  1. An attacker crafts a URL with a payload—e.g., including `%0d%0aInjectedHeader:value`—in its query string.
  2. The malicious URL is passed as the request’s full path, and, after form submission, the response header is set to this unsanitized value with the appended query string.
  3. If the header value is not validated or sanitized, the attacker may inject rogue HTTP headers.
- **Impact:**
  - HTTP response splitting may lead to header injection, which can be used for cache poisoning, cross-site scripting (XSS), or other client-side attacks.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
  - None; there is no sanitization or validation of the URL as it is used directly in the response header.
- **Missing Mitigations:**
  - Sanitize or validate the return value from `request.get_full_path()` before using it.
  - Use proper URL-building functions rather than raw string‑concatenation when constructing redirect locations.
  - Enforce strict checks that disallow newline or carriage-return characters in header values.
- **Preconditions:**
  - The attacker must be able to control part of the request’s URL (for example, by supplying a malicious query string).
  - The application uses the default behavior where `success_url` is not set, causing `get_full_path()` to be used directly.
- **Source Code Analysis:**
  - The `OrderCreateView` in `/code/extra_views_tests/views.py` does not override `get_success_url()`, so it inherits the behavior of `FormSetMixin.get_success_url()`, which returns `self.request.get_full_path()` when no explicit URL is provided.
  - In the override of `form_valid`, the code simply concatenates an extra query string (`"?form_valid_called=1"`) without sanitizing the original Location value.
- **Security Test Case:**
  1. Craft a URL request such as:
     ```
     /inlines/new/?malicious=%0d%0aInjectedHeader:value
     ```
  2. Submit a valid POST request to create an order using this URL.
  3. Capture and inspect the HTTP redirect response (particularly the `Location` header).
  4. Check whether the injected CRLF sequence results in an extra header (e.g. “InjectedHeader”) being present.
  5. A positive result confirms that unsanitized user input is being used in header construction, thus proving the vulnerability.