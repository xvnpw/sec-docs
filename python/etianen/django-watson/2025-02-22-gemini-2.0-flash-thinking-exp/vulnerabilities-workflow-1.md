## Vulnerability List

This document consolidates identified vulnerabilities in the application, combining information from multiple sources and removing duplicates.

### 1. Unrestricted Full-Text Search Information Disclosure

- **Description:**
    - The project exposes full-text search endpoints (both HTML and JSON) without any authentication or authorization checks.
    - An external attacker can easily submit an HTTP GET request (for example, to `/watson/json/?q=test`) and receive a JSON response containing search results.
    - Because `django-watson` is designed to index data from every model registered with it, if a developer registers any models that include sensitive or non-public data, an attacker might retrieve that data without needing to authenticate.
    - In short, the lack of access control on the search endpoints enables any remote user to trigger the search functionality and receive potentially sensitive details.
- **Impact:**
    - **Information Disclosure:** Sensitive or private data (if indexed) may be exposed to an unauthenticated attacker.
    - **Data Enumeration:** The attacker can learn about the underlying models and indexed fields, providing insight into the application’s internal data structure that may aid in further attacks.
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - No access control or filtering is implemented on the search endpoints. The views in `/code/watson/views.py` simply retrieve and return search data without verifying user credentials or permissions.
- **Missing Mitigations:**
    - **Access Control:** Implement authentication or authorization checks so that only permitted users can invoke the search endpoints.
    - **Sensitive Data Filtering:** Ensure that only data intended for public consumption is indexed (or redacted) before it is returned in search results.
- **Preconditions:**
    - The search endpoints (e.g. `/watson/` and `/watson/json/`) are publicly accessible.
    - Models containing sensitive or confidential fields are registered with `django-watson` and are being indexed without any additional filtering or masking.
- **Source Code Analysis:**
    - In `/code/watson/urls.py`, the search functionality is exposed via two URL patterns:
      - `re_path("^$", search, name="search")`
      - `re_path("^json/$", search_json, name="search_json")`
    - In `/code/watson/views.py`, the `SearchMixin.get_query()` method reads the query parameter (named by default “q”) directly from the GET request without any authentication logic.
    - The `SearchApiView.render_to_response()` method then serializes the search results (which include fields like title, description, url, and meta) into JSON and returns them verbatim.
    - There is no code in these modules that checks whether the requestor is authorized to retrieve the displayed content.

    ```mermaid
    graph LR
        A[User sends GET request to /watson/json/?q=test] --> B(urls.py: maps /watson/json/ to search_json view);
        B --> C(views.py: search_json view / SearchMixin.get_query());
        C --> D{No Authentication/Authorization};
        D -- No Auth --> E(views.py: SearchApiView.render_to_response());
        E --> F[JSON Response with search results (including potentially sensitive data)];
        F --> G[User receives sensitive data];
        D -- Auth Required --> H[Access Denied];
        style D fill:#f9f,stroke:#333,stroke-width:2px
    ```

- **Security Test Case:**
    - **Step 1:** From an external, unauthenticated machine (or using a tool such as curl or Postman), submit an HTTP GET request to the JSON search endpoint. For example:
      ```bash
      curl -X GET "https://<public-instance-domain>/watson/json/?q=test"
      ```
    - **Step 2:** Examine the HTTP response. Confirm that the response’s `Content-Type` header is set to `application/json; charset=utf-8` and that the body contains a JSON object with a “results” array.
    - **Step 3:** Analyze the returned search results to determine whether they include any data from models that might be sensitive or not intended for public disclosure.
    - **Step 4:** Report that the absence of any access control has enabled the disclosure of potentially sensitive indexed data.

### 2. Cross-Site Scripting (XSS) in Search Result Display

- **Description:**
    1. An attacker crafts a malicious payload, for example, a Javascript code snippet, and injects it into a field of a model instance that is registered with `django-watson` for search indexing. This could be achieved through various means depending on the application using `django-watson`, such as exploiting a separate vulnerability to modify database content or if the application allows user-generated content to be indexed without proper sanitization before indexing.
    2. The `django-watson` `buildwatson` management command or automatic index updates process this model instance, and the malicious payload is stored in the `SearchEntry` model's `title`, `description`, or `content` fields.
    3. A user performs a search query that results in the `SearchEntry` containing the malicious payload being included in the search results.
    4. The `watson.templatetags.watson.search_result_item` template tag is used to render the search results. This tag includes the potentially malicious `search_result.title`, `search_result.description` and `search_result.url` in the rendered HTML output, within the templates `watson/includes/search_result_{app_label}_{model_name}.html`, `watson/includes/search_result_{app_label}.html`, or `watson/includes/search_result_item.html`.
    5. If these templates do not properly escape the `search_result.title` and `search_result.description` when rendering them, the malicious Javascript code will be executed in the user's browser when the search results page is viewed.
- **Impact:**
    Successful exploitation of this vulnerability allows an attacker to execute arbitrary Javascript code in the context of a user's browser when they view search results. This can lead to various malicious activities, including:
    - Account hijacking (session stealing)
    - Defacement of the website
    - Redirection to malicious websites
    - Information disclosure (access to user's cookies, session tokens, and potentially sensitive data on the page)
    - Performing actions on behalf of the user
- **Vulnerability Rank:** High
- **Currently Implemented Mitigations:**
    - The project itself does not implement automatic sanitization of data before indexing. It relies on the application developer to ensure that data indexed by `django-watson` is safe.
    - The provided code does not contain explicit HTML escaping within the `watson.templatetags.watson.search_result_item` template tag or the included templates (`watson/includes/search_result_item.html` and others).
- **Missing Mitigations:**
    - **Output escaping in templates:** The `search_result_item` template tag and the included templates should use Django's template auto-escaping or explicitly use the `escape` filter to ensure that `search_result.title` and `search_result.description` are rendered safely and any HTML or Javascript code within them is escaped.
    - **Input sanitization:** While not a direct mitigation in `django-watson` itself, it's crucial for applications using `django-watson` to sanitize input data before it is stored in models that are indexed. This would prevent malicious payloads from ever reaching the search index. However, `django-watson` could provide documentation and recommendations on this best practice.
- **Preconditions:**
    - A model is registered with `django-watson` and its `title` and/or `description` fields are included in the search index.
    - An attacker is able to inject malicious content into the `title` or `description` fields of an instance of the registered model. This could be through a separate vulnerability in the application or by compromising the database directly.
    - The application uses the `watson.templatetags.watson.search_result_item` template tag to display search results without ensuring proper output escaping in the templates.
- **Source Code Analysis:**
    1. **`watson/templatetags/watson.py`**:
    ```python
    @register.simple_tag(takes_context=True)
    def search_result_item(context, search_result):
        obj = search_result.object
        content_type = ContentType.objects.get_for_id(search_result.content_type_id)

        params = {
            "app_label": content_type.app_label,
            "model_name": content_type.model,
        }
        # Render the template.
        context.push()
        try:
            context.update({
                "obj": obj,
                "result": search_result,
                "query": context["query"],
            })
            return template.loader.render_to_string((
                "watson/includes/search_result_{app_label}_{model_name}.html".format(**params),
                "watson/includes/search_result_{app_label}.html".format(**params),
                "watson/includes/search_result_item.html",
            ), context.flatten())
        finally:
            context.pop()
    ```
    This tag is responsible for rendering search result items. It loads templates based on content type and falls back to `watson/includes/search_result_item.html`. It passes `search_result` to the template context.

    2. **`watson/includes/search_result_item.html` (assuming default template if custom ones are not provided by the user)**:
    ```html+django
    <li class="search-result-item">
        <h3><a href="{{ result.url }}">{{ result.title }}</a></h3>
        <p>{{ result.description }}</p>
    </li>
    ```
    In this default template, `{{ result.title }}` and `{{ result.description }}` are rendered directly without any explicit escaping. If Django's auto-escaping is not enabled for this block or globally disabled, or if the context processor settings do not ensure escaping, this will lead to XSS.

    ```mermaid
    graph LR
        A[Malicious Payload injected into model field] --> B(buildwatson command / index updates);
        B --> C[Malicious Payload in SearchEntry (title/description)];
        D[User performs search] --> E{Search Results include malicious SearchEntry};
        E --> F(watson.templatetags.watson.search_result_item);
        F --> G(watson/includes/search_result_item.html);
        G --> H{No Output Escaping for result.title/description};
        H -- No Escaping --> I[Malicious Javascript Execution in User's Browser (XSS)];
        H -- Output Escaping --> J[Safe HTML Rendered];
        style H fill:#f9f,stroke:#333,stroke-width:2px
    ```

- **Security Test Case:**
    1. **Setup:**
        - Ensure a Django project is set up using `django-watson`.
        - Register `WatsonTestModel1` with watson and include `title` and `description` in search fields.
        - Include `watson.urls` in your project's `urls.py` to enable search views.
        - Ensure that the default `watson/includes/search_result_item.html` template is used or a custom template that does not explicitly escape output is in place.
    2. **Inject Malicious Payload:**
        - Create a `WatsonTestModel1` instance with a malicious Javascript payload in the `title` field:
        ```python
        WatsonTestModel1.objects.create(
            title='<script>alert("XSS Vulnerability");</script>Malicious Title',
            description='Test Description',
            content='Test Content'
        )
        ```
        - Run `python manage.py buildwatson` to update the search index.
    3. **Perform Search:**
        - Access the search URL (e.g., `/simple/?q=Malicious`) in a web browser.
    4. **Verify XSS:**
        - Observe if an alert box with "XSS Vulnerability" appears when the search results page loads.
        - Inspect the HTML source of the search results page and confirm that the `<script>alert("XSS Vulnerability");</script>` payload is rendered directly within the `<h3>` tag in the HTML without being escaped.