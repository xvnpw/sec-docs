Here is the combined list of vulnerabilities, formatted as markdown:

### Unprotected AJAX Endpoints Expose Model Data

This vulnerability exists due to the lack of permission checks in the AJAX endpoints provided by the `django-smart-selects` package. Specifically, the `/chaining/filter/` and `/chaining/all/` endpoints, designed to dynamically populate chained dropdown fields, are accessible to any user, including unauthenticated external attackers. By crafting specific URLs, attackers can bypass intended access controls and retrieve data from Django models that utilize `ChainedForeignKey` or `ChainedManyToManyField`. This allows for unauthorized data extraction and information disclosure.

#### Vulnerability Name
Unprotected AJAX endpoints expose model data

#### Description
The `django-smart-selects` package introduces AJAX endpoints (`/chaining/filter/` and `/chaining/all/`) that are used to dynamically populate chained dropdown fields. These endpoints, implemented in `smart_selects/views.py` within the `filterchain` and `filterchain_all` views, lack any form of permission checks. As a result, any user, including unauthenticated external attackers, can access these endpoints to retrieve data from models that utilize `ChainedForeignKey` or `ChainedManyToManyField`. By crafting specific URLs, an attacker can query and extract data from any model configured with these chained fields, effectively bypassing any intended access controls at the application level.

Steps to trigger vulnerability:
    1. Identify a Django project using `django-smart-selects`.
    2. Discover the publicly accessible AJAX endpoints provided by `django-smart-selects` at `/chaining/filter/` or `/chaining/all/`.
    3. Identify a Django model in the target application that uses `ChainedForeignKey` or `ChainedManyToManyField` from `django-smart-selects`. For example, in the test app, `Location` model uses `ChainedForeignKey` for `country` field, chained to `continent`.
    4. Determine the app name, model name, chained field name, and chained model field name used in the `ChainedForeignKey` or `ChainedManyToManyField` definition. In the `Location` example: app='test_app', model='Country', field='continent', foreign_key_app_name='test_app', foreign_key_model_name='Location', foreign_key_field_name='country'.
    5. Construct a URL to the `/chaining/filter/` endpoint using the identified parameters and a valid value for the chained field. For example, to get countries filtered by continent with ID '1', the URL would be: `/chaining/filter/test_app/Country/continent/test_app/Location/country/1/`.
    6. Send a GET request to the constructed URL.
    7. Observe the JSON response containing data from the `Country` model, filtered based on the `continent` with ID '1'. This data is exposed without any authentication or authorization.
    8. Repeat with the `/chaining/all/...` endpoint to see that even complete lists are returned without restriction.

#### Impact
- **Data Breach**: Unauthorized access to potentially sensitive data stored in Django models. An attacker can enumerate and extract data from any model exposed through `ChainedForeignKey` or `ChainedManyToManyField` fields. This could include personal information, business data, or any other information managed by the Django application.
- **Information Disclosure**: Exposure of application data can lead to further attacks. Knowing the structure and content of the database can help attackers identify other vulnerabilities or plan more targeted attacks.
- **Privacy Violations**: Exposure of personal or confidential data can lead to privacy violations.
- **Further Abuse**: Gaining insight into valid identifiers or relationships between models can lead to further abuse and compromise of the application.

#### Vulnerability Rank
High

#### Currently Implemented Mitigations
- **None**: The code in `smart_selects/views.py` does not implement any permission checks or authentication mechanisms for the `filterchain` and `filterchain_all` views.
- **Basic check for chained fields**: In the view functions (`smart_selects/views.py`), there is a check that verifies whether the target (foreign) model actually contains at least one chained field (i.e. an instance of either a `ChainedForeignKey` or `ChainedManyToManyField`). If this check fails, a `PermissionDenied` exception is raised. However, this is not a permission check in terms of user authorization.
- **README Warning**: The README.md explicitly warns about this lack of permission control. This is not a code-level mitigation.

#### Missing Mitigations
- **Permission Checks**: Implement robust permission checks in the `filterchain` and `filterchain_all` views to restrict access to authorized users only. This could involve Django's built-in permission system, custom decorators like `@login_required` or `@permission_required`, or integration with custom authentication/authorization middleware. These checks should verify if the current user has the necessary permissions to access and retrieve data from the targeted model.
- **Configuration Options for Permissions**: Provide configuration options to allow developers to specify permission requirements for the AJAX endpoints. This could be a setting to enable default permission checks or a way to register custom permission functions, allowing for different levels of permission control.
- **Rate Limiting**: Implement rate limiting on the AJAX endpoints to mitigate potential abuse and data scraping attempts, although this is not a direct mitigation for the authorization issue itself.
- **Integration with Django's permission system**: Consider integrating with Django's permission system to leverage existing permission checks and roles.
- **Mechanism to restrict data**: Implement a mechanism to restrict the data returned by these endpoints according to user roles or context, ensuring only necessary data is exposed even to authorized users.

#### Preconditions
- The Django project must be using `django-smart-selects` and have models that utilize `ChainedForeignKey` or `ChainedManyToManyField`.
- The `smart_selects.urls` must be included in the project's `urls.py`, making the vulnerable endpoints accessible.
- The application instance must be publicly accessible for an external attacker to reach the endpoints without additional network or application-level access controls.
- Chained fields are used, which causes the AJAX endpoints to return data without further verification.

#### Source Code Analysis
- File: `/code/smart_selects/views.py`
```python
@never_cache
def filterchain(
    request,
    app,
    model,
    field,
    foreign_key_app_name,
    foreign_key_model_name,
    foreign_key_field_name,
    value,
    manager=None,
):
    model_class = get_model(app, model) # Dynamically get model class based on URL param
    m2m = is_m2m(model_class, field)
    keywords = get_keywords(field, value, m2m=m2m)

    # SECURITY: Make sure all smart selects requests are opt-in
    foreign_model_class = get_model(foreign_key_app_name, foreign_key_model_name) # Dynamically get foreign model class
    if not any( # Check if any field in foreign model is ChainedManyToManyField or ChainedForeignKey
        [
            (isinstance(f, ChainedManyToManyField) or isinstance(f, ChainedForeignKey))
            for f in foreign_model_class._meta.get_fields()
        ]
    ):
        raise PermissionDenied("Smart select disallowed") # Only checks if foreign model uses chained fields, not permissions

    # filter queryset using limit_choices_to
    limit_choices_to = get_limit_choices_to(
        foreign_key_app_name, foreign_key_model_name, foreign_key_field_name
    )
    queryset = get_queryset(model_class, manager, limit_choices_to) # Get queryset

    results = do_filter(queryset, keywords) # Filter queryset based on keywords from URL param

    # Sort results if model doesn't include a default ordering.
    if not getattr(model_class._meta, "ordering", False):
        results = list(results)
        sort_results(results)

    serialized_results = serialize_results(results) # Serialize results to JSON
    return JsonResponse(serialized_results, safe=False) # Return JSON response without permission check
```
- Visualization:
```
[External Attacker] --> HTTP Request to /chaining/filter/... --> [Django App with smart_selects] --> filterchain view (smart_selects/views.py)
                                                                    |
                                                                    V
[filterchain view] --> get_model(app, model) --> Retrieve Model Class dynamically based on URL parameters
                                                                    |
                                                                    V
[filterchain view] --> get_queryset(model_class, ...) --> Retrieve Queryset of the Model
                                                                    |
                                                                    V
[filterchain view] --> do_filter(queryset, keywords) --> Filter Queryset based on URL parameters (keywords)
                                                                    |
                                                                    V
[filterchain view] --> serialize_results(results) --> Serialize Queryset to JSON
                                                                    |
                                                                    V
[filterchain view] --> JsonResponse(serialized_results) --> HTTP Response with JSON data (NO PERMISSION CHECK) <-- [External Attacker gets Model Data]
```
- The code flow shows that the `filterchain` view directly processes the URL parameters to retrieve and filter data from Django models and returns it as JSON without any checks to verify if the requester is authorized to access this data. The "security" check present in the code only verifies if the foreign model *uses* chained fields, not whether access to the data should be restricted. The same logic applies to the `filterchain_all` view.

#### Security Test Case
1. Setup a Django project with `django-smart-selects` installed and configured.
2. Define Django models similar to `test_app/models.py`, including `Continent`, `Country`, and `Location` with `ChainedForeignKey`. Ensure there is some data in these models, including sensitive data in at least one model (e.g., `Country` model with a `sensitive_data` field).
3. Ensure `smart_selects.urls` are included in the project's `urls.py`.
4. Access the Django application as an unauthenticated user (log out of admin if logged in).
5. Construct the following URL, replacing `<your_domain>` with the application's domain: `https://<your_domain>/chaining/filter/test_app/Country/continent/test_app/Location/country/1/`.
6. Send a GET request to this URL using a browser or a tool like `curl`.
7. Verify that the response is a JSON array containing `Country` objects related to `Continent` with ID '1'. For example: `[{"value": 1, "display": "Czech republic"}, {"value": 3, "display": "Germany"}, {"value": 4, "display": "Great Britain"}]`.
8. Examine the returned HTTP response. Expect a JSON response containing a list of records (e.g., country IDs and display names). Verify that no authentication challenge or permission error occurs and that the data returned is complete and sensitive (or should be protected in your use case).
9. Attempt to access other models and data by modifying the URL parameters (app name, model name, field, value). For example, try to retrieve data from the `Continent` model itself using `/chaining/filter/test_app/Continent/name/test_app/Location/continent/1/`.
10. Verify that you can successfully retrieve data from various models through the `/chaining/filter/` and `/chaining/all/` endpoints without any authentication or authorization, confirming the vulnerability.
11. Repeat with the `/chaining/all/...` endpoint to see that even complete lists (possibly including additional data) are returned without restriction.
12. Observe if sensitive data, like the `sensitive_data` field in the `Country` model, is accessible (though it might not be directly displayed in the default representation, the vulnerability grants access to all model fields via the Django ORM).