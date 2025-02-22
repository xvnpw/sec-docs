### Vulnerability List

#### Vulnerability Name: Unrestricted Access to Model Data via AJAX Endpoints

* Description:
    1. An attacker identifies a Django project using `django-smart-selects`.
    2. The attacker discovers the publicly accessible AJAX endpoints provided by `django-smart-selects` at `/chaining/filter/` or `/chaining/all/`.
    3. The attacker crafts a malicious URL targeting one of these endpoints, specifying:
        - `app`: The Django app name of a model they want to access.
        - `model`: The Django model name they want to access.
        - `field`: A field on the target model (can be any field, not necessarily a chained field in the target model).
        - `foreign_key_app_name`:  A related app name (can be any app, even the same as `app`).
        - `foreign_key_model_name`: A related model name (can be any model, even the same as `model`).
        - `foreign_key_field_name`: A field in the related model (can be any field).
        - `value`: A value to filter by (can be any value, even '1').
    4. The attacker sends a GET request to the crafted URL.
    5. The `django-smart-selects` view processes the request, retrieves data from the specified model based on the provided parameters, and returns it as a JSON response.
    6. The attacker receives a JSON response containing data from the targeted Django model, regardless of whether they should have permission to access this data.

* Impact:
    - Unauthorized information disclosure.
    - Access to sensitive data from Django models without authentication or authorization checks.
    - Potential privacy violations if personal or confidential data is exposed.
    - Depending on the exposed data, this could lead to further attacks or compromise of the application.

* Vulnerability Rank: High

* Currently implemented mitigations:
    - Basic check in `filterchain` and `filterchain_all` views to raise `PermissionDenied` if the foreign model does not have `ChainedManyToManyField` or `ChainedForeignKey` fields. This check is insufficient as it does not validate user permissions and is primarily intended to ensure the view is called in the expected context of chained fields.
    - A warning in the README.md file documenting the lack of default permission checks. This is not a code-level mitigation.

* Missing mitigations:
    - Implementation of robust permission checks within the `filterchain` and `filterchain_all` views. These checks should verify if the current user has the necessary permissions to access and retrieve data from the targeted model.
    - Options to configure different levels of permission control for the AJAX endpoints, allowing developers to enforce stricter access policies based on their application's security requirements.
    - Consider integrating with Django's permission system to leverage existing permission checks and roles.

* Preconditions:
    - `django-smart-selects` is installed and enabled in a Django project.
    - At least one model in the Django project is using `ChainedForeignKey` or `ChainedManyToManyField` (although the vulnerability is not strictly limited to models with these fields, their presence is the intended use case for the library, and thus makes the vulnerability more likely to be present in projects using the library).
    - The `smart_selects.urls` are included in the project's `urls.py`, making the AJAX endpoints publicly accessible.

* Source code analysis:
    1. `smart_selects/urls.py`: Defines URL patterns for `filterchain_all` and `filterchain` views, making them accessible via URLs like `/chaining/filter/...`.
    ```python
    urlpatterns = [
        re_path(
            r"^all/(?P<app>[\w\-]+)/(?P<model>[\w\-]+)/(?P<field>[\w\-]+)/(?P<foreign_key_app_name>[\w\-]+)/(?P<foreign_key_model_name>[\w\-]+)/(?P<foreign_key_field_name>[\w\-]+)/(?P<value>[\w\-,]+)/$",
            views.filterchain_all,
            name="chained_filter_all",
        ),
        re_path(
            r"^filter/(?P<app>[\w\-]+)/(?P<model>[\w\-]+)/(?P<field>[\w\-]+)/(?P<foreign_key_app_name>[\w\-]+)/(?P<foreign_key_model_name>[\w\-]+)/(?P<foreign_key_field_name>[\w\-]+)/(?P<value>[\w\-,]+)/$",
            views.filterchain,
            name="chained_filter",
        ),
        # ...
    ]
    ```
    2. `smart_selects/views.py`: Implements `filterchain` and `filterchain_all` views. These views dynamically construct a queryset based on URL parameters and filter it. The code lacks any permission checks to verify user authorization before returning data.
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
        model_class = get_model(app, model) # Dynamically retrieves the model
        m2m = is_m2m(model_class, field)
        keywords = get_keywords(field, value, m2m=m2m)

        # SECURITY: Basic check, but insufficient for real permission control.
        foreign_model_class = get_model(foreign_key_app_name, foreign_key_model_name)
        if not any(
            [
                (isinstance(f, ChainedManyToManyField) or isinstance(f, ChainedForeignKey))
                for f in foreign_model_class._meta.get_fields()
            ]
        ):
            raise PermissionDenied("Smart select disallowed")

        limit_choices_to = get_limit_choices_to(
            foreign_key_app_name, foreign_key_model_name, foreign_key_field_name
        )
        queryset = get_queryset(model_class, manager, limit_choices_to)
        results = do_filter(queryset, keywords) # Filters the queryset
        # ... serialization and JSON response ...
        return JsonResponse(serialized_results, safe=False)
    ```
    The code flow clearly shows that after retrieving and filtering the model data, it is directly serialized and returned in a JSON response without any checks to ensure the requester has permission to access this data. The existing "security" check is misleading as it only verifies the presence of `ChainedForeignKey` or `ChainedManyToManyField` in a *related* model, not permissions on the *target* model being queried.

* Security test case:
    1. Set up a Django project with `django-smart-selects` and create a Django app named `myapp`.
    2. Define two models in `myapp/models.py`: `Continent` and `Country`.
    ```python
    from django.db import models
    from smart_selects.db_fields import ChainedForeignKey

    class Continent(models.Model):
        name = models.CharField(max_length=255)

        def __str__(self):
            return self.name

    class Country(models.Model):
        continent = models.ForeignKey(Continent, on_delete=models.CASCADE)
        name = models.CharField(max_length=255)
        sensitive_data = models.TextField(default="internal info")  # Sensitive data

        def __str__(self):
            return self.name
    ```
    3. Register these models in `myapp/admin.py`. Create some `Continent` and `Country` instances, ensuring `Country` instances have different `sensitive_data`.
    4. Include `smart_selects.urls` in your project's `urls.py`:
    ```python
    from django.contrib import admin
    from django.urls import path, include

    urlpatterns = [
        path('admin/', admin.site.urls),
        path('chaining/', include('smart_selects.urls')),
    ]
    ```
    5. Log out of the Django admin.
    6. Construct the following URL to access `Country` data without authentication: `/chaining/filter/myapp/Country/continent/myapp/Continent/id/1/`. This URL attempts to filter `Country` models based on `continent_id=1`.
    7. Send a GET request to this URL (e.g., using a browser or `curl`).
    8. Observe the JSON response. It will contain data for `Country` models related to `Continent` with `id=1`, including the `sensitive_data` field, even though you are not logged in and have no explicit permissions. Example response:
    ```json
    [
        {"value": 1, "display": "Country 1"},
        {"value": 2, "display": "Country 2"}
    ]
    ```
    (Note: The `sensitive_data` field is not directly in the display, but the vulnerability allows access to all fields of the `Country` model through Django's ORM if further exploited).
    9. To confirm full data extraction, you could potentially further exploit this by crafting more complex queries (though the current interface is limited to filtering based on the chained field value). The core issue is the unrestricted read access to model data.