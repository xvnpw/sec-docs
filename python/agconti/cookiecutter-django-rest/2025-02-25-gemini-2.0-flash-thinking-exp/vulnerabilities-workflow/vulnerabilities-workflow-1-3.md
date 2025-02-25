### Vulnerability List

- Vulnerability Name: Insecure Default Permissions in REST Framework
- Description:
    1. The project template sets `DEFAULT_PERMISSION_CLASSES` in Django REST Framework to `IsAuthenticated` in `common.py` configuration file.
    2. This configuration makes authentication mandatory by default for all API endpoints defined using Django REST Framework.
    3. If a developer using this template creates a new ViewSet and forgets to explicitly configure `permission_classes`, the endpoint will inherit this default `IsAuthenticated` permission.
    4. This can lead to unintended access control behavior. Endpoints intended to be publicly accessible might be unintentionally protected, requiring authentication, or endpoints intended to be protected might be misconfigured if the developer misunderstands the default behavior.
    5. While the provided `UserViewSet` correctly overrides this default for user creation to allow public registration, the global default setting introduces a risk of misconfiguration for newly added endpoints.
- Impact:
    - High risk of misconfiguration in applications built using this template, potentially leading to unintended exposure of sensitive data or unintended restriction of access to public resources.
    - If developers are not fully aware of the default `IsAuthenticated` setting, they might incorrectly assume endpoints are publicly accessible when they are actually protected, or vice-versa.
- Vulnerability Rank: high
- Currently Implemented Mitigations:
    - None directly mitigate the risk of misconfiguration stemming from the default permission setting.
    - The `UserViewSet` in the template explicitly sets `permission_classes = (IsUserOrCreatingAccountOrReadOnly,)`, showing awareness of permission configuration for user creation.
- Missing Mitigations:
    - **Documentation Enhancement:** Clearly document the default `IsAuthenticated` setting in the project's documentation. Emphasize the importance of explicitly setting `permission_classes` for each new ViewSet, especially when public access is intended. Provide examples of how to set different permission classes.
    - **Consider a More Permissive Default:** Evaluate changing the default `DEFAULT_PERMISSION_CLASSES` to a more permissive setting like `AllowAny`. Then, developers would need to explicitly *add* permission restrictions for endpoints that require authentication. This approach is often considered more secure-by-default, as it reduces the risk of unintentionally exposing protected endpoints due to forgotten permission settings. However, this would be a significant change and might not be suitable for all use cases of the template.
    - **Linting/Code Analysis:** Integrate a linter or code analysis tool into the development workflow that can detect and warn developers when a new Django REST Framework ViewSet is created without explicitly defining `permission_classes`.
- Preconditions:
    - A developer uses the `cookiecutter-django-rest` template to generate a new Django REST Framework project.
    - The developer adds a new Django app with a new ViewSet to the generated project.
    - The developer either forgets to configure `permission_classes` for the new ViewSet or is unaware of the default `IsAuthenticated` setting.
- Source Code Analysis:
    1. Open the file `/code/{{cookiecutter.github_repository_name}}/{{cookiecutter.app_name}}/config/common.py`.
    2. Locate the `REST_FRAMEWORK` dictionary within the `Common` class.
    3. Find the `'DEFAULT_PERMISSION_CLASSES'` key.
    4. Observe that its value is set to `['rest_framework.permissions.IsAuthenticated']`. This line configures Django REST Framework to enforce authentication for all API endpoints by default.
    5. Examine the file `/code/{{cookiecutter.github_repository_name}}/{{cookiecutter.app_name}}/users/views.py`.
    6. Notice that the `UserViewSet` explicitly defines `permission_classes = (IsUserOrCreatingAccountOrReadOnly,)`. This explicit setting overrides the default `IsAuthenticated` for this specific ViewSet, allowing unauthenticated users to create new user accounts (as intended for a registration endpoint).
    7. Consider a scenario where a developer adds a new app, for example, a `products` app, and creates a `ProductViewSet` without setting `permission_classes`:

    ```python
    # /code/{{cookiecutter.github_repository_name}}/{{cookiecutter.app_name}}/products/views.py
    from rest_framework import viewsets
    from .models import Product
    from .serializers import ProductSerializer

    class ProductViewSet(viewsets.ModelViewSet): # permission_classes is NOT set
        queryset = Product.objects.all()
        serializer_class = ProductSerializer
    ```

    8. In this case, because `permission_classes` is not explicitly defined in `ProductViewSet`, it will inherit the default `IsAuthenticated` permission from `common.py`. This means that access to the `/api/v1/products/` endpoint (assuming it's correctly configured in `urls.py`) will require authentication, even if the developer intended it to be publicly accessible for listing products, for example.
- Security Test Case:
    1. Generate a new project using the `cookiecutter-django-rest` template.
    2. Create a new Django app named `public_api` within the generated project: `./manage.py startapp public_api`.
    3. In `public_api/models.py`, create a simple model:

    ```python
    # /code/{{cookiecutter.github_repository_name}}/{{cookiecutter.app_name}}/public_api/models.py
    from django.db import models

    class PublicData(models.Model):
        name = models.CharField(max_length=255)
        description = models.TextField()
    ```

    4. In `public_api/serializers.py`, create a serializer for this model:

    ```python
    # /code/{{cookiecutter.github_repository_name}}/{{cookiecutter.app_name}}/public_api/serializers.py
    from rest_framework import serializers
    from .models import PublicData

    class PublicDataSerializer(serializers.ModelSerializer):
        class Meta:
            model = PublicData
            fields = '__all__'
    ```

    5. In `public_api/views.py`, create a `PublicDataViewSet` without setting `permission_classes`:

    ```python
    # /code/{{cookiecutter.github_repository_name}}/{{cookiecutter.app_name}}/public_api/views.py
    from rest_framework import viewsets
    from .models import PublicData
    from .serializers import PublicDataSerializer

    class PublicDataViewSet(viewsets.ModelViewSet): # permission_classes is NOT set
        queryset = PublicData.objects.all()
        serializer_class = PublicDataSerializer
    ```

    6. In `public_api/urls.py`, register the ViewSet:

    ```python
    # /code/{{cookiecutter.github_repository_name}}/{{cookiecutter.app_name}}/public_api/urls.py
    from rest_framework import routers
    from .views import PublicDataViewSet

    router = routers.DefaultRouter()
    router.register(r'public-data', PublicDataViewSet)

    urlpatterns = router.urls
    ```

    7. Include `public_api.urls` in the main project's `urls.py`:

    ```python
    # /code/{{cookiecutter.github_repository_name}}/{{cookiecutter.app_name}}/urls.py
    from django.urls import path, include
    from rest_framework.routers import DefaultRouter
    from .users.views import UserViewSet

    router = DefaultRouter()
    router.register(r'users', UserViewSet)

    urlpatterns = [
        path('api/v1/', include(router.urls)),
        path('api/v1/', include('public_api.urls')), # Include public_api urls
        # ... other urls
    ]
    ```

    8. Run migrations: `./manage.py migrate`. Create some `PublicData` objects via Django admin or `shell`.
    9. Start the development server: `docker-compose up`.
    10. Access the endpoint `http://127.0.0.1:8000/api/v1/public-data/` in a web browser or using `curl` without any authentication headers.
    11. Expected Result: The API should return a `403 Forbidden` or `401 Unauthorized` error along with content like `{"detail":"Authentication credentials were not provided."}`. This indicates that the default `IsAuthenticated` permission is being enforced.
    12. Vulnerability Confirmation: The `403/401` response confirms that the default `IsAuthenticated` permission is active and is applied to the `PublicDataViewSet` because `permission_classes` was not explicitly set. This demonstrates the potential for misconfiguration where endpoints intended to be public are unintentionally protected due to the template's default permission settings.