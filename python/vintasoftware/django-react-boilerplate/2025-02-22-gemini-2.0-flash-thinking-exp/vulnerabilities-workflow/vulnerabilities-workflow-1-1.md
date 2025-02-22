### Vulnerability List

- Vulnerability Name: Unprotected User Registration Endpoint
- Description:
    - The `UserViewSet` in `backend/users/views.py` is registered as a `ModelViewSet` and exposed via API endpoint.
    - `ModelViewSet` by default includes a `create` action to create new user records.
    - While the project sets default permission class `IsAuthenticated` for REST Framework in `backend/project_name/settings/base.py`, `ModelViewSet`'s `create` action may still allow unauthenticated user registration if not explicitly restricted.
    - An external attacker can send a POST request to `/api/users/` endpoint with user registration data.
    - If user registration is not intended to be public, this endpoint allows anyone to create new user accounts without authentication.
- Impact:
    - Unauthorized user account creation.
    - Malicious actors can create numerous accounts, potentially leading to:
        - Resource exhaustion on the server.
        - Spam or abuse of application functionalities.
        - Potential for further attacks using created accounts.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - Default `REST_FRAMEWORK` permissions are set to `IsAuthenticated` in `backend/project_name/settings/base.py`.
    - Django Defender is included for brute-force login protection, but not for registration endpoint.
- Missing mitigations:
    - Explicitly control permissions for the `create` action in `UserViewSet` to prevent unauthorized user registration.
    - If public user registration is not intended, the `create` action should be removed from `UserViewSet` or permissions should be set to explicitly deny unauthenticated access to the create action.
- Preconditions:
    - Publicly accessible instance of the Django React Boilerplate application.
- Source code analysis:
    - `backend/users/views.py`:
        ```python
        from rest_framework import viewsets
        from .models import User
        from .serializers import UserSerializer

        class UserViewSet(viewsets.ModelViewSet):
            queryset = User.objects.all()
            serializer_class = UserSerializer
        ```
        - `UserViewSet` inherits from `ModelViewSet`, which includes default CRUD actions, including `create`.
    - `backend/users/routes.py`:
        ```python
        from .views import UserViewSet

        routes = [
            {"regex": r"users", "viewset": UserViewSet, "basename": "user"},
        ]
        ```
        - Registers `UserViewSet` to be accessible under `/api/users/` endpoint (due to DefaultRouter in `backend/project_name/urls.py`).
    - `backend/project_name/urls.py`:
        ```python
        from rest_framework.routers import DefaultRouter
        # ...
        router = DefaultRouter()
        routes = common_routes + users_routes # users_routes includes users endpoint
        for route in routes:
            router.register(route["regex"], route["viewset"], basename=route["basename"])
        urlpatterns = [
            path("api/", include(router.urls), name="api"), # API endpoints are under /api/
            # ...
        ]
        ```
        -  Registers API routes using `DefaultRouter`, making `UserViewSet` accessible.
    - `backend/project_name/settings/base.py`:
        ```python
        REST_FRAMEWORK = {
            # ...
            "DEFAULT_PERMISSION_CLASSES": [
                "rest_framework.permissions.IsAuthenticated",
            ],
            # ...
        }
        ```
        - Sets default permission `IsAuthenticated` for all REST API endpoints. However, `ModelViewSet.create` action might still allow unauthenticated requests for user registration.
    - **Vulnerability Flow:**
        1.  External attacker sends a POST request to `/api/users/`.
        2.  Django REST Framework routes the request to `UserViewSet.create` action.
        3.  If `create` action does not have explicit permission configuration, it might bypass the default `IsAuthenticated` and allow unauthenticated user creation.
        4.  A new user is created in the database without authentication.

- Security test case:
    1. Deploy the Django React Boilerplate application to a publicly accessible environment.
    2. Open a terminal or use a tool like `curl` or Postman.
    3. Send a POST request to the user creation endpoint: `POST /api/users/`
    4. Set the `Content-Type` header to `application/json`.
    5. Include the following JSON payload in the request body:
        ```json
        {
          "email": "testuser123@example.com",
          "password": "P@$$wOrd123"
        }
        ```
    6. Send the request without any authentication credentials (e.g., do not include Session cookies or Authorization headers).
    7. Check the HTTP response status code.
        - Expected Vulnerable Response: `201 Created`. This indicates that the user registration was successful.
        - Expected Secure Response (if mitigated): `403 Forbidden` or `401 Unauthorized`. This indicates that user creation is restricted to authenticated users or explicitly disabled for unauthenticated users.
    8. If the response status code is `201 Created`, log in to the Django admin panel (if accessible and you have admin credentials) or directly query the database to verify if a new user with the email "testuser123@example.com" has been created.
    9. If a new user is successfully created without authentication, the vulnerability is confirmed.