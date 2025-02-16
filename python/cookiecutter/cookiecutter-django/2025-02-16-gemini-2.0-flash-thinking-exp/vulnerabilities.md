## Vulnerability List

- **Vulnerability Name:** Insecure Direct Object Reference (IDOR) in User API
- **Description:**
    1. An attacker can access details of other users by guessing or enumerating user IDs (primary keys) via the API endpoint `/api/users/{user_id}/`.
    2. The `UserViewSet` attempts to restrict access to only the logged-in user's data using `get_queryset`.
    3. However, the `RetrieveModelMixin` first fetches the user object based on the `lookup_field` (which is 'pk' if username_type is email) from the URL.
    4. Only after fetching the object, the `get_queryset` filter is applied, but it is too late to prevent access to other user's objects if the correct `pk` is provided in the URL.
    5. Thus, an attacker can bypass the intended access control and retrieve user details by directly accessing `/api/users/{other_user_id}/`.
- **Impact:**
    - Confidentiality breach: Attackers can access user names and URLs of other users. Depending on the `UserSerializer` and `User` model, more sensitive information could potentially be exposed in the future.
- **Vulnerability Rank:** Medium
- **Currently Implemented Mitigations:**
    - The `get_queryset` method in `UserViewSet` filters the queryset to only include the current user's data.
    - Location: `/code/{{cookiecutter.project_slug}}/{{cookiecutter.project_slug}}/users/api/views.py`
- **Missing Mitigations:**
    - Implement proper permission checks in `retrieve` and `list` actions to ensure users can only access their own data.
    - Override `get_object` method in `UserViewSet` to enforce authorization before object retrieval.
- **Preconditions:**
    - The application must be deployed with the vulnerable `UserViewSet` and API configuration.
    - The `username_type` must be set to "email" (or the `lookup_field` must be 'pk').
    - Attackers must have knowledge or be able to guess valid user IDs (primary keys).
- **Source Code Analysis:**
    - File: `/code/{{cookiecutter.project_slug}}/{{cookiecutter.project_slug}}/users/api/views.py`
    ```python
    class UserViewSet(RetrieveModelMixin, ListModelMixin, UpdateModelMixin, GenericViewSet):
        serializer_class = UserSerializer
        queryset = User.objects.all()
        {%- if cookiecutter.username_type == "email" %}
        lookup_field = "pk" # Vulnerable if username_type is email
        {%- else %}
        lookup_field = "username"
        {%- endif %}

        def get_queryset(self, *args, **kwargs):
            assert isinstance(self.request.user.id, int)
            return self.queryset.filter(id=self.request.user.id) # This filter is applied after object retrieval in RetrieveModelMixin

        @action(detail=False)
        def me(self, request):
            serializer = UserSerializer(request.user, context={"request": request})
            return Response(status=status.HTTP_200_OK, data=serializer.data)
    ```
    - The vulnerability arises from the combination of `lookup_field = "pk"` (when `username_type` is email) and the use of `RetrieveModelMixin` and `ListModelMixin` with an insufficient `get_queryset` filter.
    - The `get_queryset` method is intended to restrict the results, but in `RetrieveModelMixin`, the object is first retrieved using `lookup_field` and then `get_queryset` is applied. This does not prevent fetching and potentially exposing other user's details if the `pk` is known.
- **Security Test Case:**
    1. **Setup:** Create two user accounts in the application: user1 and user2. Log in to the application as user1.
    2. **Identify Target User ID:** Obtain the user ID (primary key - pk) of user2. This could be done through various means, such as observing user IDs in other parts of the application, API enumeration if IDs are sequential, or social engineering. Let's assume user2's ID is '2'.
    3. **Craft Malicious Request:** As user1, construct a GET request to the user detail API endpoint, targeting user2's ID: `/api/users/2/`.
    4. **Send Request:** Send the crafted GET request to the application.
    5. **Analyze Response:**
        - **Expected Behavior (Secure):** The API should recognize that user1 is trying to access user2's data and prevent this access. The API should return a `404 Not Found` or `403 Forbidden` HTTP status code, indicating unauthorized access.
        - **Vulnerable Behavior (IDOR Present):** The API incorrectly retrieves and returns user2's details. The API responds with a `200 OK` HTTP status code and the response body contains user2's information (specifically, 'name' and 'url' as defined in `UserSerializer`).
    6. **Determine Vulnerability:** If the API exhibits the vulnerable behavior (step 5 - Vulnerable Behavior), it confirms the presence of the IDOR vulnerability. User1 was able to successfully access user2's data without proper authorization.