## Vulnerability List

- Vulnerability Name: Excessive Data Exposure via Include Parameter
- Description: An attacker can use the `include` query parameter to request inclusion of related resources. If the application does not properly validate or limit the depth and breadth of included resources, or if the serializers for included resources expose more data than intended for the context of the primary resource, it can lead to excessive data exposure. An attacker could potentially retrieve sensitive information from related models that they are not authorized to access directly, simply by crafting a specific `include` query.
- Impact: Exposure of sensitive data from related resources. This could include personal information, business secrets, or other confidential data, depending on the models and relationships configured in the application.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - Validation of include paths against `included_serializers` in `IncludedResourcesValidationMixin` in `/code/rest_framework_json_api/serializers.py`. This validation ensures that only paths defined in `included_serializers` are allowed. However, it does not limit depth, breadth, or perform authorization checks on included resources.
- Missing mitigations:
    - Implement validation and sanitization of the `include` parameter to ensure only allowed relationships are included. (Partially Implemented - path validation exists, but not sufficient)
    - Implement a configuration to limit the depth and breadth of allowed includes to prevent excessive data retrieval.
    - Review and potentially create specialized serializers for included resources that expose only the necessary data when included in a compound document, rather than reusing serializers intended for detailed views of those resources.
    - Consider implementing access control checks within the `extract_included` function to ensure the current user is authorized to access the included resources in the context of the primary resource.
- Preconditions:
    - Application uses Django REST framework JSON:API and enables the `include` feature.
    - Application does not have sufficient validation or limitations on the `include` parameter.
    - Serializers for included resources might expose more data than intended when included in the context of the primary resource.
- Source code analysis:
    - File: `/code/rest_framework_json_api/renderers.py`
    - Function: `JSONRenderer.extract_included`
    - Step-by-step analysis:
        1. The `extract_included` function is called during rendering to process the `include` query parameter.
        2. It retrieves the `included_resources` from the request and `included_serializers` from the serializer.
        3. It iterates through the requested `included_resources`.
        4. For each resource, it determines the related instance and serializer.
        5. It recursively calls `extract_included` for nested resources based on dot notation in the `include` parameter (e.g., `include=relation1.relation2`).
        6. **Vulnerability**: There are no explicit checks within `JSONRenderer.extract_included` function to validate if the *user is authorized* to access the requested included resources. While `IncludedResourcesValidationMixin` validates if the include path is *defined* in the serializer, it does not check *authorization*. The function blindly follows the `include` parameter and the defined `included_serializers`, fetching and including data. This allows an attacker to potentially request inclusion of any related resource defined in `included_serializers`, regardless of whether it's appropriate in the current context or if the user is authorized to access it in this manner.

    - File: `/code/rest_framework_json_api/serializers.py`
    - Class: `IncludedResourcesValidationMixin`
    - Function: `__init__`
    - Step-by-step analysis:
        1. The `__init__` method of `IncludedResourcesValidationMixin` is called when a serializer using this mixin is initialized.
        2. It retrieves the `include` query parameter from the request using `get_included_resources(request)`.
        3. It iterates through each included resource path.
        4. For each path, it splits the path by dots to handle nested includes (e.g., `relation1.relation2`).
        5. It recursively validates each segment of the path against the `included_serializers` defined in the serializer and its nested serializers.
        6. **Mitigation (Partial)**: This mixin **does** provide a level of validation by ensuring that only include paths that are explicitly defined in `included_serializers` are allowed. If an attacker tries to include a relationship that is not defined in `included_serializers`, a `ParseError` is raised, and the request is rejected.
        7. **Still Vulnerable**: However, this validation is insufficient because it only checks if the *path is defined*, not if the *user is authorized* to access the related resources. If a relationship is included in `included_serializers`, it is considered valid for inclusion, even if the user should not have access to the related data in the context of the primary resource. This validation also does not limit the depth or breadth of the include, potentially leading to performance issues and excessive data retrieval if complex include paths are defined.

    - File: `/code/rest_framework_json_api/utils.py`
    - Function: `get_included_resources`
    - Step-by-step analysis:
        1. The `get_included_resources` function simply retrieves the `include` query parameter from the request.
        2. If the parameter is present, it splits the comma-separated values into a list of included resources.
        3. If the parameter is not present, it attempts to get default included resources from the serializer's `JSONAPIMeta.included_resources`.
        4. **No Mitigation**: This function does not perform any validation or sanitization of the `include` parameter itself. It only extracts the values from the query parameter.

- Security test case:
    1. Step 1: Set up a Django REST framework JSON:API application with two models, e.g., `Article` and `Author`. `Article` has a ForeignKey relationship to `Author`.
    2. Step 2: Create serializers for `Article` and `Author`. In `ArticleSerializer`, define `included_serializers = {'author': AuthorSerializer}` and include 'author' in `JSONAPIMeta.included_resources`. In `AuthorSerializer`, include a field that is considered sensitive, e.g., `email`. Assume that in a normal `/authors/{id}` endpoint, the `email` field is protected or not always exposed.
    3. Step 3: Create a viewset for `Article` that uses `ArticleSerializer`.
    4. Step 4: Send a GET request to the `/articles/` endpoint with the `include=author` query parameter: `GET /articles/?include=author`.
    5. Step 5: Examine the JSON response. Check if the included `author` resources in the `included` section contain the sensitive `email` field.
    6. Step 6: If the `email` field is present in the included `author` resources, it confirms the excessive data exposure vulnerability. An attacker can use the `include` parameter to bypass intended data access restrictions and retrieve sensitive information through related resources.