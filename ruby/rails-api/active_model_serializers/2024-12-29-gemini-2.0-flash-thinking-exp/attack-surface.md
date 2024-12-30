*   **Attack Surface: Exposure of Sensitive Data through Incorrectly Configured Serializers**
    *   **Description:** Sensitive information from model attributes is unintentionally included in the API response due to misconfigured serializers.
    *   **How Active Model Serializers Contributes:** AMS defines which model attributes are serialized and exposed. If developers don't explicitly define the attributes or use overly broad selectors like `attributes :*`, sensitive data can be leaked.
    *   **Example:** A `User` model has a `password_digest` attribute. If the `UserSerializer` uses `attributes :*` or explicitly includes `password_digest`, this sensitive information will be exposed in the API response.
    *   **Impact:** Confidential data breach, potential for account compromise, violation of privacy regulations.
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Explicitly define attributes:**  In serializers, explicitly list only the attributes that should be exposed in the API response. Avoid using `attributes :*`.
        *   **Use `except` or `only`:** When inheriting serializers or dealing with many attributes, use `except` to exclude sensitive attributes or `only` to include specific safe attributes.
        *   **Regular security audits:** Review serializer definitions to ensure no sensitive data is inadvertently exposed.

*   **Attack Surface: Exposure of Data through Unintended Relationships**
    *   **Description:** Data from related models is exposed in the API response through associations (e.g., `has_many`, `belongs_to`) that were not intended to be publicly accessible in that context.
    *   **How Active Model Serializers Contributes:** AMS allows including associated models using the `has_many`, `belongs_to`, and `has_one` directives within serializers. Incorrectly including these relationships can expose more data than necessary.
    *   **Example:** A `Post` model `belongs_to` an `Author` model. If the `PostSerializer` includes `belongs_to :author` without considering the sensitivity of the author's data, information like the author's email or internal ID might be exposed.
    *   **Impact:** Information disclosure, potential for unauthorized access to related resources.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Carefully consider included associations:** Only include relationships that are necessary for the API endpoint's purpose.
        *   **Use nested serializers:** For related models, create separate serializers that expose only the necessary attributes for that specific context.
        *   **Implement authorization checks:**  Implement logic to ensure the current user has permission to view the associated data before including it in the response.