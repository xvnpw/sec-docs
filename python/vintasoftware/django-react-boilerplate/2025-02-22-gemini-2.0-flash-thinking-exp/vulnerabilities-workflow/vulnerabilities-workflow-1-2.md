- **Vulnerability Name:** Mass Assignment / Privilege Escalation in User API
  **Description:**
  An attacker who is already authenticated as a normal (non‑admin) user can abuse the User API endpoints to update sensitive fields. The API (implemented via the default DRF ModelViewSet for users) uses a serializer that exposes sensitive fields such as “is_staff” and “is_superuser” without marking them as read‑only. By sending a crafted PUT or PATCH request to the endpoint (for example, `/api/users/<user_id>/`), the attacker can modify these fields and escalate privileges.
  **Impact:**
  If successful, the attacker can grant themselves (or other accounts) administrative privileges. This could lead to full system compromise—such as unauthorized data access, modification, and control over backend functions.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  - The project uses DRF’s default “IsAuthenticated” permission on all API endpoints so that only signed‑in users have any access. However, no object‑level access restrictions or field‑level protections are applied on the User serializer.
  **Missing Mitigations:**
  - The serializer should mark sensitive fields (e.g. “is_staff”, “is_superuser”, “is_active”) as read‑only (or use a dedicated “update” serializer) to prevent mass assignment.
  - Additional object‑level permission checks should be added in the viewset to limit updates only to the user’s own account (or require admin rights for modifications on other users).
  **Preconditions:**
  - The attacker must be authenticated (even with a regular account).
  - The attacker must be aware of or able to enumerate user IDs (or modify their own record inappropriately).
  **Source Code Analysis:**
  - In **`backend/users/serializers.py`**, the `UserSerializer` lists sensitive fields:
    - ```python
      class UserSerializer(serializers.ModelSerializer):
          class Meta:
              model = User
              fields = [
                  "id",
                  "email",
                  "is_active",
                  "is_staff",
                  "is_superuser",
                  "created",
                  "modified",
                  "last_login",
              ]
      ```
    - No fields are explicitly marked as read‑only; hence, an update operation will allow changes to “is_staff” and “is_superuser.”
  - In **`backend/users/views.py`**, the `UserViewSet` is defined as:
    - ```python
      class UserViewSet(viewsets.ModelViewSet):
          queryset = User.objects.all()
          serializer_class = UserSerializer
      ```
    - There is no override of the update logic or the queryset that would restrict modifications to a user’s own record.
  **Security Test Case:**
  1. **Precondition:** Log in with a normal (non‑admin) account and obtain a valid session (or authentication token) to access the API.
  2. **Test Steps:**
     - Identify the current user’s record (or a target user’s ID) through a GET request at `/api/users/`.
     - Send a PATCH request to `/api/users/<user_id>/` with a payload such as:
       ```json
       {
         "is_superuser": true,
         "is_staff": true
       }
       ```
     - Verify that the response is 200 OK and then perform a subsequent GET request to confirm that the user’s record now reflects the elevated privileges.
  3. **Expected Result:**
     - The attacker’s user record (or the target user’s record) will be updated with admin-level privileges when no proper restrictions are enforced.

- **Vulnerability Name:** Insecure ALLOWED_HOSTS Configuration in Production
  **Description:**
  In production settings the value for `ALLOWED_HOSTS` is sourced from an environment variable. According to the provided deployment configuration (in **`render.yaml`** and the env var group in production settings), the default value is set to “*”. This configuration means that the Django application will accept requests for any host header. As a result, an attacker can supply a malicious host header to manipulate absolute URLs (for example, in error emails or password reset links) or facilitate host header poisoning attacks.
  **Impact:**
  An insecure host header policy can lead to host header injection and cache poisoning. It may be exploited to redirect users to malicious sites, interfere with session security, or otherwise subvert trust in the application’s URL-generated content.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The production settings use environment variables for `ALLOWED_HOSTS` (via `config("ALLOWED_HOSTS", cast=Csv())`) but do not enforce a restricted list by default.
  **Missing Mitigations:**
  - Instead of using “*”, the environment configuration should restrict `ALLOWED_HOSTS` to a whitelist of known and trusted domain(s) (for example, `["{{project_name}}-a1b2.onrender.com", "example.org"]`).
  **Preconditions:**
  - The application is deployed in a publicly accessible production environment.
  - The environment variable for `ALLOWED_HOSTS` is not properly overridden with a secure, domain‑specific list.
  **Source Code Analysis:**
  - In **`backend/project_name/settings/production.py`**, the setting is defined as:
    - ```python
      ALLOWED_HOSTS = config("ALLOWED_HOSTS", cast=Csv())
      ```
  - In the **`render.yaml`** file and the associated env var group for python services, the default value is set to `"*"`:
    - ```yaml
      envVarGroups:
        - name: python-services
          envVars:
            - key: ALLOWED_HOSTS
              value: '*'
      ```
  - With this configuration, the app will accept HTTP requests with any Host header.
  **Security Test Case:**
  1. **Precondition:** Deploy the application using the current production configuration where `ALLOWED_HOSTS` is “*”.
  2. **Test Steps:**
     - Use an HTTP client (such as curl or a browser with a proxy) to send a request to the application’s public endpoint with a malicious Host header (for example, set the Host header to `malicious.example.com`).
     - Observe if the application processes the request normally (no rejection due to host header mismatch).
  3. **Expected Result:**
     - The application should accept the request despite the non‑trusted host header, confirming that the wildcard (“*”) setting is in place and can be abused.