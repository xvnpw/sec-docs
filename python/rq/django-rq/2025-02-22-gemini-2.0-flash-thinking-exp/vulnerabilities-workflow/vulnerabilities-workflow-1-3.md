- vulnerability name: Potential Information Disclosure via stats_json API
  description: |
    The `stats_json` view in `django_rq/views.py` is intended to provide statistics about RQ queues in JSON format.
    It is accessible to staff users and, optionally, to non-staff users if an API token is provided via the `token` URL parameter.
    If the `API_TOKEN` setting is configured, an attacker could potentially gain access to sensitive information about job queues, workers, and Redis connections by guessing or finding the API token.

    Steps to trigger:
    1. Identify that the `/django-rq/stats.json/<token>` endpoint exists (e.g., through documentation or observing network requests).
    2. Attempt to access the endpoint with a guessed or discovered API token.
    3. If the token is valid, the server will respond with a JSON payload containing queue statistics.

  impact: |
    Successful exploitation of this vulnerability could lead to information disclosure, potentially revealing:
    - Names and sizes of RQ queues.
    - Number of active workers.
    - Statistics about job processing (queued, started, deferred, finished, failed, scheduled jobs count).
    - Details about the Redis connection configurations (host, port, database).
    This information could be valuable for an attacker to understand the application's backend infrastructure, job processing patterns, and potentially identify further attack vectors.

  vulnerability rank: high
  currently implemented mitigations: |
    - Access to the `stats_json` view is restricted to staff users by default via `@staff_member_required`.
    - For non-staff access, an optional `API_TOKEN` setting is introduced. If `API_TOKEN` is not set, the view is effectively restricted to staff only.
    - The code checks for the token before providing the statistics.

    ```python
    def stats_json(request, token=None):
        if request.user.is_staff or (token and token == API_TOKEN):
            return JsonResponse(get_statistics())

        return JsonResponse(
            {"error": True, "description": "Please configure API_TOKEN in settings.py before accessing this view."}
        )
    ```
  missing mitigations: |
    - **Rate limiting:** There is no rate limiting on the `stats_json` endpoint. An attacker could make repeated requests to try and brute-force the `API_TOKEN`.
    - **Token complexity and rotation:**  The documentation should emphasize the importance of using a strong, randomly generated `API_TOKEN` and recommend periodic token rotation.
    - **HTTPS enforcement:** While not directly in `django-rq` code, it's critical to ensure that the application is served over HTTPS to protect the API token in transit.

  preconditions: |
    - The `API_TOKEN` setting in `settings.py` must be configured with a non-empty string to enable non-staff access to `stats_json`.
    - The attacker needs to guess or discover a valid `API_TOKEN`.

  source code analysis: |
    1. **`django_rq/views.py` - `stats_json` function:**
    ```python
    def stats_json(request, token=None):
        if request.user.is_staff or (token and token == API_TOKEN): # [1] Authorization check
            return JsonResponse(get_statistics()) # [2] Return statistics if authorized

        return JsonResponse( # [3] Return error if not authorized
            {"error": True, "description": "Please configure API_TOKEN in settings.py before accessing this view."}
        )
    ```
    - [1] The code checks if the user is a staff member or if a token is provided and matches the `API_TOKEN` setting.
    - [2] If authorized, the `get_statistics()` function is called to gather queue statistics, which are then returned as a JSON response.
    - [3] If not authorized, an error JSON response is returned.

    2. **`django_rq/settings.py` - `API_TOKEN` setting:**
    ```python
    API_TOKEN: str = getattr(settings, 'RQ_API_TOKEN', '')
    ```
    - The `API_TOKEN` setting is retrieved from Django settings. It defaults to an empty string if not configured.

  security test case: |
    1. **Prerequisites:**
        - Ensure `API_TOKEN` is set in the Django project's `settings.py` file to a known value (e.g., `TEST_API_TOKEN`).
        - Deploy a public instance of the Django application with `django-rq` enabled and the `django-rq` URLs configured.
        - Ensure you are not logged in as a staff user in the application.

    2. **Test Steps:**
        - Construct a URL to access the `stats_json` endpoint with the correct API token: `https://<your-application-url>/django-rq/stats.json/TEST_API_TOKEN/`.
        - Send a GET request to this URL using a tool like `curl` or a web browser.
        - Verify that the response is a JSON payload containing queue statistics (e.g., queue names, job counts, worker counts).

    3. **Expected Result:**
        - The server should respond with a 200 OK status code.
        - The response body should be a JSON object containing statistics about the RQ queues.

    4. **Negative Test (Incorrect Token):**
        - Construct a URL with an incorrect API token: `https://<your-application-url>/django-rq/stats.json/WRONG_TOKEN/`.
        - Send a GET request to this URL.
        - Verify that the response is a JSON payload indicating an error.

    5. **Expected Negative Result:**
        - The server should respond with a 200 OK status code (it's still a valid request, but indicates an error).
        - The response body should be a JSON object like `{"error": true, "description": "Please configure API_TOKEN in settings.py before accessing this view."}`.

    6. **Cleanup:**
        - No specific cleanup is needed for this test case.