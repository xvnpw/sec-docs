## Combined Vulnerability Report

This report consolidates identified vulnerabilities, removing duplicates and presenting them in a structured format.

### Vulnerability: Hardcoded SECRET_KEY and Debug Mode Enabled in Django Settings

- **Description:**
  The settings file (`integration_test/integration_test/settings.py`) hardcodes a secret key and enables DEBUG mode (i.e. `DEBUG = True`). In a production deployment, an attacker who can trigger an error page (or otherwise inspect configuration details) may obtain extensive diagnostic information. Moreover, with the secret key known, cryptographic operations (such as session signing and token generation) become predictable, making session hijacking or forgery attacks possible.

  Steps to trigger:
  1. Deploy the Django application with the default insecure settings in a publicly accessible environment.
  2. Cause the application to generate an error, for example, by requesting a non-existent page. This will display a detailed debug error page if DEBUG mode is enabled.
  3. View the source code of the error page or inspect server responses to find the hardcoded `SECRET_KEY` and confirmation of `DEBUG = True`.

- **Impact:**
  Attackers may:
  - View detailed error messages including sensitive file paths, settings, and stack traces (due to DEBUG mode).
  - Forge or tamper with session cookies, authentication tokens, and other cryptographic artifacts because the secret key is publicly known.
  - Potentially bypass authentication or manipulate sensitive data, leading to a complete system compromise.

- **Vulnerability Rank:**
  Critical

- **Currently Implemented Mitigations:**
  No mitigations are applied; the secret key is directly embedded in source code and DEBUG remains enabled in the provided configuration.

- **Missing Mitigations:**
  - Load the secret key from a secure environment variable or external configuration file rather than hardcoding it.
  - Automatically force `DEBUG = False` when running in a production environment (for example, by checking an environment flag).
  - Include explicit configuration checks that block or warn deployment when insecure settings are detected.

- **Preconditions:**
  - The application is deployed with this default configuration in a production (or publicly accessible) environment.
  - An attacker can trigger error conditions (e.g. by making malformed requests) so that the debug pages are rendered.

- **Source Code Analysis:**
  In the file `integration_test/integration_test/settings.py` the following lines appear without any environment‐based conditions:
  ```python
  # SECURITY WARNING: keep the secret key used in production secret!
  SECRET_KEY = '!s1kl4g@+13igo3-&47f4+5-zfj!3j&n*sw$32@m%d65*muwni'

  # SECURITY WARNING: don't run with debug turned on in production!
  DEBUG = True
  ```
  There is no check to override these values outside of a development environment. If deployed as is, both the secret key and debug mode will be exposed to potential attackers.

- **Security Test Case:**
  1. Deploy the Django application with the current `settings.py` configuration in an environment accessible to external users.
  2. Force an error by visiting a non-existent URL (e.g., `http://<target-domain>/nonexistent-page/`) to trigger an exception. Observe the error page.
  3. Verify that the debug traceback is shown, revealing sensitive information. Check if the hardcoded secret key is visible in the output or configuration dumps on the error page.
  4. Using the hardcoded secret key, attempt to forge a session cookie or a signed token using Django’s signing functions. Try to use this forged artifact to access protected areas of the application.
  5. Document that the publicly visible secret key and detailed debug output allow an attacker to gain sensitive internal information and potentially compromise the application’s security.

---

### Vulnerability: Unauthenticated and CSRF‐Exempt Job Enqueue Endpoint

- **Description:**
  In the integration app’s view (`integration_test/integration_app/views.py`), the home endpoint is decorated with `@csrf_exempt` and does not enforce any authentication or authorization. This view accepts POST requests and immediately enqueues a background job by passing user‐provided input (the “name” POST parameter) to the `add_mymodel` function. Because no access control or input validation is performed, an external attacker can abuse this endpoint to submit arbitrary jobs.

  Steps to trigger:
  1. Identify the publicly accessible endpoint that enqueues jobs (in this case, the root URL "/").
  2. Send a POST request to this endpoint with a crafted "name" parameter.
  3. Observe that the application enqueues a job based on the provided input without any authentication or CSRF protection.

- **Impact:**
  An attacker may:
  - Enqueue arbitrary jobs repeatedly (for example, with crafted input values) without any verification, potentially polluting the job queue and the database table (`MyModel`).
  - Use the job‐enqueue mechanism as a foothold into the job processing pipeline if, in other parts of the system, similar unsanitized functions are enqueued with more sensitive operations.
  - Trigger unintended behavior, possibly interfering with legitimate processing or corrupting application data.

- **Vulnerability Rank:**
  High

- **Currently Implemented Mitigations:**
  - The endpoint is marked with `@csrf_exempt`, disabling CSRF protection. No authentication or authorization mechanisms are in place.

- **Missing Mitigations:**
  - Remove (or limit) the use of `@csrf_exempt` to enforce CSRF protection.
  - Implement user authentication and authorization to ensure only authorized users can enqueue jobs.
  - Validate and sanitize the input data (the “name” field) before using it to create or enqueue a job to prevent potential injection attacks or data corruption.

- **Preconditions:**
  - The integration app, including the vulnerable endpoint, is deployed in a publicly accessible environment.
  - An attacker can send POST requests to the home endpoint (i.e., “/”) without any authentication.

- **Source Code Analysis:**
  The view is implemented in `integration_test/integration_app/views.py`:
  ```python
  from django.http import HttpResponse
  from django.views.decorators.csrf import csrf_exempt

  from .models import *
  import django_rq

  @csrf_exempt
  def home(request):
      if request.method == 'POST':
          django_rq.enqueue(add_mymodel, request.POST["name"])
          return HttpResponse("Enqueued")
      names = [m.name for m in MyModel.objects.order_by("name")]
      return HttpResponse("Entries: {}".format(",".join(names)))
  ```
  - The `@csrf_exempt` decorator disables CSRF protection.
  - There is no authentication or permission check, allowing any client to POST to this endpoint.
  - The user-supplied value (`request.POST["name"]`) is directly passed to the `add_mymodel` function, which interacts with the database.

- **Security Test Case:**
  1. Deploy the application with the integration app publicly accessible.
  2. Use a tool like `curl` or Postman to send an HTTP POST request to the root URL (`http://<target-domain>/`) with the parameter `name` set to a test value, such as "test_job".
     ```bash
     curl -X POST -d "name=test_job" http://<target-domain>/
     ```
  3. Verify that the response is "Enqueued".
  4. Check the `MyModel` database table to confirm that a new record with the value "test_job" has been created, indicating successful job enqueueing.
  5. Repeat with different input values, including potentially malicious inputs, to confirm arbitrary job submission is possible without authentication or CSRF protection.
  6. Document that the endpoint allows unauthenticated job enqueueing and lacks CSRF protection, enabling unauthorized job submissions.

---

### Vulnerability: Potential Information Disclosure via stats_json API

- **Description:**
  The `stats_json` view in `django_rq/views.py` provides statistics about RQ queues in JSON format. While intended for staff users, it can be accessed by non-staff users if a valid API token is provided via the `token` URL parameter. If the `API_TOKEN` setting is configured with a weak or easily guessable token, or if the token is inadvertently exposed, an attacker could gain unauthorized access to sensitive information about job queues, workers, and Redis connections.

  Steps to trigger:
  1. Identify the `/django-rq/stats.json/<token>` endpoint. This might be discovered through documentation, code analysis, or by observing network requests.
  2. Attempt to access the endpoint with a guessed or discovered API token via a GET request.
  3. If the token is valid and matches the configured `API_TOKEN`, the server will respond with a JSON payload containing queue statistics.

- **Impact:**
  Successful exploitation of this vulnerability could lead to information disclosure, potentially revealing:
  - Names and sizes of RQ queues, providing insights into job types and system load.
  - Number of active workers, indicating processing capacity.
  - Statistics about job processing (queued, started, deferred, finished, failed, scheduled jobs count), revealing job processing patterns and potential bottlenecks.
  - Details about the Redis connection configurations (host, port, database), which, while less sensitive directly, can contribute to a broader understanding of the infrastructure.
  This information could be valuable for an attacker to understand the application's backend infrastructure, job processing patterns, and potentially identify further attack vectors or plan denial-of-service attacks.

- **Vulnerability Rank:**
  High

- **Currently Implemented Mitigations:**
  - Access to the `stats_json` view is primarily restricted to staff users by default through the `@staff_member_required` decorator.
  - Optional non-staff access is controlled by an `API_TOKEN` setting. If `API_TOKEN` is not set in Django settings, the view is effectively staff-only.
  - The code explicitly checks if the provided token in the URL matches the configured `API_TOKEN` before returning statistics.

  ```python
  def stats_json(request, token=None):
      if request.user.is_staff or (token and token == API_TOKEN):
          return JsonResponse(get_statistics())

      return JsonResponse(
          {"error": True, "description": "Please configure API_TOKEN in settings.py before accessing this view."}
      )
  ```

- **Missing Mitigations:**
  - **Rate limiting:** Implement rate limiting on the `stats_json` endpoint to prevent brute-force attempts to guess the `API_TOKEN`.
  - **Token complexity and rotation enforcement:**  Documentation should strongly emphasize the necessity of using a strong, randomly generated `API_TOKEN` with sufficient length and complexity. Regular token rotation should be recommended as a security best practice.
  - **HTTPS enforcement:** While not directly within `django-rq`'s codebase, it's crucial to ensure the application is served over HTTPS. This protects the API token during transmission and prevents eavesdropping, especially when the token is passed in the URL.
  - **Consider alternative authentication methods:** For more robust security, consider using more established API authentication methods like API keys passed in headers or OAuth 2.0 instead of relying solely on a token in the URL.

- **Preconditions:**
  - The `API_TOKEN` setting in `settings.py` must be configured with a non-empty string to enable non-staff access to `stats_json`. If left empty, the vulnerability is mitigated by default as only staff users can access it.
  - The attacker needs to obtain or guess a valid `API_TOKEN`. This could be through weak token generation, accidental exposure, or brute-force attempts if rate limiting is absent.

- **Source Code Analysis:**
  1. **`django_rq/views.py` - `stats_json` function:**
     ```python
     def stats_json(request, token=None):
         if request.user.is_staff or (token and token == API_TOKEN): # [1] Authorization check
             return JsonResponse(get_statistics()) # [2] Return statistics if authorized

         return JsonResponse( # [3] Return error if not authorized
             {"error": True, "description": "Please configure API_TOKEN in settings.py before accessing this view."}
         )
     ```
     - [1] The authorization logic checks if the user is a staff member OR if a token is provided in the URL and it matches the `API_TOKEN` configured in Django settings.
     - [2] If authorized (either staff or valid token), the `get_statistics()` function retrieves queue statistics, which are then returned as a JSON response.
     - [3] If not authorized, an error JSON response is returned, indicating that the `API_TOKEN` needs to be configured.

  2. **`django_rq/settings.py` - `API_TOKEN` setting:**
     ```python
     API_TOKEN: str = getattr(settings, 'RQ_API_TOKEN', '')
     ```
     - The `API_TOKEN` setting is retrieved from Django settings. It defaults to an empty string if `RQ_API_TOKEN` is not defined in the project's settings, effectively disabling token-based access by default.

- **Security Test Case:**
  1. **Prerequisites:**
     - Configure `API_TOKEN` in the Django project's `settings.py` to a known value, for example, `TEST_API_TOKEN`.
     - Deploy a public instance of the Django application with `django-rq` enabled and the `django-rq` URLs included in the URL configuration.
     - Ensure you are *not* logged in as a staff user in the application for testing non-staff access.

  2. **Test Steps (Valid Token):**
     - Construct a URL to access the `stats_json` endpoint with the correct API token: `https://<your-application-url>/django-rq/stats.json/TEST_API_TOKEN/`. Replace `<your-application-url>` with the actual URL of your deployed application.
     - Send a GET request to this URL using a tool like `curl`, Postman, or a web browser.
     - Verify that the HTTP response status code is 200 OK.
     - Examine the response body. Confirm that it is a JSON payload containing statistics about the RQ queues, such as queue names, job counts, and worker counts.

  3. **Expected Result (Valid Token):**
     - The server should respond with a 200 OK status code.
     - The response body should be a JSON object providing RQ queue statistics.

  4. **Negative Test (Incorrect Token):**
     - Construct a URL with an *incorrect* API token: `https://<your-application-url>/django-rq/stats.json/WRONG_TOKEN/`.
     - Send a GET request to this URL.
     - Verify that the HTTP response status code is 200 OK (as it's still a valid request to the endpoint).
     - Examine the response body. Confirm that it is a JSON payload indicating an error, specifically `{"error": true, "description": "Please configure API_TOKEN in settings.py before accessing this view."}`.

  5. **Expected Negative Result (Incorrect Token):**
     - The server should respond with a 200 OK status code.
     - The response body should be the JSON error object: `{"error": true, "description": "Please configure API_TOKEN in settings.py before accessing this view."}`.

  6. **Negative Test (No Token):**
     - Construct a URL *without* any token: `https://<your-application-url>/django-rq/stats.json/`.
     - Send a GET request to this URL.
     - Verify that the HTTP response status code is 403 Forbidden. This is because without a token and not being a staff user, access should be denied. (Note: This might depend on Django's URL configuration and how `stats_json` is wired up - ensure it correctly enforces staff/token access).

  7. **Expected Negative Result (No Token):**
     - The server should respond with a 403 Forbidden status code, indicating unauthorized access.

  8. **Cleanup:**
     - No specific cleanup is needed for this test case. Remember to handle the `API_TOKEN` securely in a real deployment and avoid hardcoding test tokens in production configurations.