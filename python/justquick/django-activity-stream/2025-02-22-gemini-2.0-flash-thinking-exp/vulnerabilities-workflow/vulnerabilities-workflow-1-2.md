- **Vulnerability Name:** CSRF Vulnerability in Follow/Unfollow Endpoint
  **Description:**
  The view function that handles follow and unfollow operations (defined in `/code/actstream/views.py` as `follow_unfollow`) is decorated with both `@login_required` and `@csrf_exempt`. Although authentication is required, the use of `@csrf_exempt` disables Django’s built‐in CSRF protection even for state‑changing operations. An attacker can craft a malicious webpage (or email with embedded HTML/JavaScript) that causes an authenticated user’s browser to send a forged request to this endpoint. By doing so, the attacker is able to trigger follow or unfollow actions on behalf of the victim without their consent.
  **Impact:**
  - An attacker may force unauthorized changes in the user’s “follow” relationships.
  - Manipulation of a user’s activity stream or social graph may result—potentially exposing confidential relationships or simply degrading trust in the service.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The endpoint does enforce that the requester must be logged in (via the `@login_required` decorator).
  **Missing Mitigations:**
  - There is no CSRF token validation on this state-changing endpoint. Removing the `@csrf_exempt` decorator (or replacing it with an explicit, alternative secure token‐based protection) is necessary.
  **Preconditions:**
  - The victim must be an authenticated user in the web application.
  - The attacker must be able to trick the victim into visiting a malicious website or clicking on a crafted link that sends a request to this endpoint.
  **Source Code Analysis:**
  - In `/code/actstream/views.py`, the `follow_unfollow` function is defined as follows:
    ```python
    @login_required
    @csrf_exempt
    def follow_unfollow(request, content_type_id, object_id, flag=None, do_follow=True, actor_only=True):
        ctype = get_object_or_404(ContentType, pk=content_type_id)
        instance = get_object_or_404(ctype.model_class(), pk=object_id)
        flag = flag or ''

        if do_follow:
            actions.follow(request.user, instance, actor_only=actor_only, flag=flag)
            return respond(request, 201)  # CREATED

        actions.unfollow(request.user, instance, flag=flag)
        return respond(request, 204)  # NO CONTENT
    ```
    Notice that while the view properly checks that the user is authenticated, the `@csrf_exempt` decorator removes the Django CSRF safeguard.
  **Security Test Case:**
  1. Log in as a valid user on the target application.
  2. From an external (malicious) webpage, automatically submit (via an auto‑submitting HTML form or AJAX request) a POST (or even GET) request to a URL such as:
     ```
     https://target.example.com/follow/5/23/?flag=malicious
     ```
  3. Verify in the application (or via the database/logs) that the logged‑in user’s “follow” relationship was modified (i.e. a follow or unfollow action was performed) even though the request did not originate from a trusted source.
  4. Document that the absence of CSRF token validation enabled this unauthorized state change.

- **Vulnerability Name:** Open Redirect via Unvalidated “next” Parameter
  **Description:**
  In the helper function `respond` (located in `/code/actstream/views.py`), the code checks for a parameter named `next` (from either GET or POST) and, if present, immediately returns an HTTP redirect to that URL without any form of validation. An attacker can supply an arbitrary external URL into the `next` parameter. When a victim follows a link that uses this endpoint, they are unknowingly redirected to a potentially malicious site.
  **Impact:**
  - Phishing attacks become possible by redirecting authenticated users to attacker‑controlled websites.
  - The attacker may leverage the redirect to simulate legitimate behavior and harvest credentials or other sensitive data.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - None specific—the endpoint blindly uses the supplied `next` value.
  **Missing Mitigations:**
  - Validate that the value of the `next` parameter is a relative URL or belongs to an approved, trusted domain.
  - Alternatively, remove support for an externally provided `next` parameter on state‑changing endpoints.
  **Preconditions:**
  - The victim must be already authenticated.
  - The attacker must provide a link with a crafted `next` parameter (e.g., through phishing email or advertisement).
  **Source Code Analysis:**
  - The `respond` function is defined as follows in `/code/actstream/views.py`:
    ```python
    def respond(request, code):
        redirect = request.GET.get('next', request.POST.get('next'))
        if redirect:
            return HttpResponseRedirect(redirect)
        return type('Response%d' % code, (HttpResponse, ), {'status_code': code})()
    ```
    No checks or sanitization of the “next” parameter are performed; it is passed directly as the destination in the HTTP redirect.
  **Security Test Case:**
  1. As an attacker, create a URL such as:
     ```
     https://target.example.com/follow/5/23/?next=https://malicious.example.com
     ```
  2. Send the link to a victim (e.g., via email or social media) who is likely to be logged in at the target site.
  3. When the victim clicks the link, observe that after the follow/unfollow action the browser is redirected to `https://malicious.example.com`.
  4. Confirm the absence of any validation on the redirect destination and document the open redirect vulnerability.

- **Vulnerability Name:** Insecure Configuration – DEBUG Mode Enabled with Hard‑Coded SECRET_KEY
  **Description:**
  The settings file (located at `/code/runtests/settings.py`) contains the following lines:
  ```python
  DEBUG = True
  SECRET_KEY = 'secret-key'
  ```
  Running Django in DEBUG mode with a known, hard‑coded secret key is acceptable only in a secure development or testing environment. If these settings are mistakenly deployed in production, they expose the application to several attacks.
  **Impact:**
  - Detailed error pages (including environment information, stack traces, and configuration details) are exposed to end‑users upon encountering any error.
  - The static, well‑known secret key compromises the integrity of cryptographic operations such as session signing and CSRF token generation. An attacker may then forge session cookies or CSRF tokens, leading to session hijacking and further exploitation of the application.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  - A comment in the file warns: "Always for debugging, dont use the runtests app in production!" However, this does not enforce the settings dynamically.
  **Missing Mitigations:**
  - Ensure that the production environment sets `DEBUG = False` and uses a cryptographically strong, secret secret key (typically sourced from environment variables or a secure secrets store).
  - Remove or isolate the testing configuration from production deployments.
  **Preconditions:**
  - The application is deployed to a production or publicly accessible environment using the settings provided in `/code/runtests/settings.py`.
  - An attacker may trigger error pages or analyze session cookies without the benefit of unique secrets.
  **Source Code Analysis:**
  - The settings file sets:
    ```python
    DEBUG = True
    SECRET_KEY = 'secret-key'
    ```
    This configuration is inherently insecure for production and exposes the system to multiple attack vectors if not overwritten by environment‑specific settings.
  **Security Test Case:**
  1. Deploy the application using the current settings without modifications in an environment that is accessible to users.
  2. Deliberately trigger a server error (for example, by accessing a non‑existent URL).
  3. Verify that Django’s detailed debug error page (including stack trace and configuration information) is displayed.
  4. Inspect session cookies in the browser to confirm that they are signed using the known secret key.
  5. Attempt to forge a session cookie using the known secret key to demonstrate that an active session can be impersonated.
  6. Document that the use of `DEBUG = True` and a hard‑coded secret key exposes significant risk if left in production.