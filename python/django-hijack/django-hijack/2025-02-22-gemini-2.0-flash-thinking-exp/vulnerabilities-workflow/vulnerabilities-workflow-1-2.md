- **Vulnerability Name:** Session Hijack History Manipulation

- **Description:**  
  The hijack mechanism stores the identifier of the original user in a session variable (“hijack_history”) when a hijack occurs. Later, when a hijacked session is “released” (via the ReleaseUserView), the view simply pops the last value from the hijack_history and logs in that user. In deployments where Django’s session engine uses client‑side storage (such as the signed cookies session engine) and the signing key is weak or improperly managed, an attacker who already holds an authenticated session may be able to tamper with the session data. By forging or manipulating hijack_history, the attacker could insert an arbitrary (target) user’s identifier. When the release endpoint is triggered, this manipulated value will be used to restore the session—thereby allowing unauthorized impersonation (privilege escalation) of a user with higher privileges.

- **Impact:**  
  If exploited, the attacker can cause the application to “release” the hijacked session into an account of the attacker’s choosing. This may result in:
  - Unauthorized user impersonation  
  - Privilege escalation (for example, an attacker may force a return to a superuser account)  
  - Access to sensitive information or restricted functionality

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**  
  - The project uses Django’s built‑in authentication “login()” function, which flushes the session on login. This helps mitigate some session fixation risks.  
  - The reliance on Django’s session framework implies that session integrity is provided via signing if deployed properly.  
  - CSRF protection is applied on both hijack acquire and release views.

- **Missing Mitigations:**  
  - There is no additional validation or integrity check on the contents of “hijack_history” beyond trusting the session’s signing. In client-side session setups, a misconfigured or weak SECRET_KEY may let an attacker forge session data.  
  - No explicit recommendation is enforced by the package to use server-side session storage (or to ensure a strong secret key) for hijack functionality.
  - The code does not verify that the user identity stored within “hijack_history” is actually associated with the original (authenticated) user beyond a simple lookup when releasing the hijack.

- **Preconditions:**  
  - The attacker must already have an authenticated session (even if as a lower‑privileged user).  
  - The application is deployed using a client‑side session storage mechanism (e.g., Django’s signed cookies) and/or is using a weak, default, or otherwise compromised SECRET_KEY such that session data can be forged.  
  - No additional server‑side validation is in place to check the authenticity of the hijack_history contents.

- **Source Code Analysis:**  
  1. **Acquisition of Hijack History:**  
     - In `AcquireUserView.post()`, the view retrieves the current hijack history from the session using:  
       `hijack_history = request.session.get("hijack_history", [])`  
     - It then appends the currently authenticated user’s identifier (via `request.user._meta.pk.value_to_string(hijacker)`) and writes it back into the session.  
  2. **Restoration on Release:**  
     - In `ReleaseUserView.post()`, the view first checks that a hijack history exists. It then pops the last element from the history:  
       `user_pk = hijack_history.pop()`  
     - The view uses `get_object_or_404` with the popped user_pk to retrieve the original user and then logs into that account with:  
       `login(request, hijacker, backend=backend)`  
  3. **Trust on Session Data:**  
     - The mechanism assumes the session (and its hijack_history) has not been tampered with. However, if the session engine is client‑side and the signing is compromised (or the key is weak), an attacker can modify hijack_history to include an arbitrary user ID.  
  4. **Visualization:**  
     - **During Hijack:**  
       - Original session: `{ ..., "hijack_history": [] }`  
       - After hijacking, session becomes: `{ ..., "hijack_history": ["<original user id>"] }`  
     - **During Release:**  
       - The view pops the value from hijack_history and uses it to log back in. If the attacker has manipulated hijack_history to contain a target user’s ID, the application will log the attacker into that account.

- **Security Test Case:**  
  1. **Setup:**  
     - Deploy the application using a client‑side session store (e.g., Django’s default signed cookies) with a weak or default SECRET_KEY for testing purposes.  
     - Authenticate as a lower‑privileged user (attacker-controlled account).  
  2. **Tamper with the Session:**  
     - Manually modify the session cookie to include an altered “hijack_history” value (e.g., encode a value containing the primary key of a higher‑privileged target account).  
     - This may be done by extracting the session cookie, decoding the signed data (if possible in the test environment), modifying the hijack_history list, and re‑signing it (or using a tool that bypasses or simulates a weak signature).
  3. **Trigger the Release Endpoint:**  
     - Using an HTTP client (or a tool like curl/Postman), send a POST request to the `/hijack/release/` URL including the necessary CSRF token and with the tampered session cookie attached.
  4. **Expected Behavior:**  
     - The response should redirect (HTTP 302) to the configured success URL.  
     - On checking the session or via a subsequent authenticated request (for example, to a “user detail” endpoint), the logged‑in user should now be the target user whose identifier was injected into hijack_history.
  5. **Verification:**  
     - Confirm that the attacker’s session has been “released” as the unintended (target) user.  
     - This demonstrates that a manipulation of session data can lead to unauthorized user impersonation.