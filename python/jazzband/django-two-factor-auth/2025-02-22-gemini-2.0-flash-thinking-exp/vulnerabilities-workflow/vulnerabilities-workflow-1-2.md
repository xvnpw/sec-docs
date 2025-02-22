- **Vulnerability Name:** Insecure Storage of Two‑Factor Authentication Secret Keys  
  **Description:**  
  In multiple parts of the system the two‑factor authentication secret values (used by TOTP devices and other methods) are generated using a helper (via Django OTP’s `random_hex`) and then stored in plaintext (as hex–encoded strings) in persistent storage or even in the session (for QR–based setup). An attacker who is able to read the database contents or the session storage (for example via SQL injection, bypassing access control, or backup compromise) can retrieve these unencrypted secrets. With these secrets the attacker can independently generate valid OTP tokens and bypass the second–factor challenge.  
  **Impact:**  
  - An attacker who gains read access to the database or session storage can generate one‑time passwords for user accounts.  
  - Bypassing two–factor authentication effectively reduces the authentication scheme to a single factor, effectively compromising user account security.  
  **Vulnerability Rank:** Critical  
  **Currently Implemented Mitigations:**  
  - The system uses Django models and forms for OTP devices (for example, in modules such as `two_factor/plugins/phonenumber/models.py` and in the TOTP form processing in `two_factor/views/core.py`) with keys generated via `django_otp.util.random_hex`.  
  - The QR generation (in `QRGeneratorView`) takes the key, converts it using `unhexlify` and `b32encode`, then stores it in session for later use in a way that presumes the underlying storage is secure.  
  **Missing Mitigations:**  
  - No encryption is applied when storing sensitive 2FA secrets (whether in the database or in session data).  
  - There is no separate key‐management layer or field–level encryption to protect these secret values at rest.  
  **Preconditions:**  
  - An attacker must be able to read the persistent storage – either via exploiting an SQL injection flaw, misconfigured database permissions, or direct access to backups/session data.  
  **Source Code Analysis:**  
  - In the TOTP setup flow inside `SetupView` (in **two_factor/views/core.py**), the secret for the “generator” method is created by calling `random_hex(20)`, stored in the wizard’s extra data, and later unhexlified in order to build a Base32–encoded version for use with OTP apps.  
  - The same pattern is visible in form and model definitions such as in `TOTPDeviceForm` (not fully shown here but referenced in the tests and saving routines) and in the phone–based devices (e.g. in **two_factor/plugins/phonenumber/models.py**).  
  - The QR code generation in `QRGeneratorView` (in **two_factor/views/core.py**) relies on retrieving the key from the session (using a session key that is set from the unhexlified secret).  
  - Because the secret key is stored as a plain hex value and not encrypted, any read compromise of either the database or the session store would yield the 2FA secret without additional difficulty.  
  **Security Test Case:**  
  1. In a controlled test environment, simulate a database read (for example, via an SQL injection test harness targeting the tables that store TOTP, phone, or WebAuthn device data).  
  2. Extract the column corresponding to the 2FA secret key (the plain hex string).  
  3. Convert the hex value to its binary form if necessary and use it in a standard TOTP generator (either via an open–source tool or online generator) to produce a current valid OTP.  
  4. Attempt to authenticate using a user account that is configured with 2FA by supplying the generated OTP in the second step of the login flow.  
  5. A successful login despite not having the user’s primary credentials confirms that the plaintext storage of secret keys can be exploited to bypass 2FA.

---

- **Vulnerability Name:** Open Redirect Vulnerability via Unvalidated “next” Parameter in Authentication Flows  
  **Description:**  
  The system extracts a redirect URL from the “next” parameter during the login process (and similarly within the OTP setup flow) and validates it using Django’s `url_has_allowed_host_and_scheme()` helper. However, both the login view (in **two_factor/views/core.py**, in the `LoginView.get_redirect_url` method) and the setup view (in `SetupView.get_redirect_url`) rely on using `[request.get_host()]` as the only allowed host. In many deployments the HTTP Host header is derived from user–controlled input, so if the deployer has not hardened Django’s `ALLOWED_HOSTS` or if the upstream server does not enforce strict host header checks, an attacker may manipulate both the “next” parameter and the Host header to force a redirection to an external, attacker–controlled domain.  
  **Impact:**  
  - After a successful authentication, users could be redirected to an attacker–controlled website.  
  - This may enable phishing attacks, session hijacking via cookie leakage, or redirection to malicious pages.  
  **Vulnerability Rank:** High  
  **Currently Implemented Mitigations:**  
  - The login view (in **two_factor/views/core.py**, within `LoginView.get_redirect_url`) and the OTP setup view use Django’s built–in helper `url_has_allowed_host_and_scheme()` to check that the redirect URL’s host is among those allowed (using `[request.get_host()]`).  
  - Automated tests (e.g. in the existing test suite for the login views) check that known safe URLs are accepted and obvious external URLs are rejected under normal conditions.  
  **Missing Mitigations:**  
  - Relying solely on `request.get_host()` makes the redirect check vulnerable to Host header spoofing if the webserver or Django settings do not properly constrain allowed hosts.  
  - A fixed whitelist of safe redirect hostnames (or a more robust validation routine that does not trust the user–supplied Host header) is not implemented.  
  **Preconditions:**  
  - The deployment must have a misconfiguration that permits an attacker to control or spoof the HTTP Host header (for example, via an overly permissive ALLOWED_HOSTS setting or misconfigured reverse proxy).  
  - The attacker must be able to control the value of the “next” parameter on an authentication request.  
  **Source Code Analysis:**  
  - In **two_factor/views/core.py** within `LoginView.get_redirect_url()`, the redirect URL is obtained from the request (via either POST or GET) and then passed to `url_has_allowed_host_and_scheme()`, with the allowed hosts being set to `[request.get_host()]`.  
  - In a similar pattern, `SetupView.get_redirect_url()` uses the same technique when determining where to redirect the user after a successful OTP setup.  
  - The vulnerability arises because if an attacker can spoof the Host header, then `[request.get_host()]` will include an attacker–controlled domain, and a malicious URL supplied in the “next” parameter may pass the check.  
  **Security Test Case:**  
  1. Craft an HTTP POST (or GET) request to the login URL (or to the OTP setup view) with valid user credentials.  
  2. Set the “next” parameter to an external URL (for example, “https://malicious.example.com”), and simultaneously manipulate the HTTP Host header so that `request.get_host()` returns “malicious.example.com” (or a matching value).  
  3. Submit the authentication request.  
  4. On successful authentication, observe that the application redirects the browser to the attacker–controlled URL rather than a trusted URL.  
  5. A successful redirection confirms that the reliance on the incoming Host header in the redirect validation check can be exploited for phishing.