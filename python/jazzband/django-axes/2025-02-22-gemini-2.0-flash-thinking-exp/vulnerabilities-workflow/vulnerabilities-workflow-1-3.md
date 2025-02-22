### Vulnerability List for django-axes Project

* Vulnerability Name: Inconsistent Lockout Enforcement due to User Agent Parameter not being Considered by Default
* Description:
    1. An attacker attempts to login with invalid credentials from a specific IP address and user agent.
    2. After exceeding the configured failure limit for the IP address, the attacker is locked out when attempting further logins from the same IP address, regardless of the user agent.
    3. However, if the attacker changes their user agent, they can bypass the lockout and continue making login attempts from the same IP address, as the default configuration only considers IP address for lockout, not user agent.
    4. This inconsistency allows an attacker to circumvent IP-based lockout by simply modifying the User-Agent header in subsequent requests.
* Impact:
    - Reduced effectiveness of the account lockout mechanism.
    - Increased risk of brute-force attacks as attackers can bypass IP-based lockout by changing user agents.
    - Potential for unauthorized access if brute-force attacks are successful due to weakened lockout.
* Vulnerability Rank: High
* Currently Implemented Mitigations:
    - The project allows administrators to configure lockout parameters to include `user_agent`.
    - The settings documentation explains `AXES_LOCKOUT_PARAMETERS` and how to configure it to consider `user_agent`.
    - However, the default configuration does not include `user_agent`.
* Missing Mitigations:
    - The default `AXES_LOCKOUT_PARAMETERS` should be changed to include `user_agent` to enforce more robust lockout by default.
    - The documentation could be improved to highlight the security implications of *not* including `user_agent` in `AXES_LOCKOUT_PARAMETERS` and recommend including it.
* Preconditions:
    - Django-axes is installed and configured with default settings (where `AXES_LOCKOUT_PARAMETERS` does not include `user_agent`).
    - An attacker is attempting to brute-force login to the application.
* Source Code Analysis:
    1. **`axes/helpers.py` - `get_client_parameters` function:**
        ```python
        def get_client_parameters(username, ip_address, user_agent, request, credentials):
            """
            Returns a list of client parameters to filter access attempts and lockouts,
            based on AXES_LOCKOUT_PARAMETERS setting.
            """
            lockout_params_raw = settings.AXES_LOCKOUT_PARAMETERS
            if not lockout_params_raw:
                lockout_params_raw = ["ip_address"] # Default lockout parameter is IP address
            ...
            for param_set in lockout_params:
                filter_kwargs = {}
                for param in param_set:
                    if param == "username":
                        filter_kwargs["username"] = username
                    elif param == "ip_address":
                        filter_kwargs["ip_address"] = ip_address
                    elif param == "user_agent":
                        filter_kwargs["user_agent"] = user_agent
                    else:
                        log.exception(
                            f"{param} lockout parameter is not allowed. "
                            f"Allowed lockout parameters: username, ip_address, user_agent"
                        )
                        raise ValueError(
                            f"{param} lockout parameter is not allowed. "
                            f"Allowed lockout parameters: username, ip_address, user_agent"
                        )
                filter_params.append(filter_kwargs)
            return filter_params
        ```
        - By default, if `AXES_LOCKOUT_PARAMETERS` is not set in settings, it defaults to `["ip_address"]`.
        - This means that by default, lockout is only enforced based on IP address, and user agent is not considered unless explicitly configured.

    2. **`axes/handlers/proxy.py` and handler implementations:**
        - The handler implementations (`database.py`, `cache.py`) use `get_client_parameters` to determine the parameters for checking lockout status.
        - Since `get_client_parameters` by default only returns IP address, the lockout checks in handlers will also only consider IP address unless configured otherwise.

* Security Test Case:
    1. **Setup:** Configure Django-axes with default settings (do not set `AXES_LOCKOUT_PARAMETERS` in `settings.py`).
    2. **Brute-force attempt 1 (User-Agent: UA-A):**
        - From attacker IP `ATTACKER_IP`, send login requests with invalid credentials for a user (e.g., `testuser`) with User-Agent `UA-A`. Repeat this until the account is locked out based on IP. Verify lockout by attempting login again from `ATTACKER_IP` with UA-A - it should be blocked (429 status).
    3. **Bypass attempt (User-Agent: UA-B):**
        - Change User-Agent to `UA-B`.
        - From the same attacker IP `ATTACKER_IP`, send another login request with invalid credentials for the same user (`testuser`).
        - Observe that the login attempt is *not* blocked (status 200 or 302, not 429). This demonstrates the bypass of IP-based lockout by changing User-Agent.
    4. **Expected Result:** The attacker should be able to bypass the IP-based lockout by changing the User-Agent, proving the vulnerability.