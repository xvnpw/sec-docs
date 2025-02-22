- **Vulnerability Name:** Potential SSRF via Exchange Rate URL Misconfiguration
  **Description:**
  An attacker who can influence the external exchange‐rate URL settings (for example, via environment variable or misconfiguration of the FIXER or OpenExchangeRates backend URL) may force the backend to use an attacker‑controlled target. In this scenario the update_rates method (invoked by a management command or a mis‑exposed endpoint) builds a URL from the configured settings and, without verifying that the URL’s host is from an allowed external domain, performs an HTTP request using Python’s urlopen with a custom SSL context. An attacker who sets the URL to an internal or malicious host may trigger SSRF (Server‑Side Request Forgery).
  **Impact:**
  - The application may be induced to make HTTP requests to internal systems or attacker‑controlled endpoints, which could reveal sensitive internal network information or allow further lateral attacks.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
  - The code creates an SSL context using certifi’s trusted CA bundle. This ensures that any HTTPS requests verify certificates properly—but it does not restrict which external URLs may be contacted.
  **Missing Mitigations:**
  - No explicit validation or whitelisting is performed on the URL (e.g. FIXER_URL or OPEN_EXCHANGE_RATES_URL) before use. A robust mitigation would involve checking that the URL belongs to a known-good host and scheme, or otherwise restricting external requests.
  **Preconditions:**
  - The attacker must be able to influence the Django settings (for example via environment variable injection or mis‑configuration) so that the exchange backend URL is changed to an attacker‑controlled or internal host.
  - In addition, either the update_rates (or similar) management function must be callable (or indirectly triggered via a mis‑exposed endpoint) from an external source.
  **Source Code Analysis:**
  - In **djmoney/contrib/exchange/backends/base.py**, the method `get_response(**params)` builds the request URL as follows:
    - `self.get_url(**params)` is called, which merges GET parameters into the base URL (set via settings).
    - The code then creates a request with a fixed User-Agent and an SSL context with certifi’s CA bundle, and finally calls `urlopen(request, context=context)` without checking that the host portion of the URL is safe.
  **Security Test Case:**
  - In a test or staging environment, set (for example) the environment variable `FIXER_URL` (or `OPEN_EXCHANGE_RATES_URL`) to a URL under the attacker's control or an internal IP (e.g. `http://127.0.0.1:80`).
  - Ensure the application uses the affected backend (by having an appropriate access key, etc.).
  - Then trigger the update mechanism by running the management command (or by invoking the update_rates function if it is callable via an exposed interface).
  - Verify via logging or network monitoring that the request is being sent to the misconfigured URL.
  - If so, the risk of SSRF is confirmed and mitigation (URL validation/whitelisting) is needed.

- **Vulnerability Name:** Unvalidated “backend” Parameter in Exchange Management Commands
  **Description:**
  The management commands for updating or clearing exchange rates allow a “backend” parameter. In the commands (for example, in **djmoney/contrib/exchange/management/commands/update_rates.py**), the code uses Django’s `import_string(options["backend"])` to retrieve the backend class without validating that the supplied import path is among an approved list. If an attacker (or an untrusted user) is able to invoke such a command—and if the application’s process exposes management commands (for example, via a web‑exposed administrative interface or remote command execution vulnerability)—then by supplying a malicious module path the attacker might force the application to import and instantiate an unexpected or dangerous object.
  **Impact:**
  - This may lead to arbitrary code execution or arbitrary function calls if the supplied backend reference is not restricted.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
  - The code assumes that these management commands are only executed by trusted administrators via the CLI. No additional input validation or restrictions on the “backend” parameter are applied.
  **Missing Mitigations:**
  - Input validation (or whitelisting) for the “backend” parameter is missing. An attacker‐controlled input (or mis‑configuration that exposes the command) should be rejected or constrained to a list of allowed backend module paths.
  - Additionally, ensuring that management commands cannot be triggered by an external attacker (for example, by not exposing administrative interfaces over the public Internet) is essential but not enforced in the code.
  **Preconditions:**
  - The attacker must be able to invoke the management command (or a web‑service wrapper around it) and supply a custom “backend” parameter.
  - Mis‑configured deployment (exposing management functionality externally) is required.
  **Source Code Analysis:**
  - In **djmoney/contrib/exchange/management/commands/update_rates.py**, the code does:
    ```
    backend = import_string(options["backend"])()
    ```
    Here, the command‐line parameter “backend” (which defaults to a setting value) is not validated. A similar pattern is found in the clear_rates command. No restrictions are applied on the string used for import.
  **Security Test Case:**
  - In a controlled environment where management commands are exposed (or via a simulated exploit), invoke the `update_rates` command supplying a malicious import path for the “backend” parameter (for example, a module or function that executes a benign test command such as printing a marker or executing an OS command).
  - Observe whether the custom backend is instantiated and whether its behavior can be exploited to execute arbitrary code.
  - If the imported module is not limited to a safe list, then this confirms a critical risk that must be mitigated by whitelisting allowed backend paths.