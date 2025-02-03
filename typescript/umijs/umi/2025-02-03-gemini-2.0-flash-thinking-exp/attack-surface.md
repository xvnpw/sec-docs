# Attack Surface Analysis for umijs/umi

## Attack Surface: [Configuration File Exposure (`config.ts` or `config.js`)](./attack_surfaces/configuration_file_exposure___config_ts__or__config_js__.md)

*   **Description:** Sensitive information (API keys, credentials, internal URLs) within UmiJS configuration files is exposed, potentially through version control, client-side bundles, or insecure access controls.
*   **UmiJS Contribution:** UmiJS relies on `config.ts` or `config.js` as the primary source of application configuration. Mismanagement of this file directly leads to potential exposure of sensitive data configured within it.
*   **Example:** A developer hardcodes database credentials directly into `config.ts` and commits it to a public repository. Attackers find the repository, extract the credentials, and gain unauthorized access to the database.
*   **Impact:** Unauthorized access to databases or external services, data breaches, internal system compromise, significant financial loss, reputational damage.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Environment Variables:**  Strictly utilize environment variables to store all sensitive configuration data. Access these variables within `config.ts` or `config.js` instead of hardcoding values.
    *   **`.gitignore`:** Ensure `config.ts` or `config.js` (if it *must* contain any non-sensitive configuration but also has potential to accidentally include secrets) is included in `.gitignore` to prevent accidental commits to version control. However, the best practice is to avoid storing any secrets in files tracked by version control.
    *   **Secure Configuration Management:** Employ secure configuration management tools or vaults to manage and inject sensitive configurations at runtime, outside of the application codebase.
    *   **Code Reviews & Secret Scanning:** Implement mandatory code reviews and automated secret scanning tools to detect and prevent accidental inclusion of secrets in configuration files before they are committed.
    *   **Client-Side Bundle Analysis:**  Regularly analyze client-side bundles to verify that no sensitive configuration data is inadvertently included in the frontend code.

## Attack Surface: [Insecure `proxy` Configuration](./attack_surfaces/insecure__proxy__configuration.md)

*   **Description:** Overly permissive or misconfigured `proxy` settings in UmiJS `config.ts` allow attackers to bypass security controls, access internal resources not intended for public access, or perform Server-Side Request Forgery (SSRF) attacks.
*   **UmiJS Contribution:** UmiJS's `proxy` configuration feature in `config.ts` directly dictates request forwarding behavior.  Insecure or overly broad proxy rules are a direct consequence of UmiJS configuration.
*   **Example:** A `proxy` configuration is set up with a wildcard path like `/api/*` that unintentionally forwards requests to an internal administration panel or a sensitive microservice without proper authentication checks at the proxy level or backend. This allows unauthorized external access to internal resources.
*   **Impact:** Unauthorized access to internal systems and sensitive data, data breaches, Server-Side Request Forgery (SSRF) vulnerabilities potentially leading to further internal network compromise, privilege escalation.
*   **Risk Severity:** **High** to **Critical** (depending on the sensitivity and accessibility of exposed internal resources).
*   **Mitigation Strategies:**
    *   **Principle of Least Privilege for Proxy Rules:** Define proxy rules with the highest level of specificity and restrictiveness possible. Only proxy necessary paths to intended, explicitly defined targets. Avoid wildcard paths unless absolutely necessary and thoroughly justified with compensating security controls.
    *   **Input Validation and Sanitization (Proxy Targets):** If proxy targets are dynamically constructed based on user input (which is highly discouraged for security reasons), rigorously validate and sanitize all inputs to prevent manipulation and SSRF vulnerabilities.
    *   **Authentication and Authorization for Proxied Resources:**  Always ensure that backend resources accessed through the proxy are protected by robust authentication and authorization mechanisms. Do not rely solely on the proxy for security.
    *   **Regular Security Audits of Proxy Configuration:** Conduct frequent security audits specifically focused on reviewing and validating the `proxy` configuration in `config.ts` to identify and rectify any overly permissive or insecure rules.

## Attack Surface: [Vulnerabilities in High-Impact UmiJS Plugins](./attack_surfaces/vulnerabilities_in_high-impact_umijs_plugins.md)

*   **Description:** Critical security vulnerabilities (e.g., remote code execution, SQL injection, significant XSS) exist within third-party or custom UmiJS plugins that are essential to the application's core functionality or have high privileges.
*   **UmiJS Contribution:** UmiJS's plugin architecture encourages extensibility through plugins.  Using vulnerable plugins directly introduces security risks into UmiJS applications. The impact is amplified when these plugins have broad access or are core to the application.
*   **Example:** A widely used UmiJS plugin for user authentication contains a remote code execution vulnerability. An attacker exploits this vulnerability to gain complete control of the server hosting the UmiJS application.
*   **Impact:** Remote code execution, full server compromise, data breaches, complete application takeover, denial of service, significant financial and reputational damage.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Rigorous Plugin Vetting and Security Audits:** Before adopting any UmiJS plugin, especially those handling sensitive data or core functionalities, conduct thorough security vetting and, ideally, independent security audits. Evaluate the plugin's code quality, security track record, and community reputation.
    *   **Prioritize Plugins from Trusted Sources:** Favor plugins from reputable developers or organizations with a strong security focus and proven history of security updates.
    *   **Dependency Scanning and Management for Plugins:**  Implement automated dependency scanning for all plugin dependencies to identify and address known vulnerabilities. Keep plugin dependencies updated to the latest secure versions.
    *   **Principle of Least Privilege for Plugins:**  When possible, design the application architecture to minimize the privileges required by plugins. Isolate plugins and restrict their access to sensitive resources.
    *   **Regular Plugin Updates and Vulnerability Monitoring:** Establish a process for regularly updating UmiJS plugins and monitoring for newly disclosed vulnerabilities. Promptly apply security patches and updates.

## Attack Surface: [Exposed Development Server (`umi dev`)](./attack_surfaces/exposed_development_server___umi_dev__.md)

*   **Description:** The UmiJS development server, intended *only* for local development, is mistakenly or intentionally exposed to the public internet, granting attackers access to development tools, debugging endpoints, and potentially enabling remote code execution or information disclosure.
*   **UmiJS Contribution:** `umi dev` is the standard UmiJS command to launch the development server.  Misunderstanding its purpose and security implications can lead to accidental public exposure, directly related to UmiJS usage.
*   **Example:** A developer runs `umi dev` on a cloud-based virtual machine and misconfigures network settings or firewall rules, making the development server accessible from the public internet. Attackers discover the exposed server and exploit debugging endpoints to gain sensitive information about the application's internal workings or even execute arbitrary code on the server.
*   **Impact:** Remote code execution, full server compromise, information disclosure (application source code, configuration details, debugging data), unauthorized access to development tools and functionalities, potential for further attacks on internal networks.
*   **Risk Severity:** **Critical**
*   **Mitigation Strategies:**
    *   **Strict Localhost Binding:** Ensure the UmiJS development server is *always* bound only to `localhost` (127.0.0.1) by default. Verify this configuration and explicitly prevent binding to public interfaces (0.0.0.0).
    *   **Firewall Rules and Network Segmentation:** Implement strict firewall rules to block all external access to the development server port. Isolate development environments within secure networks, separate from public-facing infrastructure.
    *   **VPN or Secure Tunneling for Remote Development (Discouraged):**  Avoid exposing the development server to the internet entirely. If remote development access is absolutely necessary, use secure VPNs or SSH tunnels to establish encrypted connections and restrict access to authorized developers only.  Even with these measures, the risk remains high and should be minimized.
    *   **Disable Unnecessary Development Features in Remote Scenarios:** If remote development access is unavoidable, disable any non-essential development server features that could increase the attack surface, such as debugging endpoints or hot module replacement if not strictly required.
    *   **Production Readiness Checks and Warnings:** Implement automated checks in deployment pipelines to detect and prevent accidental deployment of development server configurations or artifacts to production environments. Display clear warnings if development-specific configurations are detected in production builds.

## Attack Surface: [Accidental Deployment of Insecure Mock APIs](./attack_surfaces/accidental_deployment_of_insecure_mock_apis.md)

*   **Description:** Mock API configurations, intended solely for development and testing, are mistakenly deployed to production environments. If these mock APIs are insecure, mimic sensitive functionalities (like authentication or authorization), or return predictable or insecure data, they can introduce critical vulnerabilities in production.
*   **UmiJS Contribution:** UmiJS provides built-in mocking capabilities to facilitate development.  Lack of proper separation and controls between development and production configurations within UmiJS projects can lead to accidental deployment of mock APIs.
*   **Example:** A developer creates a mock API in UmiJS that bypasses authentication checks for testing purposes. This mock API configuration is inadvertently included in the production build and deployed. Attackers discover that the production application is using the mock API and can bypass authentication entirely, gaining unauthorized access to sensitive data and functionalities.
*   **Impact:** Authentication bypass, authorization bypass, unauthorized access to sensitive data and functionalities, data manipulation, data corruption, potential for complete application takeover depending on the scope of the insecure mock APIs.
*   **Risk Severity:** **Critical** (especially if authentication or authorization mocks are deployed).
*   **Mitigation Strategies:**
    *   **Environment-Based Mocking Configuration:**  Strictly configure mock APIs to be enabled *only* in development environments. Use environment variables or build flags to conditionally include or exclude mock API configurations based on the target environment (development vs. production).
    *   **Separate and Isolate Mock API Code:**  Physically separate mock API code and configurations from production code. Store mock API definitions in dedicated directories or files that are explicitly excluded from production builds.
    *   **Automated Build Process Checks for Mock APIs:** Implement automated checks in the build process to detect and prevent the inclusion of any mock API related code or configurations in production builds. Fail the build if mock API artifacts are detected in production.
    *   **Code Reviews Focused on Mock API Separation:** Conduct thorough code reviews specifically focused on verifying the proper separation of mock API configurations and ensuring they are not being deployed to production.
    *   **"No Mock APIs in Production" Policy:** Establish a clear and enforced policy that explicitly prohibits the deployment of any mock APIs to production environments. Educate developers on the critical security risks associated with mock API deployment in production.

