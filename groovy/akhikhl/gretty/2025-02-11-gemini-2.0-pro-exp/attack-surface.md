# Attack Surface Analysis for akhikhl/gretty

## Attack Surface: [1. Outdated Embedded Servlet Container](./attack_surfaces/1__outdated_embedded_servlet_container.md)

*   **Description:** Running an old version of Jetty or Tomcat with known vulnerabilities.
*   **How Gretty Contributes:** Gretty *directly* allows specifying the servlet container version via configuration (e.g., `gretty.servletContainerVersion`).  This is the core mechanism.
*   **Example:** Using `gretty.servletContainerVersion = 'jetty9.4.10.v20180503'` (hypothetical vulnerable version) when newer, patched versions are available.
*   **Impact:** Remote code execution, denial of service, information disclosure, depending on the specific CVEs.
*   **Risk Severity:** **Critical** (if known RCE exists) or **High** (for other significant vulnerabilities).
*   **Mitigation Strategies:**
    *   **Automated Updates:** Integrate dependency checking and updates into the CI/CD pipeline. Use tools like Dependabot.
    *   **Policy Enforcement:** Require the use of the latest stable servlet container version in Gretty configuration.
    *   **Regular Audits:** Periodically review the `gretty.servletContainerVersion` setting.

## Attack Surface: [2. Servlet Container Misconfiguration (via Gretty)](./attack_surfaces/2__servlet_container_misconfiguration__via_gretty_.md)

*   **Description:** Incorrect configuration of the embedded Jetty or Tomcat, *specifically through Gretty's configuration options*.
*   **How Gretty Contributes:** Gretty exposes configuration settings that *directly* control the underlying servlet container's behavior. This is not a general misconfiguration, but one facilitated by Gretty's settings.
*   **Example:** Exposing the Tomcat manager application (`/manager/html`) due to misconfigured `contextPath`, security constraints, or other container-specific settings *within the Gretty configuration*.
*   **Impact:** Unauthorized access to server management, deployment of malicious WAR files, server compromise.
*   **Risk Severity:** **Critical** (if management interfaces are exposed) or **High**.
*   **Mitigation Strategies:**
    *   **Least Privilege (via Gretty):** Configure the servlet container *through Gretty* with minimal privileges. Disable unnecessary features exposed by Gretty.
    *   **Secure Defaults:** Review and override Gretty's default settings related to the container to enhance security.
    *   **Documentation Review:** Thoroughly understand the implications of *each Gretty configuration option* that affects the servlet container.

## Attack Surface: [3. Development Features in Production (Enabled by Gretty)](./attack_surfaces/3__development_features_in_production__enabled_by_gretty_.md)

*   **Description:** Enabling Gretty's development features (fast reload, hot swapping, debug ports) in production.
*   **How Gretty Contributes:** These features are *core to Gretty's functionality* and are enabled/disabled *directly through Gretty's configuration*.
*   **Example:** Leaving `gretty.fastReload = true` in a production build.  Or, inadvertently enabling a debug port via a Gretty setting.
*   **Impact:** Remote code execution, server compromise.
*   **Risk Severity:** **Critical**.
*   **Mitigation Strategies:**
    *   **Separate Configurations:** Use distinct Gradle configurations (and thus, Gretty configurations) for development and production.
    *   **Environment Variables:** Control feature flags via environment variables, ensuring production environments disable Gretty's development features.
    *   **CI/CD Enforcement:** Implement checks in the CI/CD pipeline to *specifically* prevent deployments with Gretty's development features enabled.

## Attack Surface: [4. Insecure Resource Handling (via Gretty's `webappCopy`)](./attack_surfaces/4__insecure_resource_handling__via_gretty's__webappcopy__.md)

*   **Description:** Misconfiguration of Gretty's `webappCopy` feature (or similar resource-handling settings), leading to sensitive file exposure.
*   **How Gretty Contributes:** Gretty *provides the `webappCopy` feature* (or equivalent) for managing web application resources.  The vulnerability arises from *misusing this Gretty-provided functionality*.
*   **Example:** Including configuration files with secrets in the `webappCopy` directory, making them accessible via HTTP.
*   **Impact:** Information disclosure, credential theft.
*   **Risk Severity:** **High**.
*   **Mitigation Strategies:**
    *   **Careful `webappCopy` Configuration:** Thoroughly review and restrict the `webappCopy` configuration (and any related Gretty settings) to include *only* essential files.
    *   **Secrets Management:** Store sensitive data securely, *outside* of files managed by Gretty's `webappCopy` or similar features.

## Attack Surface: [5. Insecure Communication (Configured via Gretty)](./attack_surfaces/5__insecure_communication__configured_via_gretty_.md)

* **Description:** Gretty configured to use HTTP instead of HTTPS.
    * **How Gretty Contributes:** Gretty *allows configuring the protocol* used for communication (e.g., `httpPort`, `httpsPort`, SSL/TLS settings). The vulnerability is a direct result of *how Gretty is configured*.
    * **Example:** Setting `httpPort` but not configuring `httpsPort` or SSL/TLS certificates *within the Gretty configuration*.
    * **Impact:** Man-in-the-middle attacks, interception of sensitive data.
    * **Risk Severity:** **Critical**
    * **Mitigation Strategies:**
        * **Enforce HTTPS (via Gretty):** *Always* configure Gretty to use HTTPS. Obtain and install valid SSL/TLS certificates, configuring them *through Gretty*.
        * **Redirect HTTP to HTTPS (via Gretty):** Configure Gretty to automatically redirect HTTP requests to HTTPS.

