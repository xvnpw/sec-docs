# Mitigation Strategies Analysis for akhikhl/gretty

## Mitigation Strategy: [Explicit Network Binding](./mitigation_strategies/explicit_network_binding.md)

*   **Description:**
    1.  **Locate Gretty Configuration:** Open the `build.gradle` (or `build.gradle.kts`) file.
    2.  **Find the `gretty` Block:** Locate the `gretty { ... }` configuration block.
    3.  **Set `httpAddress`:** Within the `gretty` block, add or modify the `httpAddress` property.  Set it to `'127.0.0.1'` (localhost) or a *trusted* internal IP.  *Do not* use `'0.0.0.0'`.
        ```gradle
        gretty {
            httpAddress = '127.0.0.1'
            // other configurations...
        }
        ```
    4.  **Restart Gretty:** Restart the Gretty server.
    5.  **Verify:** Use `netstat` to confirm the listening address.

*   **Threats Mitigated:**
    *   **Accidental Exposure of Development Environment:** (Severity: **High**) - Prevents external access.
    *   **Unintentional exposure of .gradle or build artifacts:** (Severity: **Medium**) - Reduces the attack surface.

*   **Impact:**
    *   **Accidental Exposure of Development Environment:** Risk significantly reduced (local access only).
    *   **Unintentional exposure of .gradle or build artifacts:** Risk moderately reduced (harder to access).

*   **Currently Implemented:**
    *   **Yes/No/Partially:** (Specify one)
    *   **Location:** `build.gradle`, `gretty` block.

*   **Missing Implementation:**
    *   If "No" or "Partially", specify where it's missing or incorrect (e.g., "Set to `0.0.0.0`", "Not configured").

## Mitigation Strategy: [Strict Configuration Separation](./mitigation_strategies/strict_configuration_separation.md)

*   **Description:**
    1.  **Create Separate Configuration Files:** Create distinct files (e.g., `jetty-web-dev.xml`, `jetty-web-prod.xml`).
    2.  **Use `configFile` in Gretty:** In `build.gradle`, use the `configFile` property within the appropriate Gretty task (e.g., `appRun`, `farmRun`) to specify the correct file for each environment.
        ```gradle
        appRun {
            configFile = file('src/main/webapp/WEB-INF/jetty-web-dev.xml')
        }
        farmRun { // Or a different task for production
            configFile = file('src/main/webapp/WEB-INF/jetty-web-prod.xml')
        }
        ```
    3.  **Avoid Default Configurations:** Do not rely on Gretty's default loading.  Always specify the file explicitly.
    4.  **Review Configuration Files:** Ensure each file contains only appropriate settings for its environment.

*   **Threats Mitigated:**
    *   **Inadvertent Deployment of Development Configurations:** (Severity: **High**) - Prevents dev settings in production.

*   **Impact:**
    *   **Inadvertent Deployment of Development Configurations:** Risk significantly reduced (correct file loaded).

*   **Currently Implemented:**
    *   **Yes/No/Partially:** (Specify one)
    *   **Location:** `build.gradle`, Gretty task configurations, and separate configuration files.

*   **Missing Implementation:**
    *   If "No" or "Partially", describe what's missing (e.g., "Same file for all environments", "Not using `configFile`").

## Mitigation Strategy: [Explicit Servlet Container Version](./mitigation_strategies/explicit_servlet_container_version.md)

*   **Description:**
    1.  **Locate Gretty Configuration:** Open `build.gradle`.
    2.  **Find the `gretty` Block:** Locate `gretty { ... }`.
    3.  **Set `servletContainer`:** Add or modify the `servletContainer` property. Set it to a specific, *recent* version (e.g., `'jetty9.4'`, `'tomcat9'`). Do *not* rely on the default.
        ```gradle
        gretty {
            servletContainer = 'jetty9.4' // Be specific and up-to-date!
            // other configurations...
        }
        ```
    4.  **Check for Compatibility:** Ensure the version is compatible.
    5.  **Update Regularly:** Reconsider the version during dependency updates.

*   **Threats Mitigated:**
    *   **Dependency Vulnerabilities (Indirect):** (Severity: **Variable**) - Prevents using a vulnerable default.

*   **Impact:**
    *   **Dependency Vulnerabilities (Indirect):** Risk reduced (controlled container version).

*   **Currently Implemented:**
    *   **Yes/No/Partially:** (Specify one)
    *   **Location:** `build.gradle`, `gretty` block.

*   **Missing Implementation:**
    *   If "No" or "Partially", describe what's missing (e.g., "Not specifying `servletContainer`", "Outdated version").

## Mitigation Strategy: [Enable and Configure Java Security Manager (via Gretty/JVM Arguments)](./mitigation_strategies/enable_and_configure_java_security_manager__via_grettyjvm_arguments_.md)

*   **Description:**
    1.  **Determine if Required:** Assess if your application needs the Security Manager.
    2.  **Create a Security Policy File:** Create a file (e.g., `security.policy`) defining permissions.
    3.  **Enable in Gretty/JVM:** Add JVM arguments in `build.gradle` within the `jvmArgs` property of a Gretty task:
        ```gradle
        appRun {
            jvmArgs = [
                '-Djava.security.manager',
                '-Djava.security.policy=src/main/resources/security.policy'
            ]
        }
        ```
    4.  **Test Extensively:** Test with the Security Manager enabled.
    5.  **Iterative Refinement:** Start restrictive, add permissions as needed.

*   **Threats Mitigated:**
    *   **Overriding Security Managers:** (Severity: **High**) - Enforces access control.
    *   **Various Code-Level Vulnerabilities:** (Severity: **Variable**) - Restricts code actions.

*   **Impact:**
    *   **Overriding Security Managers:** Risk eliminated (if configured correctly).
    *   **Various Code-Level Vulnerabilities:** Risk significantly reduced.

*   **Currently Implemented:**
    *   **Yes/No/Partially:** (Specify one)
    *   **Location:** `build.gradle` (JVM arguments), and a security policy file.

*   **Missing Implementation:**
    *   If "No" or "Partially", describe what's missing (e.g., "Not enabled", "Policy file missing", "Overly permissive policy").

## Mitigation Strategy: [Careful Web Root Configuration (using `webappDir`)](./mitigation_strategies/careful_web_root_configuration__using__webappdir__.md)

*   **Description:**
    1.  **Identify Web Root:** Determine the directory Gretty serves.
    2.  **Review Contents:** Ensure it *only* contains files to be served.
    3.  **Remove Sensitive Files:** Remove `.gradle`, `build`, source code, etc.
    4.  **Configure `webappDir` (If Necessary):** Customize the web root:
        ```gradle
        gretty {
            webappDir = file('src/main/my-custom-webapp')
            // other configurations...
        }
        ```
    5. **Verify:** Try to access files that *should not* be accessible.

*   **Threats Mitigated:**
    *   **Unintentional exposure of .gradle or build artifacts:** (Severity: **Medium**) - Prevents serving sensitive files.

*   **Impact:**
    *   **Unintentional exposure of .gradle or build artifacts:** Risk significantly reduced.

*   **Currently Implemented:**
    *   **Yes/No/Partially:** (Specify one)
    *   **Location:** `build.gradle` (`webappDir` property), and web root contents.

*   **Missing Implementation:**
    *   If "No" or "Partially", describe what's missing (e.g., "`.gradle` in web root", "Sensitive files present").

