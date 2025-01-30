# Attack Surface Analysis for javalin/javalin

## Attack Surface: [Path Traversal via Path Parameters](./attack_surfaces/path_traversal_via_path_parameters.md)

*   **Description:** Attackers exploit vulnerabilities in how applications handle user-provided path parameters to access files or directories outside of the intended web root.

*   **Javalin Contribution:** Javalin's path parameter routing (`/:param`) makes it straightforward to capture URL path segments as variables. If these variables are used to construct file paths without proper validation, it directly creates a path traversal attack surface.

*   **Example:**
    ```java
    app.get("/files/:filename", ctx -> {
        String filename = ctx.pathParam("filename");
        File file = new File("uploads/" + filename); // Vulnerable line
        ctx.result(new FileInputStream(file));
    });
    ```
    An attacker requesting `/files/../../etc/passwd` could potentially access sensitive system files.

*   **Impact:** Unauthorized access to sensitive files, configuration files, source code, or even system files. Data breaches and potential system compromise.

*   **Risk Severity:** High

*   **Mitigation Strategies:**
    *   **Input Validation:**  Strictly validate path parameters. Use whitelists of allowed characters and file names.
    *   **Path Sanitization:** Sanitize path parameters to remove or encode potentially malicious characters like `..`, `/`, and `\`.
    *   **Canonicalization:**  Canonicalize paths to resolve symbolic links and ensure the path points to the intended location.
    *   **Restrict File Access:**  Use secure file access mechanisms and ensure the application only has access to necessary files and directories. Avoid constructing file paths directly from user input. Consider using UUIDs or database IDs instead of filenames in URLs.

## Attack Surface: [Deserialization Vulnerabilities](./attack_surfaces/deserialization_vulnerabilities.md)

*   **Description:**  Exploiting vulnerabilities in how applications deserialize data formats like JSON or XML. Attackers can inject malicious payloads that, when deserialized, can lead to remote code execution or denial of service.

*   **Javalin Contribution:** Javalin simplifies request body handling and automatic deserialization using libraries like Jackson (for JSON).  By making deserialization easy, Javalin indirectly contributes to this attack surface if developers don't implement secure deserialization practices.

*   **Example:**
    ```java
    app.post("/profile", ctx -> {
        UserProfile profile = ctx.bodyAsClass(UserProfile.class); // Potentially vulnerable deserialization
        // ... process profile ...
    });
    ```
    If `UserProfile` class or the underlying deserialization library is vulnerable, an attacker can send a malicious JSON payload to execute arbitrary code on the server.

*   **Impact:** Remote Code Execution (RCE), Denial of Service (DoS), data corruption, information disclosure.

*   **Risk Severity:** Critical

*   **Mitigation Strategies:**
    *   **Use Secure Deserialization Libraries:**  Keep deserialization libraries up-to-date and use secure configurations. Consider using libraries known for security and actively maintained.
    *   **Input Validation:** Validate the structure and content of deserialized objects *after* deserialization.
    *   **Principle of Least Privilege (Deserialization):**  Avoid deserializing complex objects directly from user input if possible. Consider using Data Transfer Objects (DTOs) and mapping them to internal domain objects after validation.
    *   **Disable Polymorphic Deserialization (if not needed):**  Polymorphic deserialization is a common source of deserialization vulnerabilities. Disable it if your application doesn't require it.
    *   **Regular Dependency Scanning:** Scan dependencies for known vulnerabilities, including deserialization libraries.

## Attack Surface: [CORS Misconfiguration](./attack_surfaces/cors_misconfiguration.md)

*   **Description:** Cross-Origin Resource Sharing (CORS) is a mechanism that allows controlled access to resources from different origins. Misconfigured CORS policies can allow unauthorized cross-domain requests, potentially leading to Cross-Site Scripting (XSS) or unauthorized API access.

*   **Javalin Contribution:** Javalin provides a plugin (`CorsPlugin`) for easy configuration of CORS.  Incorrectly configured CORS settings using this plugin, especially overly permissive ones, directly contribute to this attack surface.

*   **Example:**
    ```java
    Javalin.create(config -> {
        config.plugins.enableCors(cors -> {
            cors.add(CorsPluginConfig::anyHost); // Vulnerable - allows any origin
        });
    }).start(7000);
    ```
    Using `anyHost()` allows any website to make requests to the Javalin application, potentially exposing APIs to malicious websites and enabling XSS if the API returns user-controlled data.

*   **Impact:** Cross-Site Scripting (XSS), unauthorized API access, data theft, CSRF bypass.

*   **Risk Severity:** High (when misconfiguration leads to XSS or unauthorized sensitive API access)

*   **Mitigation Strategies:**
    *   **Restrict Allowed Origins:**  Specify a whitelist of allowed origins instead of using wildcard (`*`) or `anyHost()`.
    *   **Properly Configure Allowed Methods and Headers:**  Restrict allowed HTTP methods and headers to only those necessary for legitimate cross-origin requests.
    *   **Avoid `allowCredentials()` unless necessary:**  `allowCredentials(true)` should only be used when necessary and with careful consideration, as it can increase the risk if origins are not strictly controlled.
    *   **Regularly Review CORS Configuration:**  Periodically review and update CORS configurations to ensure they are still appropriate and secure.

