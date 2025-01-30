## Deep Analysis of Attack Tree Path: 1.1.2. Path Traversal via Route Parameters (Misconfiguration)

This document provides a deep analysis of the attack tree path **1.1.2. Path Traversal via Route Parameters (Misconfiguration)**, focusing on its implications for applications built using the Hapi.js framework.

### 1. Define Objective

The objective of this deep analysis is to thoroughly examine the **Path Traversal via Route Parameters (Misconfiguration)** attack path within the context of a Hapi.js application. This analysis aims to:

*   Understand the mechanics of this attack vector.
*   Identify how misconfigurations in Hapi.js routes can lead to path traversal vulnerabilities.
*   Assess the potential impact and risk associated with this vulnerability.
*   Provide detailed mitigation strategies and best practices for Hapi.js developers to prevent this type of attack.
*   Outline detection methods for identifying and addressing existing vulnerabilities.

### 2. Scope

This analysis is scoped to:

*   **Attack Tree Path:** Specifically focuses on path **1.1.2. Path Traversal via Route Parameters (Misconfiguration)**.
*   **Technology:**  Hapi.js framework (https://github.com/hapijs/hapi) and its ecosystem.
*   **Vulnerability Type:** Path Traversal (also known as Directory Traversal).
*   **Misconfiguration Focus:**  Specifically examines misconfigurations in route parameter handling within Hapi.js applications that lead to path traversal.
*   **Security Perspective:** Analyzes the vulnerability from an attacker's perspective and provides guidance for developers to secure their applications.

This analysis will **not** cover:

*   Other attack tree paths not explicitly mentioned.
*   Path traversal vulnerabilities arising from other sources (e.g., file upload vulnerabilities, template injection).
*   Detailed code review of specific Hapi.js applications (unless used for illustrative examples).
*   Specific penetration testing methodologies (although detection methods will be discussed).

### 3. Methodology

This deep analysis will employ the following methodology:

1.  **Vulnerability Description:**  Detailed explanation of the Path Traversal via Route Parameters (Misconfiguration) vulnerability, including how it works and its potential consequences.
2.  **Hapi.js Contextualization:**  Analysis of how this vulnerability manifests within Hapi.js applications, focusing on route definitions, parameter handling, and file system interactions.
3.  **Risk Assessment Breakdown:**  In-depth examination of the provided risk attributes (Likelihood, Impact, Effort, Skill Level, Detection Difficulty) and justification for each within the Hapi.js context.
4.  **Exploitation Scenario:**  Step-by-step walkthrough of a potential exploitation scenario, demonstrating how an attacker could leverage this vulnerability in a Hapi.js application.
5.  **Mitigation Strategies (Detailed):**  Elaboration on the provided mitigation strategies, providing concrete examples and best practices specifically tailored for Hapi.js development. This will include code examples where applicable.
6.  **Detection and Prevention Techniques:**  Discussion of methods for detecting and preventing this vulnerability during development and in production environments, including code review practices, static analysis tools, and dynamic testing approaches.
7.  **Conclusion and Recommendations:**  Summary of the analysis and key recommendations for Hapi.js developers to secure their applications against Path Traversal via Route Parameters (Misconfiguration) vulnerabilities.

---

### 4. Deep Analysis of Attack Tree Path 1.1.2. Path Traversal via Route Parameters (Misconfiguration)

#### 4.1. Vulnerability Description: Path Traversal via Route Parameters (Misconfiguration)

Path Traversal, also known as Directory Traversal, is a web security vulnerability that allows attackers to access files and directories that are located outside the web server's root directory. This occurs when an application uses user-supplied input, often through URL parameters, to construct file paths without proper validation and sanitization.

In the context of **Route Parameters (Misconfiguration)**, this vulnerability arises when a Hapi.js application's route definition uses parameters to dynamically construct file paths, and these parameters are not adequately validated to prevent malicious input.  An attacker can manipulate these parameters to include path traversal sequences like `../` (dot-dot-slash) to navigate up the directory structure and access sensitive files or directories outside the intended scope.

**Example of a Vulnerable Scenario (Conceptual):**

Imagine a Hapi.js route designed to serve files from a specific directory based on a filename provided in the route parameter:

```javascript
// VULNERABLE CODE - DO NOT USE IN PRODUCTION
server.route({
    method: 'GET',
    path: '/files/{filename}',
    handler: (request, h) => {
        const filename = request.params.filename;
        const filePath = `./uploads/${filename}`; // Constructing file path directly from parameter
        return h.file(filePath);
    }
});
```

In this vulnerable example, if an attacker crafts a request like `/files/../../../../etc/passwd`, the `filename` parameter will be `../../../../etc/passwd`. The application, without proper validation, will construct the `filePath` as `./uploads/../../../../etc/passwd`, which, due to path traversal, resolves to `/etc/passwd` on a Unix-like system. This allows the attacker to potentially access the system's password file, which is a severe security breach.

#### 4.2. Hapi.js Contextualization

Hapi.js, being a powerful and flexible framework, provides various ways to define routes and handle parameters.  The vulnerability arises when developers directly use route parameters to construct file paths without implementing robust security measures.

**How Misconfiguration Occurs in Hapi.js:**

*   **Direct Parameter Usage in `h.file()`:** As shown in the conceptual example above, directly passing `request.params` values into `h.file()` or similar file-serving functionalities without validation is a primary source of this vulnerability.
*   **Insufficient Input Validation:**  Failing to validate and sanitize route parameters before using them in file path construction. This includes not checking for path traversal sequences (`../`, `..\\`), absolute paths, or disallowed characters.
*   **Lack of Whitelisting:**  Instead of whitelisting allowed filenames or paths, relying on blacklisting or no validation at all. Blacklisting is often ineffective as attackers can find ways to bypass filters.
*   **Incorrect Path Resolution:**  Not using secure path manipulation functions provided by Node.js (like `path.join()` and `path.resolve()`) correctly, or misunderstanding their behavior in security contexts. Even `path.join()` can be vulnerable if not used carefully with user input.
*   **Misunderstanding of `h.file()` Options:**  Not utilizing options provided by `h.file()` (like `confine`) to restrict file access to a specific directory.

**Example of a Slightly Improved but Still Potentially Vulnerable Code:**

```javascript
const path = require('path');

server.route({
    method: 'GET',
    path: '/files/{filename}',
    handler: (request, h) => {
        const filename = request.params.filename;
        const basePath = './uploads';
        const filePath = path.join(basePath, filename); // Using path.join - better but still vulnerable
        return h.file(filePath);
    }
});
```

While using `path.join()` is generally better than simple string concatenation, it's **still vulnerable** if `filename` contains path traversal sequences. `path.join()` will normalize the path, but it won't prevent traversal if the normalized path still goes outside the intended directory. For example, `path.join('./uploads', '../../../../etc/passwd')` will resolve to `../../../../etc/passwd` relative to the current working directory, which could still lead to path traversal.

#### 4.3. Risk Assessment Breakdown

*   **Likelihood: Medium** -  While developers are generally aware of path traversal vulnerabilities, misconfigurations in route handling, especially in complex applications, can easily occur.  The ease of implementation and the pressure to quickly deliver features can sometimes lead to overlooking proper input validation and secure file handling.  Therefore, the likelihood is considered medium.
*   **Impact: High** - The impact of a successful path traversal attack can be severe. It can lead to:
    *   **Access to Sensitive Data:** Attackers can read configuration files, database credentials, source code, user data, and other confidential information.
    *   **Data Breach:**  Exposure of sensitive data can result in significant financial losses, reputational damage, and legal repercussions.
    *   **Code Execution (Indirect):** In some scenarios, if the attacker can access configuration files or upload functionality exists (even if not directly related to this path), they might be able to modify application behavior or upload malicious code, leading to remote code execution.
    *   **Denial of Service (DoS):** In certain cases, attackers might be able to access system files that could cause instability or crashes if manipulated.
*   **Effort: Low** - Exploiting this vulnerability requires minimal effort. Attackers can easily craft malicious URLs with path traversal sequences. Automated tools and scripts can also be used to scan for and exploit these vulnerabilities.
*   **Skill Level: Low** -  No advanced technical skills are required to exploit this vulnerability. Basic understanding of URLs, path traversal sequences, and web requests is sufficient. Even novice attackers can successfully exploit this vulnerability.
*   **Detection Difficulty: Easy** - Path traversal attempts often leave clear patterns in web server logs (e.g., requests containing `../` or `..\\`). Security tools like Web Application Firewalls (WAFs) and Intrusion Detection Systems (IDS) can easily detect these patterns. Furthermore, during development, code review and static analysis tools can effectively identify potential path traversal vulnerabilities.
*   **Mitigation Strategies:**  As outlined in the initial attack tree path description, the mitigation strategies are well-defined and relatively straightforward to implement.

#### 4.4. Exploitation Scenario

Let's consider a more concrete exploitation scenario in a Hapi.js application:

1.  **Vulnerable Route:** The application has a route `/download/{filepath}` intended to download files from a specific "documents" directory.

    ```javascript
    // VULNERABLE CODE - DO NOT USE IN PRODUCTION
    server.route({
        method: 'GET',
        path: '/download/{filepath*}', // Using wildcard parameter for filepath
        handler: (request, h) => {
            const filepath = request.params.filepath;
            const basePath = './documents';
            const filePath = path.join(basePath, filepath);
            return h.file(filePath);
        }
    });
    ```

    Here, `{filepath*}` captures the entire path segment after `/download/`.

2.  **Attacker Request:** An attacker wants to access the application's configuration file, which they suspect is located at `/app/config/config.json` relative to the application's root directory.

3.  **Crafted URL:** The attacker crafts the following URL:

    ```
    http://vulnerable-hapi-app.example.com/download/../../config/config.json
    ```

4.  **Path Traversal:** When the Hapi.js application receives this request:
    *   `request.params.filepath` becomes `../../config/config.json`.
    *   `basePath` is `./documents`.
    *   `filePath` is constructed using `path.join('./documents', '../../config/config.json')`.
    *   `path.join()` resolves this to something like `../config/config.json` relative to the current working directory (or potentially even further up depending on the relative paths). If the application's working directory is at the same level as `documents` and `config` directories, this could resolve to the desired configuration file path.

5.  **File Access:**  `h.file(filePath)` attempts to serve the file at the resolved path. If the application process has read permissions to `/app/config/config.json` (or the equivalent path based on the actual directory structure), the attacker will successfully download the configuration file.

6.  **Consequences:** The attacker now has access to potentially sensitive configuration data, which could include database credentials, API keys, or other secrets, leading to further compromise of the application and its data.

#### 4.5. Mitigation Strategies (Detailed for Hapi.js)

To effectively mitigate Path Traversal via Route Parameters (Misconfiguration) in Hapi.js applications, developers should implement the following strategies:

1.  **Avoid Direct File Path Construction from User Input:**  The most robust approach is to **never directly use user-controlled route parameters to construct file paths**. Instead, use indirect methods to map user input to files.

    *   **Example: Using a Whitelist or Mapping:**

        ```javascript
        const allowedFiles = {
            "document1": "report.pdf",
            "image1": "logo.png",
            "data": "data.csv"
        };

        server.route({
            method: 'GET',
            path: '/files/{fileId}',
            handler: (request, h) => {
                const fileId = request.params.fileId;
                const filename = allowedFiles[fileId];

                if (!filename) {
                    return h.response('File not found').code(404); // Handle invalid fileId
                }

                const basePath = './uploads';
                const filePath = path.join(basePath, filename);
                return h.file(filePath, { confine: basePath }); // Confine to basePath
            }
        });
        ```

        In this example, instead of directly using `request.params.fileId` as a filename, we use it as a key to look up the actual filename in a `allowedFiles` whitelist. This prevents attackers from directly controlling the filename and path.

2.  **Use Secure File Handling Libraries and `h.file()` Options:**

    *   **`h.file()` with `confine` option:**  Hapi.js's `h.file()` response handler provides the `confine` option. This is crucial for preventing path traversal.  `confine` restricts file serving to within a specified directory.

        ```javascript
        const basePath = './uploads'; // Define the allowed base directory

        server.route({
            method: 'GET',
            path: '/files/{filename}',
            handler: (request, h) => {
                const filename = request.params.filename;
                const filePath = path.join(basePath, filename);
                return h.file(filePath, { confine: basePath }); // Confine file access to basePath
            }
        });
        ```

        With `confine: basePath`, `h.file()` will reject any request that attempts to access files outside of the `./uploads` directory, even if `filePath` resolves to a path outside of it due to path traversal sequences.

    *   **`path.join()` and `path.resolve()` (Used Carefully):** While `path.join()` alone is not sufficient to prevent path traversal, it's still important for constructing paths correctly.  Use `path.resolve()` in conjunction with `confine` for more robust path handling.  `path.resolve()` resolves a sequence of paths to an absolute path.

        ```javascript
        const basePath = path.resolve('./uploads'); // Resolve basePath to an absolute path

        server.route({
            method: 'GET',
            path: '/files/{filename}',
            handler: (request, h) => {
                const filename = request.params.filename;
                const filePath = path.resolve(basePath, filename); // Resolve filePath relative to basePath
                return h.file(filePath, { confine: basePath });
            }
        });
        ```

        Using `path.resolve(basePath, filename)` and `confine: basePath` together provides a stronger defense. `path.resolve()` ensures that `filePath` is resolved relative to `basePath`, and `confine` enforces that the served file must be within `basePath`.

3.  **Strict Input Validation and Sanitization for Route Parameters:**

    *   **Validate Filename Format:**  Implement strict validation rules for route parameters used in file paths.  For example, if filenames should only contain alphanumeric characters, underscores, and hyphens, enforce this validation.

        ```javascript
        server.route({
            method: 'GET',
            path: '/files/{filename}',
            handler: (request, h) => {
                const filename = request.params.filename;

                // Regular expression to allow only alphanumeric, underscore, hyphen, and dot
                const filenameRegex = /^[a-zA-Z0-9_.-]+$/;
                if (!filenameRegex.test(filename)) {
                    return h.response('Invalid filename').code(400); // Reject invalid filenames
                }

                const basePath = './uploads';
                const filePath = path.join(basePath, filename);
                return h.file(filePath, { confine: basePath });
            },
            options: {
                validate: {
                    params: Joi.object({ // Using Joi for validation
                        filename: Joi.string().regex(/^[a-zA-Z0-9_.-]+$/).required()
                    })
                }
            }
        });
        ```

        Using Hapi.js's built-in validation options with Joi is highly recommended for robust input validation.

    *   **Reject Path Traversal Sequences:**  Explicitly reject requests containing path traversal sequences like `../` or `..\\`.

        ```javascript
        server.route({
            method: 'GET',
            path: '/files/{filename}',
            handler: (request, h) => {
                const filename = request.params.filename;

                if (filename.includes('../') || filename.includes('..\\')) {
                    return h.response('Invalid filename').code(400); // Reject path traversal attempts
                }

                const basePath = './uploads';
                const filePath = path.join(basePath, filename);
                return h.file(filePath, { confine: basePath });
            }
        });
        ```

        While this is a basic check, it's less robust than whitelisting or using `confine`. It's better to combine this with other mitigation strategies.

4.  **Enforce Proper Access Controls on File System Resources:**

    *   **Principle of Least Privilege:** Ensure that the application process runs with the minimum necessary privileges.  It should only have read access to the directories and files it needs to serve.  Avoid running the application as root or with overly permissive file system permissions.
    *   **Restrict Web Server User Permissions:**  The user account under which the Hapi.js application (and Node.js process) runs should have restricted permissions. It should not have read access to sensitive system files or directories outside of its intended scope.

#### 4.6. Detection and Prevention

**Detection:**

*   **Code Review:**  Manually review route handlers and file serving logic to identify potential areas where user-controlled route parameters are used to construct file paths without proper validation or `h.file()` `confine` option.
*   **Static Analysis Security Testing (SAST):** Utilize SAST tools that can analyze Hapi.js code and identify potential path traversal vulnerabilities. These tools can often detect patterns of insecure file path construction.
*   **Dynamic Application Security Testing (DAST) / Penetration Testing:**  Perform DAST or penetration testing to actively probe the application for path traversal vulnerabilities.  This involves sending malicious requests with path traversal sequences and observing the application's response. Tools like OWASP ZAP or Burp Suite can be used for this purpose.
*   **Web Application Firewall (WAF):** Deploy a WAF that can detect and block path traversal attempts in HTTP requests. WAFs can be configured with rules to identify common path traversal patterns.
*   **Security Logging and Monitoring:**  Implement robust logging to record all file access attempts, especially those involving route parameters. Monitor logs for suspicious patterns, such as requests containing `../` or `..\\` or attempts to access sensitive files.

**Prevention:**

*   **Secure Development Practices:**  Educate developers about path traversal vulnerabilities and secure coding practices. Emphasize the importance of input validation, sanitization, and secure file handling.
*   **Security Audits:**  Conduct regular security audits of the Hapi.js application's codebase and infrastructure to identify and remediate potential vulnerabilities.
*   **Dependency Management:** Keep Hapi.js and all its dependencies up to date with the latest security patches. Vulnerabilities in dependencies can sometimes be exploited to facilitate path traversal attacks.
*   **Automated Security Testing in CI/CD Pipeline:** Integrate SAST and DAST tools into the CI/CD pipeline to automatically detect vulnerabilities early in the development lifecycle.

### 5. Conclusion and Recommendations

Path Traversal via Route Parameters (Misconfiguration) is a critical vulnerability that can have severe consequences for Hapi.js applications. While the effort and skill level required to exploit it are low, the potential impact is high, making it a high-risk path in the attack tree.

**Key Recommendations for Hapi.js Developers:**

*   **Prioritize Mitigation:** Treat Path Traversal via Route Parameters as a high-priority security concern and implement robust mitigation strategies.
*   **Avoid Direct Parameter Usage:**  Do not directly use user-controlled route parameters to construct file paths. Use whitelists, mappings, or indirect methods.
*   **Utilize `h.file()` `confine` Option:**  Always use the `confine` option of `h.file()` to restrict file serving to a specific directory.
*   **Implement Strict Input Validation:**  Thoroughly validate and sanitize all route parameters used in file-related operations. Use Joi for validation and reject invalid input.
*   **Enforce Least Privilege:**  Run the Hapi.js application with minimal necessary permissions and restrict file system access.
*   **Adopt Secure Development Practices:**  Integrate security into the development lifecycle, including code reviews, security testing, and developer training.
*   **Regularly Test and Monitor:**  Perform regular security testing (SAST, DAST, penetration testing) and monitor application logs for suspicious activity.

By diligently implementing these recommendations, Hapi.js developers can significantly reduce the risk of Path Traversal via Route Parameters (Misconfiguration) vulnerabilities and build more secure applications.