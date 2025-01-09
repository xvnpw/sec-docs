## Attack Surface Analysis: Serving Sensitive Files through Misconfigured Assets in Hanami Applications

**Introduction:**

This document provides a deep analysis of the "Serving Sensitive Files through Misconfigured Assets" attack surface within applications built using the Hanami framework. This analysis aims to provide development teams with a comprehensive understanding of the risks, potential attack vectors, and effective mitigation strategies specific to Hanami's architecture.

**Attack Surface: Serving Sensitive Files through Misconfigured Assets**

**Detailed Analysis:**

This attack surface arises from the potential to unintentionally expose sensitive files by placing them within directories served as static assets by the application. In the context of Hanami, the primary culprit is the `public` directory. While intended for publicly accessible assets like images, CSS, and JavaScript, misplacement of sensitive files here renders them directly accessible via HTTP requests.

**Hanami's Contribution and Specific Considerations:**

* **Default Static Asset Serving:** Hanami, by default, serves files directly from the `public` directory. This is a convenient feature for developers, but it introduces risk if not managed carefully. There's no built-in mechanism within Hanami to automatically restrict access to specific files or patterns within this directory.
* **Asset Pipeline Awareness:** While Hanami has an asset pipeline, this attack surface primarily concerns files placed directly in the `public` directory, bypassing the pipeline's processing. Developers might mistakenly believe the pipeline offers inherent protection, leading to complacency.
* **Lack of Built-in Security Defaults:** Hanami prioritizes flexibility and developer control. It doesn't enforce strict security defaults regarding asset placement. This necessitates a strong security awareness and proactive implementation of secure practices by the development team.
* **Potential for Accidental Inclusion:** During development, developers might temporarily place files in the `public` directory for testing or convenience and forget to remove them before deployment. This human error is a significant contributor to this attack surface.
* **Deployment Process Vulnerabilities:**  Deployment scripts or processes might inadvertently copy sensitive files into the `public` directory if not configured correctly.

**Expanding on the Example:**

The provided example of placing a `.env` file in the `public` directory is a classic and highly critical vulnerability. However, the scope extends beyond just `.env` files. Other sensitive files that could be mistakenly exposed include:

* **Configuration Files:**  Files like `config.yml`, `database.yml`, or custom configuration files containing database credentials, API keys, or internal service URLs.
* **Backup Files:**  Database backups (e.g., `.sql` dumps), configuration backups, or other sensitive data backups.
* **Internal Documentation:**  Files containing sensitive architectural details, internal processes, or security assessments.
* **Source Code (Partial):** While unlikely to be the entire codebase, snippets of code or configuration files containing sensitive logic could be exposed.
* **API Keys and Secrets:**  Files explicitly storing API keys for third-party services or internal systems.
* **Temporary Files:**  Debug logs or temporary files created during development that might contain sensitive information.

**Attack Vectors:**

Attackers can exploit this vulnerability through various methods:

* **Direct URL Access:**  The most straightforward method. If an attacker knows or can guess the file name and path within the `public` directory, they can directly request it via a web browser or other HTTP client. For example, `https://your-application.com/.env`.
* **Directory Brute-forcing:** Attackers can use automated tools to systematically guess file and directory names within the `public` directory. Common file extensions and names associated with configuration or backup files are often targeted.
* **Information Disclosure through Errors:**  If the web server is misconfigured, error messages might reveal the existence of files within the `public` directory.
* **Analyzing Publicly Available Code:** If the application's source code repository is publicly accessible (e.g., on GitHub), attackers can identify potential file paths within the `public` directory.
* **Leveraging Search Engine Indexing:**  If the `public` directory is not properly configured to prevent indexing (e.g., through `robots.txt`), search engines might index sensitive files, making them discoverable through simple searches.

**Impact Amplification:**

The impact of exposing sensitive files can be severe and far-reaching:

* **Complete System Compromise:** Exposure of database credentials or API keys can grant attackers full access to the application's data and backend systems.
* **Data Breach:** Access to sensitive user data, financial information, or intellectual property can lead to significant financial and reputational damage.
* **Account Takeover:** Exposed API keys or authentication secrets can allow attackers to impersonate legitimate users.
* **Lateral Movement:**  Compromised credentials can be used to gain access to other internal systems and resources.
* **Reputational Damage:**  Public disclosure of a security breach can severely damage the organization's reputation and customer trust.
* **Compliance Violations:**  Exposure of sensitive data can lead to violations of data privacy regulations (e.g., GDPR, CCPA) and significant fines.

**Risk Severity Assessment:**

As correctly identified, the risk severity is **Critical**. The ease of exploitation combined with the potentially catastrophic impact makes this a high-priority security concern.

**In-Depth Analysis of Mitigation Strategies:**

Let's delve deeper into the recommended mitigation strategies and expand on them specifically for Hanami applications:

* **Careful File Placement:**
    * **Principle of Least Privilege:**  Only place truly public assets (images, CSS, JavaScript) within the `public` directory.
    * **Alternative Storage Locations:** Store sensitive configuration files, backups, and internal documentation outside the web server's document root. Use environment variables or secure configuration management tools for sensitive settings.
    * **Configuration Management:** Leverage tools like `dotenv` (but load it outside the `public` directory) or dedicated configuration management solutions to manage sensitive settings securely.
    * **Directory Structure Review:** Regularly review the contents of the `public` directory to identify any misplaced sensitive files.

* **`.gitignore` and Deployment Practices:**
    * **Comprehensive `.gitignore`:**  Ensure the `.gitignore` file includes patterns for all sensitive file types (e.g., `*.env`, `*.sql`, `*.bak`, `*.log`).
    * **Pre-commit Hooks:** Implement pre-commit hooks to automatically check for sensitive files before they are committed to the repository.
    * **Secure Deployment Pipelines:**  Automate the deployment process to minimize manual intervention and ensure that only necessary files are deployed. Avoid copying entire directories blindly.
    * **Infrastructure as Code (IaC):**  Use IaC tools to manage infrastructure and deployments, ensuring consistent and secure configurations.
    * **Secrets Management Tools:**  Integrate secrets management tools (e.g., HashiCorp Vault, AWS Secrets Manager) into the deployment process to securely manage and inject sensitive credentials.

* **Restrict Asset Access (Web Server Configuration):**
    * **Nginx Configuration:**
        ```nginx
        location ~ /\. {
          deny all;
        }
        ```
        This configuration prevents access to files starting with a dot (e.g., `.env`, `.git`).
        ```nginx
        location ~* \.(sql|bak|config|log)$ {
          deny all;
        }
        ```
        This configuration prevents access to files with specific extensions.
    * **Apache Configuration (.htaccess):**
        ```apache
        <FilesMatch "(\.env|\.sql|\.bak|\.config|\.log)$">
            Require all denied
        </FilesMatch>
        ```
        This configuration denies access to files matching the specified patterns.
    * **Content Security Policy (CSP):** While not directly preventing access to existing files, a strong CSP can help mitigate the impact if a sensitive file containing JavaScript is accidentally exposed.
    * **`robots.txt`:** While not a security measure, using `robots.txt` can prevent search engines from indexing the `public` directory or specific sensitive file paths. However, it should not be relied upon for security.

**Additional Mitigation and Prevention Strategies:**

* **Regular Security Audits and Penetration Testing:**  Conduct regular security audits and penetration tests to identify potential vulnerabilities, including misplaced sensitive files.
* **Code Reviews:** Implement thorough code reviews to catch accidental placement of sensitive files in the `public` directory.
* **Developer Training and Awareness:**  Educate developers about the risks associated with this attack surface and best practices for secure asset management.
* **Static Application Security Testing (SAST):**  Utilize SAST tools to scan the codebase for potential vulnerabilities, including the presence of sensitive file patterns in the `public` directory.
* **Dynamic Application Security Testing (DAST):**  Employ DAST tools to probe the application for accessible sensitive files during runtime.
* **Principle of Least Privilege (File System Permissions):** Ensure that the web server process has the minimum necessary file system permissions to operate. This can limit the impact if a vulnerability is exploited.
* **Monitoring and Alerting:** Implement monitoring and alerting systems to detect unusual access patterns to files within the `public` directory.

**Conclusion:**

Serving sensitive files through misconfigured assets is a critical attack surface in Hanami applications due to the framework's default behavior of serving static files from the `public` directory. While Hanami provides flexibility, it places the responsibility for secure asset management squarely on the development team. By understanding the potential attack vectors, implementing robust mitigation strategies, and fostering a strong security awareness, development teams can significantly reduce the risk of exposing sensitive information and protect their applications from potential compromise. A layered approach combining careful file placement, secure deployment practices, and web server configuration is crucial for effectively addressing this vulnerability.
