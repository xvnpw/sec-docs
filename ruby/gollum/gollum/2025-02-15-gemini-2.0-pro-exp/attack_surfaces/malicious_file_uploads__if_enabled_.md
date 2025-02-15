Okay, here's a deep analysis of the "Malicious File Uploads" attack surface for a Gollum-based application, tailored for a development team and presented in Markdown:

# Deep Analysis: Malicious File Uploads in Gollum

## 1. Objective, Scope, and Methodology

### 1.1. Objective

The primary objective of this deep analysis is to:

*   Thoroughly understand the risks associated with enabling file uploads in a Gollum wiki instance.
*   Identify specific vulnerabilities and attack vectors related to malicious file uploads.
*   Provide actionable recommendations and best practices to mitigate these risks, going beyond the high-level mitigations already identified.
*   Help the development team integrate secure file upload handling (if uploads are absolutely necessary) into the Gollum deployment and any surrounding infrastructure.

### 1.2. Scope

This analysis focuses specifically on the **"Malicious File Uploads"** attack surface within the context of a Gollum wiki.  It considers:

*   Gollum's configuration options related to file uploads.
*   The underlying Git repository's role in storing and managing uploaded files.
*   The web server environment hosting the Gollum instance.
*   Potential interactions with other system components (e.g., reverse proxies, load balancers).
*   Client-side risks stemming from malicious file downloads.

This analysis *does not* cover:

*   Other attack surfaces of Gollum (e.g., XSS, CSRF, authentication bypasses) *unless* they directly relate to file uploads.
*   General security hardening of the operating system or web server, except where directly relevant to file upload security.

### 1.3. Methodology

The analysis will employ the following methodologies:

*   **Code Review (Gollum Source):** Examine the Gollum codebase (Ruby) to understand how file uploads are handled, including:
    *   Input validation routines.
    *   File storage mechanisms.
    *   Configuration options related to uploads.
    *   Any existing security measures.
*   **Configuration Analysis:** Review the default and recommended configurations for Gollum and related components (web server, Git) to identify potential misconfigurations that could exacerbate upload vulnerabilities.
*   **Threat Modeling:**  Develop specific attack scenarios based on common malicious file upload techniques.
*   **Penetration Testing (Conceptual):**  Outline potential penetration testing steps that could be used to validate the effectiveness of implemented mitigations.  (Actual penetration testing is outside the scope of this document, but the conceptual steps provide a framework for testing.)
*   **Best Practices Research:**  Leverage established security best practices for file upload handling, drawing from OWASP, SANS, and other reputable sources.

## 2. Deep Analysis of the Attack Surface

### 2.1. Gollum-Specific Considerations

*   **Upload Configuration:** Gollum's `--allow-uploads` flag (or the equivalent configuration setting) is the critical control.  Understanding *where* this flag is set (command-line, configuration file, environment variable) and ensuring it's managed securely is paramount.  Accidental enabling of uploads is a major risk.
*   **Git as Storage:** Gollum uses Git to store uploaded files.  This has implications:
    *   **Version History:**  Even if a malicious file is deleted from the wiki, it *remains in the Git history* unless explicitly removed (e.g., using `git filter-branch` or BFG Repo-Cleaner, which are complex operations).  This could allow an attacker to retrieve a previously uploaded malicious file.
    *   **.git Directory Exposure:**  If the `.git` directory is accidentally exposed to the web (a common misconfiguration), attackers could potentially download the entire repository, including all uploaded files and their history.
    *   **Git Hooks:**  While potentially useful for mitigation (e.g., pre-commit hooks to scan files), Git hooks can also be a target for attackers if they gain write access to the repository.
*   **Lack of Built-in Sanitization:** Gollum, by design, is a wiki engine, not a file upload security system.  It relies heavily on the administrator to implement proper security measures.  It does *not* provide built-in file type validation, anti-malware scanning, or other advanced security features.
* **Default upload directory**: Gollum uploads files to the root of the git repository.

### 2.2. Attack Vectors and Scenarios

Here are some specific attack scenarios, building upon the general "Malicious File Uploads" description:

*   **Scenario 1: PHP Shell Upload (Classic)**
    *   **Attacker Action:** Uploads a file named `image.jpg.php` (or similar double extension) containing PHP code.
    *   **Exploitation:**  If the web server (e.g., Apache with misconfigured `AddHandler` or `.htaccess`) executes `.php` files regardless of their position in the filename, the attacker can access the shell by navigating to `http://wiki.example.com/uploads/image.jpg.php`.
    *   **Impact:**  Full server compromise.

*   **Scenario 2:  .htaccess Bypass**
    *   **Attacker Action:** Uploads a `.htaccess` file to a directory within the upload path.
    *   **Exploitation:**  The `.htaccess` file can override server configurations, potentially disabling security measures or enabling execution of arbitrary file types.  For example, it could add a handler for `.jpg` files to be executed as PHP.
    *   **Impact:**  Server compromise, depending on the `.htaccess` contents.

*   **Scenario 3:  Client-Side Attacks (Stored XSS)**
    *   **Attacker Action:** Uploads an HTML file (or a file disguised as an image but containing HTML/JavaScript) with malicious JavaScript code.
    *   **Exploitation:**  When another user views the file (either directly or embedded in a wiki page), the JavaScript executes in their browser.
    *   **Impact:**  Session hijacking, data theft, defacement, phishing.

*   **Scenario 4:  Denial of Service (DoS) - Disk Space Exhaustion**
    *   **Attacker Action:**  Repeatedly uploads very large files.
    *   **Exploitation:**  Fills up the server's disk space, preventing the wiki (and potentially other services) from functioning.
    *   **Impact:**  Denial of service.

*   **Scenario 5:  Malware Distribution**
    *   **Attacker Action:**  Uploads a malicious executable (e.g., `.exe`, `.msi`, `.sh`) disguised as a legitimate document.
    *   **Exploitation:**  Users download and execute the file, infecting their systems.
    *   **Impact:**  Malware infection of client machines.

*   **Scenario 6:  ImageMagick Vulnerability (ImageTragick)**
    *   **Attacker Action:**  Uploads a specially crafted image file that exploits a vulnerability in ImageMagick (or other image processing libraries) if Gollum uses such a library for thumbnail generation or image manipulation.
    *   **Exploitation:**  Remote code execution through the image processing library.
    *   **Impact:**  Server compromise.

*   **Scenario 7:  Path Traversal via Filename**
    *   **Attacker Action:**  Uploads a file with a name like `../../../../etc/passwd`.
    *   **Exploitation:**  Attempts to write the file outside the intended upload directory, potentially overwriting critical system files.  This is *less likely* with Gollum's Git-based storage, but still worth considering, especially if custom scripts are used to handle uploads.
    *   **Impact:**  System compromise, data corruption.

### 2.3. Detailed Mitigation Strategies

Building on the initial mitigations, here are more detailed and actionable recommendations:

1.  **Disable Uploads (Strongly Preferred):**
    *   **Configuration:** Ensure `--allow-uploads` is *not* set, and there are no equivalent settings in configuration files or environment variables.
    *   **Verification:** Regularly audit the Gollum configuration to confirm uploads remain disabled.
    *   **Alternative Solutions:** If file sharing is needed, consider dedicated file sharing solutions (e.g., Nextcloud, ownCloud, SFTP) with proper security controls, rather than enabling uploads within the wiki.

2.  **Strict File Type Validation (If Uploads Are Essential):**
    *   **Multi-Layered Validation:**
        *   **MIME Type Check:** Use a robust library (e.g., `Rack::Mime` in Ruby) to determine the MIME type based on the file *content*, not the filename extension.
        *   **Magic Number Check:**  Verify the file's "magic number" (the first few bytes of the file) against a known list of valid file signatures.  This helps detect files that have been disguised with incorrect extensions.  Libraries like `ruby-filemagic` can be used.
        *   **File Extension Whitelist:**  Maintain a *strict whitelist* of allowed extensions (e.g., `.pdf`, `.docx`, `.txt`).  *Never* use a blacklist.
        *   **Double Extension Check:**  Specifically check for and reject files with double extensions (e.g., `.php.jpg`).
        *   **Null Byte Check:** Reject the filenames that contain null bytes.
    *   **Example (Conceptual Ruby):**

    ```ruby
    require 'rack/mime'
    require 'filemagic'

    def is_allowed_file?(file)
      allowed_mime_types = ['application/pdf', 'text/plain', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
      allowed_extensions = ['.pdf', '.txt', '.docx', '.doc']

      mime_type = Rack::Mime.mime_type(File.extname(file.original_filename), 'application/octet-stream')
      return false unless allowed_mime_types.include?(mime_type)

      fm = FileMagic.new(:mime)
      detected_mime_type = fm.file(file.tempfile.path)
      fm.close
      return false unless detected_mime_type == mime_type

      extension = File.extname(file.original_filename).downcase
      return false unless allowed_extensions.include?(extension)
      
      # Double extension check
      return false if file.original_filename.downcase.match(/\.[a-z0-9]+\.[a-z0-9]+$/)

      # Null byte check
      return false if file.original_filename.index("\0")

      true
    end
    ```

3.  **Store Outside Webroot:**
    *   **Dedicated Storage Directory:** Create a directory *outside* the web server's document root (e.g., `/var/gollum_uploads` instead of `/var/www/html/gollum/uploads`).
    *   **Controlled Access:**  Use a dedicated script (e.g., a Ruby script within the Gollum application) to serve the files.  This script should:
        *   Authenticate the user (if necessary).
        *   Validate the requested file against a list of allowed files (based on the wiki's internal representation).
        *   Read the file from the storage directory.
        *   Set appropriate `Content-Type` and `Content-Disposition` headers.
        *   Stream the file content to the user.
    *   **Prevent Direct Access:** Configure the web server (e.g., Apache, Nginx) to *deny* direct access to the storage directory.

4.  **Anti-Malware Scanning:**
    *   **ClamAV Integration:** Integrate ClamAV (or another reputable anti-malware scanner) into the upload process.
    *   **Scan Before Storage:** Scan the file *before* it's written to the storage directory.
    *   **Quarantine or Reject:**  If malware is detected, either quarantine the file or reject the upload entirely.
    *   **Regular Updates:**  Ensure the anti-malware definitions are updated regularly.
    *   **Example (Conceptual Ruby with ClamAV):**

    ```ruby
    require 'clamav'

    def scan_for_malware(file_path)
      begin
        c = ClamAV.instance
        scan_result = c.scanfile(file_path)
        if scan_result.empty?
          return false # No malware detected
        else
          puts "Malware detected: #{scan_result.join(', ')}"
          return true # Malware detected
        end
      rescue ClamAV::Error => e
        puts "ClamAV error: #{e.message}"
        return true # Treat errors as potential malware
      end
    end
    ```

5.  **File Size Limits:**
    *   **Gollum Configuration:**  If Gollum provides a configuration option for maximum file size, use it.
    *   **Web Server Configuration:**  Configure the web server (e.g., `LimitRequestBody` in Apache, `client_max_body_size` in Nginx) to enforce a reasonable file size limit.
    *   **Reverse Proxy/Load Balancer:**  If using a reverse proxy or load balancer, configure it to enforce file size limits as well.  This provides an additional layer of defense.

6.  **Rename Uploaded Files:**
    *   **Unique Filenames:**  Generate unique filenames for uploaded files (e.g., using a UUID or a hash of the file content) to prevent filename collisions and potential overwriting of existing files.
    *   **Store Original Filename Separately:**  If the original filename is needed, store it separately (e.g., in the wiki's metadata) rather than using it directly.

7.  **Content Security Policy (CSP):**
    *   **Restrict Script Execution:**  Use a strict CSP to prevent the execution of inline scripts and to limit the sources from which scripts can be loaded.  This helps mitigate client-side attacks (XSS) even if a malicious HTML file is uploaded.
    *   **Example CSP Header:**

    ```
    Content-Security-Policy: default-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'self';
    ```

8.  **Regular Security Audits and Penetration Testing:**
    *   **Code Audits:** Regularly review the Gollum codebase and any custom scripts related to file uploads for security vulnerabilities.
    *   **Penetration Testing:**  Conduct regular penetration tests, specifically targeting the file upload functionality, to identify and address any weaknesses.

9.  **Monitoring and Logging:**
    *   **Log Upload Events:**  Log all file upload attempts, including successful uploads, failed uploads, and any errors encountered.
    *   **Monitor Logs:**  Regularly monitor the logs for suspicious activity, such as repeated upload attempts from the same IP address, uploads of unusual file types, or large file uploads.
    *   **Alerting:**  Configure alerts for suspicious events.

10. **.git Directory Protection:**
    *   **Web Server Configuration:** Explicitly deny access to the `.git` directory in your web server configuration.
        *   **Apache:**

        ```apache
        <DirectoryMatch "^/.*/\.git/">
            Require all denied
        </DirectoryMatch>
        ```

        *   **Nginx:**

        ```nginx
        location ~ /\.git/ {
            deny all;
        }
        ```

### 2.4. Conceptual Penetration Testing Steps

These steps outline how a penetration tester might attempt to exploit file upload vulnerabilities in a Gollum instance:

1.  **Reconnaissance:**
    *   Identify the Gollum version.
    *   Determine if file uploads are enabled (try uploading a benign file).
    *   Inspect the HTML source code and JavaScript for clues about upload handling.
    *   Check for exposed `.git` directories.

2.  **File Type Bypass:**
    *   Attempt to upload files with various extensions (e.g., `.php`, `.php5`, `.phtml`, `.shtml`, `.asp`, `.aspx`, `.jsp`, `.cgi`, `.pl`, `.py`, `.rb`, `.exe`, `.msi`, `.sh`).
    *   Try double extensions (e.g., `.jpg.php`).
    *   Try variations in capitalization (e.g., `.PhP`).
    *   Try null bytes (e.g., `image.php%00.jpg`).
    *   Try long filenames.
    *   Try unusual characters in filenames.

3.  **Content-Based Attacks:**
    *   Upload files with malicious content disguised as legitimate file types (e.g., HTML with JavaScript in a `.jpg` file).
    *   Upload files designed to exploit vulnerabilities in image processing libraries (ImageTragick).

4.  **.htaccess Attacks:**
    *   Attempt to upload `.htaccess` files to various directories.

5.  **Path Traversal:**
    *   Attempt to upload files with names containing path traversal sequences (e.g., `../../`).

6.  **Denial of Service:**
    *   Attempt to upload very large files.
    *   Attempt to upload many files rapidly.

7.  **Git Repository Access:**
    *   Attempt to access the `.git` directory directly.
    *   If accessible, try to download the repository contents.

8.  **Client-Side Attacks:**
    *   Upload HTML files with malicious JavaScript.
    *   Try to embed uploaded files in wiki pages to trigger XSS.

## 3. Conclusion

Malicious file uploads represent a significant security risk for Gollum instances if uploads are enabled.  The preferred mitigation is to **disable uploads entirely**. If uploads are absolutely necessary, a multi-layered approach to security is essential, including strict file type validation, storing files outside the webroot, anti-malware scanning, file size limits, renaming files, using a strong CSP, and regular security audits.  The Git-based storage used by Gollum introduces unique considerations, particularly regarding the persistence of uploaded files in the Git history and the potential exposure of the `.git` directory.  By implementing the detailed mitigations outlined in this analysis, the development team can significantly reduce the risk of successful attacks related to malicious file uploads.