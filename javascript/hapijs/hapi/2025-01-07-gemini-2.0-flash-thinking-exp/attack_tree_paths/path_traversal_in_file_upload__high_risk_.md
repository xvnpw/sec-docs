## Deep Analysis: Path Traversal in File Upload (Hapi.js Application)

**ATTACK TREE PATH:** Path Traversal in File Upload [HIGH RISK]

**Context:** This analysis focuses on the specific attack vector of Path Traversal within the file upload functionality of a web application built using the Hapi.js framework.

**1. Detailed Explanation of the Attack:**

The core of this vulnerability lies in the application's failure to properly validate and sanitize user-supplied filenames during the file upload process. When a user uploads a file, the application typically receives the file data and the original filename provided by the user's browser. If the application directly uses this user-provided filename to store the file on the server's file system **without sanitization**, an attacker can manipulate this filename to include path traversal sequences like `../`.

**How the Attack Works:**

* **Attacker Manipulation:** The attacker crafts a malicious filename containing `../` sequences. For example:
    * `../../../etc/passwd`
    * `../../uploads/malicious.php`
    * `sensitive_data/../../config.json`
* **Bypassing Intended Directory:**  These `../` sequences instruct the operating system to move up one directory level. By strategically placing multiple `../` sequences, the attacker can navigate outside the intended upload directory.
* **Unintended File Placement:** When the application attempts to save the file using the malicious filename, the file is written to the attacker-specified location on the server's file system.

**Example Scenario:**

Imagine an application intended to store uploaded user avatars in a directory named `/var/www/app/uploads/avatars/`. If the application directly uses the user-provided filename, an attacker could upload a file with the name `../../../etc/nginx/conf.d/overwrite.conf`. The application, without proper sanitization, would attempt to write this file to `/var/www/app/uploads/avatars/../../../etc/nginx/conf.d/overwrite.conf`, which resolves to `/etc/nginx/conf.d/overwrite.conf`. This could allow the attacker to overwrite the web server's configuration.

**2. Impact Assessment (HIGH RISK):**

This vulnerability is classified as **HIGH RISK** due to the potentially severe consequences:

* **Arbitrary File Overwrite:** Attackers can overwrite critical system files, application configuration files, or even executable files. This can lead to:
    * **Denial of Service (DoS):** Overwriting essential system files can crash the server or render the application unusable.
    * **Application Malfunction:** Overwriting configuration files can disrupt the application's functionality.
* **Remote Code Execution (RCE):** By uploading malicious executable files (e.g., PHP, Python scripts) to web-accessible directories, attackers can gain the ability to execute arbitrary code on the server. This is often the primary goal of such attacks.
* **Data Breach:** Attackers can upload files to sensitive directories containing confidential data, potentially gaining unauthorized access to sensitive information.
* **Privilege Escalation:** In some scenarios, attackers might be able to overwrite files with elevated privileges, potentially gaining root access to the server.
* **Website Defacement:** Attackers can upload files to the web root directory to deface the website.

**3. Technical Deep Dive (Hapi.js Specific Considerations):**

Hapi.js, by itself, doesn't inherently handle file uploads. This functionality is typically implemented using plugins like `@hapi/inert` or custom handlers. The vulnerability arises in how the developer implements the file upload handling logic, specifically the part responsible for saving the uploaded file to the file system.

**Common Vulnerable Patterns in Hapi.js:**

* **Directly Using `request.payload[fieldName].hapi.filename`:** If the application directly uses the `hapi.filename` property from the request payload to construct the file path without any validation or sanitization, it's highly vulnerable.

   ```javascript
   // Vulnerable Example
   server.route({
     method: 'POST',
     path: '/upload',
     handler: async (request, h) => {
       const { filename, payload } = request.payload.file;
       const filePath = path.join('/var/www/app/uploads/', filename); // Directly using filename
       const fileStream = payload;
       const writeStream = fs.createWriteStream(filePath);
       await pipeline(fileStream, writeStream);
       return 'File uploaded successfully';
     },
     options: {
       payload: {
         output: 'stream',
         parse: true,
         multipart: true
       }
     }
   });
   ```

* **Insufficient Sanitization:** Implementing basic sanitization like removing special characters but not addressing `../` sequences is insufficient.

**Secure Practices in Hapi.js:**

* **Generate Unique Filenames:** Instead of relying on the user-provided filename, generate a unique filename server-side (e.g., using UUIDs, timestamps, or hashing the file content).

   ```javascript
   // Secure Example
   const crypto = require('crypto');

   server.route({
     method: 'POST',
     path: '/upload',
     handler: async (request, h) => {
       const { payload } = request.payload.file;
       const fileExtension = path.extname(request.payload.file.hapi.filename);
       const uniqueFilename = crypto.randomBytes(16).toString('hex') + fileExtension;
       const filePath = path.join('/var/www/app/uploads/', uniqueFilename);
       const fileStream = payload;
       const writeStream = fs.createWriteStream(filePath);
       await pipeline(fileStream, writeStream);
       return 'File uploaded successfully';
     },
     options: { /* ... */ }
   });
   ```

* **Strict Whitelisting of Allowed Characters:** If using the original filename (with caution), implement strict whitelisting of allowed characters. Reject any filename containing characters outside the whitelist.

* **Path Canonicalization:** Use functions like `path.resolve()` to resolve the intended upload path and the constructed file path. Compare the canonicalized paths to ensure the file remains within the designated directory.

   ```javascript
   // Secure Example with Path Canonicalization
   server.route({
     method: 'POST',
     path: '/upload',
     handler: async (request, h) => {
       const { filename, payload } = request.payload.file;
       const uploadDir = '/var/www/app/uploads/';
       const intendedPath = path.join(uploadDir, filename);
       const canonicalIntendedPath = path.resolve(intendedPath);
       const canonicalUploadDir = path.resolve(uploadDir);

       if (!canonicalIntendedPath.startsWith(canonicalUploadDir)) {
         return h.response('Invalid filename').code(400);
       }

       const fileStream = payload;
       const writeStream = fs.createWriteStream(canonicalIntendedPath);
       await pipeline(fileStream, writeStream);
       return 'File uploaded successfully';
     },
     options: { /* ... */ }
   });
   ```

* **Configure Upload Directories Carefully:** Ensure the upload directory has appropriate permissions to prevent unauthorized access or execution of uploaded files.

* **Input Validation:** Implement robust input validation on the filename before using it.

**4. Mitigation Strategies:**

To prevent Path Traversal vulnerabilities in file uploads, the development team should implement the following mitigation strategies:

* **Never Trust User Input:** Always treat user-provided filenames as potentially malicious.
* **Generate Unique Filenames Server-Side:** This is the most effective way to prevent path traversal. Use UUIDs, timestamps, or content-based hashes to create unique and predictable filenames.
* **Strict Filename Sanitization:** If using the original filename is necessary, implement strict sanitization by:
    * **Whitelisting Allowed Characters:** Only allow a predefined set of safe characters (e.g., alphanumeric characters, underscores, hyphens). Reject any filename containing other characters.
    * **Blacklisting Dangerous Sequences:** Explicitly reject filenames containing `../`, `..\\`, or other path traversal sequences.
* **Path Canonicalization:** Use `path.resolve()` to resolve both the intended upload directory and the constructed file path. Verify that the resolved file path remains within the intended directory.
* **Restrict Upload Directory Permissions:** Configure the upload directory with the least necessary permissions. Prevent execution of files within the upload directory if it's not intended to host executable content.
* **Content Security Policy (CSP):** Implement a strong CSP that restricts the sources from which scripts can be executed, mitigating the impact if a malicious script is uploaded.
* **Regular Security Audits and Penetration Testing:** Conduct regular security assessments to identify and address potential vulnerabilities.
* **Security Libraries and Framework Features:** Leverage any built-in security features or libraries provided by Hapi.js or its plugins to assist with input validation and sanitization.

**5. Detection Methods:**

Identifying Path Traversal vulnerabilities in file uploads can be achieved through various methods:

* **Code Review:** Manually review the code responsible for handling file uploads, paying close attention to how filenames are processed and used to construct file paths. Look for instances where user-provided filenames are used directly without sanitization.
* **Static Application Security Testing (SAST):** Utilize SAST tools that can analyze the codebase and identify potential vulnerabilities, including path traversal flaws.
* **Dynamic Application Security Testing (DAST):** Employ DAST tools or manual penetration testing techniques to simulate attacks by uploading files with malicious filenames containing path traversal sequences. Monitor the server's file system to see if files are written to unexpected locations.
* **Web Application Firewalls (WAFs):** Configure WAFs to detect and block requests containing suspicious filename patterns, including path traversal sequences.
* **Security Information and Event Management (SIEM):** Monitor server logs for suspicious file creation events or access attempts in unexpected directories.

**6. Real-World Examples (Illustrative):**

While specific real-world examples might be confidential, consider these illustrative scenarios:

* **Scenario 1: Overwriting Application Configuration:** An attacker uploads a file named `../../../config/database.yml` containing modified database credentials, potentially gaining unauthorized access to the application's database.
* **Scenario 2: Remote Code Execution:** An attacker uploads a PHP script named `../../../../var/www/html/shell.php`, making it accessible via the web server and allowing them to execute arbitrary commands on the server.
* **Scenario 3: Data Breach:** An attacker uploads a file named `../../../backups/sensitive_data.zip`, potentially gaining access to sensitive backup data.

**7. Conclusion:**

Path Traversal in file uploads is a critical security vulnerability that can have severe consequences for Hapi.js applications. By failing to properly sanitize user-provided filenames, developers can inadvertently create pathways for attackers to manipulate the server's file system. Implementing robust mitigation strategies, such as generating unique filenames server-side and performing thorough input validation and sanitization, is crucial to protect the application and its data. Regular security assessments and awareness of this attack vector are essential for maintaining a secure application.
