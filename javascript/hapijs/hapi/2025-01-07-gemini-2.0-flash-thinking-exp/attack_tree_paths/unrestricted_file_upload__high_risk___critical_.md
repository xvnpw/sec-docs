## Deep Analysis: Unrestricted File Upload Attack Path in a Hapi.js Application

This document provides a deep analysis of the "Unrestricted File Upload" attack path in a Hapi.js application, as described in the provided attack tree. We will break down the attack, its potential impact, specific considerations for Hapi.js, and detailed mitigation strategies.

**ATTACK TREE PATH:** Unrestricted File Upload [HIGH RISK] [CRITICAL]

**- Attack Vector:** If the application allows users to upload files without proper validation of the file type, attackers can upload malicious executable files (e.g., PHP, Python scripts, executables). If these files are placed in a publicly accessible directory and the server is configured to execute them, the attacker can achieve remote code execution on the server.

**1. Detailed Breakdown of the Attack Path:**

Let's dissect each step of this attack path:

* **Attacker Action: Uploading a Malicious File:**
    * The attacker identifies an upload functionality within the Hapi.js application.
    * They craft a malicious file. This file could be:
        * **Server-side Script (e.g., PHP, Python, Node.js):** Designed to execute commands on the server when accessed. This is the most direct route to RCE.
        * **Executable Binary:** A compiled program intended to run on the server's operating system.
        * **Web Shell:** A script that provides a web-based interface for executing commands on the server.
    * The attacker uses the application's upload mechanism to send this file to the server.

* **Application Vulnerability: Lack of Proper File Type Validation:**
    * The core weakness lies in the application's failure to adequately verify the uploaded file's legitimacy and safety. This can manifest in several ways:
        * **No Validation:** The application accepts any file type without inspection.
        * **Insufficient Validation:**  Relying solely on client-side validation (easily bypassed).
        * **Blacklisting:** Blocking specific file extensions but failing to account for variations or new threats.
        * **MIME Type Spoofing:**  Only checking the `Content-Type` header, which can be easily manipulated by the attacker.
        * **Lack of Content Analysis:** Not inspecting the actual contents of the file to determine its true type.

* **Server Configuration Vulnerability: Publicly Accessible Upload Directory & Execution Enabled:**
    * The uploaded malicious file is stored in a directory that is accessible via the web server (e.g., under the `public` directory or a similar static asset serving location).
    * The web server (e.g., Nginx, Apache) or the Node.js process itself is configured to execute files within this directory. This is a critical misconfiguration. For example:
        * **PHP:** If the server has PHP installed and configured, files with the `.php` extension in the public directory will be parsed and executed.
        * **Python/Node.js:** If the server is configured to execute Python or Node.js scripts in this directory (less common for direct web access but possible through misconfiguration or specific application logic), the uploaded scripts can be run.
        * **Executable Permissions:** The uploaded file has execute permissions on the server's file system.

* **Attacker Action: Triggering the Malicious File:**
    * Once the malicious file is uploaded and accessible, the attacker can trigger its execution by:
        * **Directly accessing the file's URL:**  If the file is a server-side script, accessing its URL will cause the server to execute it.
        * **Including the file in another web page:**  If the application has other vulnerabilities (e.g., Cross-Site Scripting - XSS), the attacker could inject code to include the malicious file.

* **Consequence: Remote Code Execution (RCE):**
    * When the malicious file is executed, it runs with the privileges of the web server process. This allows the attacker to:
        * **Execute arbitrary commands on the server's operating system.**
        * **Read, modify, or delete sensitive data.**
        * **Install malware or backdoors.**
        * **Compromise other systems on the same network.**
        * **Launch further attacks.**

**2. Impact Assessment:**

The impact of a successful unrestricted file upload leading to RCE is **critical** and can have severe consequences:

* **Complete System Compromise:** The attacker gains control over the server, potentially leading to a full breach.
* **Data Breach:** Sensitive data stored on the server can be accessed, exfiltrated, or destroyed.
* **Service Disruption:** The attacker can take the application offline, causing significant downtime and financial losses.
* **Reputational Damage:** A successful attack can severely damage the organization's reputation and customer trust.
* **Legal and Regulatory Consequences:** Data breaches can lead to significant fines and legal repercussions.
* **Supply Chain Attacks:** If the compromised server is part of a larger infrastructure, the attacker can use it as a stepping stone to attack other systems.

**3. Hapi.js Specific Considerations:**

While Hapi.js itself doesn't inherently introduce this vulnerability, the way developers implement file upload functionality can create it. Here are some key considerations for Hapi.js applications:

* **`hapi-multipart` Plugin:**  Hapi.js often uses the `hapi-multipart` plugin (or similar) to handle file uploads. It's crucial to implement validation logic *after* the file is received by the plugin.
* **Route Handling:** The route handler responsible for processing the file upload must include robust validation steps.
* **File Storage Location:**  Carefully choose where uploaded files are stored. Avoid storing them directly in publicly accessible directories unless absolutely necessary and with stringent security measures.
* **Server Configuration:** The underlying web server (e.g., Nginx, Apache) configuration is critical. Ensure that execution of scripts in the upload directory is explicitly disabled.
* **Node.js Process Security:**  The Node.js process running the Hapi.js application should be run with the least necessary privileges to limit the impact of a successful RCE.

**4. Mitigation Strategies:**

To prevent this attack, a multi-layered approach is necessary:

* **Robust Server-Side File Type Validation (CRITICAL):**
    * **Whitelist Allowed File Types:** Define a strict list of acceptable file extensions and MIME types.
    * **Verify MIME Type from Content:** Don't rely solely on the `Content-Type` header. Use libraries to inspect the file's magic numbers or initial bytes to determine its true type.
    * **File Extension Validation:**  Check the file extension against the whitelist.
    * **Content Analysis:** For critical applications, consider using libraries to analyze the file's content for malicious patterns or embedded scripts.

* **Secure File Storage:**
    * **Store Uploaded Files Outside the Web Root:**  Avoid storing files directly in publicly accessible directories like `public`. Store them in a separate location that is not directly served by the web server.
    * **Use Unique and Unpredictable File Names:**  Rename uploaded files to prevent attackers from guessing file names and accessing them directly. Use UUIDs or random strings.
    * **Restrict Access Permissions:**  Set restrictive file system permissions on the upload directory to prevent unauthorized access or execution.

* **Disable Script Execution in Upload Directories:**
    * **Web Server Configuration:** Configure your web server (Nginx, Apache) to explicitly disable script execution (e.g., PHP, Python) in the directory where uploaded files are stored. This is a crucial defense-in-depth measure.
    * **Node.js Configuration:** Ensure your Node.js application does not serve static files from the upload directory with execution privileges.

* **Input Sanitization:**
    * **Sanitize File Names:** Remove or encode potentially harmful characters from file names to prevent path traversal or other injection vulnerabilities.

* **File Size Limits:**
    * Implement appropriate file size limits to prevent denial-of-service attacks and reduce storage costs.

* **Rate Limiting and Authentication:**
    * Implement rate limiting on the upload endpoint to prevent abuse.
    * Ensure proper authentication and authorization are in place to restrict who can upload files.

* **Content Security Policy (CSP):**
    * Implement a strong CSP to mitigate the impact of potential XSS vulnerabilities that could be used to trigger uploaded malicious files.

* **Regular Security Audits and Penetration Testing:**
    * Conduct regular security audits and penetration testing to identify and address potential vulnerabilities in your file upload implementation.

* **Keep Dependencies Updated:**
    * Regularly update Hapi.js, its plugins (including `hapi-multipart`), and other dependencies to patch known security vulnerabilities.

**5. Code Examples (Illustrative - Hapi.js with `hapi-multipart`):**

**Vulnerable Code (Illustrative):**

```javascript
const Hapi = require('@hapi/hapi');
const Inert = require('@hapi/inert');
const Vision = require('@hapi/vision');
const HapiSwagger = require('hapi-swagger');
const Joi = require('joi');

const start = async function() {
    const server = Hapi.server({
        port: 3000,
        host: 'localhost',
        routes: {
            files: {
                relativeTo: __dirname + '/uploads' // Potentially vulnerable if 'uploads' is public
            }
        }
    });

    await server.register([
        Inert,
        Vision,
        {
            plugin: HapiSwagger,
            options: {
                info: {
                    title: 'File Upload API'
                }
            }
        }
    ]);

    server.route({
        method: 'POST',
        path: '/upload',
        options: {
            payload: {
                output: 'stream',
                parse: true,
                allow: 'multipart/form-data'
            }
        },
        handler: async (request, h) => {
            const { payload } = request;
            const filename = payload.file.hapi.filename;
            const path = __dirname + '/uploads/' + filename; // Direct saving without validation
            const fileStream = payload.file;

            const fs = require('fs');
            const writeStream = fs.createWriteStream(path);

            fileStream.pipe(writeStream);

            return { message: 'File uploaded successfully' };
        }
    });

    await server.start();
    console.log('Server running on %s', server.info.uri);
};

start();
```

**Secure Code (Illustrative - with validation and secure storage):**

```javascript
const Hapi = require('@hapi/hapi');
const Inert = require('@hapi/inert');
const Vision = require('@hapi/vision');
const HapiSwagger = require('hapi-swagger');
const Joi = require('joi');
const { v4: uuidv4 } = require('uuid');
const pathLib = require('path');
const fs = require('fs').promises;
const { getType } = require('mime'); // Consider using a more robust library

const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'application/pdf']; // Define allowed types
const UPLOAD_DIRECTORY = pathLib.join(__dirname, 'secure_uploads'); // Secure storage outside web root

const start = async function() {
    const server = Hapi.server({
        port: 3000,
        host: 'localhost'
    });

    await server.register([
        Inert,
        Vision,
        {
            plugin: HapiSwagger,
            options: {
                info: {
                    title: 'Secure File Upload API'
                }
            }
        }
    ]);

    server.route({
        method: 'POST',
        path: '/upload',
        options: {
            payload: {
                output: 'stream',
                parse: true,
                allow: 'multipart/form-data',
                maxBytes: 1048576 // Example: 1MB limit
            },
            validate: {
                payload: Joi.object({
                    file: Joi.object({
                        hapi: Joi.object({
                            filename: Joi.string().required(),
                            headers: Joi.object({
                                'content-type': Joi.string().valid(...ALLOWED_MIME_TYPES).required()
                            }).unknown()
                        }).required(),
                        _data: Joi.any() // Stream data
                    }).required()
                })
            }
        },
        handler: async (request, h) => {
            const { payload } = request;
            const fileStream = payload.file;
            const originalFilename = payload.file.hapi.filename;
            const mimeType = payload.file.hapi.headers['content-type'];

            // More robust MIME type check based on content (example using 'mime' library)
            const detectedMimeType = getType(originalFilename);
            if (!ALLOWED_MIME_TYPES.includes(detectedMimeType)) {
                return h.response({ error: 'Invalid file type' }).code(400);
            }

            const fileExtension = pathLib.extname(originalFilename);
            const uniqueFilename = `${uuidv4()}${fileExtension}`;
            const filePath = pathLib.join(UPLOAD_DIRECTORY, uniqueFilename);

            try {
                await fs.mkdir(UPLOAD_DIRECTORY, { recursive: true }); // Ensure directory exists
                const writeStream = fs.createWriteStream(filePath);
                fileStream.pipe(writeStream);

                await new Promise((resolve, reject) => {
                    writeStream.on('finish', resolve);
                    writeStream.on('error', reject);
                });

                return { message: 'File uploaded successfully', filename: uniqueFilename };
            } catch (error) {
                console.error('Error saving file:', error);
                return h.response({ error: 'Failed to upload file' }).code(500);
            }
        }
    });

    await server.start();
    console.log('Server running on %s', server.info.uri);
};

start();
```

**Key differences in the secure example:**

* **Whitelisting Allowed MIME Types:**  The `ALLOWED_MIME_TYPES` array defines the acceptable file types.
* **Joi Validation:**  Uses Joi to validate the payload, including the `content-type` header.
* **Content-Based MIME Type Check:**  Demonstrates using a library (`mime`) to verify the MIME type based on the file content.
* **Secure Storage Location:** Files are saved in `secure_uploads`, which should be outside the web server's document root.
* **Unique Filenames:**  Uses UUIDs to generate unique and unpredictable filenames.
* **Error Handling:** Includes basic error handling for file system operations.

**6. Conclusion:**

The "Unrestricted File Upload" attack path poses a significant risk to Hapi.js applications. By understanding the attack vector, its potential impact, and implementing robust mitigation strategies, development teams can significantly reduce the likelihood of successful exploitation. Focus on server-side validation, secure file storage, and proper server configuration to protect your application and its users. Remember that security is an ongoing process, and regular reviews and updates are crucial to maintain a strong security posture.
