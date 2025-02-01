# Mitigation Strategies Analysis for carrierwaveuploader/carrierwave

## Mitigation Strategy: [File Type Whitelisting](./mitigation_strategies/file_type_whitelisting.md)

**Description:**
    1.  **Define Allowed Types in Uploader:** Within your Carrierwave uploader class (e.g., `app/uploaders/my_uploader.rb`), use the `extension_whitelist` and/or `content_type_whitelist` methods.
    2.  **Specify Allowed Extensions:** In `extension_whitelist`, return an array of allowed file extensions as strings (e.g., `['jpg', 'png', 'pdf']`).
    3.  **Specify Allowed MIME Types:** In `content_type_whitelist`, return an array of allowed MIME types as strings (e.g., `['image/jpeg', 'application/pdf']`).
    4.  **Apply to Relevant Uploaders:** Ensure these whitelists are configured in all Carrierwave uploaders where file type restrictions are needed.
    5.  **Test Whitelisting:** Verify that only files with whitelisted extensions and/or MIME types can be uploaded successfully, and that others are rejected with appropriate error messages.
**List of Threats Mitigated:**
    *   **Malicious File Upload (High Severity):** Prevents uploading executable files or other dangerous file types that could harm the server or users.
    *   **Server-Side Vulnerabilities Exploitation (Medium Severity):** Reduces the risk of vulnerabilities in file processing libraries being exploited by unexpected file types.
**Impact:**
    *   **Malicious File Upload:** High reduction in risk by directly blocking many common malicious file types at the Carrierwave level.
    *   **Server-Side Vulnerabilities Exploitation:** Medium reduction in risk by limiting the file types processed by the application.
**Currently Implemented:** Yes, implemented in `app/uploaders/profile_image_uploader.rb` and `app/uploaders/document_uploader.rb` using `extension_whitelist` and `content_type_whitelist`.
**Missing Implementation:**  No major missing implementations in core uploaders. Review and extend whitelists if new upload functionalities are added, especially in admin areas or less controlled upload sections.

## Mitigation Strategy: [Validate File Content (Beyond MIME Type)](./mitigation_strategies/validate_file_content__beyond_mime_type_.md)

**Description:**
    1.  **Choose Validation Library:** Select a content-based validation library like `filemagic` or `mimemagic` and add it to your Gemfile.
    2.  **Create Custom Validation in Uploader:** In your Carrierwave uploader, define a custom validation method (e.g., `validate_file_integrity`).
    3.  **Use Library for Content Check:** Within the custom validation method, use the chosen library to inspect the file content (e.g., `MimeMagic.by_path(file.path)`).
    4.  **Compare Detected Content Type:**  Compare the content type detected by the library against your expected allowed types.
    5.  **Add Carrierwave Error on Invalid Content:** If the content type is invalid, use `errors.add :file, "is not a valid file type"` within the validation method to trigger a Carrierwave validation error.
    6.  **Register Validation:**  In your uploader, use `validate :validate_file_integrity` to register your custom validation method.
**List of Threats Mitigated:**
    *   **MIME Type Spoofing (Medium Severity):** Prevents bypassing MIME type whitelisting by attackers who manipulate the MIME type header.
    *   **File Extension Renaming Bypass (Medium Severity):** Reduces the effectiveness of simply renaming file extensions to bypass whitelists.
**Impact:**
    *   **MIME Type Spoofing:** High reduction in risk. Makes MIME type spoofing ineffective as the actual file content is inspected by Carrierwave validation.
    *   **File Extension Renaming Bypass:** Medium reduction in risk.  Reduces the effectiveness of simple renaming attacks.
**Currently Implemented:** Partially implemented. Basic MIME type whitelisting is present, but content-based validation using libraries like `mimemagic` within Carrierwave validation is not yet integrated.
**Missing Implementation:**  Missing in all Carrierwave uploaders (`profile_image_uploader.rb`, `document_uploader.rb`, etc.). Needs to be implemented by adding the custom validation logic and integrating a content inspection library into each relevant uploader.

## Mitigation Strategy: [Sanitize Filenames (Using Carrierwave Features)](./mitigation_strategies/sanitize_filenames__using_carrierwave_features_.md)

**Description:**
    1.  **Utilize `sanitize_name` (Default or Custom):** Carrierwave provides a default `sanitize_name` method. You can either rely on this default or override it in your uploader for custom sanitization.
    2.  **Override `filename` Method:** In your Carrierwave uploader, override the `filename` method.
    3.  **Apply Sanitization in `filename`:** Within the `filename` method, call `sanitize_name(original_filename)` (or your custom sanitization logic) and assign the result to `@name`. This ensures all filenames processed by Carrierwave are sanitized.
    4.  **Consider UUID/Hash Filenames:** For enhanced security and to completely avoid user-provided filename issues, consider generating UUIDs or hashes as filenames within the `filename` method instead of sanitizing user input.
**List of Threats Mitigated:**
    *   **Directory Traversal Attacks (High Severity):** Prevents path traversal attempts through malicious filenames by removing or sanitizing path-related characters.
    *   **File System Command Injection (Medium Severity):** Reduces the risk of command injection if filenames are improperly used in shell commands (though this practice should be avoided regardless).
    *   **URL Encoding Issues/Unexpected Behavior (Low Severity):** Prevents issues caused by special characters in filenames within URLs and file systems.
**Impact:**
    *   **Directory Traversal Attacks:** High reduction in risk. Effectively prevents directory traversal attacks via filenames processed by Carrierwave.
    *   **File System Command Injection:** Medium reduction in risk. Reduces risk, but proper coding practices are still essential.
    *   **URL Encoding Issues/Unexpected Behavior:** Low reduction in risk. Improves application stability and usability related to filenames.
**Currently Implemented:** Partially implemented. Default sanitization using `CarrierWave::SanitizedFile.strip_filename` is implicitly used by Carrierwave. Custom or more robust sanitization is not implemented.
**Missing Implementation:**  Missing more robust custom sanitization logic within uploaders. Enhance sanitization in `filename` method to handle a wider range of problematic characters. Consider implementing UUID/hash-based filenames, especially for sensitive uploads, directly within the `filename` method of relevant uploaders.

## Mitigation Strategy: [Limit File Sizes (Using Carrierwave Configuration)](./mitigation_strategies/limit_file_sizes__using_carrierwave_configuration_.md)

**Description:**
    1.  **Define `maximum_size` in Uploader:** In your Carrierwave uploader class, define the `maximum_size` method.
    2.  **Set Size Limit:** Within `maximum_size`, return the maximum allowed file size in bytes, kilobytes, megabytes, or gigabytes using Carrierwave's size helper methods (e.g., `5.megabytes`).
    3.  **Apply to Relevant Uploaders:** Configure `maximum_size` in all Carrierwave uploaders where file size limits are necessary.
    4.  **Test Size Limits:** Verify that uploads exceeding the `maximum_size` are rejected by Carrierwave with appropriate error messages.
**List of Threats Mitigated:**
    *   **Denial of Service (DoS) - Resource Exhaustion (High Severity):** Prevents DoS attacks by limiting the size of uploaded files, thus controlling resource consumption.
    *   **Storage Exhaustion (Medium Severity):** Helps prevent unintentional or malicious filling up of server storage space with excessively large uploads.
**Impact:**
    *   **Denial of Service (DoS) - Resource Exhaustion:** High reduction in risk. Effectively limits the impact of large file upload DoS attempts at the Carrierwave level.
    *   **Storage Exhaustion:** Medium reduction in risk. Helps manage storage usage related to file uploads handled by Carrierwave.
**Currently Implemented:** Yes, implemented in `app/uploaders/profile_image_uploader.rb` (2MB limit) and `app/uploaders/document_uploader.rb` (10MB limit) using `maximum_size`.
**Missing Implementation:**  File size limits are implemented, but should be periodically reviewed and adjusted based on application needs and resource availability. Consider making these limits configurable via application settings rather than hardcoding them in uploaders for easier management.

## Mitigation Strategy: [Store Uploads Outside Web Root (Configured via Carrierwave)](./mitigation_strategies/store_uploads_outside_web_root__configured_via_carrierwave_.md)

**Description:**
    1.  **Configure `config.root` in Carrierwave Initializer:** In `config/initializers/carrierwave.rb`, set `config.root` to a directory path *outside* your web server's document root (e.g., `File.join(Rails.root, '..', 'uploads')`). This is a global Carrierwave setting.
    2.  **Define `store_dir` in Uploaders:** Ensure your Carrierwave uploaders' `store_dir` method specifies a subdirectory within the `config.root` path. This defines where files are stored relative to the configured root.
    3.  **Adjust Application Logic:**  Modify your application to serve files through a controller action instead of direct URLs. Use `send_file` in Rails to securely serve files, retrieving file paths based on your configured `config.root` and `store_dir`.
**List of Threats Mitigated:**
    *   **Direct File Access Bypass (High Severity):** Prevents direct URL access to uploaded files, enforcing access control through your application.
    *   **Information Disclosure (High Severity):** Reduces the risk of sensitive files being publicly accessible if they are not stored within the web root.
    *   **Unintended File Exposure (Medium Severity):** Prevents accidental public exposure of files due to misconfigurations within the web root.
**Impact:**
    *   **Direct File Access Bypass:** High reduction in risk. Eliminates direct URL access as a vulnerability for files managed by Carrierwave.
    *   **Information Disclosure:** High reduction in risk. Significantly reduces the chance of information disclosure through direct file access to Carrierwave managed uploads.
    *   **Unintended File Exposure:** Medium reduction in risk. Makes it less likely for Carrierwave managed files to be unintentionally exposed.
**Currently Implemented:** No, currently `config.root` is likely defaulting to `public` or a subdirectory within `public`, resulting in files being stored within the web root.
**Missing Implementation:**  Missing entirely. Needs to be implemented by configuring `config.root` in `config/initializers/carrierwave.rb` to a location outside the web root and adjusting `store_dir` in uploaders accordingly.  Application logic for serving files via controller actions also needs to be implemented. This is a high priority Carrierwave-specific security improvement.

