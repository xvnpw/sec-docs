# Mitigation Strategies Analysis for thoughtbot/paperclip

## Mitigation Strategy: [File Signature Validation (Magic Numbers) within Paperclip Validation](./mitigation_strategies/file_signature_validation__magic_numbers__within_paperclip_validation.md)

**Description:**
1.  **Integrate a Gem:** Add a gem like `filemagic` to your `Gemfile` and run `bundle install`.
2.  **Create a Validation Method:** In your model (e.g., `User` with an `avatar` attachment), define a custom validation method (e.g., `file_signature_matches`).
3.  **Access Queued File:** Inside the validation, access the file queued for writing: `avatar.queued_for_write[:original]`. This is the temporary file *before* Paperclip's processing.
4.  **Use FileMagic:** Use `FileMagic` to open the temporary file and determine its *true* MIME type based on its content (magic numbers).
5.  **Whitelist Allowed Types:** Define a *strict* whitelist of allowed MIME types (e.g., `['image/jpeg', 'image/png', 'image/gif']`).
6.  **Compare and Add Errors:** Compare the detected MIME type against your whitelist. If it's not on the list, add an error to the model: `errors.add(:avatar, "is not a valid file type")`.
7.  **Ensure FileMagic is Closed:** Close the `FileMagic` instance in an `ensure` block to release resources.
8.  **Call the Validation:** Use `validate :file_signature_matches` in your model to ensure the custom validation is executed.
9. **Combine with Paperclip's `content_type`:** Keep Paperclip's `content_type` validation, but treat it as a *secondary* check. The file signature validation is the primary defense.

**List of Threats Mitigated:**
*   **MIME Type Spoofing:** (Severity: High) - Attackers upload malicious files disguised as images by changing extensions or manipulating the `Content-Type` header.
*   **File Type Confusion Attacks:** (Severity: High) - Exploits relying on the server misinterpreting the file type.
*   **Bypassing Basic Paperclip Validation:** (Severity: High) - Paperclip's built-in MIME type validation is easily bypassed.

**Impact:**
*   **MIME Type Spoofing:** Risk significantly reduced. Prevents processing based on a false MIME type.
*   **File Type Confusion Attacks:** Risk significantly reduced. Accurate file type identification prevents misinterpretation.
*   **Bypassing Basic Paperclip Validation:** Risk significantly reduced. Provides a robust alternative.

**Currently Implemented:** Partially. `filemagic` is installed, and a basic validation exists in `User`, but it only checks `image/jpeg` and lacks proper error handling.

**Missing Implementation:**
*   Expand the `User` model validation to include all allowed types (PNG, GIF).
*   Add proper error handling (closing `FileMagic` in an `ensure` block).
*   Apply the validation to *all* models with Paperclip attachments.

## Mitigation Strategy: [Paperclip `size` Validation (as a Secondary Check)](./mitigation_strategies/paperclip__size__validation__as_a_secondary_check_.md)

**Description:**
1.  **In Model Configuration:** Within your `has_attached_file` declaration in your model, use the `:size` option.
2.  **Specify a Range:** Define a reasonable file size range, e.g., `size: { in: 0..5.megabytes }`.  This should be *smaller* than any server-level limits.
3. **Treat as Secondary:** Understand that this is a *secondary* check.  The primary defense should be at the web server level (Nginx/Apache).

**List of Threats Mitigated:**
*   **Denial of Service (DoS) via Large Files:** (Severity: High) - Attackers upload large files to consume resources.
*   **Resource Exhaustion:** (Severity: High) - Similar to DoS, but can occur with moderately large files.

**Impact:**
*   **Denial of Service (DoS) via Large Files:** Risk *partially* reduced. Provides a secondary layer of defense *if* the web server limit is bypassed or misconfigured.
*   **Resource Exhaustion:** Risk *partially* reduced. Helps limit resource consumption, but the web server limit is crucial.

**Currently Implemented:** Yes. The Paperclip `:size` validation is implemented in all relevant models.

**Missing Implementation:** None, *within the context of Paperclip itself*.  The crucial missing piece is the web server configuration (which is outside the scope of this revised list).

## Mitigation Strategy: [Randomized Filenames within Paperclip](./mitigation_strategies/randomized_filenames_within_paperclip.md)

**Description:**
1.  **`before_post_process` Callback:** In your model, use a `before_post_process` callback (e.g., `before_post_process :randomize_filename`).
2.  **Generate UUID:** Inside the callback, generate a UUID using `SecureRandom.uuid`.
3.  **Get File Extension:** Extract the original file extension: `File.extname(avatar_file_name).downcase`.
4.  **Combine UUID and Extension:** Create the new filename: `#{SecureRandom.uuid}#{extension}`.
5.  **Set `file_name`:**  Set the Paperclip `file_name` attribute: `avatar.instance_write(:file_name, new_filename)`.  This is crucial to do *before* Paperclip processes the file.
6.  **Paperclip `:path` and `:url`:** Configure Paperclip's `:path` and `:url` options to use interpolation of *safe* values (like `:id`, `:style`, and a generated `:hash` using a `hash_secret`).  *Never* include user-provided data directly.  Example:
    ```ruby
    has_attached_file :avatar,
                      path: ":rails_root/public/system/:attachment/:id/:style/:hash.:extension",
                      url: "/system/:attachment/:id/:style/:hash.:extension",
                      hash_secret: "a_long_random_secret"
    ```
7. **Store Original (Sanitized):** If you need the original filename, store it in a *separate* database column (e.g., `original_file_name`) and *sanitize* it thoroughly before saving.

**List of Threats Mitigated:**
*   **Directory Traversal:** (Severity: High) - Attackers use crafted filenames (e.g., `../../etc/passwd`) to write to arbitrary locations.
*   **File Overwrite:** (Severity: High) - Attackers upload files with the same name as existing files.
*   **Cross-Site Scripting (XSS) via Filenames:** (Severity: Medium) - If filenames are displayed without escaping, they could contain malicious JavaScript.

**Impact:**
*   **Directory Traversal:** Risk eliminated. Randomized filenames prevent control over the file path.
*   **File Overwrite:** Risk significantly reduced. UUIDs ensure unique filenames.
*   **Cross-Site Scripting (XSS):** Risk reduced (if combined with proper output encoding and sanitization of the stored original filename).

**Currently Implemented:** No. The application uses the original filename.

**Missing Implementation:**
*   Add the `before_post_process` callback to all models with Paperclip attachments.
*   Update Paperclip's `:path` and `:url` options.
*   Add a new database column (`original_file_name`) and update logic to store and sanitize the original filename.

