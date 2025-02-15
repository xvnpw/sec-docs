# Mitigation Strategies Analysis for carrierwaveuploader/carrierwave

## Mitigation Strategy: [Strict File Type Whitelisting (CarrierWave API)](./mitigation_strategies/strict_file_type_whitelisting__carrierwave_api_.md)

*   **Description:**
    1.  **`extension_allowlist`:** In your CarrierWave uploader class (e.g., `app/uploaders/my_uploader.rb`), define the `extension_allowlist` method. This method should return an array of *lowercase* file extensions that are permitted.  This is CarrierWave's primary mechanism for extension-based filtering.
        ```ruby
        def extension_allowlist
          %w(jpg jpeg gif png pdf doc docx) # Example: Only these are allowed
        end
        ```
    2.  **`content_type_allowlist`:** Define the `content_type_allowlist` method. This method should return an array of allowed MIME types.  CarrierWave uses this to check the *declared* content type.
        ```ruby
        def content_type_allowlist
          [/image\//, 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
        end
        ```
    3.  **Integrate MIME Type Validation (using `Marcel`):** While `content_type_allowlist` checks the *declared* type, you should use a library like `Marcel` to check the *actual* content.  This is done via a `before :cache` callback, but it *integrates* with CarrierWave's processing pipeline.
        ```ruby
        before :cache, :validate_mime_type

        def validate_mime_type(file)
          detected_type = Marcel::MimeType.for Pathname.new(file.path)
          unless content_type_allowlist.any? { |type| type === detected_type }
            raise CarrierWave::IntegrityError, "Invalid file type: #{detected_type}"
          end
        end
        ```
    4. **Reject Files with No Extension:** Add a check within your uploader, potentially within `validate_mime_type` or as a separate validation, to reject files that lack an extension. This leverages CarrierWave's validation system.

*   **Threats Mitigated:**
    *   Remote Code Execution (RCE) (Critical)
    *   Cross-Site Scripting (XSS) (High)
    *   Bypassing Security Controls (High)
    *   Data Leakage (Medium)

*   **Impact:**
    *   RCE: Risk significantly reduced.
    *   XSS: Risk reduced (in conjunction with filename sanitization).
    *   Bypassing Security Controls: Risk significantly reduced.
    *   Data Leakage: Risk moderately reduced.

*   **Currently Implemented:**
    *   `extension_allowlist` in `ImageUploader` and `DocumentUploader`.
    *   `content_type_allowlist` and `Marcel` integration in `ImageUploader`.

*   **Missing Implementation:**
    *   `content_type_allowlist` and `Marcel` integration missing in `DocumentUploader`.
    *   Explicit rejection of files with no extension missing in all uploaders.

## Mitigation Strategy: [Filename Sanitization and Randomization (CarrierWave API)](./mitigation_strategies/filename_sanitization_and_randomization__carrierwave_api_.md)

*   **Description:**
    1.  **`filename` Method:** Override the `filename` method in your CarrierWave uploader.  This is *the* core CarrierWave mechanism for controlling filenames.  Generate a unique, random filename using `SecureRandom.uuid`.
        ```ruby
        def filename
          "#{SecureRandom.uuid}.#{file.extension}" if original_filename.present?
        end
        ```
    2.  **`store_dir` Method:** Review and ensure your `store_dir` method does *not* use any user-supplied input.  This is a CarrierWave method that controls the storage location.
        ```ruby
        def store_dir
          "uploads/#{model.class.to_s.underscore}/#{mounted_as}/#{model.id}"
        end
        ```
    3. **Sanitize Original Filename (if used):** If you *display* the original filename, sanitize it. While this isn't *directly* a CarrierWave API call, it's crucial in the context of using CarrierWave. Use a dedicated library or CarrierWave's `sanitize_regexp` (with caution).

*   **Threats Mitigated:**
    *   Directory Traversal (Critical)
    *   Cross-Site Scripting (XSS) (High)
    *   File Overwriting (High)
    *   Information Disclosure (Medium)

*   **Impact:**
    *   Directory Traversal: Risk almost eliminated.
    *   XSS: Risk significantly reduced.
    *   File Overwriting: Risk almost eliminated.
    *   Information Disclosure: Risk moderately reduced.

*   **Currently Implemented:**
    *   `filename` randomization in all uploaders.
    *   `store_dir` correctly configured in all uploaders.

*   **Missing Implementation:**
    *   Consistent, robust sanitization of the *original* filename (for display) is missing.

## Mitigation Strategy: [Image Processing Control (CarrierWave API)](./mitigation_strategies/image_processing_control__carrierwave_api_.md)

*   **Description:**
    1.  **Limit `version` Definitions:** Within your uploader, define only the *necessary* image processing `version` blocks.  Each `version` represents a potential processing pathway.  Minimize these.
        ```ruby
        version :thumb do
          process resize_to_fit: [50, 50] # Only a thumbnail is needed
        end
        ```
    2.  **Restrict `process` Calls:** Within each `version`, use only the *essential* `process` calls (e.g., `resize_to_fit`, `resize_to_fill`).  Avoid complex or unnecessary transformations.  This directly controls which MiniMagick/ImageMagick commands are executed.
    3.  **Dimension Validation (using `before :cache`):** Use a `before :cache` callback to validate image dimensions *before* CarrierWave sends the image to MiniMagick/ImageMagick. This integrates with CarrierWave's processing.
        ```ruby
        before :cache, :validate_image_dimensions

        def validate_image_dimensions(file)
          image = MiniMagick::Image.open(file.path)
          if image[:width] > 8000 || image[:height] > 8000
            raise CarrierWave::IntegrityError, "Image dimensions are too large"
          end
        end
        ```

*   **Threats Mitigated:**
    *   ImageTragick and Similar Exploits (Critical)
    *   Denial of Service (DoS) (High)
    *   Resource Exhaustion (Medium)

*   **Impact:**
    *   ImageTragick: Risk reduced (effectiveness depends on limiting operations and external library updates).
    *   DoS: Risk significantly reduced.
    *   Resource Exhaustion: Risk moderately reduced.

*   **Currently Implemented:**
    *   Basic dimension validation in `ImageUploader`.

*   **Missing Implementation:**
    *   More granular control and restriction of `version` and `process` calls could be improved.  A review of the *necessity* of each processing step is needed.

## Mitigation Strategy: [Secure Remote File Downloads (CarrierWave API)](./mitigation_strategies/secure_remote_file_downloads__carrierwave_api_.md)

*   **Description:**
    1.  **`download_whitelist`:** If using `CarrierWave::Downloader`, define the `download_whitelist` method in your uploader.  This is CarrierWave's *direct* mechanism for controlling allowed download sources.  Return an array of *fully qualified* domain names (including protocol).
        ```ruby
        def download_whitelist
          ['https://example.com', 'https://cdn.example.com']
        end
        ```
    2. **URL Validation (Integrate with CarrierWave):** While not a direct CarrierWave method, you should validate the URL *before* passing it to CarrierWave. This can be done in a `before :cache` callback or a custom validation.

*   **Threats Mitigated:**
    *   Server-Side Request Forgery (SSRF) (Critical)
    *   Denial of Service (DoS) (High)
    *   Data Exfiltration (High)

*   **Impact:**
    *   SSRF: Risk significantly reduced (almost eliminated with a strict whitelist).
    *   DoS: Risk significantly reduced.
    *   Data Exfiltration: Risk significantly reduced.

*   **Currently Implemented:**
    *   Remote file downloads are *not* currently used.

*   **Missing Implementation:**
    *   N/A (not used).  If implemented, `download_whitelist` is *essential*.

