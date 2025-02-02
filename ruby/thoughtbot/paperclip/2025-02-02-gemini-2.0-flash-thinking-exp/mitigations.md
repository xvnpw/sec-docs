# Mitigation Strategies Analysis for thoughtbot/paperclip

## Mitigation Strategy: [Strict File Type Validation](./mitigation_strategies/strict_file_type_validation.md)

**Description:**
1. Open the relevant Rails model file (e.g., `app/models/user.rb`) where you've defined your Paperclip attachment.
2. Locate the `has_attached_file` definition for the attachment (e.g., `:profile_image`).
3. Within the `has_attached_file` block, add the `content_type` validation option.
4. Use a regular expression to define the allowed content types. Be specific and avoid overly broad types like `application/*` or `image/*`. For example, to allow only JPEG and PNG images: `content_type: /\Aimage\/(jpe?g|png)\z/`.
5. Save the model file.

**List of Threats Mitigated:**
* Malicious File Upload (High Severity): Attackers upload executable files, scripts, or other malicious content disguised as allowed file types to compromise the server or other users.

**Impact:** High. Significantly reduces the risk of malicious file uploads by enforcing strict type checking based on MIME type.

**Currently Implemented:** Yes, implemented in `app/models/user.rb` for the `profile_image` attachment, allowing only `image/jpeg` and `image/png`.

**Missing Implementation:** Not yet implemented for the `document` attachment in `app/models/report.rb`, which currently accepts `application/*`.

## Mitigation Strategy: [Validate File Extensions](./mitigation_strategies/validate_file_extensions.md)

**Description:**
1. Open the same Rails model file where your Paperclip attachment is defined.
2. Below the `validates_attachment_content_type` line (if implemented), add `validates_attachment_file_name`.
3. Use the `matches` option with a regular expression or an array of allowed file extensions to whitelist permitted extensions. For example, to allow `.jpg` and `.png`: `matches: [/png\z/, /jpe?g\z/]`.
4. Save the model file.

**List of Threats Mitigated:**
* Bypassing Content Type Validation (Medium Severity): Attackers might attempt to bypass content type validation by manipulating file extensions.
* Social Engineering Attacks (Low Severity): Misleading file extensions could be used in social engineering attacks.

**Impact:** Medium. Adds a secondary layer of defense against basic file type manipulation attempts.

**Currently Implemented:** Partially implemented in `app/models/user.rb` for `profile_image`, checking for `.jpg` and `.png` extensions.

**Missing Implementation:** Missing for the `document` attachment in `app/models/report.rb`. Also, the extension validation in `app/models/user.rb` could be made more robust by ensuring case-insensitivity.

## Mitigation Strategy: [Implement Magic Number Validation (Content Sniffing Prevention)](./mitigation_strategies/implement_magic_number_validation__content_sniffing_prevention_.md)

**Description:**
1. Add the `mimemagic` gem to your `Gemfile`: `gem 'mimemagic'`. Run `bundle install`.
2. Create a custom validator (e.g., `app/validators/magic_number_validator.rb`):
   ```ruby
   class MagicNumberValidator < ActiveModel::EachValidator
     def validate_each(record, attribute, value)
       return unless value.present?

       detected_mime_type = MimeMagic.by_magic(File.open(value.queued_for_write[:original].path))&.type
       allowed_mime_types = options[:allowed_types] || []

       unless allowed_mime_types.include?(detected_mime_type)
         record.errors.add(attribute, :invalid_magic_number, message: options[:message] || "is not an allowed file type")
       end
     rescue StandardError => e # Handle potential errors during file processing
       record.errors.add(attribute, :magic_number_validation_failed, message: "could not be validated")
       Rails.logger.error("Magic Number Validation Error: #{e.message}") # Log the error for debugging
     end
   end
   ```
3. In your model, use the custom validator:
   ```ruby
   class User < ApplicationRecord
     has_attached_file :avatar
     validates_attachment :avatar, magic_number: { allowed_types: ['image/jpeg', 'image/png'] }
   end
   ```
4. Save the files.

**List of Threats Mitigated:**
* Content Type Spoofing (High Severity): Attackers bypass content type validation by crafting files with misleading MIME headers but malicious content.
* MIME Confusion Attacks (Medium Severity): Exploiting inconsistencies in MIME type detection to trigger unexpected behavior in browsers or applications.

**Impact:** High. Significantly strengthens file type validation and effectively prevents content type spoofing attacks.

**Currently Implemented:** No, magic number validation is not currently implemented in the project.

**Missing Implementation:** Missing for all Paperclip attachments across all models (`User`, `Report`, etc.). This is a critical missing security feature.

## Mitigation Strategy: [Sanitize Filenames](./mitigation_strategies/sanitize_filenames.md)

**Description:**
1. In your Paperclip configuration (e.g., `config/initializers/paperclip.rb` or within the model), customize the `filename_processing` option.
2. Use a sanitization method to remove or replace potentially harmful characters. You can use a gem like `stringex` or write custom logic. Example using `Stringex` (add `gem 'stringex'` to Gemfile and `bundle install`):
   ```ruby
   Paperclip.interpolates :sanitized_file_name do |attachment, style|
     attachment.instance.read_attribute(attachment.name).gsub(/[^a-zA-Z0-9\.\-\+_]/, '_').to_url
   end

   Paperclip::Attachment.default_options[:path] = ':rails_root/storage/:class/:attachment/:id_partition/:style/:sanitized_file_name.:extension'
   Paperclip::Attachment.default_options[:url] = '/storage/:class/:attachment/:id_partition/:style/:sanitized_file_name.:extension'
   ```
3. Alternatively, within your model, you can override the `assign_attributes` method to sanitize the filename before Paperclip processes it.
4. Save the configuration/model file.

**List of Threats Mitigated:**
* Path Traversal Vulnerabilities (Medium Severity): Malicious filenames containing path traversal sequences (`../`) could be used to access or overwrite files outside the intended storage directory.
* File System Command Injection (Low Severity): In rare cases, unsanitized filenames could be exploited for command injection if filenames are used in shell commands.
* Cross-Site Scripting (XSS) via Filenames (Low Severity):  Unsanitized filenames displayed in the UI could potentially lead to XSS if not properly handled during output encoding.

**Impact:** Medium. Reduces the risk of path traversal and other filename-related vulnerabilities.

**Currently Implemented:** No, filename sanitization is not explicitly implemented. Paperclip's default handling provides some basic safety, but explicit sanitization is missing.

**Missing Implementation:** Missing globally for all Paperclip attachments. Should be implemented in `config/initializers/paperclip.rb` or a similar configuration file to apply to all attachments.

## Mitigation Strategy: [Store Uploaded Files Outside of the Web Root](./mitigation_strategies/store_uploaded_files_outside_of_the_web_root.md)

**Description:**
1. In your Paperclip configuration (e.g., `config/initializers/paperclip.rb` or within the model), modify the `path` option.
2. Ensure the `path` points to a directory *outside* of your `public/` directory. A common practice is to use a `storage/` directory at the application root. Example:
   ```ruby
   Paperclip::Attachment.default_options[:path] = ':rails_root/storage/:class/:attachment/:id_partition/:style/:filename'
   Paperclip::Attachment.default_options[:url] = '/download/:class/:attachment/:id/:style/:filename' # Define a download URL pattern
   ```
3. Adjust your web server configuration (e.g., Nginx, Apache) to prevent direct access to the `storage/` directory.
4. Save the configuration file.

**List of Threats Mitigated:**
* Direct File Access (High Severity): Attackers directly access uploaded files by guessing or knowing their paths if stored within the web root. This can expose sensitive data or allow execution of malicious files.

**Impact:** High. Prevents direct web access to uploaded files, forcing access through application-controlled mechanisms.

**Currently Implemented:** No, currently files are stored in `public/system/`, which is within the web root and directly accessible.

**Missing Implementation:** Needs to be implemented globally by changing the default `path` in `config/initializers/paperclip.rb` and adjusting web server configuration.

## Mitigation Strategy: [Utilize Private Cloud Storage (If Applicable)](./mitigation_strategies/utilize_private_cloud_storage__if_applicable_.md)

**Description:**
1. If using cloud storage (AWS S3, Google Cloud Storage, Azure Blob Storage) with Paperclip, ensure your cloud storage bucket/container is configured for *private* access by default.
2. Configure Paperclip to generate signed URLs (pre-signed URLs) for accessing files. Paperclip can be configured to do this using the `s3_server_side_encryption`, `s3_url_options`, etc., options for S3, and similar options for other cloud providers.
3. Generate signed URLs in your controller actions when serving files for download. These URLs provide temporary, controlled access.
4. Example Paperclip configuration for S3 with signed URLs:
   ```ruby
   Paperclip::Attachment.default_options.merge!({
     storage: :s3,
     s3_credentials: {
       bucket: ENV['S3_BUCKET_NAME'],
       access_key_id: ENV['AWS_ACCESS_KEY_ID'],
       secret_access_key: ENV['AWS_SECRET_ACCESS_KEY'],
       region: ENV['AWS_REGION']
     },
     s3_url_options: { expires_in: 3600, use_ssl: true }, # Signed URL options, expires in 1 hour
     url: ':s3_domain_url',
     path: '/:class/:attachment/:id_partition/:style/:filename',
     s3_server_side_encryption: :aes256
   })
   ```
5. In your download controller action, generate the signed URL and redirect to it:
   ```ruby
   def download_document
     # ... (authentication and authorization checks) ...
     if @report.document.present?
       redirect_to @report.document.expiring_url(3600) # Generate signed URL with 1-hour expiry
     else
       # ...
     end
   end
   ```

**List of Threats Mitigated:**
* Publicly Accessible Files in Cloud Storage (High Severity): If cloud storage buckets are misconfigured as public, anyone can access uploaded files directly, leading to data breaches.
* Unauthorized Access to Cloud Storage (High Severity): Even with private buckets, misconfigured access policies or leaked credentials can lead to unauthorized access.

**Impact:** High. Leverages cloud provider security features and ensures files are not publicly accessible by default, providing controlled access through signed URLs.

**Currently Implemented:** Partially implemented. Cloud storage (AWS S3) is used, but buckets might not be strictly private, and signed URLs are not consistently used for all file access.

**Missing Implementation:** Needs to ensure all S3 buckets are private and consistently use signed URLs for all file downloads from S3. Review S3 bucket policies and Paperclip configuration.

## Mitigation Strategy: [Limit Image Processing Options](./mitigation_strategies/limit_image_processing_options.md)

**Description:**
1. Define a fixed set of image styles in your Paperclip configuration (e.g., in the `styles` option of `has_attached_file`).
2. Avoid allowing users to dynamically specify image processing parameters through user input or URL parameters.
3. If dynamic processing is absolutely necessary, carefully validate and sanitize any user-provided parameters before passing them to ImageMagick. Use whitelisting of allowed options and values.
4. Example of fixed styles:
   ```ruby
   has_attached_file :avatar, styles: { thumb: "100x100#", small: "200x200>", medium: "300x300>" }
   ```

**List of Threats Mitigated:**
* Command Injection via Image Processing (Medium Severity): Prevents attackers from injecting malicious commands into image processing operations if user input is directly used in processing commands.
* Denial of Service (DoS) via Resource Exhaustion (Medium Severity): Attackers could potentially craft requests that cause excessive resource consumption during image processing if processing options are not limited.

**Impact:** Medium. Reduces the risk of command injection and DoS attacks related to image processing by limiting user control over processing options.

**Currently Implemented:** Partially implemented. Styles are predefined in models, but there might be areas where dynamic processing or user-controlled parameters are unintentionally used.

**Missing Implementation:** Review all Paperclip usage to ensure dynamic image processing options are not being used or are properly validated and sanitized if absolutely necessary. Enforce fixed styles consistently.

