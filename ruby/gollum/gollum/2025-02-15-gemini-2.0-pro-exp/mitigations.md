# Mitigation Strategies Analysis for gollum/gollum

## Mitigation Strategy: [Secure Markup Rendering (Gollum-Specific)](./mitigation_strategies/secure_markup_rendering__gollum-specific_.md)

*   **Description:**
    1.  **Update Gollum and Dependencies:** Regularly update Gollum itself and its rendering dependencies (like `github-markup`, `kramdown`, etc.) using `bundle update`.  This ensures you have the latest security patches for these libraries.  Monitor for security advisories related to these gems.
    2.  **Configure Renderer (Gollum Config):** In Gollum's configuration file (e.g., `config.rb` or via command-line options), *explicitly* configure the Markdown renderer (and any other markup renderers you use) to disable unsafe features.  For example, with `kramdown`:
        ```ruby
        Gollum::Markup.formats[:markdown] = {
          :renderer => :kramdown,
          :options => { :input => 'GFM', :hard_wrap => false, :auto_ids => true, :parse_block_html => false, :parse_span_html => false, :html_to_native => false }
        }
        ```
        Crucially, set `parse_block_html` and `parse_span_html` to `false` to disable raw HTML parsing.  If using other renderers, find their equivalent settings to disable unsafe features.
    3.  **HTML Sanitization (Gollum Config + Custom Code):** If *any* possibility of raw HTML input exists (even indirectly through Markdown extensions), configure Gollum to use a robust HTML sanitizer.  `bleach` is a strong option.  This requires adding code to your Gollum setup:
        ```ruby
        require 'bleach'
        Gollum::Filter::Sanitize.sanitize_options = {
          :elements => ['a', 'p', 'code', 'pre', 'img', 'ul', 'ol', 'li', 'strong', 'em', 'br', 'table', 'thead', 'tbody', 'tr', 'th', 'td'], # Allowed tags
          :attributes => {
            'a' => ['href'],
            'img' => ['src', 'alt'],
            :all => ['class', 'id'] # Allowed attributes
          },
          :protocols => {
            'a' => {'href' => ['http', 'https', 'mailto', '#']} # Allowed protocols
          }
        }
        ```
        This example allows *only* a very restricted set of HTML.  Adjust this whitelist *very carefully* based on your needs.  This is *essential* if you cannot completely disable raw HTML parsing.
    4. **Input Validation (Limited - Gollum Code):** While the primary defense is secure rendering, perform *basic* input validation on page titles and filenames within your Gollum code (if you have custom extensions or modifications).  Focus on preventing obviously malicious patterns like `<script>`.  This is a supplementary measure, *not* a replacement for proper sanitization.

*   **Threats Mitigated:**
    *   **Cross-Site Scripting (XSS) (Severity: High):** Prevents attackers from injecting malicious JavaScript.
    *   **HTML Injection (Severity: High):** Prevents injection of arbitrary HTML.

*   **Impact:**
    *   **XSS:** Risk significantly reduced with secure renderer configuration and HTML sanitization.
    *   **HTML Injection:** Risk significantly reduced with HTML sanitization.

*   **Currently Implemented:**
    *   Dependency Updates: **Partially Implemented** (periodic updates, not automated).
    *   Renderer Configuration: **Implemented** (`kramdown` with safe options).
    *   HTML Sanitization: **Not Implemented**.
    *   Input Validation: **Implemented** (basic sanitization of page titles).

*   **Missing Implementation:**
    *   Automated dependency updates.
    *   Implementation of HTML sanitization using `bleach` (or similar). *Critical* missing piece.

## Mitigation Strategy: [Secure File Uploads (Gollum-Specific)](./mitigation_strategies/secure_file_uploads__gollum-specific_.md)

*   **Description:**
    1.  **Whitelist Allowed Extensions (Gollum Config):** In Gollum's configuration, *strictly* define a whitelist of allowed file extensions:
        ```ruby
        Gollum::Page.file_extensions = %w(jpg jpeg png gif pdf txt docx)
        ```
        *Never* include executable extensions.
    2.  **Validate File Content (Magic Bytes - Gollum Code):** Integrate file content validation (using magic bytes) into Gollum's file upload handling logic.  This requires adding Ruby code:
        ```ruby
        require 'filemagic'

        def valid_file?(file_path)
          fm = FileMagic.new(:mime)
          mime_type = fm.file(file_path)
          allowed_mime_types = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain', ...] # Define allowed MIME types
          allowed_mime_types.include?(mime_type)
        end
        ```
        This code checks the *actual* file content, not just the extension.  You'll need to modify Gollum's code to call this `valid_file?` function *before* accepting and saving any uploaded file.
    3.  **Rename Uploaded Files (Gollum Code):** Modify Gollum's file upload handling to generate a random, unique filename for each uploaded file.  Use a UUID or a combination of a timestamp and random string:
        ```ruby
        require 'securerandom'

        def generate_unique_filename(original_filename)
          extension = File.extname(original_filename)
          "#{SecureRandom.uuid}#{extension}"
        end
        ```
        Call this function to generate the new filename *before* saving the file.  Store the original filename in metadata if needed.
    4.  **Limit File Size (Gollum Config/Code):** While you can set limits at the web server level, you can also add a check within Gollum's code to reject files exceeding a certain size *before* they are fully uploaded. This can provide earlier feedback and potentially reduce resource consumption.
    5.  **Sanitize Original Filenames (Gollum Code):** Even with renaming, sanitize the *original* filename to remove potentially dangerous characters:
        ```ruby
        def sanitize_filename(filename)
          filename.gsub(/[^a-zA-Z0-9_\.\-]/, '_')
        end
        ```
        Call this function *before* storing the original filename in metadata.

*   **Threats Mitigated:**
    *   **Malicious File Upload (Severity: Critical):** Prevents upload and execution of malicious files.
    *   **Path Traversal (Severity: High):** Prevents crafted filenames from overwriting or accessing files outside the upload directory.
    *   **Denial of Service (DoS) via Large Files (Severity: Medium):** Prevents excessively large file uploads.

*   **Impact:**
    *   **Malicious File Upload:** Risk greatly reduced with all steps implemented.
    *   **Path Traversal:** Risk significantly reduced.
    *   **DoS via Large Files:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Whitelist Allowed Extensions: **Implemented** (in `config.rb`).
    *   Validate File Content (Magic Bytes): **Not Implemented**.
    *   Rename Uploaded Files: **Implemented**.
    *   Limit File Size: **Partially Implemented** (some checks in code, but primarily relies on web server).
    *   Sanitize Original Filenames: **Implemented**.

*   **Missing Implementation:**
    *   Implementation of file content validation using magic bytes. *Critical* missing piece.
    *   More robust file size checks within Gollum's code.

## Mitigation Strategy: [Authorization (Custom Gollum Code/Middleware)](./mitigation_strategies/authorization__custom_gollum_codemiddleware_.md)

*   **Description:**
    1.  **Implement Authorization Logic:** Since Gollum lacks built-in fine-grained authorization, you *must* implement this yourself, typically as a Rack middleware. This middleware will intercept requests and, based on the authenticated user and the requested resource (page, action), determine whether to allow or deny access.
        ```ruby
        # (Conceptual example - in a Rack middleware)
        class GollumAuthorization
          def initialize(app)
            @app = app
          end

          def call(env)
            user = get_user(env) # Get user from authentication (e.g., session)
            path = env['PATH_INFO'] # Get requested page path

            if user && user_has_permission?(user, path)
              @app.call(env)
            else
              [403, { 'Content-Type' => 'text/plain' }, ['Forbidden']]
            end
          end

          # ... (Implement get_user and user_has_permission? methods)
          # user_has_permission? would check against a database, config file, etc.
        end
        ```
        This is a simplified example.  You'll need to define how user roles/permissions are stored and how `user_has_permission?` checks them.  This is a significant development effort.
    2. **Integrate with Authentication:** This middleware must integrate with your chosen authentication system (basic auth, OAuth, etc.) to retrieve the authenticated user's identity and roles.

*   **Threats Mitigated:**
    *   **Unauthorized Access (Severity: High):** Prevents unauthorized users from performing actions they shouldn't (e.g., editing specific pages).
    *   **Lack of Accountability (Severity: Medium):** Ensures actions are tied to specific, authorized users.

*   **Impact:**
    *   **Unauthorized Access:** Risk significantly reduced with proper authorization.
    *   **Lack of Accountability:** Risk significantly reduced.

*   **Currently Implemented:**
    *   Authorization: **Not Implemented** (no fine-grained access control).

*   **Missing Implementation:**
    *   Complete implementation of authorization logic (Rack middleware or equivalent). This is a *major* missing component if fine-grained access control is required.

## Mitigation Strategy: [Keep Gollum and Dependencies Updated](./mitigation_strategies/keep_gollum_and_dependencies_updated.md)

*   **Description:**
    1.  **Monitor for Updates:** Regularly check the Gollum GitHub repository ([https://github.com/gollum/gollum](https://github.com/gollum/gollum)) for new releases and security advisories. Subscribe to notifications or use a service that tracks releases.
    2.  **Update Gollum:** When a new version of Gollum is released, update your installation promptly. Follow the official upgrade instructions.
    3.  **Update Dependencies:** Use `bundle update` regularly to update Gollum's dependencies (gems). This will install the latest compatible versions of all required libraries.
    4. **Automate (Optional):** Consider automating the update process using a script or a tool like Dependabot (for GitHub repositories). However, always test updates in a staging environment before deploying to production.

*   **Threats Mitigated:**
    *   **Exploitation of Known Vulnerabilities (Severity: Variable, can be Critical):** Prevents attackers from exploiting known vulnerabilities in Gollum or its dependencies.

*   **Impact:**
    *   **Exploitation of Known Vulnerabilities:** Risk significantly reduced by keeping software up-to-date.

*   **Currently Implemented:**
    *   Manual Updates: **Partially Implemented** (updates are performed periodically, but not consistently).

*   **Missing Implementation:**
    *   Consistent and timely updates.
    *   Automated update checks and notifications.

