### Combined Vulnerability Report

#### Webpack Stats File Injection leading to Cross-Site Scripting (XSS)

* Description:
    1. The `django-webpack-loader` library reads a `webpack-stats.json` file, typically generated by `webpack-bundle-tracker`, to render HTML tags for webpack bundles in Django templates.
    2. This library directly uses values from the `webpack-stats.json` file, such as asset paths, `publicPath`, `integrity` attributes, and chunk names, when constructing HTML tags.
    3. If an attacker can control the content of the `webpack-stats.json` file, they can inject malicious payloads into these values. This control can be achieved in several ways:
        * **Direct File System Access:** Gaining write access to the server's filesystem where the `webpack-stats.json` file is stored and directly modifying its content. This could be due to misconfigured file permissions or exploiting other vulnerabilities in the deployment environment.
        * **Compromised Build Process:**  Influencing the Webpack build process to inject malicious content into the generated `webpack-stats.json` file. For example, modifying the Webpack configuration to set a malicious `publicPath` or inject payloads into asset names or integrity values.
        * **Untrusted External Source:** In configurations using a custom loader (via `LOADER_CLASS`), the stats file might be loaded from an external and potentially untrusted URL, allowing an attacker to control the returned data.
    4. When a Django template uses template tags like `{% render_bundle %}` or `{% get_files %}`, the `django-webpack-loader` library parses the potentially malicious `webpack-stats.json` file.
    5. The library extracts the injected malicious values and uses them to build HTML `<script>` or `<link>` tags. For example, a malicious `publicPath` or an `integrity` attribute containing JavaScript code can be inserted directly into the HTML tag.
    6. The generated HTML output is marked as safe using `mark_safe` in the template tag, bypassing Django's autoescaping mechanisms.
    7. When a user accesses a webpage containing the rendered webpack bundles, their browser executes the injected malicious JavaScript code, leading to Cross-Site Scripting (XSS).

* Impact:
    * **Remote Code Execution (XSS):** Successful exploitation allows an attacker to execute arbitrary JavaScript code within the context of a user's browser when they visit a page rendering webpack assets.
    * **Session Hijacking:** Stealing user session cookies to gain unauthorized access to user accounts.
    * **Data Theft:** Accessing sensitive information displayed on the page or making API requests on behalf of the user, potentially exfiltrating user data.
    * **Website Defacement:** Modifying the visual content of the webpage presented to the user.
    * **Redirection to Malicious Sites:** Redirecting users to phishing websites or sites hosting malware, leading to further compromise.
    * **Further Exploitation:** Using the XSS vulnerability as a stepping stone to further compromise the application, the server, or the user's system.

* Vulnerability Rank: critical

* Currently implemented mitigations:
    * None. The `django-webpack-loader` library does not implement any explicit input validation, sanitization, or integrity checks on the `webpack-stats.json` file content.
    * **Implicit Assumption of Trusted Source:** The default configuration implicitly assumes that the `webpack-stats.json` file is generated by a trusted build process and stored locally with restricted file system permissions. However, this is not a robust mitigation against injection vulnerabilities if an attacker can compromise these assumptions.
    * **JSON Parsing:** The library uses `json.load()` to parse the stats file, which enforces JSON syntax but does not validate the semantic content or prevent malicious payloads within valid JSON structures.

* Missing mitigations:
    * **Stats File Integrity Verification:** Implement a mechanism to ensure the integrity and authenticity of the `webpack-stats.json` file.
        * **Digital Signatures:** Generate a digital signature for the `webpack-stats.json` file during the webpack build process and verify this signature before loading the file in the Django application.
        * **Hash Verification:** Calculate a cryptographic hash of the `webpack-stats.json` file during build time and store it securely. Upon loading the stats file, recalculate the hash and compare it to the stored hash.
    * **Input Validation and Sanitization:**  Thoroughly validate and sanitize all data read from the `webpack-stats.json` file before using it to construct HTML. This includes:
        * **URL Validation:** Validate that URLs (especially `publicPath`) are within expected domains and schemes, and sanitize them to prevent injection of malicious JavaScript.
        * **Attribute Encoding/Escaping:** Properly encode or escape attribute values like `integrity`, chunk names, and asset paths before embedding them in HTML attributes to prevent attribute injection and XSS.
        * **Schema Validation:** Implement schema validation to ensure the `webpack-stats.json` file conforms to a strict expected structure and data types, rejecting any unexpected or malicious content.
    * **Restrict File System Permissions:** Ensure that the `webpack-stats.json` file is stored in a location with appropriately restrictive file system permissions. The file should not be placed in a publicly writable directory and should only be accessible for reading by the application process.
    * **Defensive Coding for Custom Loaders:** When using custom loaders that fetch stats data from external sources, implement robust security checks and validation to prevent injection from untrusted sources.

* Preconditions:
    * The application must use `django-webpack-loader` to render webpack bundles in Django templates.
    * An attacker needs to be able to influence the content of the `webpack-stats.json` file. This can be achieved by:
        * Gaining write access to the file system where `webpack-stats.json` is stored.
        * Compromising the Webpack build process to inject malicious data into the stats file.
        * Configuring `django-webpack-loader` to load the stats file from an untrusted external source (using a custom loader).

* Source code analysis:
    * **`webpack_loader/loaders.py` - `WebpackLoader.load_assets()`:**
    ```python
    def load_assets(self):
        try:
            with open(self.config["STATS_FILE"], encoding="utf-8") as f:
                return json.load(f) # Vulnerability: json.load parses the file without content validation
        except IOError:
            raise IOError(
                "Error reading {0}. Are you sure webpack has generated "
                "the file and the path is correct?".format(self.config["STATS_FILE"])
            )
    ```
        * The `load_assets` function reads the `STATS_FILE` and directly parses it using `json.load()`, without any content validation.

    * **`webpack_loader/loaders.py` - `WebpackLoader.get_integrity_attr()`:**
    ```python
    def get_integrity_attr(self, chunk):
        if not self.config.get("INTEGRITY"):
            return " "
        integrity = chunk.get("integrity")
        if not integrity:
            raise WebpackLoaderBadStatsError("...")
        return ' integrity="{}" '.format(integrity.partition(" ")[0]) # Vulnerability: Unsanitized integrity value used directly
    ```
        * The `get_integrity_attr` function retrieves the `integrity` value from the stats file and directly formats it into an HTML attribute string without sanitization.

    * **`webpack_loader/utils.py` - `get_chunk_url()`:**
    ```python
    def get_chunk_url(chunk_file):
        public_path = chunk_file.get("publicPath")
        if public_path and public_path != "auto":
            return public_path # Vulnerability: Unsanitized publicPath returned directly

        # ... staticfiles_storage.url
    ```
        * The `get_chunk_url` function directly returns the `publicPath` from the stats file without sanitization if it's present and not "auto".

    * **`webpack_loader/utils.py` - `get_as_url_to_tag_dict()`:**
    ```python
    def get_as_url_to_tag_dict(bundle_name, extension=None, config='DEFAULT', suffix='', attrs='', is_preload=False):
        # ...
        for chunk in bundle:
            if chunk['name'].endswith(('.js', '.js.gz')):
                result[chunk['url']] = (
                    '<script src="{0}"{2}{1}></script>' # Vulnerability: chunk['url'] (potentially from unsanitized publicPath) used directly in HTML
                ).format(
                    ''.join([chunk['url'], suffix]),
                    attrs,
                    loader.get_integrity_attr(chunk), # Vulnerability: Unsanitized integrity attribute
                )
            elif chunk['name'].endswith(('.css', '.css.gz')):
                result[chunk['url']] = (
                    '<link href="{0}" rel={2}{3}{1}/>' # Vulnerability: chunk['url'] (potentially from unsanitized publicPath) used directly in HTML
                ).format(
                    ''.join([chunk['url'], suffix]),
                    attrs,
                    '"stylesheet"' if not is_preload else '"preload" as="style"',
                    loader.get_integrity_attr(chunk), # Vulnerability: Unsanitized integrity attribute
                )
        return result
    ```
        * The `get_as_url_to_tag_dict` function constructs HTML `<script>` and `<link>` tags by directly embedding potentially unsanitized `chunk['url']` (derived from `publicPath`) and the unsanitized integrity attribute.

    * **`webpack_loader/templatetags/webpack_loader.py`:**
        * The `render_bundle` and `get_files` template tags use the utility functions from `webpack_loader/utils.py` and mark the generated HTML as safe using `mark_safe`, thus bypassing Django's autoescaping.

    * **Visualization:**
    ```mermaid
    graph LR
        A[webpack-stats.json] --> B(WebpackLoader.get_assets)
        B --> C(utils.get_chunk_url)
        C --> D{Return publicPath from stats?}
        D -- Yes --> E[Return publicPath directly]
        D -- No --> F[Return staticfiles_storage.url]
        E --> G(utils.get_as_url_to_tag_dict)
        F --> G
        G --> H(Template Tags: render_bundle, get_files)
        H --> I[HTML Output with potentially malicious injected content]
    ```

* Security test case:
    1. **Setup:**
        * Deploy a Django application using `django-webpack-loader` in a test environment.
        * Configure `django-webpack-loader` with a default configuration and ensure webpack builds assets and generates `webpack-stats.json`.
        * Verify that the application correctly serves JavaScript bundles using the `render_bundle` template tag.
    2. **Craft Malicious Webpack Config:**
        * Modify the `webpack.config.js` file to set a malicious `publicPath`.
        ```javascript
        // webpack.config.js
        const path = require("path");
        const webpack = require("webpack");
        const BundleTracker = require("webpack-bundle-tracker");

        module.exports = {
          context: __dirname,
          entry: "./assets/js/index",
          output: {
            path: path.resolve(__dirname, "assets/webpack_bundles/"),
            publicPath: "<script>alert('XSS Vulnerability!')</script>", // Malicious publicPath
            filename: "[name]-[contenthash].js",
          },
          plugins: [
            new BundleTracker({ path: __dirname, filename: "webpack-stats.json" }),
          ],
        };
        ```
    3. **Run Webpack:**
        * Execute Webpack to regenerate the `webpack-stats.json` file with the malicious `publicPath`: `npx webpack --mode=development`
    4. **Start Django Application:**
        * Start the Django development server: `python manage.py runserver`
    5. **Access Vulnerable Page:**
        * Open a web browser and navigate to a page in the Django application that uses the `{% render_bundle 'main' %}` template tag.
    6. **Verify XSS:**
        * Observe that an alert box with the message 'XSS Vulnerability!' is displayed in the browser. This confirms that the malicious JavaScript code injected through `publicPath` in `webpack-stats.json` was executed, demonstrating the Stats File Content Injection vulnerability leading to Cross-Site Scripting.