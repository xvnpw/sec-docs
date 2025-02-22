### Vulnerability List

*   Path Traversal Vulnerability in CSS URL Rewriting

#### Vulnerability Name
Path Traversal Vulnerability in CSS URL Rewriting

#### Description
The `CssAbsoluteFilter` and `CssRelativeFilter` classes in `compressor/filters/css_default.py` are responsible for rewriting URLs within CSS files to make them absolute or relative to the compressed output file's location. The `guess_filename` method within `CssAbsoluteFilter` constructs a file path by joining `settings.COMPRESS_ROOT` with a `local_path` derived from the URL found in the CSS. This `local_path` is not properly sanitized to prevent path traversal attacks. An attacker could craft a CSS file containing URLs with directory traversal sequences (e.g., `../`) that, after processing by `CssAbsoluteFilter` or `CssRelativeFilter`, could lead to accessing files outside of the intended `COMPRESS_ROOT` directory on the server's filesystem when the application attempts to check the existence of these files or generate hashed URLs for them.

**Step-by-step trigger:**
1.  An attacker crafts a malicious CSS file. This CSS file contains a URL that includes directory traversal sequences, for example: `url('../../../sensitive/file.txt')`.
2.  The attacker includes this malicious CSS file in a Django template within a `{% compress css %}` block.
3.  When the Django template is rendered and the `compress` template tag is processed, the `CssAbsoluteFilter` or `CssRelativeFilter` is applied to the CSS content.
4.  The `guess_filename` method in `CssAbsoluteFilter` (or similar logic in `CssRelativeFilter`) processes the malicious URL. Due to insufficient sanitization, the directory traversal sequence `../../../` is not removed or neutralized.
5.  The `os.path.join(self.root, local_path.lstrip("/"))` in `guess_filename` constructs a file path that, due to the traversal sequences, points to a location outside of `COMPRESS_ROOT`, potentially accessing sensitive files.
6.  While the vulnerability is in path construction, the immediate impact is during file existence checks (`os.path.exists`) and hash generation (`get_hashed_mtime`, `get_hashed_content`) within the filters.  It could potentially lead to information disclosure if error messages reveal information about the file system structure or existence of files outside `COMPRESS_ROOT`.

#### Impact
High. Although direct file reading by an external attacker through this vulnerability is not immediately evident in the provided code, it represents a **Path Traversal** vulnerability that could be leveraged in combination with other vulnerabilities or misconfigurations to gain unauthorized access to the server's filesystem.  At the very least, it could lead to information disclosure if error messages expose file existence or path information outside of the intended static file directories. In more complex scenarios or with custom filters or precompilers, this could potentially be chained to more severe exploits.

#### Vulnerability Rank
High

#### Currently Implemented Mitigations
None in the provided code. The `guess_filename` method does not sanitize or validate the `local_path` to prevent directory traversal.

#### Missing Mitigations
Input sanitization for URLs in `CssAbsoluteFilter` and `CssRelativeFilter` within the `guess_filename` method (and potentially in `_converter` method as well, as it calls `guess_filename`). This should include:
-   Validation of the `local_path` to ensure it does not contain directory traversal sequences like `../` or similar.
-   Using secure path manipulation functions that prevent traversal, or explicitly resolving and checking if the resulting path stays within the allowed `COMPRESS_ROOT`.

#### Preconditions
1.  `COMPRESS_ENABLED` setting is True (or template rendering is done in a context where compression is active).
2.  `CssAbsoluteFilter` or `CssRelativeFilter` is enabled in `COMPRESS_FILTERS['css']` (which is the default configuration).
3.  The application uses the `{% compress css %}` template tag to process CSS content that could potentially contain crafted URLs.

#### Source Code Analysis
```python
File: /code/compressor/filters/css_default.py

    def guess_filename(self, url):
        local_path = url
        if self.has_scheme:
            # COMPRESS_URL had a protocol,
            # remove it and the hostname from our path.
            local_path = local_path.replace(self.protocol + self.host, "", 1)
        # remove url fragment, if any
        local_path = local_path.rsplit("#", 1)[0]
        # remove querystring, if any
        local_path = local_path.rsplit("?", 1)[0]
        # Now, we just need to check if we can find
        # the path from COMPRESS_URL in our url
        if local_path.startswith(self.url_path):
            local_path = local_path.replace(self.url_path, "", 1)
        # Re-build the local full path by adding root
        filename = os.path.join(self.root, local_path.lstrip("/")) # Vulnerable line
        return os.path.exists(filename) and filename
```
**Code Walkthrough:**
1.  The `guess_filename` method is called by `_converter` which is used by `url_converter` and `src_converter` to process URLs found in CSS content.
2.  `local_path` is initialized with the `url` extracted from the CSS.
3.  The code performs some URL cleaning like removing protocol, hostname, fragment, and querystring. It also removes `self.url_path` prefix if present.
4.  Critically, `os.path.join(self.root, local_path.lstrip("/"))` joins `COMPRESS_ROOT` (`self.root`) with the `local_path`.  `local_path.lstrip("/")` only removes leading slashes, but does not prevent directory traversal sequences within `local_path` itself.
5.  If a crafted `url` contains directory traversal sequences (e.g., `../../../`), these sequences will be preserved in `local_path` and used in `os.path.join`, potentially leading to a path outside of `COMPRESS_ROOT`.
6.  The `os.path.exists(filename)` then checks for the existence of this potentially out-of-bounds file, and `get_hashed_mtime`/`get_hashed_content` might attempt to access or hash this file.

#### Security Test Case
**Test Case Title:** Path Traversal in CSS URL Rewriting

**Preconditions for Test:**
1.  Django project with `django-compressor` installed and enabled (`COMPRESS_ENABLED = True`).
2.  Default CSS filters are active (including `CssAbsoluteFilter` or `CssRelativeFilter`).
3.  A publicly accessible Django view that renders a template using `{% compress css %}` block.
4.  Create a sensitive file outside of `COMPRESS_ROOT` but within the Django project directory or accessible to the user running the Django application (for example, a file named `sensitive.txt` in the project root).

**Test Steps:**
1.  Create a CSS file (e.g., `malicious.css`) with the following content within your static files directory (or accessible via `COMPRESS_ROOT`):
    ```css
    .malicious-class {
        background-image: url('../../../../sensitive.txt'); /* Traversal to project root or above if possible */
    }
    ```
2.  Create or modify a Django template that includes the malicious CSS within a `{% compress css %}` block:
    ```html+django
    {% load static compress %}
        {% compress css %}
            <link rel="stylesheet" href="{% static 'malicious.css' %}" type="text/css">
        {% endcompress %}
    ```
3.  Access the Django view rendering this template through a web browser or using `curl`.
4.  Examine the rendered HTML source code. Check if the URL in the `url()` of `.malicious-class` has been rewritten and if it still contains or reflects the directory traversal sequence `../../../../sensitive.txt` or if an error occurs during template rendering due to file access issues.
5.  **Expected Result (Vulnerable):** If the application is vulnerable, the template should render without a critical error. Inspecting the server logs might reveal attempts to access a path outside of `COMPRESS_ROOT`. While direct content disclosure might not be visible in the rendered HTML, the vulnerability is confirmed by the unsafe path construction and potential for information leakage via logs or error conditions in more complex scenarios.  If a hashing method is used, the application might try to hash the content of `sensitive.txt` (or fail if permissions prevent it) confirming path traversal attempt.

**Note:** This test case primarily demonstrates the path traversal in path construction. Directly observing file content disclosure might require further exploitation or different filter configurations. The key is to verify that directory traversal sequences are not properly handled, leading to path construction outside of the intended `COMPRESS_ROOT`.