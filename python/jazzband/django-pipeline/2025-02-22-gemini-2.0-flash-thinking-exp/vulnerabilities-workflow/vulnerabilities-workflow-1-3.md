### Vulnerability List

- Vulnerability Name: Path Traversal via Glob Pattern in Package Sources
- Description:
    1. The `pipeline.glob.glob` function is utilized to locate source files for CSS and JavaScript packages based on patterns specified in Django settings under `PIPELINE['STYLESHEETS']` and `PIPELINE['JAVASCRIPT']`.
    2. The `Package.sources` property, defined in `pipeline/packager.py`, employs `glob.glob` to resolve the `source_filenames` configured for each package.
    3. If these `source_filenames` patterns are not properly validated, and an attacker gains control or influence over them, a malicious pattern could be crafted to traverse directories beyond the intended static file locations.
    4. By exploiting this, an attacker could potentially include arbitrary files from the server's filesystem into the pipeline's processing flow. This could lead to information disclosure or other vulnerabilities, contingent on how these included files are subsequently processed.
- Impact:
    - High. Successful exploitation could allow an attacker to read sensitive files from the server, potentially exposing source code, configuration files, or confidential data.
- Vulnerability Rank: High
- Currently implemented mitigations:
    - No direct mitigations are implemented within the project code to sanitize glob patterns in package configurations. The project assumes that developers will provide secure patterns in their settings.
- Missing mitigations:
    - Implement robust input validation and sanitization for glob patterns defined in `PIPELINE['STYLESHEETS']` and `PIPELINE['JAVASCRIPT']` settings. Restrict patterns to only allow paths within designated static file directories, explicitly preventing directory traversal sequences such as `..`.
- Preconditions:
    1. An attacker needs to achieve a state where they can manipulate the `source_filenames` patterns within the Django settings for `PIPELINE['STYLESHEETS']` or `PIPELINE['JAVASCRIPT']`. In typical Django deployments, direct external manipulation of settings is not feasible unless a separate configuration vulnerability exists or there is an indirect mechanism for settings injection.
    2. The `pipeline` module must be actively enabled and in use within the Django application.
- Source code analysis:
    - **File: /code/pipeline/packager.py**
        ```python
        class Package:
            # ...
            @property
            def sources(self):
                if not self._sources:
                    paths = []
                    for pattern in self.config.get("source_filenames", []): # Pattern from config
                        for path in glob(pattern): # glob.glob is called here
                            if path not in paths and find(path):
                                paths.append(str(path))
                    self._sources = paths
                return self._sources
        ```
        - The `Package.sources` property retrieves `source_filenames` patterns from the package configuration and passes them to the `glob(pattern)` function.
        - These patterns originate from the Django settings files (`css_packages`, `js_packages`).

    - **File: /code/pipeline/glob.py**
        ```python
        def glob(pathname):
            """Return a list of paths matching a pathname pattern."""
            return sorted(list(iglob(pathname)))

        def iglob(pathname):
            """Return an iterator which yields the paths matching a pathname pattern."""
            if not has_magic(pathname):
                yield pathname
                return
            dirname, basename = os.path.split(pathname)
            # ... recursive glob logic ...
        ```
        - `glob.glob` and `glob.iglob` utilize standard Python library functions `os.path` and `fnmatch`, which are inherently vulnerable to path traversal attacks if the input patterns are not properly sanitized.

    - **File: /code/tests/settings.py (example)**
        ```python
        PIPELINE = {
            # ...
            "STYLESHEETS": {
                "screen": {
                    "source_filenames": (
                        "pipeline/css/first.css",
                        "pipeline/css/second.css",
                        "pipeline/css/urls.css",
                    ),
                    "output_filename": "screen.css",
                },
                # ...
            },
            "JAVASCRIPT": {
                "scripts": {
                    "source_filenames": (
                        "pipeline/js/first.js",
                        "pipeline/js/second.js",
                        "pipeline/js/application.js",
                        "pipeline/templates/**/*.jst", # Glob pattern here
                    ),
                    "output_filename": "scripts.js",
                },
                # ...
            },
        }
        ```
        - The `source_filenames` entries within the `PIPELINE` settings dictionary define the glob patterns. If an attacker could somehow alter these settings, they could inject path traversal patterns.

- Security test case:
    1. **Setup:** Configure a Django project using `django-pipeline`.
    2. **Vulnerable Configuration:** Modify the Django settings to include a malicious path traversal pattern in `PIPELINE['STYLESHEETS']` or `PIPELINE['JAVASCRIPT']`. For example, alter `PIPELINE['STYLESHEETS']['screen']['source_filenames']` to `("../../../../../../../etc/passwd",)`.
    3. **Trigger Pipeline:** Access any webpage that utilizes the `{% stylesheet "screen" %}` template tag (or the package you modified). This action will initiate the pipeline to process the "screen" CSS package.
    4. **Observe Attempted File Access:** Monitor the application's behavior and logs. Observe if the pipeline attempts to access or process the `/etc/passwd` file. In a real-world scenario, this might manifest as errors in the application logs related to file access, or potentially, depending on error handling, the contents of `/etc/passwd` could be inadvertently included in the processed output.
    5. **Verify Path Traversal:** If the pipeline attempts to access `/etc/passwd` (or a similar sensitive file outside the static file directory), it confirms the path traversal vulnerability. This indicates that `glob.glob` processes the malicious pattern, and a setting compromise could lead to unauthorized file access.

    **Note:** This test case is designed to demonstrate the vulnerability assuming a hypothetical scenario where settings can be modified. In a standard deployment, direct external manipulation of Django settings is not typically possible. However, the analysis reveals that `django-pipeline` lacks sanitization of glob patterns, making it potentially vulnerable if a method to compromise settings exists, or if user-provided data is unsafely incorporated into these patterns.

- Vulnerability Name: Command Injection via Compressor Settings
- Description:
    1. The `django-pipeline` project uses external compressor tools (like csstidy, yui, terser, uglifyjs, closure) for CSS and JavaScript minification.
    2. The paths to these tools and their arguments are configured via Django settings (e.g., `CSSTIDY_BINARY`, `CSSTIDY_ARGUMENTS`, `YUI_BINARY`, `YUI_JS_ARGUMENTS`, etc.).
    3. The `SubProcessCompressor.execute_command` function in `pipeline/compressors/__init__.py` uses `subprocess.Popen` to execute these external commands.
    4. If an attacker can control or influence the Django settings related to compressor binaries or arguments, they could inject malicious commands.
    5. Successful injection could lead to arbitrary command execution on the server.
- Impact:
    - Critical. Successful exploitation allows for arbitrary command execution on the server, potentially leading to complete system compromise, data breach, and other severe impacts.
- Vulnerability Rank: Critical
- Currently implemented mitigations:
    - No mitigations are implemented within the project to sanitize compressor binary paths or arguments. The project relies on developers to configure secure settings.
- Missing mitigations:
    - Implement strict validation and sanitization for all settings related to compressor binaries and arguments. Ensure that binary paths are absolute and point to trusted executables. Sanitize arguments to prevent injection of malicious commands. Consider using `shlex.quote` to properly escape arguments passed to subprocess.
- Preconditions:
    1. An attacker needs to achieve a state where they can manipulate Django settings related to compressor configurations (e.g., `CSSTIDY_BINARY`, `CSSTIDY_ARGUMENTS`, etc.). This is typically not directly possible from the outside unless there is another vulnerability enabling settings injection or configuration compromise.
    2. One of the compressors that use `SubProcessCompressor` must be configured and used in the Django application.
- Source code analysis:
    - **File: /code/pipeline/compressors/__init__.py**
        ```python
        class SubProcessCompressor(CompressorBase):
            def execute_command(self, command, content):
                argument_list = []
                for flattening_arg in command:
                    if isinstance(flattening_arg, (str,)):
                        argument_list.append(flattening_arg)
                    else:
                        argument_list.extend(flattening_arg)

                pipe = subprocess.Popen( # subprocess.Popen is used here
                    argument_list,
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                if content:
                    content = smart_bytes(content)
                stdout, stderr = pipe.communicate(content)
                set_std_streams_blocking()
                if stderr.strip() and pipe.returncode != 0:
                    raise CompressorError(force_str(stderr))
                elif self.verbose:
                    print(force_str(stderr))
                return force_str(stdout)
        ```
        - The `SubProcessCompressor.execute_command` method directly executes commands using `subprocess.Popen` based on the `command` argument.
        - The `command` is constructed in subclasses like `CSSTidyCompressor`, `YUICompressor`, etc., using settings.

    - **File: /code/pipeline/compressors/csstidy.py**
        ```python
        class CSSTidyCompressor(SubProcessCompressor):
            def compress_css(self, css):
                output_file = tempfile.NamedTemporaryFile(suffix=".pipeline")

                command = (
                    settings.CSSTIDY_BINARY, # Setting for binary path
                    "-",
                    settings.CSSTIDY_ARGUMENTS, # Settings for arguments
                    output_file.name,
                )
                self.execute_command(command, css)
                # ...
        ```
        - `CSSTidyCompressor` and other compressors construct the `command` tuple using settings like `settings.CSSTIDY_BINARY` and `settings.CSSTIDY_ARGUMENTS`. If these settings are compromised, command injection is possible.

- Security test case:
    1. **Setup:** Configure a Django project using `django-pipeline` and enable CSS compression using `CSSTidyCompressor`.
    2. **Vulnerable Configuration:** Modify the Django settings to include a malicious command in `settings.CSSTIDY_BINARY` or `settings.CSSTIDY_ARGUMENTS`. For example, set `PIPELINE['CSSTIDY_BINARY'] = "sh"`, and `PIPELINE['CSSTIDY_ARGUMENTS'] = ("-c", "touch /tmp/pwned")`.
    3. **Trigger Compression:** Access any webpage that utilizes CSS compression via pipeline (e.g., using `{% stylesheet %}`). This will trigger the CSS compression process, including the execution of the configured CSSTidy compressor.
    4. **Observe Command Execution:** Check if the injected command `touch /tmp/pwned` is executed on the server. Verify if the file `/tmp/pwned` is created. Successful creation of this file confirms command injection.
    5. **Verify Command Injection:** If the file `/tmp/pwned` is created after triggering the pipeline, it confirms the command injection vulnerability. This demonstrates that by manipulating compressor settings, an attacker could execute arbitrary commands on the server.

    **Note:** Similar to the Path Traversal test case, this test assumes a hypothetical scenario where settings can be modified. In a real deployment, direct external manipulation of Django settings is not typical. However, the analysis shows that `django-pipeline` is vulnerable to command injection if compressor settings are compromised or user-provided data is unsafely incorporated into these settings.