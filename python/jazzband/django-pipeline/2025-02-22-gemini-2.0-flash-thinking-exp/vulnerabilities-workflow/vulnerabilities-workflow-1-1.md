## Vulnerability List

### 1. Command Injection in SubProcessCompressor via Django Settings

* Vulnerability Name: Command Injection in SubProcessCompressor via Django Settings
* Description: An attacker with administrative privileges can modify Django settings such as `CSSTIDY_BINARY`, `CSSTIDY_ARGUMENTS`, `YUI_BINARY`, `YUI_JS_ARGUMENTS`, `YUI_CSS_ARGUMENTS`, `TERSER_BINARY`, `TERSER_ARGUMENTS`, `UGLIFYJS_BINARY`, `UGLIFYJS_ARGUMENTS`, `CLOSURE_BINARY`, `CLOSURE_ARGUMENTS`. By injecting malicious commands into these settings, they can achieve arbitrary command execution on the server when the corresponding compressor is used.
* Impact: Arbitrary command execution on the server, potentially leading to full server compromise, data breach, and other malicious activities.
* Vulnerability Rank: critical
* Currently implemented mitigations: None in the project code itself. Mitigation relies on secure Django settings management and restricting administrative access in Django applications that use django-pipeline.
* Missing mitigations: Input validation and sanitization for settings used in `SubProcessCompressor.execute_command`. While it might be argued that sanitizing Django settings within `django-pipeline` is outside the library's scope, clear documentation highlighting the security implications of directly using user-provided data in compressor settings is crucial.  Specifically, the documentation should strongly advise against allowing user-controlled values to populate these settings and recommend secure configuration practices.
* Preconditions:
    - Administrative access to the Django application to modify settings.
    - The application uses a compressor that extends `SubProcessCompressor` (like `CSSTidyCompressor`, `YUICompressor`, `TerserCompressor`, `UglifyJSCompressor`, `ClosureCompressor`).
    - CSS or Javascript compression is triggered, which uses the configured compressor.
* Source code analysis:
    - File: `/code/pipeline/compressors/__init__.py`
        ```python
        class SubProcessCompressor(CompressorBase):
            def execute_command(self, command, content):
                argument_list = []
                for flattening_arg in command:
                    if isinstance(flattening_arg, (str,)):
                        argument_list.append(flattening_arg)
                    else:
                        argument_list.extend(flattening_arg)

                pipe = subprocess.Popen(
                    argument_list,
                    stdout=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                # ...
        ```
        The `SubProcessCompressor.execute_command` method uses `subprocess.Popen` to execute external commands. The `command` argument is constructed in the compressor classes that inherit from `SubProcessCompressor`.
    - File: `/code/pipeline/compressors/csstidy.py` (Example Compressor)
        ```python
        class CSSTidyCompressor(SubProcessCompressor):
            def compress_css(self, css):
                output_file = tempfile.NamedTemporaryFile(suffix=".pipeline")

                command = (
                    settings.CSSTIDY_BINARY,
                    "-",
                    settings.CSSTIDY_ARGUMENTS,
                    output_file.name,
                )
                self.execute_command(command, css)
                # ...
        ```
        In `CSSTidyCompressor`, the `command` is constructed using `settings.CSSTIDY_BINARY` and `settings.CSSTIDY_ARGUMENTS`. Similar patterns exist in other compressors like `YUICompressor`, `TerserCompressor`, `UglifyJSCompressor`, and `ClosureCompressor`, using their respective settings. If an attacker can modify these settings to inject malicious commands, `subprocess.Popen` will execute them, leading to command injection.
* Security test case:
    1. Set up a Django project and install `django-pipeline`. Configure `pipeline` to use `CSSTidyCompressor` for CSS compression.
    2. Gain administrative access to the Django admin panel of the test project (or use any method to modify Django settings, e.g., directly editing `settings.py` if accessible).
    3. Modify the `PIPELINE_CSSTIDY_ARGUMENTS` setting in Django settings to include a malicious command, for example: `--optimise=2 & touch /tmp/pwned &`. The complete setting might look like:
        ```python
        PIPELINE = {
            'CSS_COMPRESSOR': 'pipeline.compressors.csstidy.CSSTidyCompressor',
            'CSSTIDY_BINARY': '/usr/bin/csstidy', # Replace with actual path if needed
            'CSSTIDY_ARGUMENTS': '--optimise=2 & touch /tmp/pwned &',
            # ... other pipeline settings
        }
        ```
    4. Trigger CSS compression. This can be done by:
        - Running `python manage.py collectstatic`. Pipeline compression is typically triggered during `collectstatic` if configured.
        - Accessing a page in the Django application that uses pipeline compressed CSS.
    5. After triggering compression, log into the server where the Django application is running and check if the file `/tmp/pwned` has been created.
    6. If the file `/tmp/pwned` exists, it indicates successful command injection through the `PIPELINE_CSSTIDY_ARGUMENTS` setting.