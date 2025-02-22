- **Vulnerability: Sensitive Information Disclosure via Inline Compilation Error Details**
  - **Description:**
    When asset compilation (for CSS or JavaScript) fails in django‐pipeline, the error is caught and rendered inline via the pipeline templatetag code. In particular, the method `render_error` (in `pipeline/templatetags/pipeline.py`) passes the full compiler error—including the command line that was executed and its error output—to the template “pipeline/compile_error.html” with only minimal filtering (removing ANSI escape sequences). An external attacker who is able to trigger a compiler error (for example, by requesting a package that is built from a malformed static asset) may force the application to reveal sensitive internal details.
    To trigger this vulnerability, an attacker would need to:
    1. Identify a static asset that is processed by django-pipeline.
    2. Manipulate or request an asset in a way that causes the compilation process to fail (e.g., by requesting a non-existent or malformed source file if possible, or by exploiting other application vulnerabilities to corrupt source files).
    3. Access a page that includes the pipeline templatetag referencing the problematic asset when `DEBUG=True` or `SHOW_ERRORS_INLINE=True`.
  - **Impact:**
    Sensitive details such as absolute filesystem paths, command‐line arguments, and environment details may be disclosed in the HTTP response. This information can aid an attacker in further reconnaissance and exploitation of the host system.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    The library uses the Django setting `SHOW_ERRORS_INLINE` (which by default is tied to the value of Django’s `DEBUG`) so that in a properly configured production environment (with `DEBUG=False`), inline error details will not be rendered.
  - **Missing Mitigations:**
    • No explicit enforcement exists within django‐pipeline to disable inline error detail output in production regardless of `DEBUG` or `SHOW_ERRORS_INLINE` settings.
    • There is no additional sanitization (beyond stripping certain ANSI sequences) of the error output before it is inserted into HTML.
  - **Preconditions:**
    • The application must be deployed with `DEBUG=True` (or with `SHOW_ERRORS_INLINE` inadvertently enabled) in production.
    • An attacker must be able to trigger a compiler error (for example, by referencing a static asset that fails to compile).
  - **Source Code Analysis:**
    In `pipeline/templatetags/pipeline.py` the `render_error` method receives a `CompilerError` instance and applies a regex substitution to remove ANSI escape sequences.
    ```python
    def render_error(self, e, template_name="pipeline/compile_error.html"):
        error_message = re.sub(r'\x1b[^m]*m', '', force_str(e))
        command_line = subprocess.list2cmdline(e.command)
        return mark_safe(render_to_string(template_name, {
            'error': error_message,
            'command': command_line,
            'verbose': settings.DEBUG,
        }))
    ```
    It then calls `render_to_string("pipeline/compile_error.html", …)` passing along the error message and the invoked command (via `subprocess.list2cmdline(e.command)`). No further sanitization is performed. This means that if an attacker can force a compiler error, the HTTP response will include potentially sensitive internal data. The template `pipeline/compile_error.html` then displays this information:
    ```html+django
    {% if verbose %}
        <div class="pipeline-error">
            <pre>
                Command: {{ command }}
                Error: {{ error }}
            </pre>
        </div>
    {% endif %}
    ```
  - **Security Test Case:**
    1. Configure a Django installation with django‐pipeline and set `DEBUG=True` (or explicitly enable `SHOW_ERRORS_INLINE`).
    2. Configure a pipeline asset (for example, a stylesheet) whose source file is replaced or malformed so that the underlying compiler (e.g. a SASS or CoffeeScript compiler) fails. For example, you can modify a source file of a CSS asset to contain invalid syntax.
    3. Load a page that uses a `{% stylesheet ... %}` or `{% javascript ... %}` tag referencing this asset in a browser.
    4. Inspect the rendered HTML source code in the browser.
    5. Verify that the rendered HTML contains an error block (within a `div` with class `pipeline-error`) that includes detailed information—such as absolute paths in the `command` and error details in the `error` section.
    6. Confirm that such details are no longer rendered when `DEBUG=False` (and hence when `SHOW_ERRORS_INLINE` is disabled).

- **Vulnerability: Potential Path Traversal in Static File Serving When DEBUG Is Enabled in Production**
  - **Description:**
    The view function `serve_static` (in `pipeline/views.py`) is intended for development use only. It first calls `default_collector.collect(request, files=[path])` on the requested file and then passes the request along to Django’s built‑in static file server. Although Django’s static file view uses a safe join to combine the document root with the requested path, no additional validation is performed in `serve_static` to reject path–traversal patterns (e.g. using “../”). An attacker can exploit this if `DEBUG=True` is enabled in production.
    To trigger this vulnerability, an attacker would need to:
    1. Ensure the Django application is running with `DEBUG=True` or the `--insecure` flag enabled in production.
    2. Craft a URL to the `/static/pipeline/` endpoint that includes path traversal elements (e.g., `..`). For example, `/static/pipeline/..%2F..%2F..%2Fetc%2Fpasswd`.
    3. Access this crafted URL through a web browser.
  - **Impact:**
    If the application is misconfigured and deployed with `DEBUG=True` (or run with the insecure option), an attacker may be able to craft URLs with path traversal elements that could allow reading files outside the intended static directory. This could lead to exposure of sensitive files on the filesystem.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    The function immediately raises an `ImproperlyConfigured` exception when Django’s `DEBUG` is False (unless the `--insecure` flag is explicitly used), thereby discouraging its use in production. Also, Django’s own static file serving view uses `safe_join` to limit file access within Django's `STATIC_ROOT`.
  - **Missing Mitigations:**
    • There is no explicit check within `serve_static` to sanitize or normalize the incoming `path` parameter beyond relying on Django’s static file serving logic.
    • The library depends entirely on developers ensuring that `DEBUG` is disabled in production for security.
  - **Preconditions:**
    • The application is deployed with `DEBUG=True` (or with the `--insecure` flag) in production.
    • An attacker can craft a URL with path traversal sequences in the `path` parameter.
  - **Source Code Analysis:**
    In `pipeline/views.py`, the function `serve_static` accepts a `path` parameter from the request URL and passes it to `default_collector.collect` (which uses the raw file name in its logic) and then to Django’s static file server.
    ```python
    def serve_static(request, path, insecure=False, **kwargs):
        if not settings.DEBUG and not insecure:
            raise ImproperlyConfigured(
                "The staticfiles serve view can only be used in debug mode or "
                "with the --insecure option.")
        normalized_path = safe_join(settings.STATIC_ROOT, path)
        if normalized_path is None:
            raise Http404("'%s' could not be located in STATIC_ROOT" % path)

        default_collector.collect(request, files=[path]) # Potential issue: path is not sanitized
        return static.serve(request, path, document_root=settings.STATIC_ROOT, **kwargs) # Django's serve uses safe_join
    ```
    Although Django’s implementation of `serve()` uses `safe_join` to combine `STATIC_ROOT` and `path`, the lack of additional validation (or explicit rejection) in django‐pipeline before calling `default_collector.collect(request, files=[path])` means that an attacker exploiting a misconfigured environment might attempt traversal. The `default_collector.collect` might operate on the path without proper sanitization before Django's `static.serve` handles the actual file serving.
  - **Security Test Case:**
    1. In a test Django installation with django‐pipeline, deliberately set `DEBUG=True` in `settings.py` to simulate a production misconfiguration.
    2. Ensure you have some static files deployed and `STATIC_ROOT` is configured to a directory containing these files.
    3. Craft a URL to the static serve view using a path that includes “../” (for example, if your static URL prefix is `/static/`, try `/static/pipeline/..%2Fmanage.py`). You may need to URL-encode the path traversal characters (e.g., `%2F` for `/`).
    4. Send a GET request to this crafted URL using a browser or `curl`.
    5. Observe whether the response reveals any file contents that lie outside the intended static directory (e.g., the content of `manage.py` or other sensitive files depending on your server's filesystem structure relative to `STATIC_ROOT`).
    6. Verify that if `DEBUG` is later set to `False`, accessing the same URL will result in an `ImproperlyConfigured` exception.

- **Vulnerability: Potential Command Execution via Malicious File Names in SubProcessCompiler**
  - **Description:**
    In several compiler classes (which inherit from `SubProcessCompiler` in modules such as `sass.py`, `less.py`, `coffee.py`, etc.), the command to be executed is built by “flattening” a tuple from settings (for example, settings like `SASS_BINARY`, `LESS_BINARY`, or `COFFEE_SCRIPT_BINARY`). The flattening process does little or no validation of the individual components. If an attacker can somehow cause a static asset file name—or a related setting value—to include unexpected characters (such as spaces or shell metacharacters), the resulting command–line argument list may be altered. Even though subprocess execution is done with `shell=False` (thus largely preventing shell injection), malformed or malicious file names or configuration values could theoretically cause unexpected behavior or, in conjunction with another vulnerability (for example, an insecure file–upload facility), lead to arbitrary command execution.
    To trigger this vulnerability, an attacker would need to:
    1. Find a way to introduce a malicious filename into the static asset processing pipeline. This could be through an independent file upload vulnerability, or if the application dynamically generates filenames based on user input without proper sanitization, or if an attacker can somehow modify files in the static files storage.
    2. Craft a malicious filename containing shell- Metacharacters or unexpected spaces that, when processed by a compiler, could alter the intended command execution. For example, a filename like `test; touch /tmp/pwned.coffee`.
    3. Trigger the compilation process for the asset with the malicious filename. This might involve requesting a page that uses the asset, or by manually triggering asset compilation tasks if such functionality is exposed.
  - **Impact:**
    If exploited, this vulnerability could allow an attacker for whom file names are controllable to influence the command arguments passed to external compilers. This might enable the execution of unintended commands, potentially leading to full system compromise.
  - **Vulnerability Rank:** High
  - **Currently Implemented Mitigations:**
    • The command is executed via `subprocess.Popen` with `shell=False` so that the arguments are passed as a list rather than a concatenated string, which mitigates many shell‐injection risks.
    • Under normal operation, asset file names come from a static files system that is not under attacker control.
  - **Missing Mitigations:**
    • There is no explicit sanitization or validation of file names or settings values when constructing the command argument list within `SubProcessCompiler.execute_command`.
    • The design assumes that the static asset file names (and related settings values) are trusted. An additional layer of input validation would reduce potential risk, especially in environments where file uploads or dynamic file naming is possible.
  - **Preconditions:**
    • An attacker must have an independent means (such as an insecure file upload vulnerability or a way to manipulate static file storage) to upload or modify static asset file names so that they contain malicious content.
    • The affected compiler must be triggered during asset processing so that the file name is included in the flattened command argument list.
  - **Source Code Analysis:**
    In `pipeline/compilers/__init__.py` (the `SubProcessCompiler.execute_command` method), the command is constructed by iterating over the `command` tuple defined in compiler classes.
    ```python
    class SubProcessCompiler(Compiler):
        # ...
        def execute_command(self, command, cwd=None, display_stdout=False,
                            display_stderr=False, content=None, filename=None,
                            **kwargs):
            if filename:
                command = tuple(command) + (filename,) # Filename appended without sanitization

            command = list(self.flatten_command(command)) # Flattening happens here
            command = list(filter(None, command))

            if not command:
                return '', ''
            # ...
            process = Popen(
                command, cwd=cwd, env=env,
                stdout=PIPE, stderr=PIPE, stdin=PIPE, shell=False) # shell=False is good, but filename is unsanitized
            # ...
    ```
    The `flatten_command` method handles lists and tuples within the command definition:
    ```python
    def flatten_command(self, command):
        for arg in command:
            if isinstance(arg, (list, tuple)):
                for sub_arg in self.flatten_command(arg): # Recursive flattening
                    yield sub_arg
            else:
                yield arg
    ```
    Each element of the command tuple is checked: if it is a string it is added directly, and if not (list or tuple), it is iterated over and flattened recursively. The final list of arguments is then filtered with a simple `filter(None, ...)` and passed directly to `subprocess.Popen`. No escaping or sanitization is applied to arbitrary file name inputs before being appended to the command. Although using a list of arguments (with `shell=False`) avoids classic shell injection, an attacker’s control over the file name could cause unexpected behavior in the called compiler because the filename is passed as a command-line argument without proper quoting or sanitization.
  - **Security Test Case:**
    1. Set up a test environment with django-pipeline and a compiler enabled (e.g., CoffeeScript).
    2. Create or simulate a scenario where a static asset filename can be controlled or influenced by an attacker. For a simplified test, you might manually create a file with a malicious name directly in your static files directory. Let's assume you create a file named `test;touch /tmp/pwned.coffee` (or similar, adapted to your OS).
    3. Configure a pipeline asset to process this malicious file. For example, if you are using CoffeeScript, create a pipeline configuration that includes `test;touch /tmp/pwned.coffee`.
    4. Trigger asset compilation. This could be done by running `python manage.py collectstatic` or by accessing a page that uses the relevant static asset if the compilation happens on-demand.
    5. Monitor the command executed by the compiler. You can achieve this by:
        - Replacing the actual compiler binary (e.g., `coffee`) with a simple script that logs the command-line arguments it receives and then exits.
        - Using system monitoring tools to observe the processes spawned by Python and their arguments.
    6. Verify whether the executed command includes the malicious filename directly and unsanitized, e.g., you might see something like `coffee test;touch /tmp/pwned.coffee`.
    7. Check if the side effect of the malicious command is executed. In the example `test;touch /tmp/pwned.coffee`, check if the file `/tmp/pwned` was created. If it was, it confirms that command injection is possible through malicious filenames.
    8. (Mitigation Test) Implement filename sanitization in `SubProcessCompiler.execute_command` to only allow safe characters in filenames before appending them to the command. Retest with the same malicious filename and verify that the vulnerability is no longer exploitable. For example, you could sanitize the filename to remove or escape shell-sensitive characters before command execution.