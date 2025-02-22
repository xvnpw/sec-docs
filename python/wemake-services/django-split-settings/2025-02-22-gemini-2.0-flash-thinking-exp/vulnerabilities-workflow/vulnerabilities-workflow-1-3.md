- Vulnerability name: Path Traversal in `include` function leading to Arbitrary Code Execution
- Description:
    1. The `include` function in `split_settings/tools.py` is designed to include settings from multiple files.
    2. It takes file paths as arguments, which can include wildcards for globbing.
    3. The function uses `os.path.join` to construct the full path to the settings files by combining the directory of the file calling `include` with the provided file paths.
    4. It then uses `glob.glob` to find files matching the constructed path.
    5. Crucially, the `include` function **does not sanitize or validate** the provided file paths for path traversal sequences like `../`.
    6. If a developer, either intentionally or unintentionally (e.g., through misconfiguration or compromised environment variables), provides a file path containing path traversal sequences to the `include` function, it will process these sequences.
    7. This allows including files from outside the intended settings directory.
    8. Finally, the content of the included files is executed using `exec` within the settings scope.
    9. An attacker who can influence the file paths processed by the `include` function can achieve arbitrary code execution by including and executing a malicious Python file from a location accessible via path traversal.

- Impact:
    - Critical: Remote Code Execution (RCE). Successful exploitation allows an attacker to execute arbitrary Python code on the server running the Django application. This can lead to full system compromise, data breaches, and other severe security consequences.

- Vulnerability rank: critical

- Currently implemented mitigations:
    - None. The `include` function in `split_settings/tools.py` does not implement any input validation or sanitization to prevent path traversal.

- Missing mitigations:
    - Input validation and sanitization within the `include` function.
    - Specifically, the function should validate that the resolved paths, after applying `os.path.join` and `glob.glob`, remain within the intended settings directory or a predefined set of allowed directories.
    - Implement checks to prevent path traversal sequences (e.g., `../`) in the input file paths.

- Preconditions:
    1. A Django project using `django-split-settings` to manage settings.
    2. An attacker needs to find a way to influence the file paths that are passed to the `include` function. This could be achieved through:
        - Exploiting a misconfiguration where environment variables or configuration files, used to construct settings paths, are vulnerable to injection.
        - In less likely scenarios, if user-controlled input is somehow indirectly used to construct settings paths (which would be a severe misapplication of this library, but still theoretically possible).
    3. The attacker needs to be able to place a malicious Python file in a location on the server that is accessible via path traversal from the Django project's settings directory.

- Source code analysis:
    - File: `/code/split_settings/tools.py`
    - Function: `include(*args: str, scope: dict[str, typing.Any] | None = None)`
    - Line 100: `conf_path = os.path.dirname(including_file)` - Determines the base path for included files.
    - Line 104: `pattern = os.path.join(conf_path, conf_file)` - Constructs the full file path by joining the base path with the user-provided `conf_file`. At this point, if `conf_file` contains path traversal sequences, they are incorporated into the `pattern`.
    - Line 107: `files_to_include = glob.glob(pattern)` -  `glob.glob` expands the `pattern`, including resolving path traversal sequences, to find matching files. **No sanitization or validation occurs before this step.**
    - Line 119: `with open(included_file, 'rb') as to_compile:` - Opens the file found by `glob.glob`. If path traversal was successful, this could be a file outside the intended settings directory.
    - Line 121: `compiled_code = compile(to_compile.read(), included_file, 'exec')` - Compiles the content of the potentially attacker-controlled file as Python code.
    - Line 123: `exec(compiled_code, scope)` - Executes the compiled code within the settings scope. **This is where arbitrary code execution occurs if the attacker has successfully included a malicious file through path traversal.**

- Security test case:
    1. Set up a test Django project and install `django-split-settings`.
    2. Create a settings package, for example, `test_project/settings`.
    3. In `test_project/settings/__init__.py`, include a component like `include('components/base.py')`.
    4. Create a directory `/tmp/malicious_settings/` outside the project directory.
    5. Inside `/tmp/malicious_settings/`, create a file named `malicious.py` with the following content:
        ```python
        import os
        MALICIOUS_CODE_EXECUTED = True
        os.system('touch /tmp/rce_vulnerable') # Indicator of successful RCE
        ```
    6. Modify `test_project/settings/__init__.py` to include the malicious settings file using a path traversal sequence. For testing purposes, you can directly edit the `include` call to:
        ```python
        from split_settings.tools import include

        include('../../../tmp/malicious_settings/malicious.py') # Path traversal to include malicious file
        ```
        In a real-world scenario, this path traversal would likely be injected indirectly through configuration.
    7. Run any Django management command that loads settings, for example: `python test_project/manage.py check`.
    8. After running the command, check for the following indicators of successful exploitation:
        - Verify if the file `/tmp/rce_vulnerable` has been created. Its presence indicates that the code within `malicious.py` was executed.
        - Check if the `MALICIOUS_CODE_EXECUTED` variable is present in the Django settings. You might need to access settings programmatically after running the management command to verify this.
    9. If `/tmp/rce_vulnerable` exists, and/or `MALICIOUS_CODE_EXECUTED` is in settings, the test case confirms the path traversal vulnerability leading to arbitrary code execution.