### Vulnerability List for django-split-settings

* Vulnerability Name: Local File Inclusion via Path Traversal in `include` function
* Description:
    1. An attacker can control the `settings.py` file of a Django application that uses `django-split-settings`.
    2. The attacker modifies `settings.py` to use the `include` function with a crafted file path containing path traversal sequences like `..`. For example: `include('../../../sensitive_file.py')`.
    3. When the Django application loads settings using `django-split-settings`, the `include` function processes the crafted path.
    4. Due to the use of `os.path.join(conf_path, conf_file)` in the `include` function, path traversal sequences like `..` are not neutralized and allow navigating up the directory structure, starting from the directory of the initial settings file. `conf_path` is derived from the directory of the current settings file being processed.
    5. The `glob.glob` function resolves this traversed path.
    6. `include` attempts to read and execute the file at the attacker-specified location, potentially outside the intended project settings directory.
    7. If the attacker can specify a path to a file they control or a sensitive file on the server, they can achieve local file inclusion. If the included file is a Python file, its code will be executed in the context of the Django application, potentially leading to Remote Code Execution (RCE).
* Impact:
    - **High:** An attacker can read arbitrary files on the server if they know or can guess the file paths. If the included file contains Python code, it will be executed in the context of the Django application, potentially leading to Remote Code Execution (RCE). This can compromise the entire application and server.
* Vulnerability Rank: high
* Currently Implemented Mitigations:
    - None. The `include` function uses `os.path.join` which, while correctly joining paths, does not prevent path traversal when `..` sequences are used in the included file path.
* Missing Mitigations:
    - **Path Sanitization:** Implement path sanitization within the `include` function to prevent path traversal. This could involve:
        - Validating that the resolved file path, after using `os.path.abspath` to resolve `..` and other relative components, remains within the intended settings directory.
        - Using `os.path.commonpath` to ensure the included file is a subdirectory of the expected base settings directory.
        - Restricting the characters allowed in file paths to prevent injection of path traversal sequences, although this might be less flexible. A robust approach is to normalize the path and verify it's within the expected boundaries.
* Preconditions:
    - The attacker needs to be able to modify the main `settings.py` file or control the content of a file that is used as the main settings file for a Django application using `django-split-settings`. While direct modification of `settings.py` in a production environment by an external attacker is unlikely in many scenarios, there could be situations where configuration is managed externally, or in development/staging environments where such modifications are possible. If an attacker gains control over the deployment process or a configuration management system, they could inject malicious `include` paths.
* Source Code Analysis:
    ```python
    def include(  # noqa: WPS210, WPS231, C901
        *args: str,
        scope: dict[str, typing.Any] | None = None,
    ) -> None:
        ...
        conf_path = os.path.dirname(including_file)
        ...
        for conf_file in args:
            ...
            pattern = os.path.join(conf_path, conf_file) # Vulnerable line: Path traversal possible here
            ...
            files_to_include = glob.glob(pattern)
            ...
            for included_file in files_to_include:
                ...
                with open(included_file, 'rb') as to_compile: # Reads file from potentially traversed path
                    compiled_code = compile(  # noqa: WPS421
                        to_compile.read(), included_file, 'exec',
                    )
                    exec(compiled_code, scope)  # noqa: S102, WPS421 # Executes code from potentially traversed path
    ```
    - The vulnerability is in the line `pattern = os.path.join(conf_path, conf_file)`. When `conf_file` contains path traversal sequences like `../`, `os.path.join` resolves them relative to `conf_path`, but does not prevent moving up the directory tree. Subsequently, `glob.glob(pattern)` and `open(included_file, 'rb')` will operate on the potentially traversed path, leading to local file inclusion. If the included file is a Python file, `exec(compiled_code, scope)` executes its content.
* Security Test Case:
    1. Set up a test Django project and install `django-split-settings`.
    2. Create a directory structure like this in your test project root (outside of the Django project's settings directory, e.g., alongside `manage.py`):
        ```
        sensitive_files/
        ├── sensitive_info.py  # Contains SECRET_DATA = "ATTACKER_CONTROLLED_SECRET"
        ```
        `sensitive_info.py` content:
        ```python
        SECRET_DATA = "ATTACKER_CONTROLLED_SECRET"
        ```
    3. Modify the main `settings.py` file of your Django project to include the sensitive file using path traversal:
        ```python
        from split_settings.tools import include
        import os

        SETTINGS_DIR = os.path.dirname(os.path.abspath(__file__))

        include(
            os.path.join(SETTINGS_DIR, 'components/base.py'), # Example component
            '../../../sensitive_files/sensitive_info.py', # Path Traversal to include sensitive file
            scope=globals(),
        )
        ```
        Ensure you also have a `components/base.py` or any other valid settings component to avoid immediate errors unrelated to path traversal.
    4. Run the Django development server: `python manage.py runserver`.
    5. Access any part of your Django application.
    6. Open the Django shell: `python manage.py shell`.
    7. In the shell, check if the `SECRET_DATA` variable is available in the settings:
        ```python
        from django.conf import settings
        print(settings.SECRET_DATA)
        ```
    8. If the output is `"ATTACKER_CONTROLLED_SECRET"`, the local file inclusion via path traversal is successful. This demonstrates that an attacker can include and execute code from files outside the intended settings directory by manipulating the `include` path. For further testing of code execution, `sensitive_info.py` could contain code to write a file to `/tmp` or perform other observable actions.