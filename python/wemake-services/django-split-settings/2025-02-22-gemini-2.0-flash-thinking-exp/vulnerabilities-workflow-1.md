Here is the combined list of vulnerabilities, formatted as markdown:

### Vulnerability List for django-split-settings

#### Vulnerability Name: Path Traversal in `include` function leading to Arbitrary Code Execution

**Description:**

1.  The `include` function in `split_settings/tools.py` is designed to include settings from multiple files in a Django project.
2.  This function takes file paths as arguments, which can include wildcards for globbing to specify multiple files.
3.  The `include` function constructs the full path to the settings files by using `os.path.join`. It combines the directory of the settings file where `include` is called (`conf_path`) with the provided file paths (`conf_file`).
4.  It then uses `glob.glob` to find all files that match the constructed path pattern.
5.  Critically, the `include` function **does not sanitize or validate** the provided file paths for path traversal sequences like `../`.
6.  If an attacker can control the `settings.py` file (or a file included by it) of a Django application that uses `django-split-settings`, they can introduce path traversal sequences in the file paths passed to the `include` function. For example, an attacker could modify `settings.py` to use `include('../../../sensitive_file.py')`.
7.  When the Django application loads settings, the `include` function processes these crafted paths. Due to the lack of sanitization, path traversal sequences are not neutralized and allow navigating up the directory structure, starting from the directory of the initial settings file.
8.  The `glob.glob` function resolves this traversed path, and `include` attempts to read and execute the file at the attacker-specified location, potentially outside the intended project settings directory.
9.  If the attacker can specify a path to a file they control or a sensitive file on the server, they can achieve local file inclusion. If the included file is a Python file, its code will be compiled and executed within the context of the Django application, potentially leading to Remote Code Execution (RCE).

**Impact:**

*   **Critical:** Remote Code Execution (RCE). Successful exploitation allows an attacker to execute arbitrary Python code on the server running the Django application. This can lead to full system compromise, data breaches, access to sensitive data, and further malicious activities like pivoting to other network targets.

**Vulnerability Rank:** critical

**Currently Implemented Mitigations:**

*   None. The `include` function uses `os.path.join` for path construction and `glob.glob` for file discovery, but it lacks any input validation or sanitization to prevent path traversal. There are no explicit runtime checks performed on file paths to ensure they remain within intended boundaries.

**Missing Mitigations:**

*   **Path Sanitization and Validation:** Implement path sanitization within the `include` function to prevent path traversal. This should include:
    *   Validating that the resolved file path, after using `os.path.abspath` to resolve `..` and other relative components, remains within the intended settings directory or a predefined set of allowed directories.
    *   Using `os.path.commonpath` to ensure the included file is a subdirectory of the expected base settings directory.
    *   Implementing checks to explicitly reject file paths containing path traversal sequences (e.g., `../`).
*   **Principle of Least Privilege:**  The library currently operates under the assumption that all included settings files are trusted. Future mitigations could include mechanisms to limit the capabilities of included settings files, although this would fundamentally change the design of the library.

**Preconditions:**

1.  A Django project using `django-split-settings` to manage settings.
2.  An attacker needs to find a way to influence the file paths that are passed to the `include` function. This could be achieved through:
    *   Exploiting a misconfiguration where environment variables or configuration files, used to construct settings paths, are vulnerable to injection.
    *   In scenarios where configuration is managed externally or in development/staging environments, if an attacker gains control over the deployment process or a configuration management system, they could inject malicious `include` paths into the main `settings.py` file or files included by it.
    *   In less likely scenarios, if user-controlled input is somehow indirectly used to construct settings paths (which would be a severe misapplication of this library, but still theoretically possible).
3.  The attacker needs to be able to place a malicious Python file in a location on the server that is accessible via path traversal from the Django project's settings directory, or be able to include existing sensitive files.

**Source Code Analysis:**

*   File: `/code/split_settings/tools.py` (and `split_settings/tools.py` in original lists)
*   Function: `include(*args: str, scope: dict[str, typing.Any] | None = None)`

    ```python
    def include(  # noqa: WPS210, WPS231, C901
        *args: str,
        scope: dict[str, typing.Any] | None = None,
    ) -> None:
        ...
        conf_path = os.path.dirname(including_file) # Determines the base path for included files (Line 100 in List 3, inferred line number from List 1)
        ...
        for conf_file in args:
            ...
            pattern = os.path.join(conf_path, conf_file) # Vulnerable line: Path traversal possible here (Line 104 in List 3, inferred line number from List 1)
            ...
            files_to_include = glob.glob(pattern) # Glob resolves path traversal (Line 107 in List 3, inferred line number from List 1)
            ...
            for included_file in files_to_include:
                ...
                with open(included_file, 'rb') as to_compile: # Opens file from potentially traversed path (Line 119 in List 3, inferred line number from List 1)
                    compiled_code = compile(  # noqa: WPS421
                        to_compile.read(), included_file, 'exec', # Compiles code from potentially traversed path (Line 121 in List 3, inferred line number from List 1)
                    )
                    exec(compiled_code, scope)  # noqa: S102, WPS421 # Executes code from potentially traversed path (Line 123 in List 3, inferred line number from List 1)
    ```

    - The vulnerability lies in the line `pattern = os.path.join(conf_path, conf_file)`. When `conf_file` contains path traversal sequences like `../`, `os.path.join` correctly joins the paths, resolving the traversal relative to `conf_path`, but does not prevent moving outside the intended directory.
    - Subsequently, `glob.glob(pattern)` expands the pattern, including resolving path traversal sequences, to find files. **Crucially, no sanitization or validation is performed before this step.**
    - The code then iterates through the found files. For each `included_file`, it opens the file using `open(included_file, 'rb')`, compiles its content using `compile(...)`, and executes it using `exec(compiled_code, scope)`.
    - If path traversal is successful, `included_file` can point to a file outside the intended settings directory, and its content will be executed as Python code within the Django application's settings context, leading to arbitrary code execution.

**Security Test Case:**

1.  Set up a test Django project and install `django-split-settings`.
2.  Create a directory structure like this in your test project root (outside of the Django project's settings directory, e.g., alongside `manage.py`):
    ```
    sensitive_files/
    ├── sensitive_info.py  # Contains SECRET_DATA = "ATTACKER_CONTROLLED_SECRET"
    ```
    `sensitive_info.py` content:
    ```python
    SECRET_DATA = "ATTACKER_CONTROLLED_SECRET"
    ```
    Alternatively, create a directory `/tmp/malicious_settings/` outside the project directory and inside it create `malicious.py` with:
    ```python
    import os
    MALICIOUS_CODE_EXECUTED = True
    os.system('touch /tmp/rce_vulnerable') # Indicator of successful RCE
    ```
3.  Modify the main `settings.py` file of your Django project to include the sensitive or malicious file using path traversal. For example:
    ```python
    from split_settings.tools import include
    import os

    SETTINGS_DIR = os.path.dirname(os.path.abspath(__file__))

    include(
        os.path.join(SETTINGS_DIR, 'components/base.py'), # Example component (optional, but avoids errors if main settings file needs to include something valid)
        '../../../sensitive_files/sensitive_info.py', # Path Traversal to include sensitive file (adjust path based on where sensitive_files is created)
        # or
        '../../../tmp/malicious_settings/malicious.py', # Path Traversal to include malicious file (adjust path based on where malicious_settings is created)
        scope=globals(),
    )
    ```
    Ensure you also have a `components/base.py` or any other valid settings component to avoid immediate errors unrelated to path traversal, if needed.
4.  Run the Django development server: `python manage.py runserver` or run any Django management command that loads settings, for example: `python test_project/manage.py check`.
5.  Access any part of your Django application, or just execute the management command.
6.  For sensitive file inclusion test: Open the Django shell: `python manage.py shell`. In the shell, check if the `SECRET_DATA` variable is available in the settings:
    ```python
    from django.conf import settings
    print(settings.SECRET_DATA)
    ```
    If the output is `"ATTACKER_CONTROLLED_SECRET"`, the local file inclusion via path traversal is successful.
7.  For arbitrary code execution test: After running the management command, check for the following indicators of successful exploitation:
    *   Verify if the file `/tmp/rce_vulnerable` has been created. Its presence indicates that the code within `malicious.py` was executed.
    *   Check if the `MALICIOUS_CODE_EXECUTED` variable is present in the Django settings. You might need to access settings programmatically after running the management command to verify this.
8.  If the sensitive data is exposed or `/tmp/rce_vulnerable` exists, and/or `MALICIOUS_CODE_EXECUTED` is in settings, the test case confirms the path traversal vulnerability leading to arbitrary code execution.

#### Vulnerability Name: Arbitrary Code Execution via Malicious Settings File Inclusion

**Description:**

1.  The core function for including settings files, `include()` in `split_settings/tools.py`, uses Python’s built-in `compile()` and `exec()` functions to execute the complete content of every file matching the provided glob pattern.
2.  An attacker who manages to place or modify a file in the settings directory can inject arbitrary Python code. This could be achieved through various means such as exploiting a file upload vulnerability in the application or leveraging misconfigured file system permissions on the server.
3.  The attacker crafts a Python file (e.g., `malicious.py`) and places it into a directory that is subsequently included by the settings loader. This malicious file contains arbitrary code, such as code that calls `os.system()` to execute system commands or exfiltrates sensitive data to an external location.
4.  The attacker then triggers the application (or a test process) to load its settings. This could be done by restarting the application server, initiating a settings reload, or running tests that load the settings.
5.  When the `include()` function is executed, it picks up the malicious file via its glob pattern and executes its contents using `compile()` and `exec()`.

**Impact:**

*   **Critical:** Successfully triggering this vulnerability results in arbitrary code execution on the server. The attacker can completely compromise the system, gain unauthorized access to sensitive data, install backdoors, or use the compromised system as a pivot point to attack other systems on the network.

**Vulnerability Rank:** critical

**Currently Implemented Mitigations:**

*   The library is designed under the assumption that only trusted, version-controlled settings files will be present in the settings directories. Consequently, there are no explicit runtime checks performed on file ownership, permissions, or digital signatures of the settings files. The library inherently trusts all files it is instructed to include.

**Missing Mitigations:**

*   **Input Validation and Integrity Checks:** No validation or integrity checks of the settings files are performed before executing them. The system blindly executes any Python file it finds based on the include patterns.
*   **Sandboxing or Whitelisting:** There is no sandboxing or whitelisting mechanism to restrict which files may be executed by the loader. Any file that matches the glob pattern and is a valid Python file will be executed.
*   **Secure File System Permissions Enforcement or Runtime File Verification:** No secure file-system permissions enforcement or runtime file verification (e.g., checking file ownership, permissions, or using cryptographic hashes) is built into the logic to ensure the integrity and trustworthiness of settings files.

**Preconditions:**

*   The attacker must be able to write or modify files in a directory that is included as part of the application's settings. This precondition can be met if:
    *   File system permissions on the settings directory are misconfigured, allowing unauthorized write access.
    *   Another vulnerability exists in the broader application, such as an insecure file upload handler, that the attacker can exploit to upload malicious files to the settings directory.
    *   In development or testing environments, if security practices are lax and write access to the settings directory is not properly controlled.

**Source Code Analysis:**

*   File: `split_settings/tools.py`
*   Function: `include(*args: str, scope: dict[str, typing.Any] | None = None)`

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
            pattern = os.path.join(conf_path, conf_file)
            ...
            files_to_include = glob.glob(pattern)
            ...
            for included_file in files_to_include:
                ...
                with open(included_file, 'rb') as to_compile: # Opens the included file in binary read mode
                    compiled_code = compile(  # noqa: WPS421
                        to_compile.read(), included_file, 'exec', # Compiles the entire content of the file
                    )
                    exec(compiled_code, scope)  # noqa: S102, WPS421 # Executes the compiled code
    ```

    - The `include()` function resolves file paths based on the directory of the file calling `include`. It uses `glob.glob()` to find files matching the provided patterns.
    - For each resolved file, it opens the file in binary mode (`'rb'`), compiles its entire content using `compile(..., 'exec')`, and immediately executes it using `exec(compiled_code, scope)`.
    - There are no checks performed before running the file's code to verify its origin, integrity, or permissions. The function implicitly trusts all files it finds and executes them.

**Security Test Case:**

1.  **Setup:** In a controlled test environment, set up a Django project using `django-split-settings`. Identify the settings directory used by the application.
2.  **Insertion:** Create a file named `malicious.py` (or any `.py` file) within the settings directory. This file should contain easily verifiable malicious Python code. For example:
    ```python
    # malicious.py
    import os
    with open('/tmp/compromised.txt', 'w') as f:
        f.write('Application Compromised: Malicious settings file executed!')
    MALICIOUS_SETTINGS_INCLUDED = True
    ```
3.  **Trigger:** Force the application to load its settings. This can be done by restarting the Django application server (e.g., using `python manage.py runserver` again), running a management command that loads settings (e.g., `python manage.py check`), or triggering any other process that causes the settings to be re-merged using the `include()` function.
4.  **Verify:** After triggering the settings load, check for the presence and content of `/tmp/compromised.txt`. The existence of this file with the expected content confirms that the malicious code in `malicious.py` was executed. Additionally, check if the `MALICIOUS_SETTINGS_INCLUDED` variable is available in Django settings to further confirm successful inclusion and execution.
5.  **Cleanup & Logging:** Remove the `malicious.py` file and `/tmp/compromised.txt` after testing. In a real-world scenario, ensure that security logs would capture any abnormal file creation or execution events that could indicate a successful exploitation attempt.

#### Vulnerability Name: TOCTOU Race Condition in Settings File Inclusion

**Description:**

1.  The `include()` function in `split_settings/tools.py` first discovers file paths using `glob.glob()` based on the provided patterns. This operation retrieves a list of settings files that match the specified patterns.
2.  After obtaining the list of files, the function iterates through each file path. For each file, it proceeds to open the file using `open(included_file, 'rb')`, compile its contents with `compile()`, and then execute the compiled code using `exec()`.
3.  A Time-Of-Check-To-Time-Of-Use (TOCTOU) race condition exists in the time window between when `glob.glob()` retrieves the list of file paths and when each file in that list is actually opened and executed.
4.  An attacker who has write access to the settings directory can exploit this race condition. If the attacker can modify a settings file in the very short time interval between its discovery by `glob.glob()` and its subsequent opening and execution by `include()`, they can replace the original file content with malicious code.
5.  Even if the settings file was initially benign when `glob.glob()` listed it, by the time `include()` attempts to open and execute it, the attacker-modified malicious content will be processed.

**Impact:**

*   **High:** This race condition can lead to arbitrary code execution. Even if the settings files are initially secure and benign, an attacker exploiting this TOCTOU vulnerability can inject and execute arbitrary code, potentially leading to full system compromise. The impact is high because it bypasses the initial security of having trusted settings files if an attacker can manipulate them in the race window.

**Vulnerability Rank:** high

**Currently Implemented Mitigations:**

*   There is no mechanism in the code to ensure atomicity between the file listing operation performed by `glob.glob()` and the subsequent file reading and execution operations. The code does not account for the possibility that a file's content might change between these steps.

**Missing Mitigations:**

*   **Atomic File Operations or File Locking:** The code should implement file locking or an atomic file-opening strategy to ensure that the content read from the file is the same as it was when the file path was initially discovered. This would prevent modifications during the race window.
*   **Content Verification:** Implement verification of the file content before execution. This could involve using cryptographic hashes or digital signatures to ensure that the file content has not been tampered with since it was last checked or signed.
*   **Timestamp Comparison:** A less robust but potentially simpler mitigation could be to compare file timestamps between the listing and opening operations to detect if a file has been modified in the interim, although this is still susceptible to race conditions under certain circumstances.

**Preconditions:**

*   The attacker must have file system write access to the settings directory. This access is necessary to modify the settings files during the narrow time window between when `glob.glob()` lists the files and when `include()` opens and executes them. The attacker needs to be fast enough to perform the modification within this race window.

**Source Code Analysis:**

*   File: `split_settings/tools.py`
*   Function: `include(*args: str, scope: dict[str, typing.Any] | None = None)`

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
            pattern = os.path.join(conf_path, conf_file)
            ...
            files_to_include = glob.glob(pattern) # File discovery using glob (Step 1)
            ...
            for included_file in files_to_include: # Iteration over discovered files
                ...
                with open(included_file, 'rb') as to_compile: # Opens and reads file (Step 2 - Potential Race Condition)
                    compiled_code = compile(
                        to_compile.read(), included_file, 'exec',
                    )
                    exec(compiled_code, scope) # Executes file content (Step 3)
    ```

    - The function first gathers file paths using `files_to_include = glob.glob(pattern)`.
    - It then iterates over each file in `files_to_include`. For each `included_file`, it directly calls `open(included_file, 'rb')` to read and compile the file contents, followed by `exec(compiled_code, scope)` to execute it.
    - There is a time gap between the `glob.glob()` call and the subsequent `open()` call for each file. During this gap, if an attacker has sufficient privileges to modify files in the settings directory, they can replace the content of a file that was listed by `glob.glob()` with malicious code.

**Security Test Case:**

1.  **Setup:** In a controlled test environment, ensure that the file system permissions allow you (simulating an attacker with write access) to modify files in the settings directory. Prepare a benign settings file (e.g., `settings.py`) in the designated directory.
2.  **Simulated Race:**
    *   Modify the test environment or create a test harness to simulate the race condition. This involves pausing execution immediately after `glob.glob()` has listed the files but before the `open(included_file, 'rb')` call within the loop.
    *   In this paused state, use a separate process or thread (or a carefully timed script) to replace or modify the content of one of the settings files that was listed by `glob.glob()`. Insert malicious code into this file. For example, the malicious code could create a file named `race_triggered.txt` with a known marker string.
3.  **Trigger:** Resume the execution of the settings loader (`include()` function).
4.  **Verify:** After the settings loader has completed, check whether the modified (malicious) payload was executed. Verify this by checking for the creation and content of `race_triggered.txt`. If this file exists and contains the expected marker, it confirms that the malicious code inserted during the race window was indeed executed.
5.  **Result Analysis:** A successful test, indicated by the execution of the modified file content, demonstrates the presence of the TOCTOU vulnerability. This confirms that an attacker with write access can exploit the race condition to achieve code execution even if the initial settings files are benign.