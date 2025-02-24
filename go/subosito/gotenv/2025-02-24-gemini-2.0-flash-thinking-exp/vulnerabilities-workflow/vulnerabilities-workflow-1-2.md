- **Vulnerability Name:** Unrestricted Environment Variable Override
  - **Description:**
    The package provides override functions (namely, `gotenv.OverLoad` and `gotenv.OverApply`) that unconditionally set environment variables using values supplied in an input file or stream. An attacker who can control the contents of this file (or the input stream passed to these functions) can force the application to load attacker‑supplied key/value pairs. In practice, if an externally accessible interface lets a threat actor supply a malicious environment file, they can include entries for security‑critical variables (for example, overriding database credentials, system PATH, or other configuration parameters).
    **Step by step trigger:**
    1. Identify (or force) a use case in the publicly available application where the override functions are used on input that an attacker can control (for example, via a file‑upload endpoint or an API accepting raw .env content).
    2. Craft an environment file payload including entries such as:
       ```
       PATH=/malicious/bin
       DB_PASSWORD=evilpassword
       ```
    3. Submit this payload as the input to the override loader (using `gotenv.OverApply` or `gotenv.OverLoad`).
    4. The function processes the input and calls `setenv(key, val, override)`, which (with `override=true`) sets each environment variable without validation.
    5. As a result, the process’s critical configuration is altered according to attacker input.

  - **Impact:**
    By overriding critical environment variables, an attacker can change the application’s runtime configuration. This could lead to consequences such as bypassing authentication, redirecting connections, executing unexpected binaries (if PATH or similar variables are affected), or even enabling further attacks like privilege escalation. In environments where configuration controls application security, such an override can be extremely dangerous.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - The non‑overriding functions (`gotenv.Load` and `gotenv.Apply`) do check for an already‑set environment variable and do not override it. However, the override variants (`OverLoad`/`OverApply`) purposely disregard any pre-existing value.

  - **Missing Mitigations:**
    - No validation or sanitization on the keys or values provided in the override mode.
    - No whitelist or restriction on which critical environment variables may be updated.
    - No authentication/authorization check on the source of the .env file or input stream.

  - **Preconditions:**
    - The attacker must be able to supply or modify the .env file (or the "io.Reader" input) that is being processed by the override functions.
    - The application must be using `gotenv.OverLoad` or `gotenv.OverApply` on input that is externally controllable.

  - **Source Code Analysis:**
    - In `gotenv.go`, the `OverLoad` function is defined as a simple call to `loadenv(true, filenames...)`.
    - In the helper function `loadenv`, each file’s contents are parsed by `parset(f, override)`, where the boolean flag (`override = true` for overload operations) is passed along.
    - In the loop inside `parset`, each parsed key/value pair is set by calling `setenv(key, val, override)`.
    - The `setenv` function directly calls `os.Setenv(key, val)` when `override` is true, without any filtering or validation on the key name or the value.
    - This code path gives an attacker–controlled file full authority to set arbitrary environment variables.

  - **Security Test Case:**
    1. Deploy a test instance of the application where an endpoint (or similar mechanism) accepts an environment file and calls `gotenv.OverApply` to reload configuration.
    2. Create a malicious .env payload such as:
       ```
       PATH=/malicious/bin
       SECRET_KEY=attackers_secret
       ```
    3. Submit this payload through the externally accessible endpoint.
    4. After processing, use an internal monitor or log retrieval to call `os.Getenv("PATH")` and `os.Getenv("SECRET_KEY")` from within the application.
    5. Verify that the environment variables reflect the attacker’s supplied values and that the overriding behavior has taken effect.

---

- **Vulnerability Name:** Arbitrary File Write via Path Traversal in Write Function
  - **Description:**
    The public `Write` function serializes the environment map and writes the resulting content to a file whose path is supplied by the caller. The function creates necessary directories using `os.MkdirAll(filepath.Dir(filename), 0o775)` and then creates (or truncates) the file using `os.Create(filename)`. Because no sanitization or validation is performed on the passed filename, an attacker who can control this parameter could supply a filename with directory traversal sequences (for example, using "../../") to cause the file to be written outside of the intended directory structure.
    **Step by step trigger:**
    1. Identify an externally accessible functionality (such as an API endpoint) in the application that uses the `Write` function with a filename derived from user input.
    2. Craft a filename string that includes directory traversal characters, for example:
       ```
       ../../etc/passwd
       ```
       (or another sensitive path that the process user is allowed to write to).
    3. Supply valid environment content along with this malicious filename.
    4. Trigger the endpoint that calls the `Write` function.
    5. Verify that the file is written to the unintended location, thereby overwriting or creating files outside of the safe directory.

  - **Impact:**
    Successful exploitation of this vulnerability can allow an attacker to perform arbitrary file writes. This might lead to the corruption of system configuration files, introduction of malicious configurations, privilege escalation, or even remote code execution if critical files or scripts are targeted. The danger is compounded by the fact that the function does not restrict what path is used.

  - **Vulnerability Rank:** Critical

  - **Currently Implemented Mitigations:**
    - There are no checks implemented in the `Write` function regarding the validity or safety of the file path provided. The function simply accepts the filename and writes to it.

  - **Missing Mitigations:**
    - No sanitization or validation of the filename (for example, checking for directory traversal characters such as "../").
    - No restrictions on absolute versus relative paths.
    - No confinement of file write operations to a safe or configured directory.

  - **Preconditions:**
    - The attacker must be able to control the filename parameter passed to `Write`. This typically requires that the application exposes an interface where the filename is derived (even partly) from external input.
    - The process must have filesystem permissions that allow writing to the target directory.

  - **Source Code Analysis:**
    - In `gotenv.go`, the `Write` function is defined as follows:
      - The function first calls `Marshal(env)`, which converts the environment map to a string.
      - It then ensures that the directory exists by calling:
        ```go
        if err := os.MkdirAll(filepath.Dir(filename), 0o775); err != nil { … }
        ```
        Here, `filepath.Dir(filename)` is computed directly from the input without sanitization.
      - It then calls `os.Create(filename)` to create or truncate the file at that location.
    - Because no checks are performed on the structure (or contents) of the filename, an attacker–supplied string could easily navigate outside of any intended safe directory.

  - **Security Test Case:**
    1. In a controlled test environment, expose an API endpoint that accepts both the desired environment variables (as data) and a filename parameter; have that endpoint use `gotenv.Write` to save the file.
    2. Craft a request with a filename such as `../../tmp/malicious.env` (or another path based on your test setup) and supply benign environment variable content.
    3. Send the request to the endpoint.
    4. Check the filesystem to see whether the file was written in the unintended location (for example, verify that `../../tmp/malicious.env` exists and contains the expected data).
    5. Confirm that this behavior demonstrates the lack of proper path validation.