- **Vulnerability Name:** Sensitive Information Disclosure via Panic Logging in UnboundedExecutor

  - **Description:**
    When a goroutine started via the UnboundedExecutor panics, the recovery mechanism logs detailed error information—including the function name, source file path, line number, and a full stack trace. An attacker who can trigger a controlled panic (for example, in a handler function invoked by a public endpoint) may cause these logs to be generated. If the application’s logging output is misconfigured (for instance, if stderr or log files are inadvertently exposed), the attacker can obtain sensitive internal details about the application’s code structure and execution flow.
    **Step-by-step trigger:**
    1. An attacker identifies a public endpoint that eventually calls a handler function managed by UnboundedExecutor.
    2. The handler is manipulated (or replaced in a testing scenario) to trigger a panic (e.g., by executing `panic("attacker-triggered panic")`).
    3. The panic is caught in the deferred recovery block inside the `Go()` method in UnboundedExecutor, which then calls the configured panic handler (or the default one).
    4. The default panic handler logs the panic details along with a full stack trace that discloses internal file names, function names, and line numbers.
    5. If these logs are visible externally (through misconfigured log exposure), the attacker can harvest this sensitive diagnostic data.

  - **Impact:**
    Detailed internal error information (including file paths, function names, and stack traces) greatly aids an attacker in mapping the internal workings of the application. This knowledge can facilitate further targeted attacks by revealing potential weak points and internal logic details that were meant to remain private. Information disclosure of this nature is therefore a significant risk.

  - **Vulnerability Rank:** High

  - **Currently Implemented Mitigations:**
    - The UnboundedExecutor’s `Go()` method wraps the handler invocation in a deferred recovery block that calls a panic handler (either the executor’s `HandlePanic` if set or the default one).
    - The default `HandlePanic` function (defined in `/code/unbounded_executor.go`) logs the panic message and full stack trace using `debug.Stack()` to the ErrorLogger (which by default writes to `os.Stderr`).

  - **Missing Mitigations:**
    - **Sanitization:** There is no filtering or sanitization of the logged error information to prevent exposure of sensitive internal details.
    - **Configurable Logging:** There is no production-ready configuration option to disable detailed stack trace logging. Implementing a mode that reduces log verbosity or omits internal file paths would mitigate the risk.
    - **Log Exposure Controls:** Measures to strictly control access to the error logs (such as ensuring that logs are not routed to publicly accessible endpoints) are not enforced within the project code.

  - **Preconditions:**
    - The application must expose a code path that an attacker can drive into (either directly or indirectly) such that a handler invoked by UnboundedExecutor panics.
    - The overall logging configuration must be misconfigured or overly permissive—for example, if stderr or internal log files are accessible by an external attacker.

  - **Source Code Analysis:**
    - In `/code/unbounded_executor.go`, the `Go(handler func(ctx context.Context))` method captures the function pointer of the supplied handler using `reflect.ValueOf(handler).Pointer()` and obtains file/line details via `runtime.FuncForPC(pc)` and `f.FileLine(pc)`.
    - The handler is then executed inside a new goroutine with a `defer` block that uses `recover()` to catch any panic.
    - Upon recovery, the deferred function invokes the panic handler: if `executor.HandlePanic` is set it is called, otherwise the default `HandlePanic` (defined at the top of the file) is used.
    - The default `HandlePanic` logs the panic information by printing a formatted message (including the extracted function name) and dumping the output of `debug.Stack()`, which provides the complete stack trace with internal file locations.
    - Since no sanitization is applied to this output, all retrieved internal details are logged in full.

  - **Security Test Case:**
    1. **Setup:**
       - Deploy the application (or a test instance) that uses UnboundedExecutor.
       - Misconfigure the logging so that the ErrorLogger’s output (stderr) is routed to an externally accessible location (for example, via a web-accessible log viewer endpoint or by collecting container logs that are externally accessible).
    2. **Execution:**
       - Create a handler function (similar to the `willPanic` function from `/code/unbounded_executor_test.go`) that intentionally invokes a panic (e.g., `panic("triggered panic")`).
       - Use the UnboundedExecutor’s `Go()` method to run this handler.
    3. **Observation:**
       - Wait a short time to let the goroutine start and the panic be handled.
       - Access the externally exposed logs.
    4. **Verification:**
       - Confirm that the logs contain a detailed error message with sensitive information (including the internal function name, file path, line numbers, and full stack trace).
       - This confirms that an attacker capable of triggering such a panic could obtain detailed internal diagnostics.
    5. **Cleanup:**
       - Restore proper logging configurations to ensure logs are not exposed externally after testing.