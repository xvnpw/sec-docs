## Vulnerability: Information Disclosure via Panic Logging in UnboundedExecutor

This vulnerability arises from the default panic handling mechanism within the `concurrent.UnboundedExecutor` in the Go programming language. When a goroutine managed by this executor panics, the default `HandlePanic` function logs detailed error information, including the panic message and a full stack trace. By default, this information is written to `os.Stderr`. If the application's logging system redirects `os.Stderr` to a location accessible to attackers, such as a shared log file, centralized logging system with weak access controls, or a misconfigured web interface, sensitive internal details of the application can be disclosed. This information can include file paths, function names, line numbers, and even potentially fragments of user input that triggered the panic, all of which can aid an attacker in understanding the application's internal workings and planning further attacks.

### Vulnerability Name: Information Disclosure via Panic Logging in UnboundedExecutor

### Description:
1. An application uses the `concurrent.UnboundedExecutor` to manage concurrent goroutines for task execution.
2. A goroutine is initiated using `executor.Go`, and this goroutine's handler function processes user-provided input or performs other operations that might lead to a panic.
3. A malicious user crafts a specific input or triggers a condition designed to induce a panic within the handler function during processing.
4. When a panic occurs within the goroutine, the `concurrent` library's `HandlePanic` function is invoked to manage the error. By default, `HandlePanic` is configured to log the panic message and the complete stack trace using the `ErrorLogger`.
5. The `ErrorLogger`, by default, is set to output to `os.Stderr`.  Application environments often capture `os.Stderr` and redirect it to log files or centralized logging systems for monitoring and debugging.
6. If these logs are stored in or routed to a location accessible to an attacker, whether due to misconfiguration, weak access controls, or accidental exposure through a web interface, the attacker can access and review them.
7. The panic message or the stack trace inadvertently contains sensitive information – such as internal file paths, function names, database connection details, internal identifiers, or portions of the user's malicious input itself. This sensitive diagnostic data is then disclosed to the attacker through the accessible logs.

### Impact:
Information Disclosure. A successful exploit of this vulnerability can lead to the disclosure of sensitive information. This information may include:
- Internal application details revealing the application's architecture and code structure.
- System paths exposing directory structures and potentially sensitive file locations.
- Configuration data inadvertently included in stack traces or panic messages.
- Fragments of user input that triggered the panic, which may contain sensitive user-provided data.
- Function names and line numbers that reveal internal logic and potential weak points in the application's code.

The severity of this vulnerability is high because the leaked information can significantly aid attackers in understanding the application's internal workings, facilitating further targeted attacks and potentially leading to more severe security breaches.

### Vulnerability Rank: High

### Currently implemented mitigations:
The `concurrent` library itself provides a basic recovery mechanism from panics in goroutines managed by `UnboundedExecutor`. The `Go()` method wraps the handler function invocation within a `defer recover()` block. When a panic occurs, this recovery block is executed, invoking the `HandlePanic` function.

The `HandlePanic` function, by default, logs the panic message and a full stack trace using the `ErrorLogger`. The `ErrorLogger` is initialized to write to `os.Stderr` by default.

However, these mechanisms are not mitigations against information disclosure. They are designed for error handling and logging, and in their default configuration, they inadvertently contribute to the vulnerability by logging potentially sensitive information to a location that might be accessible to attackers.

The library does offer the flexibility to override the default `HandlePanic` function. This allows developers to implement custom panic handling logic, which *can* be used as a mitigation if developers are aware of the information disclosure risk and implement secure logging practices. However, the default behavior is not secure.

### Missing mitigations:
- **Documentation Enhancement:** The `concurrent` library's documentation should prominently highlight the security implications of the default `HandlePanic` behavior, specifically regarding the potential for information disclosure through logs. It should strongly advise developers to carefully consider what information might be included in panic messages and stack traces, especially when processing user input, and to configure logging securely.
- **Best Practices Guidance:** The documentation should provide best practices for securely using `HandlePanic`. This includes suggesting sanitization or filtering of panic messages before logging in security-sensitive applications. It should also recommend against logging full stack traces in production environments, or at least ensuring that such logs are directed to secure, access-controlled locations.
- **Configurable Logging Verbosity:** Implement a configurable option to control the verbosity of panic logs, especially in production environments. This could include options to:
    - Disable stack trace logging entirely.
    - Log a reduced stack trace, omitting internal file paths or less critical stack frames.
    - Provide a structured logging format that allows for easier filtering and redaction of sensitive information before logging.
- **Secure Default Logging Behavior:** Consider changing the default `HandlePanic` to be more security-conscious. This could involve logging less verbose information by default, such as only the panic message without the stack trace, or providing a clear and easy way to disable stack trace logging in production via a configuration setting.
- **Sanitization of Logged Data:**  Explore the feasibility of automatically sanitizing the panic message and stack trace before logging to remove potentially sensitive information. However, this must be balanced with the debugging utility of detailed logs and might be too opinionated for a library. A configurable sanitization option might be more appropriate.
- **Log Exposure Controls:** While not strictly a mitigation within the `concurrent` library itself, emphasize in the documentation the importance of secure log management and access control. Remind developers to ensure that `os.Stderr` (or any configured log output) is not inadvertently exposed to external attackers.

### Preconditions:
1. The target application must utilize the `concurrent.UnboundedExecutor` to manage goroutines that process user-provided input or perform operations that could lead to panics.
2. The application's goroutine handler function must be susceptible to panics when processing specific inputs or under certain conditions, potentially triggered by malicious user actions.
3. The application's logging configuration must capture the output of `os.Stderr` (or the configured `ErrorLogger`'s output) and store it in a location that is accessible, or potentially accessible, to external attackers. This could be due to misconfigured access controls on log files, exposed logging endpoints, or insecure centralized logging systems.
4. The panic messages or stack traces generated by the application in response to triggered panics must contain sensitive information, such as internal paths, function names, or fragments of user input.

### Source code analysis:
1. **File: `/code/unbounded_executor.go` - Function: `UnboundedExecutor.Go(handler func(ctx context.Context))`**
   - The `Go` function in `unbounded_executor.go` is responsible for executing handler functions in goroutines. It includes a `defer recover()` block to handle panics that might occur within the handler function.
   ```go
   go func() {
       defer func() {
           recovered := recover()
           if recovered != nil {
               if executor.HandlePanic == nil {
                   HandlePanic(recovered, funcName) // Invokes default HandlePanic if executor-specific handler is not set
               } else {
                   executor.HandlePanic(recovered, funcName) // Invokes custom HandlePanic if set
               }
           }
           // ... (other deferred logic)
       }()
       handler(executor.ctx) // The user-provided handler function is executed here
   }()
   ```
   - When `recover()` catches a panic (`recovered != nil`), it checks if a custom `HandlePanic` function is set on the `executor`. If not, it calls the default `HandlePanic` function.

2. **File: `/code/unbounded_executor.go` - Variable: `HandlePanic` (Default Panic Handler)**
   - The default `HandlePanic` function is defined in `unbounded_executor.go` and is responsible for logging panic information.
   ```go
   // HandlePanic logs goroutine panic by default
   var HandlePanic = func(recovered interface{}, funcName string) {
       ErrorLogger.Println(fmt.Sprintf("%s panic: %v", funcName, recovered)) // Logs panic message
       ErrorLogger.Println(string(debug.Stack()))                               // Logs full stack trace - Vulnerability
   }
   ```
   - This function logs a formatted panic message including the function name where the panic occurred and the recovered panic value. Critically, it then logs the full stack trace by calling `debug.Stack()` and writing the result to `ErrorLogger`. This stack trace contains detailed information about the execution flow, including file paths and function names.

3. **File: `/code/log.go` - Variable: `ErrorLogger` (Default Error Logger)**
   - The `ErrorLogger` is initialized in `log.go` and, by default, is configured to write to `os.Stderr`.
   ```go
   // ErrorLogger is used to print out error, can be set to writer other than stderr
   var ErrorLogger = log.New(os.Stderr, "", 0) // Default ErrorLogger is configured to write to os.Stderr
   ```
   - `os.Stderr` is the standard error stream, which is commonly captured by logging systems in production environments.

**Visualization of Vulnerability Flow:**

```
[User Input/Action] --> [Triggers Panic in Handler Function] --> [Goroutine Managed by UnboundedExecutor]
    |
    V
[Panic Caught by defer recover() in Go method] --> [Default HandlePanic Function Invoked]
    |
    V
[HandlePanic Logs Panic Message & Full Stack Trace to ErrorLogger] --> [ErrorLogger Writes to os.Stderr]
    |
    V
[os.Stderr Logs Captured by Application's Logging System] --> [Logs Stored/Exposed in Potentially Accessible Location]
    |
    V
[Attacker Gains Access to Logs] --> [Information Disclosure: Sensitive Application Details Leaked via Stack Trace]
```

### Security test case:
1. **Setup Vulnerable Application:**
   - Create a Go application that imports the `concurrent` library and exposes an HTTP endpoint.
   - Within the HTTP handler for this endpoint, use `concurrent.NewUnboundedExecutor()` to create an executor.
   - Define a handler function for `executor.Go()` that processes a user-provided input string from the HTTP request.
   - Implement logic in the handler function to intentionally panic if the input string matches a predefined malicious value (e.g., "sensitive_input"). Make the panic value include the malicious input itself to simulate data leakage.
   - Configure the application to redirect `os.Stderr` to a file named "panic.log" in the application's directory.

2. **Configure Logging Redirection:**
   - In the main function of your Go application, add code to redirect `os.Stderr` to the "panic.log" file. This simulates a scenario where application logs are being captured.

3. **Deploy and Run Application:**
   - Compile and run the Go application. Ensure it is accessible for external requests.

4. **Trigger the Panic:**
   - As an attacker, send an HTTP request to the application's endpoint. Include the predefined malicious input string ("sensitive_input") in the request (e.g., as a query parameter or in the request body). This input should trigger the intentional panic in the goroutine's handler function.

5. **Access and Examine Logs:**
   - After sending the malicious request and allowing time for the goroutine to execute and panic, access the "panic.log" file created in the application's directory. If the application is running in a containerized environment, you might need to access the logs through container logs or a mounted volume where logs are stored.

6. **Verify Information Disclosure:**
   - Open the "panic.log" file and examine its contents.
   - Confirm that the log file contains an error entry generated by `HandlePanic`.
   - Verify that this log entry includes:
     - The panic message, which should contain the malicious input string ("sensitive_input") or a derivative, demonstrating the leakage of user-provided data in the panic log.
     - A stack trace following the panic message. Examine the stack trace to confirm it reveals internal application details such as:
       - File paths of your application's source code.
       - Function names from your application's code execution path.
       - Potentially, depending on the complexity and Go version, data values present on the stack at the time of the panic might be visible within the stack trace.

7. **Cleanup:** After testing, ensure to remove the logging redirection and any test-specific code from the application to restore its normal operation and secure logging configuration. In a real-world scenario, ensure that logs are properly secured and not publicly accessible.

By successfully completing these steps, you will demonstrate that an attacker can trigger a panic in an application using the `concurrent` library and potentially cause sensitive information to be logged and disclosed through accessible logs due to the default `HandlePanic` behavior. This test case validates the information disclosure vulnerability via panic logs.