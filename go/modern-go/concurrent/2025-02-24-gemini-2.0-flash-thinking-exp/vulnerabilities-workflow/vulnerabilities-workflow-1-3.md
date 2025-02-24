### Vulnerability List:

- Vulnerability Name: Information Leakage via Panic Handling

- Description:
    When a goroutine managed by `concurrent.UnboundedExecutor` panics, the default `HandlePanic` function logs the panic message and the full stack trace to `ErrorLogger`. By default, `ErrorLogger` is configured to write to `os.Stderr`. In scenarios where `os.Stderr` logs are accessible to external attackers, this can lead to information leakage. The stack trace can reveal sensitive details about the application's internal workings, including file paths, function names, and potentially data values present in the stack frames at the time of the panic. This information can be valuable to an attacker for reconnaissance and further exploitation.

- Impact:
    Information leakage. An attacker can gain insights into the application's internal structure, code paths, and potentially sensitive data by analyzing the stack traces logged due to panics. This leaked information can aid in understanding the application's vulnerabilities and crafting more targeted attacks.

- Vulnerability Rank: High

- Currently Implemented Mitigations:
    No direct mitigations are implemented in the default configuration. The `HandlePanic` function is exposed as a variable that can be overridden by developers. This allows developers to implement custom panic handling logic, but the default behavior remains vulnerable.

- Missing Mitigations:
    The default `HandlePanic` function should be modified to avoid logging the full stack trace to `ErrorLogger` by default. Instead, it should only log the panic message or provide a configuration option to disable stack trace logging. The documentation should also emphasize the security implications of logging stack traces in production environments and encourage developers to implement custom, secure `HandlePanic` functions that sanitize or redact sensitive information before logging, or log to a more secure location.

- Preconditions:
    - A goroutine managed by `concurrent.UnboundedExecutor` must panic during its execution.
    - The application's `os.Stderr` logs (or wherever `ErrorLogger` is configured to write) must be accessible, or potentially accessible, to external attackers. This is common in many server environments where logs are collected and might be exposed through misconfiguration or other vulnerabilities.

- Source Code Analysis:
    1. **`unbounded_executor.go` - `Go` method:**
       ```go
       func (executor *UnboundedExecutor) Go(handler func(ctx context.Context)) {
           // ...
           go func() {
               defer func() {
                   recovered := recover()
                   if recovered != nil {
                       if executor.HandlePanic == nil {
                           HandlePanic(recovered, funcName) // Calls global HandlePanic if executor's HandlePanic is not set
                       } else {
                           executor.HandlePanic(recovered, funcName)
                       }
                   }
                   // ...
               }()
               handler(executor.ctx)
           }()
       }
       ```
       The `Go` method uses a `defer recover()` to catch panics within goroutines. If a panic is caught, it calls the `HandlePanic` function.

    2. **`unbounded_executor.go` - Default `HandlePanic`:**
       ```go
       // HandlePanic logs goroutine panic by default
       var HandlePanic = func(recovered interface{}, funcName string) {
           ErrorLogger.Println(fmt.Sprintf("%s panic: %v", funcName, recovered))
           ErrorLogger.Println(string(debug.Stack())) // <--- Vulnerable line: Logs full stack trace
       }
       ```
       The default `HandlePanic` function explicitly logs the stack trace using `debug.Stack()`.

    3. **`log.go` - `ErrorLogger` initialization:**
       ```go
       // ErrorLogger is used to print out error, can be set to writer other than stderr
       var ErrorLogger = log.New(os.Stderr, "", 0) // <--- Default destination is os.Stderr
       ```
       `ErrorLogger` by default writes to `os.Stderr`.

    **Visualization:**

    ```
    [Goroutine started by UnboundedExecutor] --> [Panic!] --> [defer recover() in Go method] --> [HandlePanic function] --> [ErrorLogger.Println(stack trace)] --> [os.Stderr] --> [Potential Log Exposure] --> [Attacker Access to Logs]
    ```

    This flow shows how a panic leads to the stack trace being logged to `os.Stderr` via the default `HandlePanic` function, and how this log could potentially be accessed by an attacker.

- Security Test Case:
    1. **Setup:** Create a Go application that imports the `concurrent` library. Initialize an `UnboundedExecutor`. Configure the application to redirect `os.Stderr` to a file (e.g., "panic.log") for easy examination.
    2. **Trigger Panic:** In the main function, use the `executor.Go` method to start a goroutine that intentionally panics. For example:
       ```go
       package main

       import (
           "context"
           "fmt"
           "os"
           "github.com/modern-go/concurrent"
       )

       func main() {
           // Redirect stderr to a file
           logFile, err := os.Create("panic.log")
           if err != nil {
               panic(err)
           }
           defer logFile.Close()
           os.Stderr = logFile

           executor := concurrent.NewUnboundedExecutor()
           executor.Go(func(ctx context.Context) {
               panic("Intentional panic for testing")
           })

           // Wait for a short duration to allow goroutine to execute and panic
           select {} // Keep application running to observe logs, in real test sleep for a while
       }
       ```
    3. **Run Application:** Compile and run the Go application.
    4. **Examine Logs:** After running the application, open the "panic.log" file.
    5. **Verify Stack Trace:** Check the "panic.log" file. It should contain the following:
       - A line indicating the panic message: "Intentional panic for testing".
       - A stack trace starting with "goroutine [number] [running]:". This stack trace will include:
         - File paths of your application's source code.
         - Function names from your application's code execution path leading to the panic.
         - Potentially, if data is on the stack at the point of panic, it might be visible in the stack trace depending on the Go version and optimization.
    6. **Conclusion:** The presence of a detailed stack trace in the "panic.log" (which represents `os.Stderr`) demonstrates that sensitive information is being leaked when a goroutine panics and the default `HandlePanic` function is used. This confirms the information leakage vulnerability.