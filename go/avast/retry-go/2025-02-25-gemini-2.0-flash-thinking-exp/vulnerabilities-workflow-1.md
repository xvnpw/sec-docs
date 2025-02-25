### Vulnerability List

- **Vulnerability Name:** Unexpected Error Type Returned with `LastErrorOnly`, `Attempts(0)`, and `WrapContextErrorWithLastError`

- **Description:**
    When using `retry-go` with infinite retry attempts (`Attempts(0)`), context cancellation, and both `LastErrorOnly(true)` and `WrapContextErrorWithLastError(true)` options, the error returned upon context cancellation might be the context cancellation error itself instead of the last error returned by the retried function. This contradicts the expected behavior of `LastErrorOnly(true)` which should always return only the last error from the retried function, regardless of context cancellation.

    Steps to trigger:
    1. Configure `retry-go` to use infinite retry attempts by setting `Attempts(0)`.
    2. Enable context wrapping with the last error by setting `WrapContextErrorWithLastError(true)`.
    3. Enable last error only mode by setting `LastErrorOnly(true)`.
    4. Provide a context that will be cancelled during the retry operation.
    5. Execute `retry.Do` or `retry.DoWithData` with this configuration.
    6. Cancel the context while the retry operation is in progress.
    7. Observe the returned error type. It will be the context cancellation error, not the last error from the retried function as might be expected with `LastErrorOnly(true)`.

- **Impact:**
    Applications relying on `retry-go` and using `LastErrorOnly(true)` in combination with infinite retries and context cancellation might experience unexpected error handling. They might be designed to specifically handle the last error from the retried function when `LastErrorOnly(true)` is set, but instead, they receive a context cancellation error. This can lead to incorrect application logic execution following a retry operation cancellation, potentially causing unexpected states or failures in dependent processes.

- **Vulnerability Rank:** high

- **Currently Implemented Mitigations:**
    No specific mitigation is implemented for this behavior. The current implementation in `retry.go` prioritizes returning the context error within the infinite retry loop when `WrapContextErrorWithLastError(true)` is enabled, even if `LastErrorOnly(true)` is also set.

- **Missing Mitigations:**
    The expected behavior with `LastErrorOnly(true)` should be to always return the last error from the retried function if it failed, or nil if it succeeded. In the case of context cancellation with infinite retries and `WrapContextErrorWithLastError(true)`, the library should ideally return an error that wraps both the context cancellation error and the last error from the retried function, but when `LastErrorOnly(true)` is set, it should unwrap this combined error and return only the last error from the retried function.

    To mitigate this, the logic in the `DoWithData` function within the infinite retry loop should be adjusted to respect `LastErrorOnly(true)` even when a context cancellation occurs.  If `LastErrorOnly(true)` is enabled, the function should ensure that the unwrapped last error from the retried function is returned, possibly wrapping the context error as a cause, but ensuring the primary returned error is the last error from the retried function.

- **Preconditions:**
    - `retry-go` library is used with `Do` or `DoWithData` functions.
    - Options `Attempts(0)`, `Context(ctx)`, `LastErrorOnly(true)`, and `WrapContextErrorWithLastError(true)` are used together.
    - The provided context `ctx` is cancelled during the retry operation.

- **Source Code Analysis:**

    ```go
    // File: /code/retry.go
    func DoWithData[T any](retryableFunc RetryableFuncWithData[T], opts ...Option) (T, error) {
        // ...
        if config.attempts == 0 { // Infinite retry loop
            for {
                // ...
                select {
                case <-config.timer.After(delay(config, n, err)):
                case <-config.context.Done():
                    if config.wrapContextErrorWithLastError {
                        return emptyT, Error{config.context.Err(), lastErr} // Context error returned here
                    }
                    return emptyT, config.context.Err() // Context error returned here
                }
            }
        }
        // ...
        if config.lastErrorOnly {
            return emptyT, errorLog.Unwrap() // Last error unwrapped here, but not in infinite loop case
        }
        return emptyT, errorLog
    }
    ```

    In the `DoWithData` function, when `config.attempts == 0`, the context cancellation logic within the `select` statement directly returns the context error when `config.wrapContextErrorWithLastError` is true, or just the context error otherwise. It does not consider the `config.lastErrorOnly` option in this path.

    For finite attempts (the `else` block of `if config.attempts == 0`), the `lastErrorOnly` option is considered *after* the retry loop completes, by calling `errorLog.Unwrap()`. This logic is missing for the infinite retry case with context cancellation.

    Visualization:

    ```
    [Infinite Retry Loop with Context] --> Context Cancelled?
        | Yes --> WrapContextErrorWithLastError?
        |      | Yes --> Return Error{context.Err(), lastErr}  <-- Returns Context Error, ignoring LastErrorOnly
        |      | No  --> Return context.Err()                 <-- Returns Context Error, ignoring LastErrorOnly
        | No  --> Continue Retry
    [Finite Retry Loop] --> After Loop --> LastErrorOnly?
        | Yes --> Return errorLog.Unwrap()                   <-- Returns Last Error
        | No  --> Return errorLog
    ```

- **Security Test Case:**

    ```go
    // File: /code/retry_test.go
    func TestLastErrorOnlyWithInfiniteRetriesAndContextCancel(t *testing.T) {
        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        testErr := errors.New("test error from retryable func")
        retrySum := 0
        var returnedErr error

        returnedErr = Do(
            func() error {
                retrySum++
                if retrySum == 2 {
                    cancel() // Cancel context on second attempt
                }
                return testErr
            },
            Attempts(0),
            Context(ctx),
            LastErrorOnly(true),
            WrapContextErrorWithLastError(true),
        )

        assert.Error(t, returnedErr, "Expected an error to be returned")
        assert.NotEqual(t, context.Canceled, returnedErr, "Expected last error from retryable func, not context.Canceled when LastErrorOnly(true)")
        assert.Equal(t, testErr, returnedErr, "Expected to receive the last error from retryable function")
    }
    ```

    To run this test case, add it to `/code/retry_test.go` and execute `go test ./code`. This test case will fail with the current implementation because it will assert that the returned error is `testErr`, but the current implementation will return `context.Canceled` (or an error wrapping `context.Canceled` and `testErr` if `WrapContextErrorWithLastError` is false, and then unwrapped to `context.Cancelled` due to `LastErrorOnly(true)`). The assertion `assert.NotEqual(t, context.Canceled, returnedErr, ...)` will fail, proving the vulnerability.