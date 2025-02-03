# Threat Model Analysis for facebook/folly

## Threat: [Buffer Overflow in `fbstring` Operations](./threats/buffer_overflow_in__fbstring__operations.md)

* **Description:** An attacker crafts input that, when processed by application code using `fbstring` (e.g., string concatenation, formatting, copying), causes a buffer overflow within `fbstring`'s internal memory management. This can overwrite adjacent memory regions. The attacker might exploit this to inject malicious code or corrupt critical data structures.
    * **Impact:**
        * Information Disclosure: Reading sensitive data from overwritten memory.
        * Denial of Service: Crashing the application due to memory corruption.
        * Elevation of Privilege: Potentially executing arbitrary code if the overflow overwrites instruction pointers or function return addresses.
    * **Folly Component Affected:** `folly/FBString.h`, specifically functions like `fbstring::append`, `fbstring::operator+=`, `fbstring::copy`, and formatting functions using `fbstring`.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * Use bounds-checking functions where available in `fbstring` or standard C++ string operations.
        * Thoroughly validate input sizes and lengths before string operations.
        * Employ memory sanitizers (e.g., AddressSanitizer) during development and testing to detect buffer overflows.
        * Regularly update Folly to benefit from bug fixes and security patches.

## Threat: [Use-After-Free in Asynchronous Task Handling with `Future`/`Promise`](./threats/use-after-free_in_asynchronous_task_handling_with__future__promise_.md)

* **Description:** An attacker triggers a race condition or exploits a flaw in Folly's asynchronous task handling, specifically within `Future` and `Promise` primitives. This leads to accessing memory that has already been freed, potentially due to incorrect object lifetime management in callbacks or continuations within Folly's asynchronous framework. The attacker might be able to read freed memory or corrupt program state by writing to freed memory.
    * **Impact:**
        * Information Disclosure: Reading data from freed memory that might still contain sensitive information.
        * Denial of Service: Crashing the application due to memory corruption or unpredictable behavior.
        * Elevation of Privilege: In some scenarios, writing to freed memory can be exploited for control flow hijacking.
    * **Folly Component Affected:** `folly/futures/Future.h`, `folly/futures/Promise.h`, `folly/executors/Executor.h`, and related asynchronous primitives within Folly.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Carefully manage object lifetimes in asynchronous callbacks and continuations, ensuring correct usage of Folly's asynchronous primitives.
        * Thoroughly review asynchronous code for potential race conditions and lifetime issues related to Folly's `Future`/`Promise` usage.
        * Use memory sanitizers (e.g., AddressSanitizer) to detect use-after-free errors during development and testing, specifically targeting Folly's asynchronous code paths.
        * Employ static analysis tools to identify potential lifetime management issues in asynchronous code involving Folly.

## Threat: [Denial of Service via Executor Thread Pool Exhaustion](./threats/denial_of_service_via_executor_thread_pool_exhaustion.md)

* **Description:** An attacker sends a large number of requests that trigger asynchronous tasks submitted to a Folly `Executor` (e.g., `ThreadPoolExecutor`). If the executor implementation within Folly or its default configuration lacks sufficient safeguards, or if the application misuses the executor, the attacker can exhaust the thread pool. This prevents legitimate tasks from being processed by Folly's executor, causing a denial of service.
    * **Impact:**
        * Denial of Service: Application becomes unresponsive or significantly degraded for legitimate users due to Folly's executor being overloaded.
    * **Folly Component Affected:** `folly/executors/Executor.h`, `folly/executors/ThreadPoolExecutor.h`, and other executor implementations within Folly.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Configure `Executor` thread pools with appropriate maximum sizes and queue limits to prevent unbounded growth, considering Folly's executor configuration options.
        * Implement request rate limiting and throttling *before* tasks are submitted to Folly's executor to prevent attackers from overwhelming it.
        * Monitor executor thread pool usage and queue lengths to detect potential DoS attacks targeting Folly's executor.
        * Consider using different executor types or strategies (e.g., `IOExecutor`) provided by Folly based on workload characteristics to optimize resource usage and DoS resilience.

## Threat: [Integer Overflow in Data Parsing with `io::Cursor`](./threats/integer_overflow_in_data_parsing_with__iocursor_.md)

* **Description:** An attacker provides crafted input data that, when parsed using `folly::io::Cursor`, leads to an integer overflow in size calculations or index manipulation within `io::Cursor`'s internal logic. This can result in out-of-bounds reads or writes when accessing the underlying data buffer through the cursor, due to flaws in `io::Cursor`'s handling of large or malicious input sizes.
    * **Impact:**
        * Information Disclosure: Reading data from outside the intended buffer boundaries due to `io::Cursor`'s incorrect bounds calculation.
        * Denial of Service: Crashing the application due to out-of-bounds memory access triggered by `io::Cursor`.
        * Potentially Elevation of Privilege: In specific scenarios, out-of-bounds writes caused by `io::Cursor` could be exploited.
    * **Folly Component Affected:** `folly/io/Cursor.h`, and functions within `io::Cursor` used for data parsing and manipulation.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Validate input data sizes and lengths *before* using `io::Cursor` to prevent excessively large values that could trigger overflows in `io::Cursor`.
        * Use safe integer arithmetic functions or checks *within* code that uses `io::Cursor` to prevent overflows during size calculations performed in conjunction with cursor operations.
        * Carefully review code using `io::Cursor` for potential integer overflow vulnerabilities, paying attention to how sizes and offsets are handled by `io::Cursor`.
        * Employ fuzzing techniques specifically targeting data parsing logic that utilizes `io::Cursor` with various input sizes and formats to uncover potential overflow issues in `io::Cursor`'s implementation or usage.

