### Vulnerability List

- Vulnerability Name: Algorithmic Complexity and Unbounded Resource Consumption in Glob Matching

- Description:
    - The `Glob` function in `glob.go` is susceptible to algorithmic complexity and unbounded resource consumption vulnerabilities when processing specially crafted glob patterns.
    - **Algorithmic Complexity (Quadratic Blowup):** When processing patterns with a high number of glob characters ('*') and long subject strings, the function's execution time can increase quadratically. This is primarily due to the repeated use of `strings.Index` and string slicing within a loop.  Specifically, the function splits the pattern by '*' and then iterates through the parts, searching for each part in the subject string using `strings.Index`.  For patterns like `"*a*a*a*..."` and long subject strings, `strings.Index` might scan almost the entire subject string in each iteration, leading to quadratic time complexity.
    - **Unbounded Memory Allocation:** The `strings.Split` function, used to split the pattern by '*', can lead to unbounded memory allocation. If the pattern consists of a very long sequence of '*' characters, it results in a very large number of empty strings in the `parts` slice. Although processing each empty string part is fast, the sheer number of parts causes significant memory consumption, especially when called repeatedly with attacker-controlled patterns.

- Impact: High
    - Successful exploitation of this vulnerability can lead to significant performance degradation and resource exhaustion.
    - **CPU Exhaustion:** Crafted patterns can cause excessive CPU consumption due to the algorithmic complexity, potentially leading to denial of service. In shared hosting environments or systems with resource limits, this could impact other services or users.
    - **Memory Exhaustion:** Patterns with excessive '*' characters can lead to unbounded memory allocation, degrading performance and potentially impacting other services running on the same machine if memory resources are exhausted. While not a crash, it affects the availability and performance of the application.

- Vulnerability Rank: High

- Currently Implemented Mitigations: None
    - The current implementation of the `Glob` function in `glob.go` does not include any mitigations for either the algorithmic complexity or the unbounded memory allocation issues.

- Missing Mitigations:
    - **Algorithmic Improvement:** Implement a more efficient glob matching algorithm. Algorithms like dynamic programming or two-pointer approaches could reduce the time complexity from quadratic to linear or near-linear.
    - **Input Validation and Limits:**
        - Implement input validation to limit the number of glob characters ('*') allowed in a pattern.
        - Limit the maximum length of the subject string.
        - Limit the overall length of the pattern string.
        - Limit the size of the `parts` slice after splitting the pattern.
    - **Timeouts and Resource Limits:** Introduce timeouts for glob matching operations to prevent indefinite execution in case of complex patterns and subjects. Implement resource limits to restrict memory allocation and CPU usage by glob matching operations.

- Preconditions:
    - The application must use the `Glob` function from the `go-glob` library to match patterns against subject strings.
    - An external attacker must be able to control the pattern string that is passed to the `Glob` function, either directly or indirectly through application inputs.

- Source Code Analysis:
    - The vulnerability is located in the `Glob` function in `/code/glob.go`.
    - **Pattern Splitting:** The function begins by splitting the pattern string by the glob character '*' using `strings.Split(pattern, GLOB)`. This is where unbounded memory allocation can occur if the pattern has many '*' characters.
        ```go
        parts := strings.Split(pattern, GLOB)
        ```
    - **Iterative Matching:** The function then iterates through the resulting `parts` slice in a `for` loop to perform the glob matching.
        ```go
        for i := 0; i < end; i++ {
            idx := strings.Index(subj, parts[i])
            // ...
            subj = subj[idx+len(parts[i]):]
        }
        ```
    - **`strings.Index` Complexity:** Inside the loop, `strings.Index(subj, parts[i])` is called to find the index of the current part `parts[i]` within the subject string `subj`. If `parts[i]` is a short string or an empty string (due to consecutive '*' in the pattern) and `subj` is a long string, `strings.Index` can take linear time in the length of `subj` in the worst case. Repeated calls to `strings.Index` in the loop contribute to the algorithmic complexity.
    - **String Slicing:** `subj = subj[idx+len(parts[i]):]` creates a new substring of `subj`. While string slicing in Go is generally efficient, excessive slicing in a loop with long strings can still contribute to performance overhead.
    - **Combined Effect:** When the pattern contains many '*' characters, `parts` will be large (memory allocation). The loop iterates many times, and repeated `strings.Index` calls on potentially long `subj` strings lead to increased CPU consumption and execution time, resulting in both algorithmic complexity and resource consumption vulnerabilities.

- Security Test Case:
    1. **Setup**: Prepare a test environment where you can execute Go code, measure execution time, and monitor memory consumption.
    2. **Craft Malicious Input**:
        - Create a long subject string: `subject = strings.Repeat("b", 100000)`.
        - Create a malicious pattern with many glob characters and repeating short string: `pattern = "*" + strings.Repeat("*a", 1000) + "c"` (for algorithmic complexity test).
        - Create a malicious pattern with excessive '*' characters: `memoryPattern = strings.Repeat("*", 1000000)` (for memory consumption test).
    3. **Measure Resource Consumption (Algorithmic Complexity Case)**:
        - Record the start time and memory usage before calling `glob.Glob(pattern, subject)`.
        - Execute `glob.Glob(pattern, subject)`.
        - Record the end time and memory usage after the function returns.
        - Calculate execution time and memory allocated.
    4. **Measure Resource Consumption (Memory Consumption Case)**:
        - Record the start time and memory usage before calling `glob.Glob(memoryPattern, subject)`.
        - Execute `glob.Glob(memoryPattern, subject)`.
        - Record the end time and memory usage after the function returns.
        - Calculate execution time and memory allocated.
    5. **Measure Resource Consumption (Benign Case)**:
        - Use the same subject string: `subject = strings.Repeat("b", 100000)`.
        - Create a benign pattern: `benignPattern = "normalPattern"`.
        - Repeat steps in 4 to measure execution time and memory usage for `glob.Glob(benignPattern, subject)`.
    6. **Compare Resource Consumption**:
        - Compare the execution times and memory allocated for malicious patterns (`pattern`, `memoryPattern`) against the benign pattern (`benignPattern`).
        - **Expected Result for Algorithmic Complexity Case:** The execution time for `pattern` should be significantly longer than for `benignPattern`, and memory allocation may also be noticeably higher.
        - **Expected Result for Memory Consumption Case:** The memory allocation for `memoryPattern` should be significantly higher than for `benignPattern`, and execution time may also be higher due to memory operations.
        - The tests should demonstrate that crafted patterns can induce excessive CPU and/or memory consumption, confirming the algorithmic complexity and unbounded resource consumption vulnerabilities.