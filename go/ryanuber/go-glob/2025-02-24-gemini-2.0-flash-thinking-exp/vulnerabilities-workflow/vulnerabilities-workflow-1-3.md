- Vulnerability name: Uncontrolled resource consumption due to unbounded memory allocation in glob matching
- Description: The `Glob` function in `glob.go` uses unbounded memory allocation when processing patterns with many '*' characters. Specifically, the `strings.Split` function splits the pattern string by the GLOB character ('*'), and if the pattern consists of a very long sequence of '*' characters, it will result in a very large number of empty strings in the `parts` slice. Subsequently, the loop iterates through this large slice. While the processing of each empty string part is fast, the sheer number of parts can lead to significant memory consumption and potentially performance degradation, especially when called repeatedly with attacker-controlled patterns. Although this is not a denial of service vulnerability as excluded by the prompt, it represents uncontrolled resource consumption.
- Impact: High. An attacker can cause significant memory consumption on the server by providing a specially crafted pattern string with a large number of '*' characters. This can lead to performance degradation and potentially impact other services running on the same machine if memory resources are exhausted. While not a crash, it affects the availability and performance of the application.
- Vulnerability rank: High
- Currently implemented mitigations: None. The code does not limit the number of '*' characters in the pattern or the size of the `parts` slice.
- Missing mitigations: Implement a limit on the number of '*' characters allowed in the pattern or limit the size of the `parts` slice to prevent excessive memory allocation. Consider alternative algorithms that are more efficient in handling patterns with many '*' characters.
- Preconditions: The application must use the `Glob` function to match user-provided patterns against subject strings. The attacker needs to control the pattern string.
- Source code analysis:
    1. The `Glob` function takes two string arguments: `pattern` and `subj`.
    2. `parts := strings.Split(pattern, GLOB)`: This line splits the pattern string by the '*' character. If the pattern is `****************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************`, `parts` will be a slice containing many empty strings.
    3. `for i := 0; i < end; i++`: This loop iterates through the `parts` slice. If `parts` is very large, this loop will also iterate many times.
    4. Inside the loop, `idx := strings.Index(subj, parts[i])` is called. When `parts[i]` is an empty string, `strings.Index` is very fast, but the loop overhead and memory allocation for `parts` become the bottleneck.
    5. `subj = subj[idx+len(parts[i]):]` is called to trim the subject.

    ```go
    func Glob(pattern, subj string) bool {
        // ...
        parts := strings.Split(pattern, GLOB) // Step 2: Splitting pattern by '*'
        // ...
        for i := 0; i < end; i++ {          // Step 3: Looping through parts
            idx := strings.Index(subj, parts[i]) // Step 4: Indexing subject
            // ...
            subj = subj[idx+len(parts[i]):]     // Step 5: Trimming subject
        }
        // ...
    }
    ```

- Security test case:
    1. Create a test application that uses the `glob.Glob` function and allows users to input a pattern string and a subject string.
    2. As an attacker, input a pattern string consisting of a very long sequence of '*' characters, for example, 1 million '*'.
    3. Input any subject string, for example, "test".
    4. Measure the memory consumption and execution time of the `Glob` function call. Observe that memory consumption increases significantly and the execution time might also increase noticeably compared to normal patterns.
    5. Repeat the test with increasing lengths of '*' characters in the pattern to demonstrate the unbounded resource consumption.

```go
package main

import (
	"fmt"
	"github.com/ryanuber/go-glob"
	"runtime"
	"strings"
	"time"
)

func main() {
	pattern := strings.Repeat("*", 1000000) // Craft a long pattern of '*'
	subject := "test"

	var memStatsBefore runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)
	startTime := time.Now()
	result := glob.Glob(pattern, subject) // Call Glob with the crafted pattern
	elapsedTime := time.Since(startTime)
	var memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsAfter)

	memAllocated := memStatsAfter.Alloc - memStatsBefore.Alloc

	fmt.Printf("Pattern: %s...\n", pattern[:min(50, len(pattern))])
	fmt.Printf("Subject: %s\n", subject)
	fmt.Printf("Result: %t\n", result)
	fmt.Printf("Elapsed Time: %s\n", elapsedTime)
	fmt.Printf("Memory Allocated: %d bytes\n", memAllocated)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

```

Run this test case and observe the memory allocated. It should be significant, demonstrating the vulnerability.