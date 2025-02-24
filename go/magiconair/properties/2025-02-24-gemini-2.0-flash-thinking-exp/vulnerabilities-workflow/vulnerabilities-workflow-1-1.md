### Vulnerability List:

- Vulnerability Name: **Uncontrolled Resource Consumption via Recursive Property Expansion**
- Description:
    - An attacker can craft a properties file or URL content with deeply nested or circular property references.
    - When the application loads and attempts to expand these properties using the `properties` library's `Get` or `Decode` methods, it triggers a recursive expansion process.
    - Due to the unbounded nature of the recursion in case of circular references or very deep nesting, this can lead to excessive CPU and memory consumption.
    - Step 1: Attacker crafts a malicious properties file or prepares a malicious URL endpoint serving such a file. This file contains deeply nested property expansions or a circular dependency, for example: `key1=${key2}\nkey2=${key3}\n...\nkeyN=${key1}` or deeply nested structure like `key1=${key2}\nkey2=${key3}\n...\nkeyN=${key_N+1}`.
    - Step 2: The application, using the `properties` library, is configured to load properties from the attacker-controlled source (file or URL).
    - Step 3: The application calls `p.Get("someKey")` or `p.Decode(&config)` where `p` is the `Properties` object loaded from the malicious source.
    - Step 4: The `properties` library's expansion mechanism starts processing the nested references.
    - Step 5: In case of circular dependency, the `expand` function will recursively call itself, leading to an infinite loop. In case of deep nesting, it will lead to stack overflow or excessive CPU usage.
- Impact:
    - High CPU consumption, potentially leading to application slowdowns or unresponsiveness.
    - High memory consumption, potentially leading to out-of-memory errors and application crashes.
    - In a shared hosting environment, this could impact other applications on the same server.
- Vulnerability Rank: high
- Currently implemented mitigations:
    - The `expand` function in `properties.go` includes a `maxExpansionDepth` constant (currently set to 64) to limit the depth of recursion and prevent infinite loops in case of circular references.
    - Circular reference detection within the `expand` function, which returns an error when a cycle is detected.
- Missing mitigations:
    - While `maxExpansionDepth` and circular reference detection are present, the depth limit might be too high, still allowing significant resource consumption before the limit is reached.
    - There is no configuration option to adjust or disable property expansion, which could be useful in scenarios where expansion is not needed or introduces unacceptable risk.
    - No rate limiting or resource quotas are implemented to restrict the amount of resources consumed by property expansion operations, especially when loading from external sources.
- Preconditions:
    - The application must be configured to load properties from an external source (file or URL) that can be influenced or controlled by the attacker.
    - The application must use the `properties` library's `Get` or `Decode` methods that trigger property expansion.
    - Property expansion must be enabled (i.e., `DisableExpansion` is false, which is the default).
- Source code analysis:
    - **File: /code/properties.go, Function: `expand`**
        ```go
        func expand(s string, keys []string, prefix, postfix string, values map[string]string) (string, error) {
            if len(keys) > maxExpansionDepth { // Mitigation: Depth limit
                return "", fmt.Errorf("expansion too deep")
            }

            for {
                start := strings.Index(s, prefix)
                if start == -1 {
                    return s, nil
                }

                keyStart := start + len(prefix)
                keyLen := strings.Index(s[keyStart:], postfix)
                if keyLen == -1 {
                    return "", fmt.Errorf("malformed expression")
                }

                end := keyStart + keyLen + len(postfix) - 1
                key := s[keyStart : keyStart+keyLen]

                // ... Circular reference check ...
                for _, k := range keys {
                    if key == k { // Mitigation: Circular reference detection
                        var b bytes.Buffer
                        b.WriteString("circular reference in:\n")
                        for _, k1 := range keys {
                            fmt.Fprintf(&b, "%s=%s\n", k1, values[k1])
                        }
                        return "", fmt.Errorf(b.String())
                    }
                }

                val, ok := values[key]
                if !ok {
                    val = os.Getenv(key)
                }
                new_val, err := expand(val, append(keys, key), prefix, postfix, values) // Recursive call
                if err != nil {
                    return "", err
                }
                s = s[:start] + new_val + s[end+1:]
            }
        }
        ```
        - The `expand` function recursively substitutes property values.
        - `maxExpansionDepth` and circular reference check are in place to mitigate infinite recursion, but the depth limit might be too high for practical purposes.
        - The function can be triggered by loading properties from any source and then calling `Get` or `Decode`.
- Security test case:
    - Step 1: Prepare a malicious properties file named `evil.properties` with the following content representing a circular dependency:
        ```properties
        key1=${key2}
        key2=${key1}
        ```
    - Step 2: Create a Go program that uses the `properties` library to load this file and then attempts to get the value of `key1`.
        ```go
        package main

        import (
            "fmt"
            "github.com/magiconair/properties"
            "time"
        )

        func main() {
            start := time.Now()
            p := properties.MustLoadFile("evil.properties", properties.UTF8)
            _, err := p.Get("key1")
            duration := time.Since(start)
            if err != nil {
                fmt.Println("Error:", err)
            }
            fmt.Println("Processing time:", duration)
        }
        ```
    - Step 3: Run the Go program.
    - Step 4: Observe the CPU and memory usage of the program. Even with the `maxExpansionDepth` limit, the program will consume resources for a noticeable duration before detecting the circular dependency and returning an error. In case of very deep but non-circular nesting, the resource consumption can be significantly higher and might not even trigger an error immediately, leading to a temporary hang or slowdown.

    - Step 5: (Improved Test Case for Deep Nesting - requires creating a larger file) Create a malicious properties file `deep_nesting.properties` with a deep chain of dependencies, for example, create 100 keys where each key depends on the next one:
        ```properties
        key1=${key2}
        key2=${key3}
        key3=${key4}
        ...
        key99=${key100}
        key100=value
        ```
    - Step 6: Modify the Go program to load `deep_nesting.properties`.
        ```go
        package main

        import (
            "fmt"
            "github.com/magiconair/properties"
            "time"
        )

        func main() {
            start := time.Now()
            p := properties.MustLoadFile("deep_nesting.properties", properties.UTF8)
            val, _ := p.Get("key1")
            duration := time.Since(start)
            fmt.Println("Value:", val)
            fmt.Println("Processing time:", duration)
        }
        ```
    - Step 7: Run the modified Go program and observe the increased processing time and resource usage compared to loading a benign properties file. The processing time should be noticeably higher due to the recursive expansion, even if it completes successfully.

- Missing Mitigations:
    - Implement a configurable expansion depth limit that can be set to a lower value or even zero to disable expansion entirely if needed.
    - Consider adding resource usage monitoring and limits within the expansion process itself, potentially halting expansion if it exceeds certain CPU or memory thresholds.
    - Provide guidance in documentation to users about the risks of loading properties from untrusted sources and recommend disabling expansion or setting a very low depth limit when handling external input.