Okay, I understand the task. I need to perform a deep analysis of the "Denial of Service (DoS) via Format String Complexity and Resource Exhaustion" attack surface for applications using the `fmtlib/fmt` library. I will structure the analysis as requested, starting with the objective, scope, and methodology, and then proceeding with the deep analysis itself.

Here's the plan:

1.  **Define Objective:** State the purpose of this analysis.
2.  **Scope:** Define the boundaries of the analysis, focusing on the specified DoS attack surface.
3.  **Methodology:** Outline the approach I will take to conduct the analysis.
4.  **Deep Analysis of Attack Surface:**
    *   **Technical Breakdown:** Explain *how* complex format strings lead to resource exhaustion in `fmtlib/fmt`.
    *   **Vulnerability Assessment:** Evaluate the likelihood and impact of this vulnerability.
    *   **Detailed Mitigation Strategies:** Elaborate on each mitigation strategy with practical advice.
    *   **Example Scenarios:** Provide code examples to illustrate the vulnerability and mitigations.
    *   **Developer Considerations:** Offer actionable advice for developers.

Let's proceed with generating the markdown output.

```markdown
## Deep Analysis: Denial of Service (DoS) via Format String Complexity and Resource Exhaustion in `fmtlib/fmt`

### 1. Objective

The objective of this deep analysis is to thoroughly investigate the "Denial of Service (DoS) via Format String Complexity and Resource Exhaustion" attack surface in applications utilizing the `fmtlib/fmt` library. This analysis aims to:

*   Understand the technical mechanisms by which maliciously crafted format strings can lead to excessive resource consumption.
*   Assess the potential impact and severity of this vulnerability in real-world applications.
*   Evaluate and elaborate on the proposed mitigation strategies, providing actionable recommendations for development teams to prevent and address this attack vector.
*   Provide a comprehensive understanding of the risks associated with uncontrolled format string complexity when using `fmtlib/fmt`.

### 2. Scope

This analysis is specifically focused on the following attack surface:

*   **Denial of Service (DoS) via Format String Complexity and Resource Exhaustion:**  This encompasses scenarios where an attacker can provide or influence the format string used by `fmtlib/fmt` in a way that causes the library to consume excessive CPU and memory resources during parsing and formatting operations, leading to a denial of service.

The analysis will consider:

*   The internal workings of `fmtlib/fmt` related to format string parsing and processing.
*   The types of format string complexities that can trigger resource exhaustion.
*   The impact on application performance and availability.
*   Practical mitigation techniques applicable to applications using `fmtlib/fmt`.

This analysis will *not* cover:

*   Other potential attack surfaces of `fmtlib/fmt` (e.g., format string vulnerabilities leading to information disclosure or code execution, which are generally considered mitigated by `fmtlib/fmt`'s design compared to `printf`-style functions).
*   General Denial of Service attacks unrelated to format string processing.
*   Specific vulnerabilities in particular versions of `fmtlib/fmt` (unless directly relevant to the complexity issue).

### 3. Methodology

This deep analysis will be conducted using the following methodology:

1.  **Literature Review:** Review the `fmtlib/fmt` documentation, relevant security advisories (if any), and general information on format string vulnerabilities and DoS attacks.
2.  **Code Analysis (Conceptual):**  Analyze the general principles of how format string parsing and processing are likely implemented in libraries like `fmtlib/fmt`, focusing on potential areas of computational complexity.  While a detailed code audit of `fmtlib/fmt` is beyond the scope, understanding the algorithmic nature is crucial.
3.  **Attack Vector Modeling:**  Develop a deeper understanding of how an attacker can craft complex format strings to exploit resource consumption. This involves considering different types of format specifiers, nesting, repetition, and large values.
4.  **Mitigation Strategy Evaluation:**  Critically evaluate the effectiveness and practicality of the proposed mitigation strategies (Input Validation, Rate Limiting, Resource Monitoring, Code Review).  This will include considering the trade-offs and implementation challenges for each strategy.
5.  **Example Scenario Development:** Create illustrative code examples to demonstrate vulnerable scenarios and how mitigation strategies can be applied.
6.  **Documentation and Reporting:**  Document the findings of the analysis in a clear and structured manner, providing actionable recommendations for development teams.

### 4. Deep Analysis of Attack Surface: DoS via Format String Complexity and Resource Exhaustion

#### 4.1. Technical Breakdown: How Format String Complexity Leads to Resource Exhaustion

`fmtlib/fmt`, like other format string processing libraries, needs to parse and interpret the format string provided by the user. This process involves several steps:

1.  **Parsing:** The library needs to parse the format string to identify literal text and format specifiers (placeholders). Complex format strings with deeply nested specifiers, a large number of specifiers, or unusual combinations increase the parsing time. Regular expressions or recursive parsing algorithms, while powerful, can exhibit performance degradation with highly complex inputs.

2.  **Format Specifier Interpretation:**  Each format specifier (e.g., `{:width.precisionf}`, `{:x}`, `{:p}`) needs to be interpreted.  This involves:
    *   **Width and Precision Handling:**  Large width and precision values, especially when combined with floating-point or string formatting, can lead to significant memory allocation for intermediate buffers and increased processing time to generate the formatted output.
    *   **Type Conversion and Formatting Logic:**  Different format specifiers trigger different formatting logic. Complex specifiers might involve more intricate calculations or string manipulations.

3.  **Argument Processing:**  The library needs to fetch and process the arguments corresponding to the format specifiers. While argument fetching itself is usually not the primary bottleneck, the *number* of arguments and the operations performed on them during formatting contribute to the overall resource consumption.

4.  **Output Buffer Management:**  `fmtlib/fmt` needs to manage output buffers to store the formatted string.  Extremely large width/precision values or a massive number of formatted elements can lead to significant memory allocation for these buffers.

**Specific Complexity Factors Contributing to Resource Exhaustion:**

*   **Deeply Nested Format Specifiers:**  While `fmtlib/fmt`'s format string syntax is generally not designed for deep nesting in the same way as some template languages, complex combinations of specifiers and flags can still increase parsing and interpretation complexity.
*   **Excessive Width and Precision Values:**  Specifying extremely large width or precision values (e.g., `{:1000000f}`, `{:.*s}` with a very large width) can force `fmtlib/fmt` to allocate large buffers and perform computationally intensive formatting operations, even if the actual output string is much smaller.
*   **Large Number of Format Specifiers:**  A format string with an extremely high number of format specifiers (e.g., `"{}{}{}{}{}{}{}{}{}{}" * 10000`) will increase parsing time and the overhead of processing each specifier and its corresponding argument.
*   **Combinations of Complex Specifiers:**  Combining multiple complex format specifiers within a single format string can exacerbate the resource consumption. For example, using large widths and precisions with complex formatting types repeatedly.

**Example of a Complex Format String (Illustrative):**

```python
# Python example to demonstrate the concept - fmtlib/fmt syntax is similar
complex_format_string = "{:{}.{}}".format("test", 100000, 100000) # Very large width and precision
```

While `fmtlib/fmt` is designed to be efficient, the inherent complexity of parsing and formatting, especially when dealing with user-controlled input, can be exploited to cause resource exhaustion if complexity is not managed.

#### 4.2. Vulnerability Assessment

**Likelihood:**

The likelihood of this vulnerability being exploitable depends heavily on how format strings are used within the application:

*   **High Likelihood:** If format strings are directly or indirectly derived from external, untrusted sources (e.g., user input, data from network requests, external configuration files) *without* proper validation and complexity limits, the likelihood is **high**. Attackers can easily craft and inject malicious format strings.
*   **Medium Likelihood:** If format strings are partially influenced by external sources but undergo some form of sanitization or filtering, the likelihood is **medium**.  The effectiveness of the sanitization will determine the actual risk.  Subtle bypasses might be possible.
*   **Low Likelihood:** If format strings are entirely static and hardcoded within the application's source code and never influenced by external input, the likelihood is **low**. However, even in this case, if extremely complex static format strings are unintentionally used, it could still lead to performance issues, although not directly exploitable by an external attacker.

**Impact:**

The impact of a successful DoS attack via format string complexity can be **High**:

*   **Application Unresponsiveness:** Excessive CPU consumption can lead to application slowdowns and unresponsiveness for legitimate users.
*   **Service Outage:** In severe cases, resource exhaustion can lead to complete service outages, requiring restarts or manual intervention to recover.
*   **Resource Starvation:**  The affected application might starve other processes on the same system of resources, potentially impacting other services or the entire system.
*   **Financial and Reputational Damage:** Service disruptions can lead to financial losses, damage to reputation, and loss of user trust.

**Risk Severity:**  As stated in the initial description, the Risk Severity is **High** due to the potential for significant service disruption.

#### 4.3. Detailed Mitigation Strategies

##### 4.3.1. Input Validation & Complexity Limits (Important)

This is the **most critical** mitigation strategy when dealing with format strings that are even indirectly influenced by external sources.

*   **Format String Whitelisting/Blacklisting (Difficult & Not Recommended for Complexity):**  Attempting to whitelist or blacklist specific format specifiers to control complexity is generally **not recommended** and very difficult to do effectively. The complexity arises from *combinations* and *values* within specifiers, not just the specifiers themselves.

*   **Complexity Metrics and Limits (Recommended):**  Instead of trying to parse the *meaning* of the format string, focus on limiting its *syntactic complexity*.  Implement checks *before* passing the format string to `fmt::format` or `fmt::print`:

    *   **Maximum Format Specifier Count:** Limit the total number of format specifiers (`{}`) allowed in a single format string.  A reasonable limit should be determined based on the application's expected use cases.
    *   **Maximum Nesting Depth (If Applicable):**  While `fmtlib/fmt`'s syntax isn't deeply nested, if you are using custom format string extensions or pre-processing, limit nesting levels.
    *   **Maximum Width and Precision Values:**  Enforce maximum allowed values for width and precision specifiers.  Reject format strings with values exceeding these limits.  Consider very conservative limits if format strings are from untrusted sources.
    *   **Maximum Format String Length:** Limit the overall length of the format string itself.  Extremely long format strings are often indicative of malicious intent or unintentional complexity.
    *   **Character Whitelisting (Basic Sanitization):**  While not directly addressing complexity, ensure the format string only contains allowed characters.  Reject strings with unexpected or control characters that might be used in exploits (though this is less relevant for DoS via complexity).

**Example Validation Logic (Conceptual - C++):**

```c++
#include <string>
#include <iostream>
#include <algorithm>

bool is_format_string_complex(const std::string& format_str, int max_specifiers, int max_width_precision) {
    int specifier_count = 0;
    int max_width = 0;
    int max_precision = 0;

    for (size_t i = 0; i < format_str.length(); ++i) {
        if (format_str[i] == '{') {
            specifier_count++;
            if (specifier_count > max_specifiers) return true; // Too many specifiers

            size_t end_brace = format_str.find('}', i);
            if (end_brace != std::string::npos) {
                std::string specifier = format_str.substr(i + 1, end_brace - i - 1);
                // (Simplified) Check for width/precision - more robust parsing needed in real code
                size_t dot_pos = specifier.find('.');
                size_t colon_pos = specifier.find(':');
                size_t start_width_precision = (colon_pos == std::string::npos) ? 0 : colon_pos + 1;

                if (dot_pos != std::string::npos && dot_pos > start_width_precision) {
                    std::string width_str = specifier.substr(start_width_precision, dot_pos - start_width_precision);
                    std::string precision_str = specifier.substr(dot_pos + 1);
                    try {
                        if (!width_str.empty() && std::isdigit(width_str[0])) {
                            max_width = std::max(max_width, std::stoi(width_str));
                            if (max_width > max_width_precision) return true; // Width too large
                        }
                        if (!precision_str.empty() && std::isdigit(precision_str[0])) {
                            max_precision = std::max(max_precision, std::stoi(precision_str));
                            if (max_precision > max_width_precision) return true; // Precision too large
                        }
                    } catch (const std::exception&) {
                        // Handle potential stoi exceptions - invalid width/precision format
                    }
                } else if (colon_pos != std::string::npos) { // Check width only if no precision
                    std::string width_str = specifier.substr(colon_pos + 1);
                    try {
                        if (!width_str.empty() && std::isdigit(width_str[0])) {
                            max_width = std::max(max_width, std::stoi(width_str));
                            if (max_width > max_width_precision) return true; // Width too large
                        }
                    } catch (const std::exception&) {
                        // Handle potential stoi exceptions
                    }
                }

                i = end_brace;
            } else {
                // Unclosed brace - invalid format string (handle as needed)
            }
        }
    }
    return false; // Format string is within complexity limits
}

int main() {
    std::string format1 = "Hello, {}!";
    std::string format2 = "{:1000000s}";
    std::string format3 = "{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{}{