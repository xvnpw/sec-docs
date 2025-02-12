Okay, let's craft a deep dive analysis of the "Large Number Handling (DoS)" attack surface for applications using `fasterxml/jackson-core`.

## Deep Analysis: Large Number Handling (DoS) in `jackson-core`

### 1. Define Objective, Scope, and Methodology

**Objective:**

The primary objective of this deep analysis is to thoroughly understand the vulnerabilities associated with large number handling in `jackson-core`, identify specific code paths and configurations that exacerbate the risk, and propose concrete, actionable mitigation strategies beyond the high-level overview.  We aim to provide developers with the knowledge to proactively prevent DoS attacks stemming from malicious or malformed JSON input containing excessively large numbers.

**Scope:**

This analysis focuses specifically on the `jackson-core` library, the foundation for other Jackson modules like `jackson-databind`.  We will examine:

*   The parsing mechanisms for both integer and floating-point numbers within `jackson-core`.
*   Relevant configuration options and their impact on large number handling.
*   The interaction between `jackson-core` and the underlying JVM's number handling capabilities.
*   Potential bypasses of common mitigation techniques.
*   The streaming API (`JsonParser`) and its role in mitigating this vulnerability.

**Methodology:**

1.  **Code Review:**  We will examine the source code of `jackson-core` (specifically classes related to number parsing, like `JsonParserBase`, `ReaderBasedJsonParser`, `UTF8StreamJsonParser`, and relevant number utility classes) to understand how numbers are read, validated, and converted.
2.  **Configuration Analysis:** We will identify and analyze configuration options within `JsonFactory`, `JsonParser.Feature`, and other relevant settings that influence number parsing behavior.
3.  **Experimentation:** We will construct test cases with various large and edge-case numeric values to observe the behavior of `jackson-core` under different configurations.  This includes testing for memory consumption, CPU usage, and potential exceptions.
4.  **Literature Review:** We will consult existing security advisories, CVEs, and research papers related to JSON parsing vulnerabilities and large number handling.
5.  **Mitigation Validation:** We will evaluate the effectiveness of proposed mitigation strategies by attempting to bypass them with crafted inputs.

### 2. Deep Analysis of the Attack Surface

**2.1. Parsing Mechanisms:**

`jackson-core` employs different parsing strategies depending on the input source (byte stream or character stream) and the underlying implementation.  Key classes involved in number parsing include:

*   **`JsonParserBase`:**  Provides common functionality for parsing JSON, including basic number handling logic.
*   **`ReaderBasedJsonParser`:**  Handles character-based input (e.g., from a `Reader`).
*   **`UTF8StreamJsonParser`:**  Handles byte-based input (e.g., from an `InputStream`) encoded in UTF-8.
*   **Number Utility Classes:** Classes like `NumberInput` and `NumberOutput` contain methods for converting between string representations and numeric types.

The parsing process generally involves:

1.  **Tokenization:** The parser identifies the start of a number token (e.g., a digit or a minus sign).
2.  **Character Accumulation:**  The parser reads characters until it encounters a non-numeric character (e.g., a comma, bracket, or whitespace).
3.  **Conversion:** The accumulated characters are converted to a numeric type (e.g., `int`, `long`, `double`, `BigDecimal`).

**2.2. Vulnerability Details:**

The core vulnerability lies in the potential for unbounded resource consumption during the "Character Accumulation" and "Conversion" phases.

*   **Memory Exhaustion (OOM):**  If an extremely long sequence of digits is provided (e.g., `123456789...` repeated millions of times), the parser might attempt to store the entire sequence in memory before converting it to a numeric type.  This can lead to an `OutOfMemoryError`.  This is particularly problematic when using the tree model (`JsonNode`) or data-binding (`ObjectMapper`) without appropriate size limits.
*   **CPU Exhaustion:**  Even if the number doesn't cause an OOM, the conversion process itself can be computationally expensive for very large numbers.  The algorithms used for converting strings to `BigDecimal` or `BigInteger`, for instance, can have non-linear time complexity.  An attacker could craft a number that takes a significant amount of CPU time to process, tying up server resources.
*   **`BigDecimal` and `BigInteger`:** While `BigDecimal` and `BigInteger` are designed to handle arbitrarily large numbers, they are not immune to DoS.  Excessive precision or scale in a `BigDecimal` can still lead to significant memory and CPU consumption.
* **Floating Point Specifics:** Parsing very long decimal representations (many digits after the decimal point) can be particularly slow.  Also, extremely large or small exponents (e.g., `1e999999999`) can trigger slow code paths or even internal errors within the JVM's floating-point handling routines.

**2.3. Configuration Options and Their Impact:**

Several configuration options can influence how `jackson-core` handles numbers:

*   **`JsonParser.Feature.ALLOW_NON_NUMERIC_NUMBERS`:**  This feature controls whether non-standard numeric values like `NaN` and `Infinity` are allowed.  While not directly related to large numbers, it's important to be aware of this setting as it can affect parsing behavior.
*   **`JsonFactory.Feature.FAIL_ON_NUMBERS_FOR_LOCATORS`:** This feature, when enabled, throws an exception if a number is encountered in a context where a string is expected (e.g., as a field name).  This is primarily for error handling and doesn't directly mitigate large number attacks.
*   **`StreamReadConstraints` (Jackson 2.15+):** This is the *most important* configuration for mitigating this attack surface.  Introduced in Jackson 2.15, `StreamReadConstraints` allows setting limits on:
    *   **`maxNumberLength()`:**  Limits the maximum number of characters allowed for a number.  This is *crucial* for preventing memory exhaustion.
    *   **`maxStringLength()`:** Limits the maximum length of string values.  While not directly related to numbers, it's a good general security practice.
    *   **`maxNestingDepth()`:** Limits the maximum nesting depth of JSON objects and arrays.
    *   **`maxNameLength()`:** Limits the maximum length of JSON field names.

**2.4. Interaction with JVM:**

`jackson-core` relies on the JVM's built-in number handling capabilities (e.g., `Integer.parseInt`, `Double.parseDouble`, `BigDecimal` constructor).  Therefore, any limitations or vulnerabilities in the JVM's number handling can also affect `jackson-core`.  For example, certain versions of the JVM might have had performance issues or bugs related to parsing extremely large or small floating-point numbers.

**2.5. Potential Bypasses:**

*   **Disabling `StreamReadConstraints`:** If `StreamReadConstraints` are not configured or are accidentally disabled, the vulnerability remains.
*   **Incorrect `StreamReadConstraints` Configuration:** Setting `maxNumberLength()` too high (e.g., allowing millions of digits) would still allow for significant resource consumption.
*   **Exploiting Edge Cases:**  There might be specific edge cases in the parsing logic or in the interaction with the JVM that could allow an attacker to bypass length limits or trigger unexpected behavior.  For example, numbers with many leading zeros or specific combinations of digits and exponents might require further investigation.
* **Using older Jackson versions:** Versions before 2.15 do not have `StreamReadConstraints` and are therefore more vulnerable.

**2.6. Streaming API (`JsonParser`) Advantages:**

The streaming API (`JsonParser`) offers a significant advantage in mitigating this vulnerability because it processes the JSON input incrementally.  Instead of loading the entire number into memory at once, the parser can read it in chunks.  This allows for:

*   **Early Detection:**  The application can check the length of the number as it's being read and abort processing if it exceeds a predefined limit.
*   **Reduced Memory Footprint:**  The parser only needs to store a small portion of the number in memory at any given time.
*   **Fine-Grained Control:**  The application has more control over the parsing process and can implement custom logic for handling large numbers.

### 3. Mitigation Strategies (Detailed)

Here's a breakdown of mitigation strategies, with specific code examples and considerations:

**3.1. Limit Input Size (Pre-Parsing):**

*   **Concept:**  Before even passing the input to Jackson, enforce a maximum size limit on the entire JSON payload.  This is a crucial first line of defense.
*   **Implementation:**  This can be done at the network layer (e.g., using a web server configuration or a reverse proxy) or in the application code before calling Jackson.
*   **Example (Java):**

    ```java
    import java.io.InputStream;
    import java.io.IOException;

    public class InputSizeLimiter {

        private static final long MAX_INPUT_SIZE = 1024 * 1024; // 1MB

        public static InputStream limitInputStream(InputStream inputStream) {
            return new LimitedInputStream(inputStream, MAX_INPUT_SIZE);
        }

        private static class LimitedInputStream extends InputStream {
            private final InputStream wrappedInputStream;
            private final long maxSize;
            private long bytesRead;

            public LimitedInputStream(InputStream wrappedInputStream, long maxSize) {
                this.wrappedInputStream = wrappedInputStream;
                this.maxSize = maxSize;
                this.bytesRead = 0;
            }

            @Override
            public int read() throws IOException {
                if (bytesRead >= maxSize) {
                    throw new IOException("Input stream exceeds maximum size limit: " + maxSize + " bytes");
                }
                int b = wrappedInputStream.read();
                if (b != -1) {
                    bytesRead++;
                }
                return b;
            }
            //Implement other read methods similarly
        }
    }

    // Usage:
    InputStream originalInputStream = ...; // Your original input stream
    InputStream limitedInputStream = InputSizeLimiter.limitInputStream(originalInputStream);
    // Now use limitedInputStream with Jackson
    ```

**3.2. Configure `StreamReadConstraints` (Jackson 2.15+):**

*   **Concept:**  Use the `StreamReadConstraints` class to set limits on the maximum number length.  This is the *preferred* method for Jackson 2.15 and later.
*   **Implementation:**  Configure `StreamReadConstraints` on the `JsonFactory` and use that factory to create your `ObjectMapper` or `JsonParser`.
*   **Example (Java):**

    ```java
    import com.fasterxml.jackson.core.StreamReadConstraints;
    import com.fasterxml.jackson.core.JsonFactory;
    import com.fasterxml.jackson.databind.ObjectMapper;
    import com.fasterxml.jackson.core.JsonParser;

    public class JacksonConfig {

        public static ObjectMapper createSecureObjectMapper() {
            StreamReadConstraints constraints = StreamReadConstraints.builder()
                    .maxNumberLength(1000) // Limit numbers to 1000 characters
                    .build();

            JsonFactory factory = JsonFactory.builder()
                    .streamReadConstraints(constraints)
                    .build();

            return new ObjectMapper(factory);
        }

        public static JsonParser createSecureJsonParser(InputStream in) throws IOException{
            StreamReadConstraints constraints = StreamReadConstraints.builder()
                .maxNumberLength(1000) // Limit numbers to 1000 characters
                .build();

            JsonFactory factory = JsonFactory.builder()
                .streamReadConstraints(constraints)
                .build();
            return factory.createParser(in);
        }
    }

    // Usage (ObjectMapper):
    ObjectMapper mapper = JacksonConfig.createSecureObjectMapper();
    // Use mapper to read JSON

    //Usage (JsonParser):
    InputStream in = ...;
    JsonParser parser = JacksonConfig.createSecureJsonParser(in);
    //Use parser to read JSON
    ```

**3.3. Use Streaming API (`JsonParser`) with Custom Validation:**

*   **Concept:**  Use the `JsonParser` to process the JSON input incrementally and implement custom logic to check the length of numbers as they are being read.
*   **Implementation:**  Iterate through the JSON tokens using `JsonParser.nextToken()`.  When you encounter a `VALUE_NUMBER_INT` or `VALUE_NUMBER_FLOAT` token, use `JsonParser.getTextCharacters()`, `JsonParser.getTextOffset()`, and `JsonParser.getTextLength()` to get the raw characters of the number and check its length.
*   **Example (Java):**

    ```java
    import com.fasterxml.jackson.core.*;
    import java.io.IOException;
    import java.io.StringReader;

    public class StreamingParserExample {

        private static final int MAX_NUMBER_LENGTH = 1000;

        public static void parseJson(String json) throws IOException {
            JsonFactory factory = new JsonFactory();
            JsonParser parser = factory.createParser(new StringReader(json));

            while (parser.nextToken() != null) {
                if (parser.currentToken() == JsonToken.VALUE_NUMBER_INT ||
                    parser.currentToken() == JsonToken.VALUE_NUMBER_FLOAT) {

                    int length = parser.getTextLength();
                    if (length > MAX_NUMBER_LENGTH) {
                        throw new IOException("Number exceeds maximum allowed length: " + length);
                    }

                    // Process the number (e.g., get its value)
                    // ...
                }
            }
            parser.close();
        }
    }
    ```

**3.4. Input Validation (Pre-Jackson):**

*   **Concept:**  Perform basic validation of the JSON input *before* passing it to Jackson.  This can help catch obviously malformed numbers.
*   **Implementation:**  Use regular expressions or other string manipulation techniques to check for excessively long sequences of digits or invalid number formats.
*   **Example (Java - Regex):**

    ```java
    import java.util.regex.Pattern;
    import java.util.regex.Matcher;

    public class InputValidator {

        private static final Pattern LARGE_NUMBER_PATTERN = Pattern.compile("\\d{1001,}"); // Matches 1001+ digits

        public static boolean containsLargeNumbers(String json) {
            Matcher matcher = LARGE_NUMBER_PATTERN.matcher(json);
            return matcher.find();
        }
    }

     //Usage
     String jsonInput = ...;
     if (InputValidator.containsLargeNumbers(jsonInput)) {
         // Reject the input
     } else {
         // Proceed with Jackson parsing
     }
    ```
    **Important:** Regex validation should be used as a *supplementary* measure, not a replacement for `StreamReadConstraints` or the streaming API approach.  Regex can be complex and prone to errors, and it's difficult to cover all possible edge cases.

**3.5.  Web Application Firewall (WAF):**

* **Concept:** Use a WAF to filter out requests containing potentially malicious JSON payloads.
* **Implementation:** Configure WAF rules to limit the size of request bodies and to detect and block requests containing excessively long numbers.  Many WAFs have built-in rules for JSON parsing and can be customized to enforce specific limits.

**3.6. Monitoring and Alerting:**

*   **Concept:**  Monitor application performance (CPU usage, memory consumption, response times) and set up alerts to notify you of any unusual activity that might indicate a DoS attack.
*   **Implementation:**  Use application performance monitoring (APM) tools to track resource usage and configure alerts based on thresholds.

### 4. Conclusion

The "Large Number Handling" attack surface in `jackson-core` presents a significant DoS risk.  By understanding the underlying parsing mechanisms, configuration options, and potential bypasses, developers can implement effective mitigation strategies.  The combination of **limiting input size**, **using `StreamReadConstraints` (for Jackson 2.15+)**, and employing the **streaming API with custom validation** provides the most robust defense.  Regular expression validation and WAFs can offer additional layers of protection.  Continuous monitoring and alerting are crucial for detecting and responding to potential attacks.  Always prioritize using the latest stable version of Jackson and keeping your dependencies up-to-date to benefit from security fixes and improvements.