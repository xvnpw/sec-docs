### Vulnerability List

This document summarizes the vulnerabilities identified across multiple reports for the `json-iterator/go` library. Duplicate vulnerabilities have been consolidated into single entries, maintaining the original descriptions and details.

#### 1. Integer Overflow in Float Parsing (`readPositiveFloat64` and `readPositiveFloat32`)

*   **Vulnerability Name:** Integer Overflow in Float Parsing
*   **Description:**
    1.  The `readPositiveFloat64` and `readPositiveFloat32` functions in `iter_float.go` use integer arithmetic to parse the integer part of a floating-point number before the decimal point.
    2.  These functions accumulate the integer value by multiplying the current value by 10 and adding the next digit: `value = (value << 3) + (value << 1) + uint64(ind) // value = value * 10 + ind;`.
    3.  There is a check `if value > uint64SafeToMultiple10` before the multiplication in the loop. However, `uint64SafeToMultiple10` is not sufficiently small to prevent overflow when parsing very large integers.
    4.  If a JSON number with a very large integer part (before the decimal point) is provided, this multiplication can lead to an integer overflow.
    5.  This integer overflow can result in incorrect parsing of the floating-point number, potentially leading to unexpected behavior in applications using `json-iterator/go` to parse such JSON data.
*   **Impact:**
    *   Incorrect parsing of large floating-point numbers.
    *   Potential for application logic errors if the application relies on the parsed float value.
    *   Although not directly exploitable for remote code execution or data breach, incorrect data parsing can lead to application-level vulnerabilities or misbehavior.
*   **Vulnerability Rank:** High
*   **Currently Implemented Mitigations:**
    *   There is a check `if value > uint64SafeToMultiple10` in `readPositiveFloat64` and `readPositiveFloat32`, but `uint64SafeToMultiple10` is not effective enough to prevent overflows for very large numbers.
    *   The project includes tests in `value_tests/int_test.go`, specifically `Test_read_int_overflow`, which indicate awareness of integer overflow issues and include tests that trigger errors on integer overflow. However, these tests do not fully prevent the vulnerability of incorrect parsing due to integer overflow before the error is detected.
*   **Missing Mitigations:**
    *   Implement robust overflow checking during the integer parsing phase in `readPositiveFloat64` and `readPositiveFloat32`.
    *   Consider using `big.Float` or similar arbitrary-precision arithmetic for parsing very large numbers to avoid overflow issues, especially when high precision is not strictly required but correct parsing is critical.
    *   Alternatively, limit the size of the integer part that is parsed using integer arithmetic and switch to `strconv.ParseFloat` earlier for larger numbers.
*   **Preconditions:**
    *   The application must use `json-iterator/go` to parse JSON data.
    *   The attacker must be able to control the input JSON data and include a floating-point number with a very large integer part that can cause integer overflow during parsing.
*   **Source Code Analysis:**
    *   File: `/code/iter_float.go`
    *   Function: `readPositiveFloat64` and `readPositiveFloat32`

    ```go
    func (iter *Iterator) readPositiveFloat64() (ret float64) {
        // ...
        value := uint64(ind)
        // chars before dot
    non_decimal_loop:
        for ; i < iter.tail; i++ {
            c = iter.buf[i]
            ind := floatDigits[c]
            switch ind {
            // ...
            case dotInNumber:
                break non_decimal_loop
            }
            if value > uint64SafeToMultiple10 { // Ineffective overflow check
                return iter.readFloat64SlowPath()
            }
            value = (value << 3) + (value << 1) + uint64(ind) // Potential overflow here
        }
        // ...
    }
    ```

    The vulnerability lies in the multiplication within the loop. Even with the `uint64SafeToMultiple10` check, an attacker can craft a long enough sequence of digits to eventually cause `value` to overflow `uint64`, leading to incorrect calculation of the floating-point number.

*   **Security Test Case:**
    1.  Prepare a JSON payload containing a floating-point number with a very large integer part, for example: `{"field": 922337203685477580700000.1}`. This number is designed to cause an overflow when parsed as a `uint64` during the fast path float parsing.
    2.  Write a Go program that uses `json-iterator/go` to unmarshal this JSON payload into a struct containing a `float64` field.
    3.  Execute the program and observe the parsed `float64` value.
    4.  Verify that the parsed value is not the expected value `922337203685477580700000.1` due to integer overflow during parsing.
    5.  Compare the result with the standard `encoding/json` library, which should handle this case correctly (though possibly slower).

    ```go
    package main

    import (
        "fmt"
        jsoniter "github.com/json-iterator/go"
        "encoding/json"
    )

    type TestStruct struct {
        Field float64 `json:"field"`
    }

    func main() {
        jsonPayload := []byte(`{"field": 922337203685477580700000.1}`)

        // Test with json-iterator
        var testStructJsoniter TestStruct
        err := jsoniter.Unmarshal(jsonPayload, &testStructJsoniter)
        if err != nil {
            fmt.Println("jsoniter Unmarshal error:", err)
            return
        }
        fmt.Println("jsoniter Parsed value:", testStructJsoniter.Field)

        // Test with encoding/json
        var testStructEncodingJson TestStruct
        err = json.Unmarshal(jsonPayload, &testStructEncodingJson)
        if err != nil {
            fmt.Println("encoding/json Unmarshal error:", err)
            return
        }
        fmt.Println("encoding/json Parsed value:", testStructEncodingJson.Field)
    }
    ```

    **Expected Result:** The `jsoniter` parsed value will be significantly different from the expected value due to integer overflow, while `encoding/json` should parse it correctly (though possibly slower). This demonstrates the integer overflow vulnerability in `json-iterator/go`.

#### 2. Integer Overflow in Unsigned Integer Parsing (`readUint32` and `readUint64`)

*   **Vulnerability Name:** Integer Overflow in Unsigned Integer Parsing
*   **Description:**
    1.  The `readUint32` and `readUint64` functions in `iter_int.go` use integer arithmetic to parse unsigned integer numbers.
    2.  These functions accumulate the integer value by multiplying the current value by 10 and adding the next digit: `value = (value << 3) + (value << 1) + uint32(ind) // value = value * 10 + ind;` or `value = (value << 3) + (value << 1) + uint64(ind) // value = value * 10 + ind;`.
    3.  There is a check `if value > uint32SafeToMultiply10` (for `readUint32`) and `if value > uint64SafeToMultiple10` (for `readUint64`) before the multiplication in the loop. However, `uint32SafeToMultiply10` and `uint64SafeToMultiple10` are not sufficiently small to prevent overflow when parsing very large integers.
    4.  If a JSON number representing a very large unsigned integer is provided, this multiplication can lead to an integer overflow.
    5.  This integer overflow can result in incorrect parsing of the unsigned integer number, potentially leading to unexpected behavior in applications using `json-iterator/go` to parse such JSON data.
*   **Impact:**
    *   Incorrect parsing of large unsigned integer numbers.
    *   Potential for application logic errors if the application relies on the parsed integer value.
    *   Although not directly exploitable for remote code execution or data breach, incorrect data parsing can lead to application-level vulnerabilities or misbehavior.
*   **Vulnerability Rank:** High
*   **Currently Implemented Mitigations:**
    *   There are checks `if value > uint32SafeToMultiply10` in `readUint32` and `if value > uint64SafeToMultiple10` in `readUint64`, but these constants are not effective enough to prevent overflows for very large numbers.
    *   Wrap-around check `if value2 < value` after multiplication, which detects overflow after it happened, but the value is already corrupted.
    *   The project includes tests in `value_tests/int_test.go`, specifically `Test_read_int_overflow`, which indicate awareness of integer overflow issues and include tests that trigger errors on integer overflow. However, these tests do not fully prevent the vulnerability of incorrect parsing due to integer overflow before the error is detected.
*   **Missing Mitigations:**
    *   Implement robust overflow checking during the integer parsing phase in `readUint32` and `readUint64`.
    *   Consider using `big.Int` or similar arbitrary-precision arithmetic for parsing very large numbers to avoid overflow issues, especially when high precision is not strictly required but correct parsing is critical.
    *   Alternatively, limit the size of the integer part that is parsed using integer arithmetic and switch to `strconv.ParseUint` earlier for larger numbers.
*   **Preconditions:**
    *   The application must use `json-iterator/go` to parse JSON data.
    *   The application must parse JSON data containing unsigned integers.
    *   The attacker must be able to control the input JSON data and include an unsigned integer with a very large value that can cause integer overflow during parsing.
*   **Source Code Analysis:**
    *   File: `/code/iter_int.go`
    *   Function: `readUint32` and `readUint64`

    ```go
    func (iter *Iterator) readUint32(c byte) (ret uint32) {
        // ...
        for {
            for i := iter.head; i < iter.tail; i++ {
                ind = intDigits[iter.buf[i]]
                if ind == invalidCharForNumber {
                    iter.head = i
                    iter.assertInteger()
                    return value
                }
                if value > uint32SafeToMultiply10 { // Ineffective overflow check
                    value2 := (value << 3) + (value << 1) + uint32(ind)
                    if value2 < value { // Wrap-around check, but overflow already occurred
                        iter.ReportError("readUint32", "overflow")
                        return
                    }
                    value = value2
                    continue
                }
                value = (value << 3) + (value << 1) + uint32(ind) // Potential overflow here
            }
            // ...
        }
    }
    ```

    ```go
    func (iter *Iterator) readUint64(c byte) (ret uint64) {
        // ...
        for {
            for i := iter.head; i < iter.tail; i++ {
                ind = intDigits[iter.buf[i]]
                if ind == invalidCharForNumber {
                    iter.head = i
                    iter.assertInteger()
                    return value
                }
                if value > uint64SafeToMultiple10 { // Ineffective overflow check
                    value2 := (value << 3) + (value << 1) + uint64(ind)
                    if value2 < value { // Wrap-around check, but overflow already occurred
                        iter.ReportError("readUint64", "overflow")
                        return
                    }
                    value = value2
                    continue
                }
                value = (value << 3) + (value << 1) + uint64(ind) // Potential overflow here
            }
            // ...
        }
    }
    ```

    The vulnerability lies in the multiplication within the loop. Even with the `uint32SafeToMultiply10`/`uint64SafeToMultiple10` check and wrap-around detection, an attacker can craft a long enough sequence of digits to eventually cause `value` to overflow `uint32`/`uint64`, leading to incorrect calculation of the integer number.  The wrap-around check only detects the overflow after it has already occurred and corrupted the value.

*   **Security Test Case:**
    1.  Prepare a JSON payload containing a large unsigned integer, for example: `{"field": 184467440737095516150}`. This number is designed to cause an overflow when parsed as a `uint64` during the fast path integer parsing.
    2.  Write a Go program that uses `json-iterator/go` to unmarshal this JSON payload into a struct containing a `uint64` field.
    3.  Execute the program and observe the parsed `uint64` value.
    4.  Verify that the parsed value is not the expected value `184467440737095516150` due to integer overflow during parsing.
    5.  Compare the result with the standard `encoding/json` library, which should handle this case correctly (though possibly slower or by returning error).

    ```go
    package main

    import (
        "fmt"
        jsoniter "github.com/json-iterator/go"
        "encoding/json"
    )

    type TestStruct struct {
        Field uint64 `json:"field"`
    }

    func main() {
        jsonPayload := []byte(`{"field": 184467440737095516150}`)

        // Test with json-iterator
        var testStructJsoniter TestStruct
        err := jsoniter.Unmarshal(jsonPayload, &testStructJsoniter)
        if err != nil {
            fmt.Println("jsoniter Unmarshal error:", err)
            return
        }
        fmt.Println("jsoniter Parsed value:", testStructJsoniter.Field)

        // Test with encoding/json
        var testStructEncodingJson TestStruct
        err = json.Unmarshal(jsonPayload, &testStructEncodingJson)
        if err != nil {
            fmt.Println("encoding/json Unmarshal error:", err)
            return
        }
        fmt.Println("encoding/json Parsed value:", testStructEncodingJson.Field)
    }
    ```

    **Expected Result:** The `jsoniter` parsed value will be significantly different from the expected value due to integer overflow, while `encoding/json` may parse it correctly or return an error due to number exceeding uint64 range. This demonstrates the integer overflow vulnerability in `json-iterator/go` when parsing large unsigned integers.

#### 3. Unsafe Conversion of Byte Slice to String in Lazy JSON Value Representations

*   **Vulnerability Name:** Unsafe Conversion of Byte Slice to String in Lazy JSON Value Representations
*   **Description:**
    When the library lazily captures portions of the input JSON (for example via its “Any” API) it stores raw bytes in an internal buffer. Later, when the code needs to return a string representation of a lazy value it performs a conversion by reinterpreting the memory pointer of a byte slice as a string. For example, a method may look like:
    ```go
    func (any *objectLazyAny) ToString() string {
        return *(*string)(unsafe.Pointer(&any.buf))
    }
    ```
    Because the library internally reuses buffers (via pooling) for performance, the unsafe conversion does not copy the underlying data. As a result, an attacker who supplies carefully crafted JSON payloads—and then later triggers another JSON parse on the same goroutine (or process instance) that causes the reused buffer to be overwritten—may cause the previously obtained string value to change unexpectedly. This can lead to data corruption or misinterpretation of values.
*   **Impact:**
    *   **Data Integrity Issues:** A string obtained from a lazy conversion may later reflect entirely different data if its underlying buffer is reused.
    *   **Unexpected Behavior & Security Bypass:** Business logic that depends on the immutability of such string values may be tricked into accepting altered values.
    *   **Potential Information Leakage:** If cached data based on these string values is used in security decisions, an attacker might manipulate comparisons or validations.
*   **Vulnerability Rank:** High
*   **Currently Implemented Mitigations:**
    *   The library uses an aggressive pooling strategy to reuse internal buffers (for both iterators and streams) to maximize performance.
    *   However, in the lazy conversion functions (such as in `objectLazyAny.ToString()` and similar methods for arrays and numbers), the conversion from a byte slice to a string is performed by an unsafe pointer cast without an explicit copy of data.
*   **Missing Mitigations:**
    *   There is no explicit copying or freezing of the captured bytes before they are converted to a string.
    *   It is not documented (in the public API or usage guidelines) that strings returned by lazy methods are only transient “views” into internal pooled buffers.
    *   A safer conversion method (for example, by explicitly copying the byte slice into a new string) is missing.
*   **Preconditions:**
    *   The application is using the lazy parsing APIs (for example, by calling methods like `jsoniter.Get` to obtain a lazy Any value).
    *   The application retains or later reuses the string returned from the lazy value beyond the immediate JSON parse call.
    *   Internal buffers are recycled by the library (e.g. in a high–throughput environment), so that a later JSON parse reuses the same memory that backs the previously returned string.
*   **Source Code Analysis:**
    *   In the lazy representations (found in files such as “any_object.go”, “any_array.go”, etc.) the function to convert the internal byte slice to a string uses an unsafe pointer conversion without copying:
      ```go
      func (any *objectLazyAny) ToString() string {
          return *(*string)(unsafe.Pointer(&any.buf))
      }
      ```
    *   The buffer (`any.buf`) is originally populated with raw bytes from the input JSON and is later returned to the internal pool.
    *   Because the returned string “points” to the same memory as the byte slice, if the buffer is reused for a subsequent JSON parse the string may then reflect the new data rather than the original value.
*   **Security Test Case:**
    1.  **Setup:**
       - Build a test harness that uses the lazy Any API to parse a JSON payload containing one or more fields that yield a lazy value.
       - For example, send a JSON request that contains a nested object or array.
    2.  **Extraction:**
       - Immediately extract the lazy value by calling, for example,
         ```go
         lazyVal := jsoniter.Get(input, "key")
         originalStr := lazyVal.ToString()
         ```
       - Store the returned string in a variable.
    3.  **Trigger Buffer Reuse:**
       - In a separate request (or in a subsequent operation), parse a different JSON payload to force the internal buffer pool to reuse the same memory region.
         (For instance, simulate a high–throughput scenario where the same iterator or stream instance is used consecutively.)
    4.  **Verification:**
       - After the second parse, verify that the previously stored `originalStr` no longer holds the expected original value (or has been altered).
       - This confirms that the unsafe conversion leads to a “dangling” string whose content changes when the underlying buffer is reused.