Here is the combined list of vulnerabilities, formatted as markdown:

## Combined Vulnerability List for mapstructure Library

### 1. Potential Type Confusion via Decode Hooks

- **Description:**
    1. An attacker crafts a malicious input map.
    2. This input is designed to be decoded into a Go struct using the `mapstructure` library.
    3. The decoding process utilizes a `DecodeHookFunc` that is intended to perform type conversions or data sanitization.
    4. However, due to a vulnerability in the decode hook logic or the way `mapstructure` handles decode hooks, the attacker can cause a type confusion.
    5. This type confusion allows the decode hook to return a value of an unexpected type, which is then incorrectly processed by the `mapstructure` library in subsequent decoding steps.
    6. This can lead to unexpected behavior, such as incorrect data being written to the target struct, program logic bypasses, or potentially memory corruption if the type confusion is severe enough and mishandled later in the application using the decoded struct.
    7. **Specific Scenario with WeaklyTypedInput:** When `WeaklyTypedInput` is enabled, the initial type checking might be bypassed.  The `DecodeHookFunc`, expecting a certain type based on the (potentially bypassed) initial type check, might receive a different type than anticipated. This type mismatch within the `DecodeHookFunc` can further exacerbate type confusion issues.

- **Impact:**
    - High: Depending on the application logic that uses the decoded struct, this vulnerability can lead to data integrity issues, application malfunctions, or in severe cases, potentially escalate to other vulnerabilities if the type confusion allows bypassing security checks or corrupting memory in a way that can be exploited. The impact is highly application-dependent, but the potential for significant issues is there. Type confusion can lead to unexpected program behavior and in certain scenarios, if the `DecodeHookFunc` interacts with external systems or performs security-sensitive operations based on type assumptions, this vulnerability could be escalated to information disclosure or other more severe impacts depending on the application context.

- **Vulnerability Rank:** high

- **Currently implemented mitigations:**
    - None in the `mapstructure` library itself to prevent misuse of decode hooks. The library provides the functionality of decode hooks but relies on the user to implement them securely and correctly.  Similarly, there are no mitigations in the `mapstructure` library to specifically address the interaction issue between `WeaklyTypedInput` and `DecodeHookFunc`.

- **Missing mitigations:**
    - Input validation within the `mapstructure` library to verify the type returned by `DecodeHookFunc` against the expected type.
    - Clearer documentation and examples emphasizing the security implications of using decode hooks and the importance of careful type handling within them.
    - Potentially, a mechanism to enforce stricter type contracts for decode hooks, although this might reduce flexibility.
    - **Input Validation within Decode Hooks:** Decode hooks should implement robust type checking and validation of the input `data` they receive, especially when used with `WeaklyTypedInput`. This is currently the responsibility of the user of the library, but the potential for misuse could be highlighted more clearly in documentation and examples.
    - **Documentation Warning:**  Stronger warnings in the documentation about the potential risks of using `WeaklyTypedInput` in conjunction with `DecodeHookFunc` without careful type handling within the hooks.
    - **Example of Safe Decode Hook Usage with WeaklyTypedInput:** Provide examples in documentation and tests demonstrating how to write decode hooks that are resilient to weakly typed input and perform necessary type assertions and error handling.

- **Preconditions:**
    - The application using `mapstructure` must be using `DecodeHookFunc`.
    - The attacker must have control over the input data being decoded.
    - The decode hook implementation must have a flaw that allows it to return an unexpected type under certain input conditions.
    - **For WeaklyTypedInput scenario:** `DecoderConfig` is configured with `WeaklyTypedInput: true`. The target struct and decode hook logic are designed in a way that a type mismatch in the hook can lead to exploitable behavior.

- **Source code analysis:**
    1. **File: /code/decode_hooks.go**
    2. The `DecodeHookExec` function is responsible for executing decode hooks:
       ```go
       func DecodeHookExec(
           raw DecodeHookFunc,
           from reflect.Value, to reflect.Value) (interface{}, error) {

           switch f := typedDecodeHook(raw).(type) {
           case DecodeHookFuncType:
               return f(from.Type(), to.Type(), from.Interface())
           case DecodeHookFuncKind:
               return f(from.Kind(), to.Kind(), from.Interface())
           case DecodeHookFuncValue:
               return f(from, to)
           default:
               return nil, errors.New("invalid decode hook signature")
           }
       }
       ```
    3. This function calls the user-provided decode hook and directly returns the `interface{}` result.
    4. **File: /code/mapstructure.go**
    5. The `decode` function, which is the core decoding logic, calls `DecodeHookExec`:
       ```go
       if d.config.DecodeHook != nil {
           // We have a DecodeHook, so let's pre-process the input.
           var err error
           input, err = DecodeHookExec(d.config.DecodeHook, inputVal, outVal)
           if err != nil {
               return fmt.Errorf("error decoding '%s': %w", name, err)
           }
       }
       ```
    6. The result of `DecodeHookExec` is assigned back to `input` and used in subsequent decoding steps (`d.decode("", input, reflect.ValueOf(d.config.Result).Elem())`).
    7. **Vulnerability:** If a malicious `DecodeHookFunc` (either intentionally crafted by a developer or due to a vulnerability in a legitimate hook) returns a value with a type that is not expected by the subsequent `decode` logic, type confusion can occur. For example, a hook intended to sanitize strings might mistakenly return an integer or a struct in certain edge cases. The `decode` function might then try to process this unexpected type as if it were the original expected type, leading to incorrect behavior or errors. The `mapstructure` library does not perform runtime type checks on the return value of the decode hook to ensure it's compatible with the expected decoding path.
    8. **WeaklyTypedInput Scenario Analysis:**
        - **`mapstructure.go:DecodeHookExec` Function:** The `DecodeHookExec` function calls the user-provided decode hook (`raw`). If `WeaklyTypedInput` is enabled, the `from` `reflect.Value` might represent a weakly-typed value that has undergone type conversion.
        - **`mapstructure.go:decode*` Functions:** The various `decode*` functions (e.g., `decodeInt`, `decodeString`, `decodeBool`) handle type conversions when `WeaklyTypedInput` is true. These conversions happen *before* the `DecodeHookFunc` is called. The `decode` function is the core decoding logic. The `DecodeHookExec` is called *before* the type-specific decoding logic.
        - **Vulnerability Scenario with WeaklyTypedInput:** Consider a struct with an integer field and a decode hook expecting an integer. If `WeaklyTypedInput` is enabled and the input map provides a string value for this field, the `decodeInt` function (or similar) might weakly convert the string to an integer *before* the decode hook is called. However, if the decode hook logic assumes the *original* input was an integer (perhaps for specific validation or processing), it could be confused by receiving a string that was weakly converted, leading to unexpected behavior.

- **Security test case:**
    1. **General Type Confusion Test Case:**
        1. Create a vulnerable `DecodeHookFunc` that, under a specific input condition, returns a value of an unexpected type. For example, a hook that should return a string but returns an integer when the input string is "SPECIAL_VALUE".
        2. Define a target struct that expects a string field.
        3. Craft an input map that includes the "SPECIAL_VALUE" for the field that will be processed by the vulnerable decode hook.
        4. Configure `mapstructure` decoder to use the vulnerable `DecodeHookFunc` and decode the malicious input map into the target struct.
        5. Assert that the decoding process does not result in an error (as basic type checks might pass), but the target struct field contains an unexpected value or type (e.g., an integer instead of a string, or a default value due to type mismatch) indicating type confusion.
        6. Demonstrate how this type confusion can be leveraged in a simple application scenario to cause unintended behavior, such as bypassing a validation check that assumes the field is always a string, while it's now an integer due to the hook's unexpected output.
    2. **WeaklyTypedInput Type Confusion Test Case:**
        1. **Define a vulnerable struct and decode hook:**
            ```go
            type VulnerableStruct struct {
                Value int
            }

            var typeConfusionTriggered bool

            decodeHook := func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
                if to == reflect.TypeOf(VulnerableStruct{}) {
                    // Intentionally incorrect type assertion to simulate vulnerability
                    strValue := data.(string) // Expecting string, but could be int due to weak type conversion
                    if strValue == "trigger" {
                        typeConfusionTriggered = true
                    }
                }
                return data, nil
            }
            ```
        2. **Craft a malicious input map:**
            ```go
            input := map[string]interface{}{
                "value": "123", // Intended to be weakly converted to int
            }
            ```
        3. **Configure Decoder with WeaklyTypedInput and the vulnerable decode hook:**
            ```go
            var result VulnerableStruct
            config := &DecoderConfig{
                WeaklyTypedInput: true,
                DecodeHook:      decodeHook,
                Result:           &result,
            }
            decoder, err := NewDecoder(config)
            if err != nil {
                panic(err)
            }
            ```
        4. **Execute Decode:**
            ```go
            err = decoder.Decode(input)
            if err != nil {
                panic(err)
            }
            ```
        5. **Assert vulnerability:** Check if `typeConfusionTriggered` is true, or if the program exhibits unexpected behavior due to the type confusion in the decode hook.
            ```go
            if typeConfusionTriggered {
                fmt.Println("Vulnerability Triggered: Type confusion occurred in decode hook.")
                // Fail the test or report vulnerability
            } else {
                fmt.Println("Vulnerability Not Triggered as expected (or mitigation in place).")
                // Pass the test if mitigation is expected
            }
            ```
        6. **Expected Result:** The test case should demonstrate that even though the input value is a string "123", due to `WeaklyTypedInput`, it gets weakly converted to an integer before reaching the decode hook. If the decode hook incorrectly asserts the type to be a string (as shown in the example), it will panic or exhibit unexpected behavior, demonstrating the type confusion vulnerability.

---

### 2. Information Disclosure via Detailed Error Messages in Type Conversion

- **Description:**
  The library’s various type‐conversion routines (for example, in functions such as `decodeInt`, `decodeString`, `decodeBool`, etc.) generate error messages that explicitly include the expected type, the actual type encountered, and even the raw input value. An external attacker who is able to supply untrusted (or crafted) input can deliberately send values with mismatched types (for instance, supplying an integer for a field defined as a string). When the conversion fails, the returned error message contains detailed internal information about the expected structure and type details. If these error messages are propagated—whether directly to a user in an API response or via logs that are accessible to an attacker—the internal implementation details of the system are disclosed.

- **Impact:**
  Attackers can leverage the detailed error messages to learn about the internal data structures and type expectations of the target application. This information can be used to craft further targeted attacks (such as using the exposed data model and type details to bypass validation or to improve probing of system behavior). In environments where error messages are returned to clients or stored in accessible logs, sensitive internal metadata may be disclosed.

- **Vulnerability Rank:** High

- **Currently Implemented Mitigations:**
  The library itself does not perform any sanitization or abstraction on these error messages. The errors are constructed directly via calls to functions such as `fmt.Errorf` (as seen in functions like `decodeInt`, `decodeString`, etc.) and then aggregated into a custom `Error` type (defined in *error.go*). There is no built‑in mechanism to remove or mask internal type names or raw data values from these messages.

- **Missing Mitigations:**
  A mitigating control would be to add a configuration option (or to modify the default behavior) so that when errors are generated during type conversion, the library either:  
  • Redacts or abstracts away internal type information and raw input data (for example, by replacing them with generic placeholders) before propagating the error, or  
  • Logs the full details only on an internal debug channel while returning a sanitized error message to a caller.  
  As it stands, no such mitigation exists in the library code.

- **Preconditions:**
  An attacker must be able to supply input data (for example, via a JSON payload or other data stream that is decoded by the application using this library) and—more critically—have the application return or log the detailed error messages to a location where the attacker can retrieve them. In other words, the vulnerability is exploitable when untrusted input is decoded and error details are not suitably sanitized before exposure.

- **Source Code Analysis:**
  - In functions such as `decodeInt` (and similarly in `decodeString`, `decodeBool`, etc.), after attempting to convert the input value to the expected type, the code uses a statement like:  
    ```go
    return fmt.Errorf("'%s' expected type '%s', got unconvertible type '%s', value: '%v'", name, val.Type(), dataVal.Type(), data)
    ```  
    This error string reveals the field name, the expected type (derived from the target struct), the actual dynamic type of the supplied data, and the unaltered value itself.
  - These errors are then aggregated into an `Error` struct (see *error.go*) that simply joins the messages together.  
  - Because there is no filtering or sanitization of the error text, if an application passes these errors along—whether in logs or as part of an HTTP response—the internal type and structure information becomes visible to any external party who can trigger a type mismatch.

- **Security Test Case:**
  1. **Setup:**  
     Create a simple struct that defines the expected type for a field. For example:
     ```go
     type User struct {
         Username string
     }
     ```
  2. **Malicious Input:**  
     Prepare an input map that deliberately uses the wrong type for the field:
     ```go
     input := map[string]interface{}{
         "Username": 123,  // the field expects a string
     }
     ```
  3. **Triggering the Vulnerability:**  
     Invoke the decoder:
     ```go
     var user User
     err := Decode(input, &user)
     if err != nil {
         // The error message will be returned.
         fmt.Println(err.Error())
     }
     ```
  4. **Observation:**  
     The returned error message should look similar to:
     ```
     'Username' expected type 'string', got unconvertible type 'int', value: '123'
     ```
     This confirms that internal type information and the raw input value are exposed.
  5. **Result:**  
     An attacker monitoring responses or logs where such errors are output could use the detailed information to map out internal data structures and refine further attacks.