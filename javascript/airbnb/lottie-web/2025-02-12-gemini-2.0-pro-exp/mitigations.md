# Mitigation Strategies Analysis for airbnb/lottie-web

## Mitigation Strategy: [Strict Schema Validation](./mitigation_strategies/strict_schema_validation.md)

1.  **Identify Requirements:** Determine the absolute minimum set of Lottie features your application *needs*.
2.  **Choose a Validator:** Select a JSON schema validator library (e.g., `ajv`).
3.  **Create a Restrictive Schema:** Craft a JSON schema that *strictly* defines the allowed structure and data types for your Lottie animations. Key aspects:
    *   **`additionalProperties: false`:** Prevents any undefined properties.
    *   **Type Restrictions:** Use specific types (`integer`, `number`, `string`, etc.).
    *   **Property-Specific Restrictions:**
        *   **`e` (Expressions):** If not needed, set `e: { type: 'null' }` or omit. If needed, *severely* restrict content.
        *   **`u` (Asset URLs):** Use a regular expression or custom validator to ensure URLs point to trusted locations.
        *   **`t` (Text Layers):** Consider `maxLength` restriction.
        *   **Array Lengths:** Use `minItems` and `maxItems`.
        *   **Numeric Ranges:** Use `minimum` and `maximum`.
4.  **Implement Validation:** Integrate the validator. Validate the Lottie JSON *before* passing it to `lottie-web`.
5.  **Error Handling:** If validation fails, *reject* the animation, log the error, and provide a user-friendly message.
6.  **Testing:** Test with valid and *invalid* Lottie files.

## Mitigation Strategy: [Disable Expressions](./mitigation_strategies/disable_expressions.md)

1.  **Assess Necessity:** Determine if expressions are truly required.
2.  **Control Animation Creation:** If you create animations, export *without* expressions.
3.  **Sanitize and Re-export (Third-Party):** If from third parties:
    *   Validate and sanitize (strict schema).
    *   Re-export *without* expressions after sanitization.
4.  **No Lottie-Web Option:** There's *no* `lottie-web` option to disable; prevent them in the JSON.

## Mitigation Strategy: [Sanitize Input](./mitigation_strategies/sanitize_input.md)

1.  **Identify Dangerous Strings:** Find string values that could contain malicious content (text layer content, asset URLs, etc.).
2.  **Choose a Sanitization Library:** Select an HTML sanitization library (e.g., `DOMPurify`).
3.  **Implement Sanitization:**
    *   *Before* passing JSON to `lottie-web`, sanitize identified strings.
    *   Don't modify the JSON structure; only sanitize *content*.
    *   Configure the library restrictively.
4.  **Testing:** Test with various inputs, including malicious payloads.

## Mitigation Strategy: [Resource Limits (Within Lottie JSON)](./mitigation_strategies/resource_limits__within_lottie_json_.md)

1.  **Limit Animation Complexity (Schema Validation):** Use schema validation to limit:
    *   Dimensions (`w`, `h`).
    *   Frame rate (`fr`).
    *   Number of layers/elements (`minItems`, `maxItems` for arrays).
    *   File size (server-side checks may be needed).
2. **Animation Authoring:** Educate creators about keeping animations simple.

## Mitigation Strategy: [Avoid Regular Expressions in Lottie Files](./mitigation_strategies/avoid_regular_expressions_in_lottie_files.md)

1. **Understand the Risk:** Regular expressions in Lottie files (especially in expressions) can cause ReDoS.
2. **Control Animation Creation:** Avoid using regular expressions in the animation data.
3. **Schema Validation (If Necessary):** If regex are *absolutely* required (strongly discouraged), add strict validation:
    * Limit regex complexity.
    * Limit input string length.
    * Test against ReDoS payloads.
4. **Sanitize and Re-export (Third-Party):** Remove regular expressions during sanitization.

