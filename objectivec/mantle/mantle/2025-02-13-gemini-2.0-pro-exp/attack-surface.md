# Attack Surface Analysis for mantle/mantle

## Attack Surface: [1. Data Exposure via Model Mapping](./attack_surfaces/1__data_exposure_via_model_mapping.md)

*   **Description:** Unintentional exposure of sensitive data through the JSON serialization/deserialization process due to misconfigured `MTLModel` mappings.
*   **Mantle Contribution:** Mantle's core functionality – automatic mapping between model properties and JSON keys (via `+JSONKeyPathsByPropertyKey`) – creates this risk if not carefully managed. This is a *direct* consequence of Mantle's design.
*   **Example:** A `User` model has a `passwordHash` property. If `+JSONKeyPathsByPropertyKey` doesn't explicitly exclude it, the hash is exposed in serialized JSON.
*   **Impact:** Leakage of sensitive data (passwords, API keys, internal IDs), leading to unauthorized access or data breaches.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Explicit and Minimal Mapping:** Define `+JSONKeyPathsByPropertyKey` meticulously. *Only* include properties intended for external representation. Use `NSNull` to explicitly exclude properties.
    *   **Property Renaming:** Use different keys for JSON representation than internal property names (e.g., `internalUserID` maps to `userId` in JSON).
    *   **`NSValueTransformer` Sanitization:** Use `NSValueTransformer` to sanitize or transform data *before* serialization (e.g., hashing, replacing with placeholders).
    *   **Mandatory Code Reviews:** Require code reviews specifically for `MTLModel` definitions to prevent accidental exposure.

## Attack Surface: [2. Type Confusion with `NSValueTransformer`](./attack_surfaces/2__type_confusion_with__nsvaluetransformer_.md)

*   **Description:** Exploitation of vulnerabilities in *custom* `NSValueTransformer` implementations to inject unexpected data types, leading to crashes or potentially code execution.
*   **Mantle Contribution:** Mantle's heavy reliance on `NSValueTransformer` for data type conversion is the direct source of this risk. While `NSValueTransformer` itself is an Apple class, Mantle's *usage pattern* makes this a key attack surface.
*   **Example:** A custom transformer expects a string but doesn't validate. An attacker injects a dictionary, causing a crash or unexpected behavior.
*   **Impact:** Application crashes, denial of service, *potential* for arbitrary code execution (if type confusion leads to memory corruption or logic flaws).
*   **Risk Severity:** High (potentially Critical if code execution is possible)
*   **Mitigation Strategies:**
    *   **Rigorous Type Checking:** Within `transformedValue:` and `reverseTransformedValue:`, *always* validate the input type using `isKindOfClass:` *before* any operations.
    *   **Input Sanitization:** After type checking, sanitize the input to ensure it conforms to expected formats (e.g., date format validation).
    *   **Robust Error Handling:** Return `nil` (and set an `NSError`) for invalid input. Do *not* attempt to "recover."
    *   **Fuzz Testing:** Fuzz test custom transformers with a wide range of unexpected inputs.
    *   **Prefer Built-in Transformers:** Use Apple's built-in `NSValueTransformer` subclasses whenever possible.
    *   **Minimize Transformer Complexity:** Keep custom transformers as simple as possible.

## Attack Surface: [3. Deserialization Attacks (via `NSSecureCoding`)](./attack_surfaces/3__deserialization_attacks__via__nssecurecoding__.md)

*   **Description:** Exploitation of vulnerabilities during the unarchiving (deserialization) of Mantle models, potentially leading to object injection and arbitrary code execution.
*   **Mantle Contribution:** Mantle models *commonly* conform to `NSSecureCoding` for persistence. This *intended use* of Mantle, combined with the inherent risks of deserialization, makes this a direct Mantle-related attack surface.
*   **Example:** An attacker provides a crafted archive with an object of an unexpected class. Using `decodeObjectForKey:` without class validation instantiates the attacker's object, potentially executing malicious code.
*   **Impact:** Arbitrary code execution, complete system compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Mandatory `decodeObjectOfClass:forKey:`:** *Always* use `decodeObjectOfClass:forKey:` (or `decodeObjectOfClasses:forKey:`) to enforce class validation during unarchiving. Specify the expected class(es) explicitly.
    *   **Avoid Custom `initWithCoder:`:** Rely on Mantle's default `initWithCoder:` implementation if at all possible. If customization is *essential*, it must be thoroughly audited.
    *   **Post-Unarchiving Validation:** Even after class-validated unarchiving, perform additional input validation on the unarchived object's properties.

