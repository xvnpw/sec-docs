```python
# Thinking Process for generating the Python code examples:

1. **Understand the Goal:** The request asks for Python code examples demonstrating the vulnerability and the mitigation strategies within the context of an application using the Guzzle library (even though Guzzle is PHP, the principles are transferable and the request is about demonstrating the concepts). The aim is to show *how* the vulnerability arises and how to fix it.

2. **Choose a Relevant Python HTTP Library:** Since Guzzle is PHP, we need a comparable Python library for making HTTP requests. `requests` is the most popular and analogous choice.

3. **Illustrate the Vulnerability:**
    * **Identify the Entry Point:**  Simulate user input. `input()` is the most straightforward way to do this.
    * **Direct Header Setting:** Show how to directly incorporate this user input into the `headers` dictionary when making a request with `requests`. This directly mirrors the vulnerable PHP code concept.
    * **Craft a Malicious Input:**  Provide an example of what a malicious input might look like, including `\r\n` for response splitting and a basic HTML payload for XSS.

4. **Demonstrate Mitigation Strategies:**

    * **Avoid Direct User Input:** Show the preferred approach: hardcoding or generating headers server-side. Provide a simple example.
    * **Strict Validation:**
        * **Allow List:** Create a list of allowed header names and check if the user-provided header is in it.
        * **Regular Expression:** Use `re.match` to validate the header value against a pattern that restricts allowed characters.
    * **Sanitization:**
        * **Encoding:** Use `urllib.parse.quote` to URL-encode the header value, which will escape potentially harmful characters.
        * **Stripping:**  Show how to remove `\r` and `\n` characters. Explain the limitations of this approach.

5. **Structure the Code:**
    * **Clear Sections:** Use comments to separate the vulnerable code and the different mitigation strategies.
    * **Executable Examples:** Make sure the code snippets are runnable and clearly demonstrate the concepts.
    * **Output/Explanation:** Include `print()` statements to show the generated headers and explain what's happening in each section. Explain *why* a particular mitigation works.

6. **Address the Guzzle Context (Even in Python):** While using `requests`, explicitly mention in the comments and explanations how these concepts translate to Guzzle's `headers` array. Emphasize that the underlying principle of not trusting user input for headers is the same.

7. **Review and Refine:**  Check for clarity, accuracy, and completeness. Ensure the code examples are easy to understand and follow. Make sure the explanations are clear about the security implications. For instance, initially, I might have only shown stripping, but then I'd realize encoding is generally a better approach and add that. I'd also double-check that the malicious input is actually effective in demonstrating the vulnerability.

By following these steps, the goal is to create Python code examples that effectively illustrate the header injection vulnerability and the corresponding mitigation strategies in a way that's understandable even within the context of the original PHP/Guzzle scenario.
```python
import requests
import re
from urllib.parse import quote

# --- Vulnerable Code Example ---
print("--- Vulnerable Code Example ---")
user_provided_header_value = input("Enter a value for a custom header: ")

headers = {
    "User-Agent": "My Application",
    "X-Custom-Input": user_provided_header_value
}

print("Generated Headers (Vulnerable):", headers)

# In a real application, this 'headers' dictionary would be passed to the 'requests' library
# which is analogous to Guzzle in PHP.
# requests.get("https://example.com", headers=headers)

print("\n**Potential Attack Scenario:**")
print("If the user enters something like: 'evil\\r\\n\\r\\nHTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\n\\r\\n<script>alert(\\'XSS\\')</script>'")
print("This could lead to response splitting and XSS.")

# --- Mitigation Strategy 1: Avoid Directly Using User Input ---
print("\n--- Mitigation Strategy 1: Avoid Directly Using User Input ---")
# Best practice: If possible, don't let users directly control header values.
# Instead, use predefined values or generate them server-side.

safe_headers = {
    "User-Agent": "My Application",
    "X-Request-ID": "generated_unique_id_123" # Example of a server-generated value
}
print("Generated Headers (Safe):", safe_headers)

# --- Mitigation Strategy 2: Strict Validation ---
print("\n--- Mitigation Strategy 2: Strict Validation ---")
user_provided_header_value_validate = input("Enter a value for a custom header (with validation): ")

# Example 1: Using an allow list
allowed_header_values = ["value1", "value2", "safe-value"]
if user_provided_header_value_validate in allowed_header_values:
    validated_headers = {
        "User-Agent": "My Application",
        "X-Custom-Validated": user_provided_header_value_validate
    }
    print("Generated Headers (Allow List Validation):", validated_headers)
else:
    print("Invalid header value. Not in the allowed list.")

# Example 2: Using regular expressions
pattern = r"^[a-zA-Z0-9-]+$"  # Allow only alphanumeric characters and hyphens
if re.match(pattern, user_provided_header_value_validate):
    validated_headers_regex = {
        "User-Agent": "My Application",
        "X-Custom-Validated-Regex": user_provided_header_value_validate
    }
    print("Generated Headers (Regex Validation):", validated_headers_regex)
else:
    print("Invalid header value. Does not match the required pattern.")

# --- Mitigation Strategy 3: Sanitization ---
print("\n--- Mitigation Strategy 3: Sanitization ---")
user_provided_header_value_sanitize = input("Enter a value for a custom header (for sanitization): ")

# Example 1: Encoding (URL encoding is a good general approach)
sanitized_encoded_value = quote(user_provided_header_value_sanitize)
sanitized_headers_encoded = {
    "User-Agent": "My Application",
    "X-Custom-Sanitized-Encoded": sanitized_encoded_value
}
print("Generated Headers (Encoded):", sanitized_headers_encoded)

# Example 2: Stripping potentially dangerous characters (less recommended than encoding)
sanitized_stripped_value = user_provided_header_value_sanitize.replace('\r', '').replace('\n', '')
sanitized_headers_stripped = {
    "User-Agent": "My Application",
    "X-Custom-Sanitized-Stripped": sanitized_stripped_value
}
print("Generated Headers (Stripped):", sanitized_headers_stripped)
print("**Note:** Stripping can be problematic if legitimate characters are removed or if new attack vectors using different characters emerge. Encoding is generally safer.")

# --- Mitigation Strategy 4: Use Predefined Header Constants (Less Applicable in Python's requests) ---
print("\n--- Mitigation Strategy 4: Use Predefined Header Constants (Conceptual) ---")
print("In PHP with Guzzle, you might use predefined constants for common headers.")
print("While Python's 'requests' doesn't have explicit header constants in the same way,")
print("using string literals for well-known headers is a similar concept for clarity and correctness.")
predefined_headers = {
    "User-Agent": "My Application",
    "Content-Type": "application/json" # Using string literal for a standard header
}
print("Generated Headers (Predefined - Conceptual):", predefined_headers)

print("\n**Key Takeaway:** Always treat user input as untrusted and implement robust validation and/or sanitization before using it to set HTTP headers in Guzzle (or any HTTP client library). Avoiding direct user control over headers is the most secure approach.")
```