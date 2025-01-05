```python
# This is a conceptual Python script to illustrate potential checks and mitigations.
# It is not a complete or runnable solution for Mattermost.

def sanitize_message(message):
    """
    Conceptual function to sanitize message content.
    In reality, this would be a more complex process.
    """
    # Example: Basic HTML escaping
    message = message.replace("<", "&lt;")
    message = message.replace(">", "&gt;")
    # More advanced sanitization would involve parsing and filtering HTML tags and attributes.
    return message

def render_message(message, use_csp=True):
    """
    Conceptual function to render a message for display.
    """
    sanitized_message = sanitize_message(message)
    html_output = f"<p>{sanitized_message}</p>"

    if use_csp:
        # In a real application, CSP headers would be set at the server level.
        # This is a simplified illustration.
        csp_header = "Content-Security-Policy: default-src 'self';"
        print(f"Setting CSP Header: {csp_header}")

    return html_output

# Example of a malicious message
malicious_message = "<script>alert('XSS Vulnerability!')</script> This is a message."

# Rendering the malicious message with sanitization
rendered_safe = render_message(malicious_message)
print(f"Rendered (Sanitized): {rendered_safe}")

# Rendering without proper sanitization (Illustrative of the vulnerability)
def render_message_vulnerable(message):
    """
    Conceptual vulnerable rendering function.
    """
    html_output = f"<p>{message}</p>"
    return html_output

rendered_vulnerable = render_message_vulnerable(malicious_message)
print(f"Rendered (Vulnerable): {rendered_vulnerable}")

# ---  Illustrative CSP Enforcement (Conceptual) ---
# In a real browser, CSP would prevent the script from executing.

def simulate_browser_with_csp(html_content):
    """
    Conceptual simulation of a browser enforcing CSP.
    """
    if "<script>" in html_content:
        print("CSP Violation: Inline script blocked.")
    else:
        print("Rendering content (CSP Compliant).")
        # In a real browser, the HTML would be rendered.

print("\nSimulating Browser with CSP:")
simulate_browser_with_csp(rendered_safe)
simulate_browser_with_csp(rendered_vulnerable)
```