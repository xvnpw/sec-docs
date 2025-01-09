## Deep Dive Analysis: Cross-Site Scripting (XSS) through Unescaped Template Output in Hanami

This analysis delves into the attack surface of Cross-Site Scripting (XSS) through unescaped template output within a Hanami application. We will explore the mechanics, Hanami's role, potential impacts, and provide a comprehensive set of mitigation strategies.

**1. Understanding the Vulnerability: XSS through Unescaped Template Output**

At its core, this vulnerability arises when an application renders user-controlled or untrusted data directly into HTML templates without proper sanitization or escaping. This allows attackers to inject malicious scripts that will be executed within the victim's browser when they view the affected page.

**Key Concepts:**

* **User-Controlled Data:**  Data originating from user input, such as form submissions, URL parameters, cookies, or even data retrieved from external sources that is influenced by users.
* **Untrusted Data:** Any data that hasn't been explicitly verified and sanitized by the application. This includes data from databases, external APIs, or any source outside the direct control of the application.
* **HTML Templates:** Files that define the structure and presentation of web pages. In Hanami, these are typically ERB files.
* **Escaping:** The process of converting potentially harmful characters (e.g., `<`, `>`, `"`, `'`, `&`) into their HTML entities (e.g., `&lt;`, `&gt;`, `&quot;`, `&#39;`, `&amp;`). This prevents the browser from interpreting them as HTML or JavaScript code.

**The Attack Flow:**

1. **Injection:** An attacker crafts malicious input containing JavaScript code (the payload).
2. **Transmission:** This malicious input is submitted to the Hanami application, often through URL parameters or form fields.
3. **Processing:** The Hanami action receives the input and passes it to the template.
4. **Vulnerable Rendering:** The template directly renders the attacker's input without escaping.
5. **Execution:** The victim's browser receives the HTML containing the injected script and executes it, leading to various malicious outcomes.

**2. Hanami's Contribution to the Attack Surface (ERB and Developer Responsibility)**

Hanami, by default, utilizes Embedded Ruby (ERB) for its templating engine. While ERB provides mechanisms for escaping output, it doesn't enforce it automatically. This design choice places the responsibility squarely on the developer to explicitly escape any potentially untrusted data before rendering it in the template.

**Specific Points:**

* **ERB's Explicit Nature:** ERB's `<%= ... %>` tag directly evaluates the Ruby code within and inserts the result into the HTML. If the result is a string containing HTML markup, it will be rendered as such.
* **`raw()` Helper:** Hanami provides the `raw()` helper, which explicitly tells the template engine *not* to escape the provided string. While useful for rendering trusted HTML, misuse of `raw()` is a common source of XSS vulnerabilities.
* **Lack of Default Automatic Escaping:** Unlike some other frameworks that automatically escape output by default, Hanami requires developers to be conscious of escaping. This can lead to vulnerabilities if developers are unaware of the risk or forget to implement proper escaping.
* **Component-Based Architecture:** While Hanami's component-based architecture promotes modularity, it doesn't inherently prevent XSS within individual components if proper escaping isn't applied in their templates.

**3. Deep Dive into the Example:**

The provided example perfectly illustrates the vulnerability:

```ruby
# Action
module Web::Controllers::Users
  class Show
    include Web::Action

    expose :name

    def call(params)
      @name = params[:name]
    end
  end
end

# Template (apps/web/templates/users/show.html.erb)
<p><%= @name %></p>
```

If a user navigates to `/users/1?name=<script>alert('XSS')</script>`, the following happens:

1. The `Show` action receives the `name` parameter.
2. The `@name` instance variable is set to the malicious string.
3. The template renders the `<p>` tag, directly inserting the value of `@name`.
4. The browser interprets `<script>alert('XSS')</script>` as JavaScript code and executes the alert.

This simple example highlights the direct consequence of rendering unescaped user input.

**4. Impact of Successful Exploitation (Beyond the Basics):**

While the provided impact description is accurate, let's elaborate on the potential consequences:

* **Account Takeover:**
    * **Session Hijacking:** Attackers can steal session cookies through JavaScript and use them to impersonate the victim.
    * **Credential Theft:**  Malicious scripts can capture keystrokes or redirect users to fake login pages to steal usernames and passwords.
* **Session Hijacking (Detailed):**  Beyond simply stealing the cookie, attackers can use XSS to:
    * **Send authenticated requests:** Execute actions on behalf of the logged-in user.
    * **Modify user data:** Change profile information, preferences, or even financial details.
    * **Access sensitive information:** View restricted content or data accessible to the authenticated user.
* **Defacement (Beyond Simple Alteration):**
    * **Reputation Damage:** Displaying offensive content or altering the site's branding can severely damage the application's reputation.
    * **Phishing Attacks:** Injecting fake login forms or misleading content to trick users into revealing sensitive information.
* **Redirection to Malicious Sites (Sophisticated Attacks):**
    * **Drive-by Downloads:** Redirecting users to websites that automatically download malware.
    * **Exploit Kits:** Leading users to sites that attempt to exploit vulnerabilities in their browsers or plugins.
    * **Social Engineering:** Redirecting users to realistic-looking but fake websites designed to steal credentials or personal information.
* **Information Disclosure:**
    * **Accessing Browser Data:**  Scripts can potentially access browser history, local storage, and other sensitive information.
    * **Internal Network Scanning:** In some scenarios, XSS can be used to probe internal networks.
* **Denial of Service (Indirect):**  While not a direct DoS, injecting resource-intensive scripts can degrade the user experience or even crash the user's browser.

**5. Comprehensive Mitigation Strategies:**

Building upon the initial mitigation strategies, let's provide a more detailed and actionable approach:

* **Prioritize Automatic Escaping:**
    * **Investigate Hanami Extensions/Libraries:** Explore if any community-developed gems or extensions provide automatic escaping as a configuration option. While not default, such options might exist.
    * **Custom Helper Implementation:** Consider creating a custom Hanami helper that automatically escapes output by default, requiring explicit opt-out for unescaped content. This shifts the burden to explicitly declaring unescaped content.
* **Enforce Explicit Escaping Rigorously:**
    * **Consistent Use of `escape_html()`:**  Train developers to consistently use the `escape_html()` helper (or its alias `h()`) for all potentially untrusted data rendered in templates.
    * **Context-Aware Escaping:** Understand that different contexts require different escaping methods. For example, escaping for HTML attributes is different from escaping for JavaScript strings. Hanami's `escape_javascript()` helper is crucial when embedding data within `<script>` tags or event handlers.
    * **Code Reviews Focused on Escaping:** Implement mandatory code reviews with a specific focus on verifying proper escaping in templates.
* **Strengthen Content Security Policy (CSP):**
    * **`default-src 'self'`:** Start with a restrictive default policy that only allows resources from the application's origin.
    * **`script-src` Directive:**  Carefully define allowed sources for JavaScript. Avoid `'unsafe-inline'` and `'unsafe-eval'` unless absolutely necessary and with a strong justification. Consider using nonces or hashes for inline scripts.
    * **`object-src 'none'`:** Disable the `<object>`, `<embed>`, and `<applet>` elements to prevent Flash-based XSS.
    * **`style-src` Directive:** Control the sources of CSS.
    * **Report-URI or report-to:** Configure CSP reporting to monitor and identify potential XSS attempts.
* **Implement Robust Input Validation and Sanitization:**
    * **Validation at the Controller Level:** Validate all user input to ensure it conforms to expected formats and types. Reject invalid input.
    * **Sanitization for Rich Text:** If the application needs to allow rich text input (e.g., using a WYSIWYG editor), use a well-vetted HTML sanitizer library (like Loofah or Sanitize) to remove potentially malicious tags and attributes. Be extremely cautious with sanitization and prefer output escaping whenever possible.
    * **Principle of Least Privilege:** Only store the necessary data. Avoid storing raw, potentially malicious input if it can be processed and rendered safely.
* **Employ Template Security Linters:**
    * **Integrate Linters into the Development Workflow:** Utilize linters specifically designed to detect potential XSS vulnerabilities in ERB templates. These tools can identify instances where variables are rendered without proper escaping.
    * **Static Analysis Tools:** Incorporate static analysis tools that can analyze the entire codebase for potential vulnerabilities, including XSS.
* **Regular Security Audits and Penetration Testing:**
    * **Professional Security Assessments:** Engage security experts to conduct regular audits and penetration tests to identify vulnerabilities that might have been missed during development.
    * **Automated Security Scanning:** Use automated tools to scan the application for common web vulnerabilities, including XSS.
* **Developer Training and Awareness:**
    * **Educate Developers on XSS Risks:** Ensure developers understand the mechanics of XSS attacks and the importance of secure coding practices.
    * **Promote Secure Templating Practices:** Emphasize the need for explicit escaping and the dangers of rendering untrusted data directly.
* **Framework and Dependency Updates:**
    * **Stay Up-to-Date:** Regularly update Hanami and all its dependencies to patch known security vulnerabilities.
    * **Monitor Security Advisories:** Subscribe to security advisories for Hanami and related libraries to stay informed about potential threats.
* **Consider Using Alternative Templating Engines (with Caution):** While ERB is the default, Hanami allows the use of other templating engines. However, switching engines doesn't automatically solve XSS issues; developers still need to understand and apply appropriate escaping mechanisms for the chosen engine.

**6. Detection and Prevention During Development:**

* **Code Reviews:** Implement mandatory code reviews with a strong focus on template rendering and data handling.
* **Static Analysis Tools:** Integrate static analysis tools into the CI/CD pipeline to automatically scan for potential XSS vulnerabilities.
* **Template Linters:** Use linters specifically designed for ERB templates to identify missing escaping.
* **Security Testing in Development:** Encourage developers to perform basic security testing, including attempting to inject simple XSS payloads during development.

**7. Testing Strategies for XSS through Unescaped Template Output:**

* **Manual Testing:**
    * **Simple Payloads:** Start with basic payloads like `<script>alert('XSS')</script>` to confirm the vulnerability.
    * **Context-Specific Payloads:** Craft payloads that are relevant to the specific context where the data is being rendered (e.g., within HTML attributes, JavaScript strings).
    * **Bypass Attempts:** Try various encoding techniques (e.g., URL encoding, HTML entity encoding) to see if the application is vulnerable to bypasses.
* **Automated Testing:**
    * **Dedicated XSS Scanning Tools:** Utilize specialized tools like OWASP ZAP, Burp Suite, or Acunetix to automatically scan the application for XSS vulnerabilities.
    * **Integration with CI/CD:** Integrate security testing tools into the CI/CD pipeline to automatically test for XSS with each code change.
    * **Unit and Integration Tests:** Write tests that specifically target template rendering and verify that data is being properly escaped.

**8. Code Examples (Vulnerable and Secure):**

**Vulnerable Code:**

```ruby
# Action
module Web::Controllers::Posts
  class Show
    include Web::Action

    expose :title

    def call(params)
      @title = params[:title]
    end
  end
end

# Template (apps/web/templates/posts/show.html.erb)
<h1><%= @title %></h1>
```

**Secure Code:**

```ruby
# Action (No changes needed in this simple case)
module Web::Controllers::Posts
  class Show
    include Web::Action

    expose :title

    def call(params)
      @title = params[:title]
    end
  end
end

# Template (apps/web/templates/posts/show.html.erb)
<h1><%= escape_html(@title) %></h1>
```

or using the alias:

```erb
<h1><%= h(@title) %></h1>
```

**Example using `raw()` (Use with Extreme Caution):**

```ruby
# Action
module Web::Controllers::Articles
  class Show
    include Web::Action

    expose :content

    def call(params)
      # Assume content is sanitized elsewhere and trusted
      @content = "<p>This is <strong>trusted</strong> content.</p>"
    end
  end
end

# Template (apps/web/templates/articles/show.html.erb)
<div class="article-content"><%= raw(@content) %></div>
```

**Conclusion:**

Cross-Site Scripting through unescaped template output is a significant attack surface in Hanami applications due to ERB's explicit nature. Developers must be acutely aware of the risks and consistently apply proper escaping techniques. A multi-layered approach, combining automatic escaping where possible, rigorous explicit escaping, strong CSP implementation, input validation, security testing, and developer training, is crucial to effectively mitigate this vulnerability and build secure Hanami applications. Ignoring this attack surface can lead to severe consequences, impacting user security and the application's integrity.
