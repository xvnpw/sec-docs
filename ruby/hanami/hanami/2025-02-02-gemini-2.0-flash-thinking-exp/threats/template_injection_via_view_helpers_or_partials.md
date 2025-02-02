## Deep Analysis: Template Injection via View Helpers or Partials in Hanami Applications

### 1. Define Objective of Deep Analysis

The objective of this deep analysis is to thoroughly investigate the threat of "Template Injection via View Helpers or Partials" in Hanami applications. This analysis aims to:

*   Understand the mechanisms by which this threat can be exploited within the Hanami framework.
*   Identify specific vulnerable areas within Hanami components (Views, View Helpers, Partials, Template Engine).
*   Elaborate on the potential impact of successful exploitation, differentiating between XSS and SSTI in this context.
*   Provide a detailed breakdown of mitigation strategies, tailored to Hanami development practices, and suggest additional preventative measures.
*   Offer actionable recommendations for the development team to secure Hanami applications against this threat.

### 2. Scope

This analysis will focus on the following aspects related to Template Injection in Hanami:

*   **Hanami Components:** Views, View Helpers, Partials, and the underlying Template Engine (Tilt, and potentially others if configurable).
*   **Threat Vectors:** Injection points within View Helpers and Partials that handle user-provided data.
*   **Attack Types:** Server-Side Template Injection (SSTI) and Cross-Site Scripting (XSS).
*   **Mitigation Strategies:**  Default escaping, input sanitization, secure coding practices within Hanami views and helpers, and Content Security Policy (CSP).
*   **Code Examples (Illustrative):**  Demonstrating vulnerable and secure code snippets within Hanami context.

This analysis will **not** cover:

*   Vulnerabilities in the underlying Ruby language or operating system.
*   Other types of injection attacks (e.g., SQL Injection, Command Injection) unless directly related to template injection.
*   Detailed code review of a specific Hanami application (this is a general threat analysis).

### 3. Methodology

The methodology for this deep analysis will involve:

1.  **Threat Modeling Review:** Re-examine the provided threat description to fully understand the nature of the vulnerability, its potential impact, and suggested mitigations.
2.  **Hanami Framework Analysis:**
    *   **Documentation Review:**  Study Hanami's official documentation, specifically sections related to Views, View Helpers, Partials, and Template Engines. Understand how data is passed and rendered within these components.
    *   **Code Examination (Conceptual):**  Analyze the general architecture of Hanami views and helpers to identify potential injection points. Consider how user input might flow into templates through these components.
    *   **Template Engine Behavior:** Investigate the default template engine (Tilt) and its escaping mechanisms. Determine if default escaping is enabled in Hanami and how developers can control escaping behavior.
3.  **Attack Vector Identification:**  Brainstorm potential scenarios where an attacker could inject malicious code through View Helpers or Partials. Consider different types of user input and how they might be processed in Hanami views.
4.  **Impact Assessment:**  Analyze the consequences of successful template injection, differentiating between XSS and SSTI in terms of severity and potential damage to the application and server.
5.  **Mitigation Strategy Evaluation:**  Assess the effectiveness of the provided mitigation strategies in the context of Hanami. Identify any gaps and suggest additional or more specific mitigation techniques tailored to Hanami development.
6.  **Documentation and Reporting:**  Compile the findings into a structured report (this document), detailing the analysis, findings, and actionable recommendations for the development team.

### 4. Deep Analysis of Template Injection via View Helpers or Partials

#### 4.1 Understanding Template Injection

Template Injection vulnerabilities arise when a web application dynamically embeds user-provided data into templates without proper sanitization or escaping. This allows attackers to manipulate the template rendering process, potentially leading to:

*   **Server-Side Template Injection (SSTI):**  The attacker injects code that is executed on the server by the template engine. This can lead to **Remote Code Execution (RCE)**, allowing the attacker to take complete control of the server, access sensitive data, or perform other malicious actions. SSTI is generally considered a **critical** vulnerability.
*   **Cross-Site Scripting (XSS):** The attacker injects client-side scripts (typically JavaScript) into the template. When a user views the rendered page, the malicious script executes in their browser. XSS can be used to steal session cookies, redirect users to malicious websites, deface websites, or perform actions on behalf of the user. XSS vulnerabilities are typically categorized as **high** to **medium** severity, depending on the context and impact.

In the context of Hanami, both SSTI and XSS are potential risks if View Helpers or Partials are not implemented securely.

#### 4.2 Hanami Components and Injection Points

*   **Views:** Hanami Views are Ruby classes responsible for preparing data for templates. They often use View Helpers and Partials to structure and render content. Views themselves are less likely to be direct injection points unless they directly manipulate template strings based on user input (which is generally bad practice in Hanami).
*   **View Helpers:** View Helpers are Ruby methods designed to encapsulate reusable view logic. They are frequently used to format data, generate HTML elements, or perform other view-related tasks. **View Helpers are a primary potential injection point.** If a View Helper takes user input as an argument and directly renders it into the template without proper escaping, it becomes vulnerable.
    *   **Example Vulnerable View Helper:**

        ```ruby
        # app/views/helpers/unsafe_helper.rb
        module Helpers
          module UnsafeHelper
            def unsafe_greeting(name)
              "<h1>Hello, #{name}!</h1>" # Directly embedding input without escaping
            end
          end
        end
        ```

        If the `name` argument comes from user input and is not sanitized, an attacker can inject HTML or JavaScript.

*   **Partials:** Partials are reusable template snippets. They are often used to render common UI elements or sections of a page. **Partials are another significant injection point.** If a Partial receives user-provided data as variables and renders it without escaping, it can be vulnerable.
    *   **Example Vulnerable Partial (`_unsafe_partial.html.erb`):**

        ```erb
        <p>User Comment: <%= comment %></p> <%# Directly embedding input without escaping %>
        ```

        If the `comment` variable contains unescaped user input, it can lead to XSS or, in more complex scenarios, SSTI depending on the template engine and context.

*   **Template Engine (Tilt):** Hanami uses Tilt as its default template engine, which supports various template languages like ERB, Haml, Slim, etc. The template engine itself is not inherently vulnerable, but its behavior regarding escaping and how it processes dynamic content is crucial. If default escaping is not enabled or if developers bypass escaping mechanisms, vulnerabilities can arise.

#### 4.3 Attack Vectors in Hanami Applications

1.  **Unsafe View Helpers:**
    *   A View Helper accepts user input (e.g., from request parameters, database records influenced by user input) as an argument.
    *   The View Helper directly embeds this input into the HTML output without proper escaping using methods like string interpolation or concatenation.
    *   The template renders the output of the View Helper, including the unescaped user input, leading to XSS or potentially SSTI.

2.  **Vulnerable Partials:**
    *   A Partial receives user input as a variable passed from a View or another Partial.
    *   The Partial directly renders this variable within the template without escaping.
    *   The template engine processes the Partial, rendering the unescaped user input, resulting in XSS or SSTI.

3.  **Dynamic View Logic based on User Input (Less Common but Possible):**
    *   While less common in typical Hanami applications, if view logic dynamically constructs template strings or template paths based on unvalidated user input, it could potentially lead to SSTI. This is a more advanced and less likely scenario in Hanami's intended architecture.

#### 4.4 Impact of Successful Exploitation

*   **Cross-Site Scripting (XSS):**
    *   **Impact:** Stealing user session cookies, account hijacking, website defacement, redirection to malicious sites, information disclosure (e.g., accessing user data on the page), performing actions on behalf of the user.
    *   **Severity:** High to Medium, depending on the sensitivity of the application and the scope of the XSS vulnerability.

*   **Server-Side Template Injection (SSTI):**
    *   **Impact:** **Remote Code Execution (RCE)** on the server, full server compromise, data breach, denial of service, modification of application data, and all impacts of XSS.
    *   **Severity:** **Critical**. SSTI is a highly severe vulnerability that can have catastrophic consequences.

**In Hanami, while SSTI is theoretically possible depending on the template engine and how dynamic logic is implemented, XSS is the more likely and common outcome of template injection vulnerabilities in View Helpers and Partials.** However, it's crucial to prevent both.

#### 4.5 Mitigation Strategies (Detailed and Hanami-Specific)

1.  **Default Escaping:**
    *   **Hanami Recommendation:** **Ensure that Hanami's template engine (Tilt) is configured to use default escaping.**  For ERB, this often means using `<%= ...h %>` or similar escaping mechanisms provided by the template engine.  Verify Hanami's default settings and ensure they are not overridden to disable escaping.
    *   **Action:** Review Hanami's configuration and documentation to confirm default escaping is enabled. If not, configure it appropriately.

2.  **Explicit Escaping in View Helpers and Partials:**
    *   **Hanami Recommendation:** **Always explicitly escape user-provided data within View Helpers and Partials, even if default escaping is enabled.** This provides an extra layer of security and clarity.
    *   **Action:**
        *   Use Hanami's or the template engine's escaping helpers (e.g., `h()` in ERB, `escape_html()` in Ruby) to sanitize user input before rendering it in HTML.
        *   **Example (Secure View Helper):**

            ```ruby
            # app/views/helpers/safe_helper.rb
            module Helpers
              module SafeHelper
                include Hanami::Helpers::EscapeHtmlHelper # Include escaping helpers

                def safe_greeting(name)
                  "<h1>Hello, #{escape_html(name)}!</h1>" # Explicitly escape the name
                end
              end
            end
            ```
        *   **Example (Secure Partial - `_safe_partial.html.erb`):**

            ```erb
            <p>User Comment: <%= escape_html(comment) %></p> <%# Explicitly escape the comment %>
            ```

3.  **Input Validation and Sanitization (Server-Side):**
    *   **Hanami Recommendation:** **Validate and sanitize user input on the server-side *before* it reaches Views, View Helpers, or Partials.** This is a crucial defense-in-depth measure.
    *   **Action:**
        *   Use Hanami's validations in your Entities or Actions to ensure data integrity and prevent malicious input from being processed.
        *   Sanitize input to remove or encode potentially harmful characters or code before storing it in the database or passing it to views. Libraries like `sanitize` in Ruby can be helpful for more complex sanitization needs.

4.  **Avoid Constructing View Logic Based on Unvalidated User Input:**
    *   **Hanami Recommendation:** **Do not dynamically generate View Helpers, Partial paths, or template logic based on unvalidated user input.** This significantly increases the risk of SSTI and other vulnerabilities.
    *   **Action:**  Refactor any code that dynamically constructs view logic based on user input. Use predefined View Helpers and Partials and pass validated data to them.

5.  **Content Security Policy (CSP):**
    *   **Hanami Recommendation:** **Implement a Content Security Policy (CSP) to mitigate the impact of XSS vulnerabilities.** CSP is a browser security mechanism that allows you to control the resources the browser is allowed to load, reducing the effectiveness of injected scripts.
    *   **Action:**
        *   Configure your Hanami application to send appropriate CSP headers.
        *   Start with a restrictive CSP policy and gradually relax it as needed, while ensuring it effectively mitigates XSS risks.

6.  **Regular Security Audits and Code Reviews:**
    *   **Hanami Recommendation:** **Conduct regular security audits and code reviews, specifically focusing on Views, View Helpers, and Partials, to identify potential template injection vulnerabilities.**
    *   **Action:**
        *   Include template injection testing in your security testing process.
        *   Train developers on secure coding practices for Hanami views and helpers, emphasizing the importance of escaping and input validation.

7.  **Framework and Dependency Updates:**
    *   **Hanami Recommendation:** **Keep Hanami and all its dependencies (including Tilt and other gems) up to date.** Security vulnerabilities are often discovered and patched in frameworks and libraries.
    *   **Action:** Regularly update Hanami and its dependencies to benefit from security fixes and improvements.

### 5. Conclusion and Recommendations

Template Injection via View Helpers or Partials is a critical threat to Hanami applications. While Hanami likely provides mechanisms for default escaping, developers must be vigilant and adopt secure coding practices to prevent both XSS and SSTI vulnerabilities.

**Recommendations for the Development Team:**

*   **Verify and Enforce Default Escaping:** Ensure Hanami's template engine is configured for default escaping and that this setting is consistently applied across the application.
*   **Mandatory Explicit Escaping in Training:** Train developers to *always* explicitly escape user-provided data in View Helpers and Partials, regardless of default escaping settings. Make this a standard coding practice.
*   **Prioritize Input Validation and Sanitization:** Implement robust server-side input validation and sanitization to minimize the risk of malicious data reaching the view layer.
*   **Implement Content Security Policy (CSP):** Deploy a restrictive CSP to provide an additional layer of defense against XSS attacks.
*   **Regular Security Audits and Code Reviews:** Incorporate security audits and code reviews into the development lifecycle, specifically focusing on template injection vulnerabilities in views and helpers.
*   **Automated Security Testing:** Integrate automated security scanning tools into the CI/CD pipeline to detect potential template injection vulnerabilities early in the development process.

By diligently implementing these mitigation strategies and fostering a security-conscious development culture, the team can significantly reduce the risk of template injection vulnerabilities in Hanami applications and protect users and the application itself.