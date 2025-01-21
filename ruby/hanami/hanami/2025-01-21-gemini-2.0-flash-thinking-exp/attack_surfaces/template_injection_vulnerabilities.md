## Deep Analysis of Template Injection Vulnerabilities in Hanami Applications

### 1. Define Objective of Deep Analysis

The primary objective of this deep analysis is to thoroughly examine the template injection attack surface within Hanami applications. This includes understanding how Hanami's templating mechanisms can be exploited, identifying potential attack vectors, assessing the impact of successful attacks, and providing comprehensive mitigation strategies tailored to the Hanami framework. We aim to provide actionable insights for the development team to secure their Hanami applications against template injection vulnerabilities.

### 2. Scope

This analysis will focus specifically on the following aspects related to template injection vulnerabilities in Hanami applications:

*   **Hanami's Templating Engines:**  We will analyze how Hanami integrates with and utilizes template engines like ERB and Haml, focusing on the potential for injecting malicious code through these engines.
*   **User Input Handling in Templates:** We will examine scenarios where user-provided data is directly or indirectly used within template rendering logic.
*   **Custom Template Helpers:**  The analysis will cover the risks associated with custom template helpers and their potential to introduce template injection vulnerabilities.
*   **Server-Side Template Injection (SSTI):** We will delve into the mechanisms and potential impact of SSTI in Hanami applications, including remote code execution.
*   **Client-Side Template Injection (CSTI) / Cross-Site Scripting (XSS):** We will analyze how template injection can lead to client-side vulnerabilities and their consequences.
*   **Mitigation Strategies within the Hanami Ecosystem:** We will explore and recommend specific mitigation techniques that leverage Hanami's features and best practices.

This analysis will *not* cover vulnerabilities within the underlying Ruby language or the specific implementation details of the ERB or Haml gems themselves, unless directly relevant to their interaction with Hanami.

### 3. Methodology

The methodology for this deep analysis will involve the following steps:

1. **Review of Provided Information:**  A thorough review of the provided "ATTACK SURFACE" description to understand the initial assessment and identified risks.
2. **Hanami Framework Analysis:** Examination of Hanami's official documentation, source code (where necessary), and community resources to understand its templating architecture and best practices for secure template rendering.
3. **Vulnerability Pattern Analysis:**  Identifying common patterns and scenarios that lead to template injection vulnerabilities in web applications, specifically within the context of Hanami.
4. **Attack Vector Identification:**  Mapping potential entry points for attackers to inject malicious code into Hanami templates. This includes analyzing how user input flows through the application and interacts with the templating engine.
5. **Impact Assessment:**  Evaluating the potential consequences of successful template injection attacks, considering both server-side and client-side impacts.
6. **Mitigation Strategy Formulation:**  Developing specific and actionable mitigation strategies tailored to the Hanami framework, focusing on leveraging its built-in features and recommending secure coding practices.
7. **Example Scenario Development:**  Creating illustrative examples of vulnerable code and corresponding secure implementations within a Hanami context.
8. **Documentation and Reporting:**  Compiling the findings, analysis, and recommendations into a clear and concise report (this document).

### 4. Deep Analysis of Template Injection Vulnerabilities in Hanami

#### 4.1 Introduction

Template injection vulnerabilities arise when an attacker can influence the template code that is executed by the template engine. In the context of Hanami, this means manipulating the ERB or Haml code that gets rendered to generate the final HTML output. The core issue is the lack of proper sanitization or escaping of user-provided data before it's embedded within the template.

#### 4.2 Hanami's Template Engines and Potential Pitfalls

Hanami relies on template engines like ERB (Embedded Ruby) and Haml (HTML Abstraction Markup Language) to generate dynamic web pages. These engines allow developers to embed Ruby code directly within the template markup. While powerful, this capability introduces the risk of template injection if not handled carefully.

**How Hanami Contributes to the Risk:**

*   **Direct Embedding of Ruby Code:** The fundamental nature of ERB (`<%= ... %>`) and Haml (`= ...`) allows for the execution of arbitrary Ruby code within the template. If user input is placed directly within these tags without proper escaping, it will be interpreted and executed as code.
*   **Custom Template Helpers:** Hanami allows developers to create custom template helpers to encapsulate reusable logic. If these helpers directly render unescaped user input, they become a prime vector for template injection.
*   **Implicit Trust in User Input:**  Developers might inadvertently trust user input, assuming it's safe to render directly. This is a common mistake that leads to vulnerabilities.

#### 4.3 Mechanisms of Template Injection

Template injection occurs when an attacker can control part of the template code that is processed by the template engine. This can happen in several ways:

*   **Direct Injection via Parameters:** As illustrated in the provided example, if a view uses a helper like `<%= unsafe_render(params[:content]) %>` and the `unsafe_render` method doesn't escape the input, an attacker can inject malicious code through the `content` parameter. For instance, providing `params[:content]` as `<% system('rm -rf /') %>` could lead to severe consequences on the server (in a vulnerable scenario where `system` is accessible and not properly sandboxed).
*   **Injection via Database Records:** If data stored in the database contains malicious code (e.g., entered by a privileged but compromised user or through another vulnerability) and is rendered without escaping, it can lead to template injection.
*   **Injection via Flash Messages:**  If flash messages are rendered without proper escaping and an attacker can influence their content, they can inject malicious code.
*   **Injection via Configuration:** In less common scenarios, if application configuration values are directly used in templates without escaping and an attacker can modify these configurations, it could lead to template injection.

#### 4.4 Server-Side Template Injection (SSTI)

Server-Side Template Injection is a critical vulnerability where the attacker's injected code is executed on the server. This can have devastating consequences:

*   **Remote Code Execution (RCE):**  The attacker can execute arbitrary commands on the server, potentially gaining full control of the system. This allows them to steal sensitive data, install malware, or disrupt services.
*   **Data Breach:**  Attackers can access sensitive data stored on the server, including database credentials, API keys, and user information.
*   **Denial of Service (DoS):**  Attackers can execute commands that consume server resources, leading to a denial of service for legitimate users.
*   **Privilege Escalation:**  In some cases, attackers might be able to escalate their privileges on the server.

**Example of SSTI in Hanami (Conceptual):**

```ruby
# In a view or helper
def unsafe_render(content)
  content # Directly returns the content without escaping
end

# In a template (ERB)
<p><%= unsafe_render(params[:data]) %></p>
```

If `params[:data]` is set to `<%= system('whoami') %>`, the server would execute the `whoami` command and potentially display the output on the page (depending on the context and escaping of the surrounding HTML).

#### 4.5 Client-Side Template Injection (CSTI) / Cross-Site Scripting (XSS)

While often less severe than SSTI, client-side template injection can still pose a significant risk. In this scenario, the attacker injects code that is executed in the user's browser. This is essentially a form of Cross-Site Scripting (XSS).

*   **Session Hijacking:** Attackers can steal session cookies, allowing them to impersonate legitimate users.
*   **Data Theft:** Attackers can access sensitive information displayed on the page or interact with other web services on behalf of the user.
*   **Redirection to Malicious Sites:** Attackers can redirect users to phishing sites or other malicious domains.
*   **Defacement:** Attackers can modify the content of the web page displayed to the user.

**Example of CSTI in Hanami (Conceptual):**

```ruby
# In a view or helper
def unsafe_display(message)
  message # Directly returns the message without escaping
end

# In a template (ERB)
<p><%= unsafe_display(params[:message]) %></p>
```

If `params[:message]` is set to `<script>alert('You are hacked!');</script>`, the browser would execute this script, displaying an alert box. More sophisticated attacks could involve stealing cookies or redirecting the user.

#### 4.6 Attack Vectors in Hanami Applications

Several areas in a Hanami application can be potential attack vectors for template injection:

*   **Controller Parameters:**  As demonstrated in the examples, directly using `params` within templates without escaping is a primary risk.
*   **Database Records Displayed in Views:**  Data fetched from the database and rendered in views needs careful escaping.
*   **Flash Messages:**  If flash messages are not properly escaped, they can be exploited for client-side injection.
*   **Custom Template Helpers:**  Helpers that directly output user-provided data without escaping are a significant risk.
*   **Form Input Fields:**  While not direct template injection, if user input in form fields is rendered back to the user without escaping, it can lead to XSS.

#### 4.7 Impact Assessment

The impact of template injection vulnerabilities in Hanami applications can range from high to critical:

*   **Server-Side Template Injection (SSTI):** **Critical**. The ability to execute arbitrary code on the server poses the highest risk, potentially leading to complete system compromise.
*   **Client-Side Template Injection (CSTI) / XSS:** **High**. While the impact is limited to the user's browser, it can still lead to significant security breaches like session hijacking and data theft.

### 5. Mitigation Strategies for Hanami Applications

To effectively mitigate template injection vulnerabilities in Hanami applications, the following strategies should be implemented:

*   **Prioritize Escaping User-Provided Data:**
    *   **Utilize Hanami's Default Escaping:** Hanami's template engines (ERB and Haml) provide mechanisms for automatic escaping. Use the `=` syntax in Haml or `<%= ... %>` in ERB for outputting data, which will automatically escape HTML entities by default.
    *   **Explicitly Escape When Necessary:** If you need to render raw HTML in specific cases, use the `raw` helper judiciously and only when absolutely necessary for trusted content. Carefully review the source of this trusted content.
    *   **Be Mindful of Context:**  Consider the context in which the data is being rendered. Escaping for HTML might not be sufficient for other contexts like JavaScript or CSS.

*   **Secure Custom Template Helpers:**
    *   **Avoid Direct Rendering of Unescaped Input:**  Do not create helpers that directly output user-provided data without escaping.
    *   **Escape Data Within Helpers:** If a helper needs to process user input, ensure it escapes the data before rendering it.
    *   **Review Helper Logic Carefully:**  Thoroughly review the logic of custom helpers to identify potential injection points.

*   **Keep Template Engines Updated:**
    *   **Regularly Update Dependencies:** Ensure that the `erb` or `haml` gems are kept up-to-date to patch any known vulnerabilities in the template engines themselves. Use a dependency management tool like Bundler to manage and update gem versions.

*   **Consider Using a Template Engine with Strong Security Features:**
    *   While ERB and Haml are widely used, explore other template engines that might offer more robust security features or sandboxing capabilities if your application has particularly stringent security requirements. However, understand the trade-offs in terms of performance and developer familiarity.

*   **Implement Input Validation and Sanitization:**
    *   **Validate User Input:**  Validate all user input on the server-side to ensure it conforms to expected formats and constraints. This can help prevent malicious code from even reaching the template rendering stage.
    *   **Sanitize Input (with Caution):**  While escaping is generally preferred, in some specific cases, you might need to sanitize input by removing potentially harmful characters or code. However, be extremely careful with sanitization, as it can be complex and prone to bypasses. Escaping is generally a safer approach.

*   **Implement Content Security Policy (CSP):**
    *   **Mitigate Client-Side Attacks:**  Implement a strong Content Security Policy (CSP) to control the resources that the browser is allowed to load. This can help mitigate the impact of client-side template injection (XSS) by restricting the execution of inline scripts and other potentially malicious content.

*   **Regular Security Audits and Code Reviews:**
    *   **Proactive Identification:** Conduct regular security audits and code reviews, specifically focusing on areas where user input interacts with template rendering logic.
    *   **Automated Static Analysis:** Utilize static analysis tools that can help identify potential template injection vulnerabilities in the codebase.

### 6. Conclusion

Template injection vulnerabilities represent a significant security risk for Hanami applications. By understanding the mechanisms of these attacks and implementing the recommended mitigation strategies, development teams can significantly reduce their attack surface. Prioritizing proper escaping of user-provided data within templates and carefully reviewing custom template helpers are crucial steps in building secure Hanami applications. Continuous vigilance, regular security audits, and staying updated with the latest security best practices are essential to protect against this prevalent and potentially devastating vulnerability.