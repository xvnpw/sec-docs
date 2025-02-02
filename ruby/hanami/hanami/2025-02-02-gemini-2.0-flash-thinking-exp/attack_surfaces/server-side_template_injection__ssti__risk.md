## Deep Analysis: Server-Side Template Injection (SSTI) Risk in Hanami Applications

This document provides a deep analysis of the Server-Side Template Injection (SSTI) attack surface in applications built using the Hanami framework (https://github.com/hanami/hanami). It outlines the objective, scope, and methodology of this analysis, followed by a detailed examination of the SSTI risk, its implications, and mitigation strategies.

---

### 1. Define Objective of Deep Analysis

The primary objective of this deep analysis is to thoroughly investigate the Server-Side Template Injection (SSTI) attack surface within Hanami applications. This includes:

*   **Understanding the root cause:**  Identifying how Hanami's architecture and design choices contribute to the SSTI risk.
*   **Analyzing attack vectors:**  Exploring potential scenarios and methods attackers could use to exploit SSTI vulnerabilities in Hanami applications.
*   **Evaluating impact and severity:**  Assessing the potential consequences of successful SSTI attacks.
*   **Providing actionable mitigation strategies:**  Offering practical and effective recommendations for developers to prevent and remediate SSTI vulnerabilities in their Hanami applications.
*   **Raising awareness:**  Highlighting the importance of SSTI security within the Hanami development community.

Ultimately, this analysis aims to empower Hanami developers with the knowledge and tools necessary to build secure applications resilient to SSTI attacks.

### 2. Scope

This deep analysis focuses specifically on the Server-Side Template Injection (SSTI) attack surface within Hanami applications. The scope includes:

*   **Hanami's View Layer:**  Specifically examining how Hanami handles views and templates, including the use of ERB and other supported templating engines.
*   **Developer Responsibility:**  Analyzing the extent to which Hanami relies on developers to implement proper input sanitization and output escaping within templates.
*   **Common SSTI Scenarios:**  Identifying typical situations in Hanami applications where SSTI vulnerabilities are likely to occur.
*   **Mitigation Techniques within Hanami Context:**  Focusing on mitigation strategies that are directly applicable and effective within the Hanami framework and its ecosystem.

**Out of Scope:**

*   **Other Attack Surfaces:** This analysis is limited to SSTI and does not cover other potential attack surfaces in Hanami applications (e.g., SQL Injection, Cross-Site Scripting (XSS) outside of templates, etc.).
*   **Specific Application Code Review:**  This is a general analysis of the SSTI risk in Hanami, not a code review of a particular Hanami application.
*   **Detailed Templating Engine Internals:** While we will touch upon templating engines, a deep dive into the internal workings of ERB or other engines is outside the scope.

### 3. Methodology

The methodology for this deep analysis involves the following steps:

1.  **Review of Hanami Documentation:**  Examining the official Hanami documentation, particularly sections related to views, templates, and security best practices.
2.  **Analysis of Hanami Architecture:**  Understanding how Hanami's view layer is designed and how it interacts with templating engines.
3.  **Deconstruction of Attack Surface Description:**  Breaking down the provided description of the SSTI risk to identify key areas of concern.
4.  **Identification of Attack Vectors:**  Brainstorming and documenting potential attack vectors and scenarios that could lead to SSTI exploitation in Hanami applications.
5.  **Evaluation of Mitigation Strategies:**  Analyzing the effectiveness of the suggested mitigation strategies (Output Escaping, Avoid Direct Embedding, Templating Engine Security Features) and exploring additional relevant techniques.
6.  **Development of Recommendations:**  Formulating actionable recommendations for Hanami developers to prevent and mitigate SSTI risks, and potentially suggesting improvements for the Hanami framework itself.
7.  **Documentation and Reporting:**  Compiling the findings into this comprehensive markdown document, clearly outlining the analysis, findings, and recommendations.

---

### 4. Deep Analysis of Server-Side Template Injection (SSTI) Risk

#### 4.1. Introduction to SSTI in Hanami

Server-Side Template Injection (SSTI) is a critical vulnerability that arises when user-controlled input is directly embedded into server-side templates without proper sanitization or escaping. Templating engines, like ERB used in Hanami, are designed to dynamically generate web pages by embedding data and logic within templates. When user input is treated as code within these templates, attackers can inject malicious code that is then executed by the server.

In the context of Hanami, which emphasizes developer control and convention over configuration, the responsibility for securing templates against SSTI falls squarely on the developer. This inherent design characteristic, while offering flexibility, also contributes to the SSTI attack surface.

#### 4.2. Hanami's View Layer and Templating: Developer Responsibility

Hanami's view layer is designed to be lightweight and focused on presentation logic. It leverages standard Ruby templating engines like ERB (Embedded Ruby) by default, but can also support others.  Hanami views are Ruby classes that prepare data for templates, and templates themselves are typically ERB files containing HTML mixed with Ruby code.

**Key aspects of Hanami's view layer relevant to SSTI:**

*   **Direct Template Rendering:** Hanami views render templates directly.  There is no built-in, automatic escaping mechanism applied to variables passed to templates.
*   **ERB and Raw Output:** ERB, by default, outputs the result of Ruby code blocks (`<%= ... %>`) directly into the HTML output. This means any unescaped user input within these blocks will be rendered as is, potentially leading to SSTI.
*   **Helper Methods:** Hanami provides view helpers, including the `h()` helper for HTML escaping. However, developers must explicitly use these helpers to escape user input.
*   **Convention over Configuration:** Hanami prioritizes developer control and explicit actions. This means security measures like output escaping are not automatically enforced and are the developer's responsibility to implement correctly.

This design philosophy, while empowering developers, inherently increases the risk of SSTI if developers are not fully aware of the vulnerability and do not consistently apply proper escaping techniques.

#### 4.3. Mechanism of SSTI in Hanami: Unescaped User Input

The core mechanism of SSTI in Hanami revolves around the direct embedding of user-controlled input into templates without proper escaping. Consider the example provided:

```erb
<h1>Hello, <%= params[:name] %>!</h1>
```

In this scenario, if the `params[:name]` value is directly rendered into the template without escaping, an attacker can manipulate the `name` parameter to inject malicious code.

**Example Attack Vector:**

An attacker could provide the following payload as the `name` parameter:

```
<%= system('whoami') %>
```

When this payload is rendered by the ERB template engine, the `system('whoami')` Ruby code will be executed on the server, and the output of the `whoami` command will be embedded into the HTML output. This demonstrates direct code execution on the server, the hallmark of SSTI.

**More Complex Payloads:**

Attackers can inject more sophisticated payloads to:

*   **Read sensitive files:** `<%= File.read('/etc/passwd') %>`
*   **Execute arbitrary commands:** `<%= system('rm -rf /tmp/*') %>` (highly dangerous)
*   **Establish reverse shells:**  Inject code to connect back to an attacker-controlled server.
*   **Bypass authentication and authorization:**  Manipulate application logic through code injection.

The power of SSTI lies in the attacker's ability to leverage the full capabilities of the underlying programming language (Ruby in this case) through the templating engine.

#### 4.4. Attack Vectors and Scenarios in Hanami Applications

SSTI vulnerabilities can arise in various parts of a Hanami application where user input is incorporated into templates. Common scenarios include:

*   **Displaying Usernames or Content:**  Rendering user-provided names, comments, blog post content, or any other text directly in templates without escaping.
*   **Search Results:**  Displaying search queries or results within templates, especially if the query itself is reflected back to the user.
*   **Error Messages:**  Including user input in error messages displayed to the user, particularly in development or debugging environments.
*   **Dynamic Form Generation:**  Generating form fields dynamically based on user input or database data, if not handled carefully.
*   **Custom View Helpers:**  If custom view helpers are not implemented with proper escaping in mind, they can become sources of SSTI if they handle user input.
*   **Redirect URLs:**  While less direct, if redirect URLs are constructed using user input within templates, and not properly validated, it could potentially be chained with other vulnerabilities.

Any situation where data originating from user input (parameters, cookies, database records influenced by user input, etc.) is rendered in a template without explicit and appropriate escaping is a potential SSTI attack vector.

#### 4.5. Impact and Severity: Critical Risk

The impact of a successful SSTI attack is **Critical**. It can lead to:

*   **Remote Code Execution (RCE):** As demonstrated in the examples, attackers can execute arbitrary code on the server. This is the most severe consequence, allowing complete control over the server.
*   **Server Compromise:**  RCE can lead to full server compromise, allowing attackers to install malware, create backdoors, and pivot to other systems within the network.
*   **Data Breach:** Attackers can access sensitive data stored on the server, including databases, configuration files, and user data.
*   **Privilege Escalation:**  Attackers might be able to escalate privileges within the application or the server operating system.
*   **Denial of Service (DoS):**  In some cases, attackers might be able to cause denial of service by injecting code that crashes the application or consumes excessive resources.
*   **Website Defacement:**  Attackers can modify the content of the website, leading to reputational damage.

Due to the potential for complete system compromise and data breaches, SSTI vulnerabilities are consistently ranked as **Critical** severity.

#### 4.6. Mitigation Strategies (Detailed Explanation and Expansion)

To effectively mitigate SSTI risks in Hanami applications, developers must implement robust security practices, primarily focusing on output escaping and minimizing direct embedding of user input.

##### 4.6.1. Output Escaping: The First Line of Defense

**Explanation:** Output escaping is the process of converting potentially harmful characters in user input into their safe HTML entity representations. This prevents the browser from interpreting these characters as code or HTML tags.

**Hanami's `h()` Helper:** Hanami provides the `h()` helper method (aliased as `escape_html` in views) specifically for HTML escaping. This helper should be used **consistently** whenever rendering user-provided data within templates.

**Example of Correct Usage:**

```erb
<h1>Hello, <%= h(params[:name]) %>!</h1>
```

In this corrected example, the `h(params[:name])` call ensures that any potentially malicious characters in `params[:name]` are escaped before being rendered, preventing code execution.

**Context-Aware Escaping:** While `h()` provides basic HTML escaping, in more complex scenarios, context-aware escaping might be necessary. This means escaping data differently depending on where it's being inserted in the HTML (e.g., escaping for HTML attributes, JavaScript, CSS).  For most common cases in Hanami templates, `h()` is sufficient for HTML content.

**Importance of Consistency:**  The key to effective output escaping is **consistency**. Developers must be vigilant and escape *all* user-controlled input rendered in templates.  Even seemingly innocuous data can be exploited if not properly escaped.

##### 4.6.2. Avoid Direct Embedding: Separation of Concerns

**Explanation:** Minimizing direct embedding of user input in templates reduces the attack surface and improves code maintainability.  This involves moving data processing and formatting logic out of templates and into view helpers or presenters.

**Using View Helpers and Presenters:**

*   **View Helpers:** Create dedicated view helper methods to handle data formatting and escaping. These helpers can encapsulate the logic for safely rendering specific types of user input.

    ```ruby
    # app/views/application_view.rb
    module Views::ApplicationView
      def safe_user_name(name)
        h(name) # Escape the name
      end
    end

    # app/views/users/show.html.erb
    <h1>User: <%= safe_user_name(@user.name) %></h1>
    ```

*   **Presenters:**  Use presenters (or decorators) to encapsulate presentation logic and data formatting outside of views and templates. Presenters can prepare data for safe rendering in templates.

    ```ruby
    # app/presenters/user_presenter.rb
    class UserPresenter
      def initialize(user)
        @user = user
      end

      def safe_name
        h(@user.name)
      end
    end

    # app/views/users/show.html.erb
    <% presenter = UserPresenter.new(@user) %>
    <h1>User: <%= presenter.safe_name %></h1>
    ```

By moving data processing and escaping logic into helpers or presenters, templates become cleaner, easier to read, and less prone to SSTI vulnerabilities.

##### 4.6.3. Templating Engine Security Features (Limited in ERB)

**Explanation:** Some templating engines offer built-in security features to mitigate SSTI. However, ERB, the default engine in Hanami, has limited built-in security features specifically for SSTI prevention.

**ERB's Focus:** ERB primarily focuses on embedding Ruby code within HTML. It does not have automatic escaping mechanisms or sandboxing features to prevent code execution from injected input.

**Alternative Templating Engines (Consider with Caution):** While Hanami can support other templating engines, switching engines solely for security reasons should be carefully considered.  Ensure the chosen engine genuinely provides robust SSTI protection and is well-maintained and secure itself.  Even with more secure engines, developers still need to understand and utilize their security features correctly.

**Recommendation:** Rely primarily on output escaping and avoiding direct embedding rather than solely depending on templating engine security features for SSTI prevention in Hanami, especially when using ERB.

##### 4.6.4. Content Security Policy (CSP) - Defense in Depth

**Explanation:** Content Security Policy (CSP) is a browser security mechanism that helps mitigate various web vulnerabilities, including XSS and, to a lesser extent, can offer some defense-in-depth against SSTI exploitation.

**How CSP Helps:** CSP allows you to define a policy that restricts the sources from which the browser is allowed to load resources (scripts, stylesheets, images, etc.). By carefully configuring CSP, you can limit the impact of a successful SSTI attack by preventing the execution of externally loaded malicious scripts.

**Limitations for SSTI:** CSP is not a direct mitigation for SSTI itself. It primarily helps limit the *consequences* of a successful SSTI attack by making it harder for attackers to inject and execute external malicious scripts. It does not prevent the initial code execution on the server.

**Recommendation:** Implement a strong CSP as a defense-in-depth measure. While it won't prevent SSTI, it can significantly reduce the potential damage by limiting the attacker's ability to execute external scripts or load malicious resources.

##### 4.6.5. Regular Security Audits and Testing

**Explanation:** Proactive security measures are crucial. Regular security audits and penetration testing should be conducted to identify and address potential SSTI vulnerabilities in Hanami applications.

**Types of Testing:**

*   **Static Code Analysis:** Use static analysis tools to scan code for potential SSTI vulnerabilities. While these tools may not catch all instances, they can help identify common patterns.
*   **Dynamic Application Security Testing (DAST):**  Use DAST tools to automatically test the running application for vulnerabilities, including SSTI.
*   **Manual Penetration Testing:**  Engage security experts to manually test the application for SSTI and other vulnerabilities. Manual testing can uncover vulnerabilities that automated tools might miss.

**Recommendation:** Integrate security testing into the development lifecycle. Conduct regular security audits and penetration tests, especially after significant code changes or feature additions.

#### 4.7. Recommendations for Developers

*   **Always Escape User Input:**  Make output escaping a standard practice. Use `h()` or appropriate escaping mechanisms for *all* user-controlled data rendered in templates.
*   **Default to Escaping:**  Adopt a "default to escaping" mindset. Assume all user input is potentially malicious and escape it unless there is a very specific and well-justified reason not to (and even then, proceed with extreme caution).
*   **Minimize Direct Embedding:**  Refactor code to minimize direct embedding of user input in templates. Utilize view helpers and presenters to handle data formatting and escaping outside of templates.
*   **Code Reviews:**  Conduct thorough code reviews, specifically focusing on template code and how user input is handled. Train developers to recognize and prevent SSTI vulnerabilities.
*   **Security Training:**  Provide developers with security training on SSTI and other common web vulnerabilities.
*   **Use Linters and Static Analysis:**  Integrate linters and static analysis tools into the development workflow to help identify potential SSTI issues early on.
*   **Stay Updated:**  Keep up-to-date with security best practices and emerging SSTI attack techniques.

#### 4.8. Recommendations for Hanami Framework (Optional)

While Hanami's design philosophy emphasizes developer responsibility, the framework could consider some enhancements to further mitigate SSTI risks:

*   **Promote Escaping in Documentation:**  Place a stronger emphasis on output escaping in the official Hanami documentation, providing clear examples and best practices for SSTI prevention.
*   **Consider Default Escaping (Optional and with Caution):**  Explore the possibility of introducing a framework-level option for default output escaping. However, this should be carefully considered as it might break existing applications and could lead to developers becoming complacent and less aware of the underlying security principles.  If implemented, it should be opt-in and clearly documented.
*   **Security Focused Guides and Examples:**  Provide dedicated security guides and examples within the Hanami documentation, specifically addressing SSTI and other common web vulnerabilities.
*   **Community Awareness:**  Actively promote awareness of SSTI risks within the Hanami community through blog posts, tutorials, and conference talks.

### 5. Conclusion

Server-Side Template Injection (SSTI) is a critical attack surface in Hanami applications due to the framework's design that places the responsibility for output escaping directly on developers.  The potential impact of SSTI is severe, ranging from remote code execution to data breaches.

By understanding the mechanisms of SSTI, consistently applying output escaping techniques (especially using Hanami's `h()` helper), minimizing direct embedding of user input, and implementing other defense-in-depth measures like CSP and regular security testing, Hanami developers can significantly reduce the risk of SSTI vulnerabilities in their applications.

Proactive security practices, developer awareness, and a commitment to secure coding are essential for building robust and secure Hanami applications that are resilient to SSTI attacks.