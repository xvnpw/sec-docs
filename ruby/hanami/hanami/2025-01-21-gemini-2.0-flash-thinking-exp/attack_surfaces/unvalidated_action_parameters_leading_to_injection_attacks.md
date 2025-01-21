## Deep Analysis of Attack Surface: Unvalidated Action Parameters Leading to Injection Attacks in Hanami Applications

This document provides a deep analysis of the attack surface related to unvalidated action parameters leading to injection attacks in applications built using the Hanami framework.

### 1. Define Objective of Deep Analysis

The primary objective of this analysis is to thoroughly examine the risks associated with directly using request parameters within Hanami actions without proper sanitization or validation. This includes identifying potential injection vulnerabilities (Cross-Site Scripting (XSS), SQL Injection, and Command Injection), understanding their impact, and recommending specific mitigation strategies tailored to the Hanami framework.

### 2. Scope

This analysis focuses specifically on the following aspects related to unvalidated action parameters:

*   **Direct use of `params` object:** How Hanami's `params` object exposes request data to actions and views.
*   **Cross-Site Scripting (XSS):** Vulnerabilities arising from rendering unsanitized parameters in views.
*   **SQL Injection:** Vulnerabilities arising from using unsanitized parameters in database queries, particularly when bypassing Hanami's repository pattern.
*   **Command Injection:** Vulnerabilities arising from using unsanitized parameters in system commands.
*   **Mitigation strategies within the Hanami ecosystem:**  Leveraging Hanami's features and recommended practices for secure development.

This analysis will **not** cover other potential attack surfaces within a Hanami application, such as authentication/authorization flaws, CSRF vulnerabilities, or dependency vulnerabilities, unless they are directly related to the handling of unvalidated action parameters.

### 3. Methodology

The methodology employed for this deep analysis involves:

*   **Review of Hanami Documentation:** Examining official Hanami documentation, guides, and examples to understand how request parameters are handled and best practices for secure development.
*   **Threat Modeling:** Identifying potential attack vectors and scenarios where unvalidated parameters can be exploited to inject malicious code or commands.
*   **Code Analysis (Conceptual):**  Analyzing common patterns and potential pitfalls in Hanami applications related to parameter handling, without performing a specific code audit of a particular application.
*   **Best Practices Review:**  Referencing industry-standard security best practices for input validation, output encoding, and secure database interactions.
*   **Hanami Feature Mapping:**  Identifying specific Hanami features and tools that can be used to mitigate the identified risks.

### 4. Deep Analysis of Attack Surface: Unvalidated Action Parameters Leading to Injection Attacks

As highlighted in the initial description, the ease of accessing request parameters through Hanami's `params` object within actions presents a significant attack surface if not handled carefully. Developers might inadvertently use these parameters directly in views or database interactions, creating opportunities for injection attacks.

**4.1. Cross-Site Scripting (XSS)**

*   **Mechanism:** When user-supplied data from `params` is directly rendered in HTML views without proper encoding, attackers can inject malicious JavaScript code. This code executes in the victim's browser when they view the page.
*   **Hanami Context:** Hanami's view rendering system, while offering convenience, can be a direct conduit for XSS if developers use `<%= params[:some_param] %>` without considering the potential for malicious input.
*   **Example:**
    ```ruby
    # In an action
    module Web::Controllers::Posts
      class Show
        include Web::Action

        expose :title

        def call(params)
          @title = params[:title]
        end
      end
    end

    # In the corresponding view (app/web/templates/posts/show.html.erb)
    <h1><%= @title %></h1>
    ```
    If a user navigates to `/posts/1?title=<script>alert('XSS')</script>`, the JavaScript will execute.
*   **Impact:** XSS can lead to:
    *   **Session Hijacking:** Stealing session cookies to impersonate users.
    *   **Data Theft:** Accessing sensitive information displayed on the page or making unauthorized requests on behalf of the user.
    *   **Account Takeover:**  Potentially gaining control of user accounts.
    *   **Defacement:** Modifying the content of the web page.
    *   **Redirection to Malicious Sites:**  Redirecting users to phishing or malware distribution sites.
*   **Mitigation in Hanami:**
    *   **Automatic Output Escaping:** Hanami's default ERB rendering automatically escapes HTML entities, mitigating many XSS vulnerabilities. However, developers need to be aware of contexts where automatic escaping might not be sufficient (e.g., within HTML attributes or JavaScript code).
    *   **Explicit Escaping:** Use Hanami's `h` helper or similar methods for explicit escaping in views, especially when dealing with user input in attributes or JavaScript.
        ```erb
        <input type="text" value="<%= h @title %>">
        ```
    *   **Content Security Policy (CSP):** Implement a strong CSP to control the sources from which the browser is allowed to load resources, significantly reducing the impact of XSS attacks.

**4.2. SQL Injection**

*   **Mechanism:** If request parameters are directly incorporated into SQL queries without proper sanitization or the use of parameterized queries, attackers can inject malicious SQL code. This code can manipulate the database, potentially leading to data breaches, data modification, or even complete database takeover.
*   **Hanami Context:** While Hanami encourages the use of repositories and ORM-like features that generally protect against SQL injection, developers might still write raw SQL queries or use database adapters directly, especially for complex or legacy scenarios. Directly concatenating `params` into these queries is a critical vulnerability.
*   **Example:**
    ```ruby
    # In an action or repository (BAD PRACTICE)
    module Web::Controllers::Search
      class Index
        include Web::Action

        expose :results

        def call(params)
          # Vulnerable to SQL Injection
          @results = DB.fetch("SELECT * FROM users WHERE username = '#{params[:username]}'").to_a
        end
      end
    end
    ```
    An attacker could send a request like `?username=' OR '1'='1` to retrieve all user records.
*   **Impact:**
    *   **Data Breach:** Accessing sensitive data stored in the database.
    *   **Data Manipulation:** Modifying or deleting data.
    *   **Authentication Bypass:** Circumventing login mechanisms.
    *   **Denial of Service:**  Executing queries that overload the database.
    *   **Remote Code Execution (in some cases):**  Depending on database configurations and permissions.
*   **Mitigation in Hanami:**
    *   **Parameterized Queries:**  Always use parameterized queries or prepared statements when interacting with the database directly. This ensures that user input is treated as data, not executable code.
        ```ruby
        # Using parameterized queries (SAFE)
        module Web::Controllers::Search
          class Index
            include Web::Action

            expose :results

            def call(params)
              @results = DB.fetch("SELECT * FROM users WHERE username = ?", params[:username]).to_a
            end
          end
        end
        ```
    *   **Hanami Repositories:** Leverage Hanami's repository pattern, which typically uses ORM-like features that handle parameter escaping and prevent SQL injection.
    *   **Input Validation:**  Validate and sanitize user input before using it in database queries, even with parameterized queries, to enforce expected data types and formats.
    *   **Principle of Least Privilege:** Ensure database users have only the necessary permissions to perform their tasks, limiting the potential damage from a successful SQL injection attack.

**4.3. Command Injection**

*   **Mechanism:** If request parameters are used to construct and execute system commands without proper sanitization, attackers can inject malicious commands that will be executed on the server.
*   **Hanami Context:** While less common in typical web applications, scenarios might exist where a Hanami application interacts with the operating system (e.g., generating reports, processing files). Directly using `params` in system calls is extremely dangerous.
*   **Example:**
    ```ruby
    # In an action or service (EXTREMELY BAD PRACTICE)
    module Web::Controllers::Reports
      class Generate
        include Web::Action

        def call(params)
          # Highly vulnerable to Command Injection
          system("convert input.txt output_#{params[:filename]}.pdf")
        end
      end
    end
    ```
    An attacker could send a request like `?filename=report; rm -rf /` to potentially delete critical system files.
*   **Impact:**
    *   **Remote Code Execution:**  Gaining complete control over the server.
    *   **Data Breach:** Accessing sensitive files and data on the server.
    *   **System Compromise:**  Potentially installing malware or creating backdoors.
    *   **Denial of Service:**  Crashing the server or consuming resources.
*   **Mitigation in Hanami:**
    *   **Avoid Executing System Commands Based on User Input:**  Whenever possible, avoid executing system commands based on user-provided data.
    *   **Strict Validation and Sanitization:** If executing system commands is absolutely necessary, implement extremely strict validation and sanitization of all user-provided input. Use whitelisting to allow only specific, safe characters or values.
    *   **Use Secure Alternatives:** Explore safer alternatives to system commands, such as using libraries or built-in functions for tasks like file processing.
    *   **Principle of Least Privilege:** Run the web application with minimal privileges to limit the impact of a successful command injection attack.

**4.4. General Mitigation Strategies for Unvalidated Action Parameters in Hanami**

Beyond the specific mitigations for each injection type, the following general strategies are crucial for securing Hanami applications against vulnerabilities arising from unvalidated action parameters:

*   **Input Validation:**  Always validate user input on the server-side. This includes checking data types, formats, lengths, and allowed values. Hanami provides mechanisms for validation within actions.
*   **Output Encoding/Escaping:**  Encode or escape user-provided data before rendering it in views to prevent XSS. Hanami's default ERB escaping is a good starting point, but be mindful of contexts requiring explicit escaping.
*   **Principle of Least Privilege:** Grant only the necessary permissions to database users and the web application process.
*   **Security Audits and Code Reviews:** Regularly review code for potential vulnerabilities related to parameter handling.
*   **Security Testing:** Perform penetration testing and vulnerability scanning to identify and address weaknesses.
*   **Stay Updated:** Keep Hanami and its dependencies up-to-date with the latest security patches.

**Conclusion:**

The attack surface presented by unvalidated action parameters is a critical concern for Hanami applications. By understanding the mechanisms of XSS, SQL Injection, and Command Injection, and by implementing the recommended mitigation strategies, development teams can significantly reduce the risk of these vulnerabilities. A proactive approach to security, including thorough input validation, output encoding, and adherence to secure coding practices, is essential for building robust and secure Hanami applications.