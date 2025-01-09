## Deep Analysis of Insecure Route Parameter Handling in Hanami Applications

This document provides a deep dive into the "Insecure Route Parameter Handling" attack surface within Hanami applications. We will explore the mechanics of this vulnerability, its potential impact, and actionable mitigation strategies tailored to the Hanami framework.

**1. Understanding the Attack Surface: Insecure Route Parameter Handling**

At its core, this attack surface arises when user-supplied data, specifically extracted from URL route parameters, is treated as trustworthy and directly used within the application's logic without proper scrutiny. This lack of validation and sanitization opens doors for attackers to inject malicious payloads that can manipulate application behavior, access sensitive data, or even compromise the entire system.

**2. Hanami's Role in Exposing This Attack Surface:**

Hanami's routing mechanism, while powerful and flexible, directly contributes to this attack surface by providing a straightforward way to define and access route parameters.

* **Direct Parameter Accessibility:** Hanami makes route parameters readily available within actions through the `params` hash. This ease of access, while convenient for developers, can be a double-edged sword if not handled responsibly. Developers might be tempted to directly use these parameters without implementing necessary security checks.
* **Convention over Configuration:** Hanami's emphasis on convention means that the framework doesn't enforce input validation or sanitization by default. This responsibility falls squarely on the developer. If the developer is unaware of the risks or lacks the necessary security mindset, vulnerabilities can easily slip through.
* **Flexibility in Route Definition:**  Hanami allows for complex route patterns, including optional parameters and wildcard segments. While this offers great flexibility, it also increases the potential for overlooking specific parameter handling requirements and edge cases, making thorough validation even more crucial.

**3. Detailed Attack Vectors and Scenarios:**

Let's expand on the initial SQL injection example and explore other potential attack vectors:

* **SQL Injection (as described):**
    * **Vulnerable Route:** `/users/:id`
    * **Attack Payload:** `/users/1 UNION SELECT username, password FROM admins--`
    * **Mechanism:** The attacker crafts a malicious `id` parameter that, when directly incorporated into a database query without proper sanitization or parameterized queries, allows them to execute arbitrary SQL commands. This can lead to data breaches, modification, or even deletion.

* **Command Injection:**
    * **Vulnerable Route:** `/tools/execute/:command`
    * **Attack Payload:** `/tools/execute/ls -l && cat /etc/passwd`
    * **Mechanism:** If the `command` parameter is used directly in a system call (e.g., using `Kernel.system` or backticks) without sanitization, an attacker can inject arbitrary shell commands. This could allow them to execute malicious scripts, gain unauthorized access, or disrupt the system.

* **Path Traversal (Local File Inclusion):**
    * **Vulnerable Route:** `/files/:filename`
    * **Attack Payload:** `/files/../../../../etc/passwd`
    * **Mechanism:** If the `filename` parameter is used to construct a file path without proper validation, an attacker can use ".." sequences to navigate outside the intended directory and access sensitive files on the server.

* **Cross-Site Scripting (XSS) via Route Parameters (Less Common but Possible):**
    * **Vulnerable Route:** `/search/:query`
    * **Attack Payload:** `/search/<script>alert('XSS')</script>`
    * **Mechanism:** If the `query` parameter is directly rendered in the application's HTML output without proper encoding, an attacker can inject malicious JavaScript code that will be executed in the victim's browser. This can lead to session hijacking, cookie theft, or defacement.

* **Logic Flaws and Unexpected Behavior:**
    * **Vulnerable Route:** `/products/:quantity`
    * **Attack Payload:** `/products/-1` or `/products/abc`
    * **Mechanism:** If the application expects a positive integer for `quantity` and doesn't validate it, providing negative values or non-numeric input can lead to unexpected behavior, errors, or even application crashes.

**4. Impact Analysis (Beyond the Initial Description):**

The impact of insecure route parameter handling can be severe and far-reaching:

* **Data Breaches:** As demonstrated by SQL injection, attackers can gain unauthorized access to sensitive data, including user credentials, financial information, and confidential business data.
* **Data Manipulation and Corruption:** Attackers can modify or delete critical data, leading to business disruption, financial losses, and reputational damage.
* **System Compromise:** Command injection can allow attackers to gain complete control over the server, enabling them to install malware, steal data, or launch further attacks.
* **Denial of Service (DoS):**  By providing unexpected or malicious input, attackers might be able to crash the application or consume excessive resources, leading to service unavailability.
* **Account Takeover:** XSS vulnerabilities arising from route parameters can be used to steal user session cookies, allowing attackers to impersonate legitimate users.
* **Reputational Damage:**  Security breaches can severely damage an organization's reputation and erode customer trust.
* **Legal and Regulatory Consequences:** Depending on the nature of the data breach and applicable regulations (e.g., GDPR, CCPA), organizations can face significant fines and legal repercussions.

**5. Deep Dive into Mitigation Strategies (Hanami Specific Implementation):**

Let's elaborate on the suggested mitigation strategies and provide Hanami-specific implementation details:

* **Input Validation:**
    * **Hanami Validations:** Leverage Hanami's built-in validation framework within your actions. You can define validations for the `params` hash, including type checks, presence checks, format checks, and custom validation logic.

    ```ruby
    # app/actions/users/show.rb
    module Web::Actions::Users
      class Show < Web::Action
        params do
          required(:id).value(:integer, gt: 0)
        end

        def handle(params)
          if params.valid?
            @user = UserRepository.new.find(params[:id])
            if @user
              # ... render user details
            else
              halt 404
            end
          else
            # Handle validation errors (e.g., return 400 Bad Request)
            self.status = 400
            self.body = { errors: params.errors.to_h }.to_json
          end
        end
      end
    end
    ```

    * **Custom Validation Logic:** For more complex validation scenarios, you can implement custom validation methods within your actions or dedicated validator classes.

* **Parameterized Queries (Using ROM):**
    * **ROM's Prepared Statements:** When interacting with the database using ROM, always utilize parameterized queries. ROM handles the escaping and quoting of parameters, preventing SQL injection.

    ```ruby
    # app/repositories/user_repository.rb
    class UserRepository < Hanami::Repository
      def find_by_id(id)
        users.where(id: id).one
      end
    end

    # app/actions/users/show.rb
    module Web::Actions::Users
      class Show < Web::Action
        # ... validation logic ...

        def handle(params)
          if params.valid?
            @user = UserRepository.new.find_by_id(params[:id]) # Using parameterized query
            # ...
          end
        end
      end
    end
    ```

* **Type Casting:**
    * **Explicit Casting:** While Hanami's validation can handle type checks, explicitly casting parameters to the expected type can provide an extra layer of security and prevent unexpected behavior.

    ```ruby
    # app/actions/products/show.rb
    module Web::Actions::Products
      class Show < Web::Action
        def handle(params)
          product_id = Integer(params[:id]) rescue nil # Explicitly cast to integer
          if product_id && product_id > 0
            @product = ProductRepository.new.find(product_id)
            # ...
          else
            halt 400, 'Invalid product ID'
          end
        end
      end
    end
    ```

* **Principle of Least Privilege:** Ensure that the database user your application uses has only the necessary permissions. This limits the potential damage an attacker can inflict even if they manage to execute SQL injection.

* **Security Headers:** Implement security headers like Content Security Policy (CSP) and X-Frame-Options to mitigate XSS and clickjacking attacks, which could be related to how route parameters are handled and rendered.

* **Regular Security Audits and Penetration Testing:**  Conduct periodic security assessments to identify and address potential vulnerabilities in your route parameter handling and other areas of your application.

**6. Detection and Prevention During Development:**

* **Code Reviews:**  Implement thorough code reviews, specifically focusing on how route parameters are being used and whether proper validation and sanitization are in place.
* **Static Analysis Security Testing (SAST):** Utilize SAST tools that can automatically analyze your codebase for potential security vulnerabilities, including insecure route parameter handling.
* **Security Training for Developers:**  Ensure your development team is educated on common web security vulnerabilities and best practices for secure coding, including secure route parameter handling.
* **Adopt a Secure Development Lifecycle (SDL):** Integrate security considerations into every stage of the development process, from design to deployment.

**7. Testing Strategies:**

* **Manual Testing:**  Manually test your application with various malicious inputs in route parameters to identify potential vulnerabilities.
* **Automated Testing:** Write integration tests that specifically target route parameter handling, including tests for different types of invalid and malicious input.
* **Fuzzing:** Use fuzzing tools to automatically generate a large number of potentially malicious inputs to identify unexpected behavior or crashes.
* **Penetration Testing:** Engage external security experts to perform penetration testing on your application to identify vulnerabilities that might have been missed during development.

**8. Hanami Specific Considerations and Best Practices:**

* **Leverage Hanami's Validation Features:**  Embrace Hanami's built-in validation framework as the primary mechanism for validating route parameters.
* **Utilize ROM for Database Interactions:**  Always use ROM's parameterized queries to prevent SQL injection.
* **Be Mindful of Implicit Type Conversions:** While Hanami might perform some implicit type conversions, don't rely on them for security. Explicit validation and casting are crucial.
* **Consider Using a Dedicated Input Sanitization Library:** For more complex sanitization requirements, consider using a dedicated library.
* **Keep Hanami and its Dependencies Up-to-Date:** Regularly update your Hanami application and its dependencies to patch any known security vulnerabilities.

**Conclusion:**

Insecure route parameter handling is a critical attack surface in web applications, and Hanami applications are no exception. By understanding how Hanami exposes this surface and implementing the detailed mitigation strategies outlined above, development teams can significantly reduce the risk of exploitation. A proactive approach that incorporates secure coding practices, thorough testing, and regular security assessments is essential for building robust and secure Hanami applications. Remember that security is an ongoing process, and continuous vigilance is required to protect your application and its users.
