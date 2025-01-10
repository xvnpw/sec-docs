## Deep Dive Analysis: SQL Injection via `createQueryBuilder` with Unsafe Input in TypeORM

This document provides a deep analysis of the identified SQL injection attack surface within an application utilizing the TypeORM library. We will explore the technical details, potential attack vectors, impact, and comprehensive mitigation strategies.

**Attack Surface:** SQL Injection via `createQueryBuilder` with Unsafe Input

**Component:** TypeORM `createQueryBuilder`

**Vulnerability Class:** SQL Injection (CWE-89)

**1. Detailed Explanation of the Vulnerability:**

While TypeORM provides mechanisms to prevent SQL injection, specifically through parameter binding, developers can inadvertently introduce vulnerabilities when constructing queries dynamically using string concatenation with user-controlled input within the `createQueryBuilder`.

The core issue lies in directly embedding user-provided data into the SQL query string. This bypasses TypeORM's prepared statement functionality, which is designed to treat user input as data rather than executable code.

**Breakdown of the Vulnerable Code:**

```typescript
const searchParam = req.query.search; // User-provided input
const users = await userRepository
  .createQueryBuilder('user')
  .where(`user.name LIKE '%${searchParam}%'`) // VULNERABLE: String concatenation
  .getMany();
```

In this example:

* `req.query.search` retrieves user input from the query parameters.
* This input is directly inserted into the `where` clause using template literals (backticks).
* If `searchParam` contains malicious SQL code, it will be interpreted and executed by the database.

**Why This is a Problem:**

* **Bypasses Parameterization:** TypeORM's intended security mechanism involves using placeholders and passing user input as separate parameters. This ensures the database treats the input as data, not as part of the SQL command structure. String concatenation defeats this protection.
* **Direct Code Execution:**  The database directly executes the constructed SQL string, including any malicious code injected by the user.
* **No Input Sanitization:** The example code lacks any sanitization or validation of the `searchParam`.

**2. Technical Deep Dive:**

Let's analyze how an attacker could exploit this vulnerability:

**Scenario:** An attacker aims to extract all user passwords from the database.

**Attack Payload:**  Assume the attacker provides the following input for `searchParam`:

```
' OR 1=1 --
```

**Resulting Vulnerable Query:**

```sql
SELECT * FROM user user WHERE user.name LIKE '%%' OR 1=1 --%'
```

**Explanation of the Payload:**

* **`' OR 1=1`**: This part of the payload injects a condition that is always true (`1=1`). Combined with the `OR` operator, this effectively bypasses the intended `LIKE` condition.
* **`--`**: This is an SQL comment. It comments out the remaining part of the original `LIKE` clause (`%'`), preventing syntax errors.

**Database Execution:**

The database will execute this modified query. The `OR 1=1` condition will cause the `WHERE` clause to always evaluate to true, effectively returning all rows from the `user` table. This could expose sensitive information like user credentials (if stored in the `user` table).

**Other Potential Attack Vectors:**

* **Data Exfiltration:** Attackers can use `UNION SELECT` statements to retrieve data from other tables.
* **Data Modification:**  Attackers can use `UPDATE` or `DELETE` statements to modify or delete data.
* **Privilege Escalation:** If the database user has sufficient privileges, attackers could execute administrative commands.
* **Denial of Service (DoS):**  Attackers could inject queries that consume excessive resources, leading to a denial of service.

**3. Impact Assessment (Expanded):**

The impact of this vulnerability is **Critical** due to the potential for complete database compromise. Here's a more detailed breakdown:

* **Data Breach:**  Sensitive data, including user credentials, personal information, and business-critical data, can be exposed and exfiltrated. This can lead to significant financial losses, reputational damage, and legal repercussions (e.g., GDPR violations).
* **Data Manipulation/Corruption:** Attackers can modify or delete data, leading to inconsistencies, loss of data integrity, and potential disruption of business operations.
* **Account Takeover:** If user credentials are compromised, attackers can gain unauthorized access to user accounts and perform actions on their behalf.
* **System Compromise:** In severe cases, attackers might be able to execute operating system commands on the database server, potentially leading to full system compromise.
* **Reputational Damage:** A successful SQL injection attack can severely damage the organization's reputation and erode customer trust.
* **Legal and Regulatory Penalties:**  Data breaches resulting from SQL injection can lead to significant fines and legal action.

**4. Mitigation Strategies (Detailed):**

Implementing robust mitigation strategies is crucial to prevent this vulnerability.

* **Primary Mitigation: Parameter Binding with `createQueryBuilder`:**
    * **How it works:**  Instead of embedding user input directly into the SQL string, use placeholders and provide the values separately. TypeORM and the underlying database driver handle the proper escaping and quoting of these values.
    * **Secure Example:**
        ```typescript
        const searchParam = req.query.search;
        const users = await userRepository
          .createQueryBuilder('user')
          .where("user.name LIKE :name", { name: `%${searchParam}%` })
          .getMany();
        ```
        * **Explanation:** The `:name` is a placeholder. The `{ name: `%${searchParam}%` }` object provides the value for the placeholder. TypeORM will ensure that `searchParam` is treated as a literal value, preventing SQL injection.

* **Avoid String Concatenation for Dynamic Conditions:**
    * **Principle:**  Never directly concatenate user input into SQL query strings.
    * **Best Practices:** Utilize TypeORM's query builder methods for constructing dynamic conditions safely:
        * **`.andWhere()` and `.orWhere()`:**  Use these methods to add conditions dynamically.
        * **Conditional Logic:**  Build conditions based on the presence or value of user input using JavaScript logic, then apply them using the query builder methods with parameter binding.
        * **Example:**
            ```typescript
            const queryBuilder = userRepository.createQueryBuilder('user');
            if (req.query.search) {
              queryBuilder.andWhere("user.name LIKE :name", { name: `%${req.query.search}%` });
            }
            if (req.query.email) {
              queryBuilder.andWhere("user.email = :email", { email: req.query.email });
            }
            const users = await queryBuilder.getMany();
            ```

* **Input Validation and Sanitization:**
    * **Purpose:**  While parameter binding is the primary defense, validating and sanitizing user input adds an extra layer of security.
    * **Techniques:**
        * **Whitelisting:** Define allowed characters or patterns for specific input fields.
        * **Blacklisting (Less Recommended):**  Identify and reject known malicious patterns. This is less effective as attackers can find ways to bypass blacklists.
        * **Escaping Special Characters:** Escape characters that have special meaning in SQL (e.g., single quotes, double quotes). However, relying solely on escaping is generally insufficient.
    * **Example (Basic Validation):**
        ```typescript
        const searchParam = req.query.search;
        if (typeof searchParam === 'string' && searchParam.length < 100) { // Basic length and type check
          const users = await userRepository
            .createQueryBuilder('user')
            .where("user.name LIKE :name", { name: `%${searchParam}%` })
            .getMany();
        } else {
          // Handle invalid input (e.g., return an error)
        }
        ```

* **Principle of Least Privilege:**
    * **Database User Permissions:** Ensure that the database user used by the application has only the necessary permissions to perform its operations. Avoid granting excessive privileges that could be exploited in case of an SQL injection.

* **Regular Security Audits and Code Reviews:**
    * **Importance:**  Regularly review code for potential vulnerabilities, including SQL injection flaws. Utilize static analysis tools to help identify potential issues.
    * **Focus Areas:** Pay close attention to sections of code where user input is used to construct database queries.

* **Web Application Firewall (WAF):**
    * **Functionality:** A WAF can help detect and block malicious SQL injection attempts by analyzing incoming HTTP requests.
    * **Limitations:** WAFs are not a foolproof solution and should be used in conjunction with secure coding practices.

* **Stay Updated with TypeORM Security Advisories:**
    * **Importance:** Keep your TypeORM library updated to the latest version to benefit from security patches and bug fixes.

**5. Code Review Checklist for this Attack Surface:**

When reviewing code for this specific vulnerability, look for the following patterns:

* **Usage of `createQueryBuilder`:** Identify all instances where `createQueryBuilder` is used.
* **String Concatenation in `where`, `having`, `orderBy`, `groupBy`:**  Specifically examine the arguments passed to these methods. Look for template literals (backticks) or the `+` operator used to embed variables directly into the SQL string.
* **Lack of Parameter Binding:** Verify that placeholders (`:placeholder`) and a corresponding parameter object are used when incorporating user input into the query conditions.
* **Direct Use of `req.query`, `req.params`, `req.body` (or similar input sources) within SQL strings:**  Be suspicious of any direct insertion of user-provided data without proper parameterization.
* **Dynamic Construction of SQL Fragments:** Analyze how SQL fragments are being built. If string manipulation is involved, investigate for potential vulnerabilities.

**Example of Code Review Finding:**

```typescript
// Potentially vulnerable code
const category = req.params.category;
const products = await productRepository
  .createQueryBuilder('product')
  .where("product.category = '" + category + "'") // ALERT: String concatenation
  .getMany();
```

**6. Testing Strategies:**

To ensure the effectiveness of mitigation strategies, implement the following testing methods:

* **Manual Penetration Testing:**  Security experts can manually craft SQL injection payloads to test the application's resilience.
* **Automated Security Scanning (SAST/DAST):**
    * **Static Application Security Testing (SAST):** Tools analyze the source code for potential vulnerabilities without executing the application. Look for tools that specifically support TypeORM and JavaScript/TypeScript.
    * **Dynamic Application Security Testing (DAST):** Tools interact with the running application and attempt to inject malicious payloads to identify vulnerabilities.
* **Fuzzing:**  Feed the application with a large number of random and malformed inputs to uncover unexpected behavior and potential vulnerabilities.
* **Unit and Integration Tests:**  Write tests that specifically target the data access layer and verify that queries are constructed securely with parameter binding.

**7. Developer Education and Best Practices:**

* **Security Awareness Training:** Educate developers about common web application vulnerabilities, including SQL injection, and the importance of secure coding practices.
* **Secure Coding Guidelines:** Establish and enforce secure coding guidelines that explicitly prohibit the use of string concatenation for building SQL queries with user input.
* **Code Reviews:** Implement mandatory code reviews to catch potential vulnerabilities before they reach production.
* **Utilize Linters and Static Analysis Tools:** Integrate tools that can automatically detect potential security flaws during development.

**8. Conclusion:**

The SQL injection vulnerability arising from unsafe input handling within TypeORM's `createQueryBuilder` is a critical security risk. By directly embedding user input into SQL query strings, developers bypass TypeORM's built-in protection mechanisms and expose their applications to potentially devastating attacks.

**Key Takeaways:**

* **Always use parameter binding when incorporating user input into SQL queries.**
* **Avoid string concatenation for dynamic query construction.**
* **Implement input validation and sanitization as an additional layer of defense.**
* **Educate developers on secure coding practices.**
* **Conduct regular security audits and penetration testing.**

By diligently implementing the recommended mitigation strategies and fostering a security-conscious development culture, teams can effectively protect their applications from this prevalent and dangerous vulnerability.
