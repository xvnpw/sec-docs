Okay, here's a deep analysis of the "SQL Injection via Custom Filters or Actions" threat, tailored for Active Admin, as requested.

```markdown
# Deep Analysis: SQL Injection via Custom Filters or Actions (Active Admin Specific)

## 1. Objective

The primary objective of this deep analysis is to thoroughly understand the mechanisms by which SQL injection vulnerabilities can be introduced into an Active Admin application through custom filters and actions.  We aim to identify common coding patterns that lead to this vulnerability, analyze the potential impact, and reinforce the importance of secure coding practices within the Active Admin context.  This analysis will serve as a guide for developers to prevent and remediate such vulnerabilities.

## 2. Scope

This analysis focuses exclusively on SQL injection vulnerabilities introduced through *developer-created customizations* within Active Admin.  It specifically addresses:

*   **Custom Filters:**  Code blocks defined using the `filter` method within an Active Admin resource definition.
*   **Custom Actions:**  Actions defined within Active Admin resources (e.g., member actions, collection actions) that interact with the database.
*   **Direct Database Interactions:** Any code within Active Admin customizations (filters, actions, page customizations, etc.) that bypasses ActiveRecord's safe query methods and interacts directly with the database using raw SQL.

This analysis *does not* cover:

*   SQL injection vulnerabilities outside the scope of Active Admin customizations (e.g., in other parts of the Rails application).
*   Other types of vulnerabilities (e.g., XSS, CSRF) within Active Admin.
*   Vulnerabilities in the Active Admin gem itself (assuming a reasonably up-to-date version is used).

## 3. Methodology

The analysis will follow these steps:

1.  **Vulnerability Definition:**  Clearly define the specific type of SQL injection vulnerability being analyzed.
2.  **Code Examples (Vulnerable and Secure):** Provide concrete examples of vulnerable Active Admin code and corresponding secure implementations.  This will illustrate the practical application of the threat.
3.  **Attack Scenario Walkthrough:**  Describe a step-by-step attack scenario, demonstrating how an attacker could exploit the vulnerability.
4.  **Impact Analysis:**  Detail the potential consequences of a successful SQL injection attack, including data breaches, data modification, and denial of service.
5.  **Mitigation Strategies (Reinforced):**  Reiterate and expand upon the provided mitigation strategies, providing specific guidance for Active Admin developers.
6.  **Testing and Verification:**  Outline methods for testing and verifying the absence of this vulnerability in Active Admin customizations.
7.  **Tools and Resources:** List helpful tools and resources for preventing and detecting SQL injection.

## 4. Deep Analysis

### 4.1 Vulnerability Definition

This specific type of SQL injection vulnerability arises when user-supplied input is directly incorporated into SQL queries within Active Admin's custom filters or actions *without proper sanitization or parameterization*.  The vulnerability exists because Active Admin, while built on Rails and ActiveRecord, allows developers to define custom logic that may bypass the built-in protections of ActiveRecord if not implemented carefully.  The key differentiator is that this vulnerability is introduced by *developer-created code within Active Admin*, not by Active Admin itself.

### 4.2 Code Examples

**Vulnerable Example (Custom Filter):**

```ruby
# app/admin/products.rb
ActiveAdmin.register Product do
  filter :name_contains, as: :string, label: 'Name Contains (VULNERABLE)'

  controller do
    def scoped_collection
      if params[:q] && params[:q][:name_contains].present?
        Product.where("name LIKE '%#{params[:q][:name_contains]}%'") # VULNERABLE!
      else
        super
      end
    end
  end
end
```

**Explanation:** This code directly interpolates the user-provided value from the `name_contains` filter into the SQL query. An attacker could enter something like `' OR 1=1 --` into the filter field, resulting in the query: `SELECT * FROM products WHERE name LIKE '%' OR 1=1 -- %'`.  This would return all products, bypassing any intended filtering.

**Secure Example (Custom Filter):**

```ruby
# app/admin/products.rb
ActiveAdmin.register Product do
  filter :name_contains, as: :string, label: 'Name Contains (SECURE)'

  controller do
    def scoped_collection
      if params[:q] && params[:q][:name_contains].present?
        Product.where("name LIKE ?", "%#{params[:q][:name_contains]}%") # SECURE: Parameterized query
      else
        super
      end
    end
  end
end
```

**Explanation:** This uses ActiveRecord's parameterized query syntax.  The `?` placeholder is replaced by the value of `params[:q][:name_contains]`, and ActiveRecord automatically handles escaping, preventing SQL injection.

**Vulnerable Example (Custom Action):**

```ruby
# app/admin/users.rb
ActiveAdmin.register User do
  member_action :delete_by_id, method: :delete do
    User.connection.execute("DELETE FROM users WHERE id = #{params[:id]}") # VULNERABLE!
    redirect_to admin_users_path, notice: "User deleted (unsafely!)"
  end
end
```

**Explanation:** This custom action directly executes a raw SQL query using string interpolation with the `params[:id]` value.  An attacker could manipulate the `id` parameter in the URL to inject malicious SQL.

**Secure Example (Custom Action):**

```ruby
# app/admin/users.rb
ActiveAdmin.register User do
  member_action :delete_by_id, method: :delete do
    User.find(params[:id]).destroy # SECURE: Uses ActiveRecord
    redirect_to admin_users_path, notice: "User deleted."
  end
end
```

**Explanation:** This uses ActiveRecord's `find` and `destroy` methods, which are inherently safe against SQL injection.

### 4.3 Attack Scenario Walkthrough (Custom Filter Example)

1.  **Target Identification:** The attacker identifies an Active Admin interface with a custom filter, like the vulnerable `name_contains` filter example above.
2.  **Probe for Vulnerability:** The attacker enters a single quote (`'`) into the filter field and submits the form.  If an error occurs (e.g., a database error message), it strongly suggests a potential SQL injection vulnerability.
3.  **Craft Payload:** The attacker crafts a malicious SQL payload.  For example:
    *   `' OR 1=1 --` (to retrieve all records)
    *   `' UNION SELECT username, password FROM users --` (to attempt to extract usernames and passwords)
    *   `'; DROP TABLE products --` (to attempt to delete the products table – a destructive attack)
4.  **Inject Payload:** The attacker enters the crafted payload into the filter field and submits the form.
5.  **Exploit Results:**  If the vulnerability exists, the attacker's payload will be executed as part of the SQL query.  The attacker might see all products (if using the `' OR 1=1 --` payload), receive sensitive data (if using the `UNION SELECT` payload), or cause data loss (if using the `DROP TABLE` payload).

### 4.4 Impact Analysis

The impact of a successful SQL injection attack via Active Admin customizations can be severe:

*   **Data Breach:**  Attackers can read any data accessible to the Active Admin user, including sensitive customer information, financial records, and internal documents.
*   **Data Modification:**  Attackers can modify or delete data, potentially corrupting the database or causing significant business disruption.
*   **Data Loss:**  Attackers can delete entire tables or databases, leading to permanent data loss.
*   **Denial of Service:**  Attackers can execute resource-intensive queries, making the application unresponsive.
*   **Privilege Escalation:**  In some cases, attackers might be able to gain administrative privileges within the application or even on the underlying server.
*   **Reputational Damage:**  A successful SQL injection attack can severely damage the reputation of the organization.
*   **Legal and Financial Consequences:**  Data breaches can lead to legal action, fines, and other financial penalties.

### 4.5 Mitigation Strategies (Reinforced)

*   **Prioritize ActiveRecord:**  Always use ActiveRecord's query methods (e.g., `where`, `find`, `find_by`, `joins`, `select`) within Active Admin customizations.  These methods provide built-in protection against SQL injection.
*   **Avoid Raw SQL:**  Minimize the use of raw SQL queries (`connection.execute`, `find_by_sql`) within Active Admin.  If raw SQL is absolutely necessary, use prepared statements.
*   **Parameterized Queries (Essential):**  When using ActiveRecord's `where` method, always use parameterized queries (e.g., `where("name LIKE ?", "%#{value}%")`) instead of string interpolation.
*   **Prepared Statements (for Raw SQL):**  If you *must* use raw SQL, use prepared statements with parameterized inputs.  Example:

    ```ruby
    sql = "SELECT * FROM users WHERE id = ?"
    records = User.connection.select_all(ActiveRecord::Base.send(:sanitize_sql_array, [sql, params[:id]]))
    ```
    Even better, use `exec_query`:
    ```ruby
     sql = "SELECT * FROM users WHERE id = ?"
     records = User.connection.exec_query(sql, 'SQL', [[nil, params[:id]]])
    ```

*   **Input Validation (Defense in Depth):**  While not a primary defense against SQL injection, validate user input within Active Admin's custom code to ensure it conforms to expected formats.  This can help prevent unexpected input from reaching the database layer.  Use Rails' built-in validation helpers or custom validation logic.
*   **Least Privilege Principle:**  Ensure that the database user used by Active Admin has only the necessary privileges.  Avoid using a database user with excessive permissions (e.g., the ability to create or drop tables).
*   **Regular Security Audits:**  Conduct regular security audits of your Active Admin code to identify and address potential vulnerabilities.
* **Keep ActiveAdmin Updated:** Use latest version of ActiveAdmin, to avoid any potential vulnerability in gem itself.

### 4.6 Testing and Verification

*   **Manual Testing:**  Manually test custom filters and actions with various inputs, including known SQL injection payloads (e.g., single quotes, `OR 1=1`, `UNION SELECT`).  Look for unexpected results or database errors.
*   **Automated Testing:**  Write automated tests (e.g., RSpec, Minitest) that specifically check for SQL injection vulnerabilities.  These tests should attempt to inject malicious SQL and verify that the application behaves correctly (e.g., does not return unexpected data).
*   **Static Code Analysis:**  Use static code analysis tools (e.g., Brakeman, RuboCop with security-related rules) to automatically scan your Active Admin code for potential SQL injection vulnerabilities.
*   **Dynamic Application Security Testing (DAST):**  Use DAST tools (e.g., OWASP ZAP, Burp Suite) to scan your running Active Admin application for vulnerabilities, including SQL injection.

### 4.7 Tools and Resources

*   **Brakeman:** A static analysis security vulnerability scanner for Ruby on Rails applications.  Highly recommended.
*   **RuboCop:** A Ruby static code analyzer and formatter, with extensions for security checks.
*   **OWASP ZAP:** A free and open-source web application security scanner.
*   **Burp Suite:** A commercial web application security testing tool.
*   **OWASP SQL Injection Prevention Cheat Sheet:**  [https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
*   **Rails Security Guide:** [https://guides.rubyonrails.org/security.html](https://guides.rubyonrails.org/security.html)

## 5. Conclusion

SQL injection via custom filters and actions in Active Admin is a critical vulnerability that can have severe consequences.  By understanding the mechanisms of this vulnerability and consistently applying secure coding practices, developers can effectively mitigate this risk and protect their applications and data.  The key takeaway is to *always* use ActiveRecord's safe query methods whenever possible and to avoid string interpolation in SQL queries.  Regular testing and security audits are essential for ensuring the ongoing security of Active Admin customizations.