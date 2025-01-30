## Deep Analysis: Route Parameter Injection in Egg.js Applications

This document provides a deep analysis of the **Route Parameter Injection** threat within the context of applications built using the Egg.js framework (https://github.com/eggjs/egg).

### 1. Define Objective of Deep Analysis

The objective of this deep analysis is to thoroughly understand the Route Parameter Injection threat in Egg.js applications. This includes:

*   **Detailed Explanation:**  Elaborating on the nature of the threat and how it manifests in Egg.js.
*   **Impact Assessment:**  Analyzing the potential consequences of successful exploitation, specifically within the Egg.js ecosystem.
*   **Component Analysis:**  Identifying the Egg.js components most vulnerable to this threat.
*   **Attack Vector Exploration:**  Illustrating potential attack scenarios and methodologies.
*   **Mitigation Strategy Deep Dive:**  Providing detailed and Egg.js-specific guidance on implementing the recommended mitigation strategies.
*   **Raising Awareness:**  Educating development teams about the risks and best practices to prevent Route Parameter Injection in their Egg.js applications.

### 2. Scope

This analysis focuses on the following aspects of Route Parameter Injection in Egg.js applications:

*   **Route Parameters:**  Specifically examining how route parameters (both path parameters and query parameters) are handled and processed within Egg.js routing and controllers.
*   **Affected Components:**  Analyzing the impact on core Egg.js components such as:
    *   Routing system
    *   Controllers
    *   Data access layer (using common Egg.js database integrations like `egg-sequelize`, `egg-mongoose`)
    *   File system operations (if applicable within the application)
*   **Common Vulnerabilities:**  Focusing on the most prevalent vulnerabilities arising from Route Parameter Injection, including:
    *   Path Traversal
    *   Local File Inclusion (LFI)
    *   NoSQL Injection
    *   Command Injection (indirectly, if parameters are used in system commands)
*   **Mitigation Techniques:**  Concentrating on practical and effective mitigation strategies applicable to Egg.js development.

This analysis **does not** cover:

*   Other types of injection vulnerabilities (e.g., SQL Injection, XSS, CSRF) in detail, unless directly related to Route Parameter Injection.
*   Specific application logic vulnerabilities beyond the scope of route parameter handling.
*   Detailed code review of a specific Egg.js application.

### 3. Methodology

This deep analysis will employ the following methodology:

1.  **Literature Review:**  Reviewing documentation for Egg.js routing, controllers, and related components to understand how route parameters are handled. Examining general resources on Route Parameter Injection and related vulnerabilities.
2.  **Conceptual Analysis:**  Analyzing the threat description and impact in the context of Egg.js architecture and common application patterns.
3.  **Component-Specific Analysis:**  Examining how each affected Egg.js component (Routing, Controllers, Data Access, File System) can be vulnerable to Route Parameter Injection.
4.  **Attack Scenario Modeling:**  Developing hypothetical attack scenarios to illustrate how an attacker could exploit this vulnerability in an Egg.js application.
5.  **Mitigation Strategy Evaluation:**  Analyzing the effectiveness and practicality of the recommended mitigation strategies within the Egg.js framework, and providing concrete implementation guidance.
6.  **Best Practices Formulation:**  Summarizing key best practices for Egg.js developers to prevent Route Parameter Injection.

### 4. Deep Analysis of Route Parameter Injection Threat

#### 4.1. Threat Description in Egg.js Context

Route Parameter Injection in Egg.js applications occurs when user-supplied data from route parameters (path parameters defined in routes like `/users/:id` or query parameters in URLs like `/search?query=`) is directly used in application logic without proper validation and sanitization.

Egg.js, being a Node.js framework, relies on JavaScript for its backend logic.  Unsanitized route parameters can be particularly dangerous when used in operations that interact with:

*   **File System:**  Constructing file paths for reading, writing, or including files.
*   **Databases (NoSQL):**  Building queries for NoSQL databases like MongoDB (often used with Egg.js through `egg-mongoose`).
*   **System Commands:**  Although less common directly from route parameters, if parameters are indirectly used in shell commands, it can lead to command injection.

**How Route Parameters are Accessed in Egg.js:**

In Egg.js controllers, route parameters are typically accessed through the `ctx` object:

*   **Path Parameters:**  Accessed via `ctx.params`. For example, in a route `/users/:id`, `ctx.params.id` will contain the value of the `:id` segment.
*   **Query Parameters:** Accessed via `ctx.query`. For example, in a URL `/search?query=example`, `ctx.query.query` will contain the value "example".

**Example of Vulnerable Code (Conceptual):**

```javascript
// Vulnerable Egg.js Controller - DO NOT USE IN PRODUCTION
const fs = require('fs');
const path = require('path');

module.exports = class VulnerableController extends app.Controller {
  async readFile() {
    const { ctx } = this;
    const filename = ctx.params.filename; // Unsanitized route parameter
    const filePath = path.join('/app/data/', filename); // Constructing file path

    try {
      const fileContent = fs.readFileSync(filePath, 'utf8');
      ctx.body = fileContent;
    } catch (error) {
      ctx.status = 404;
      ctx.body = 'File not found';
    }
  }
};
```

In this vulnerable example, if an attacker provides a malicious `filename` like `../../../../etc/passwd`, they could potentially read sensitive files outside the intended `/app/data/` directory, leading to **Path Traversal** and **Local File Inclusion (LFI)**.

#### 4.2. Impact Analysis

Successful exploitation of Route Parameter Injection in Egg.js applications can lead to a range of severe impacts:

*   **Path Traversal:** Attackers can navigate the file system outside the intended directory by manipulating route parameters used in file path construction. This can expose sensitive files, configuration files, or even application source code.
*   **Local File Inclusion (LFI):**  Building upon Path Traversal, attackers can include and potentially execute local files if the application processes files (e.g., using `require()` or similar functions based on route parameters).
*   **Remote File Inclusion (RFI):**  In more complex scenarios, if route parameters are used to construct URLs for including remote files (though less common in direct route parameter injection), it could lead to RFI, allowing attackers to execute arbitrary code from external sources.
*   **NoSQL Injection:** If route parameters are used to build NoSQL queries (e.g., MongoDB queries using `egg-mongoose`), attackers can inject malicious operators or conditions to bypass authentication, access unauthorized data, modify data, or even cause denial of service.
*   **Command Injection (Indirect):** While less direct, if route parameters are used to construct commands executed by the system (e.g., through `child_process` in Node.js), attackers could inject malicious commands.
*   **Data Breaches:**  Exposure of sensitive data through file system access or database manipulation can lead to data breaches and compromise user privacy.
*   **Application Compromise:**  In severe cases, successful exploitation can lead to complete application compromise, allowing attackers to gain control of the server, execute arbitrary code, and potentially pivot to other systems.

#### 4.3. Egg Component Affected Analysis

*   **Routing System:** The Egg.js routing system itself is not inherently vulnerable, but it's the entry point where malicious parameters are introduced.  The way routes are defined and parameters are extracted sets the stage for potential injection if not handled carefully later.
*   **Route Parameters:** Route parameters (both path and query) are the direct source of the threat.  If these parameters are treated as trusted input, vulnerabilities arise.
*   **Controllers:** Controllers are the primary Egg.js components where route parameters are processed and used in application logic.  This is where validation, sanitization, and secure coding practices are crucial to prevent injection vulnerabilities. Controllers are the most directly affected component in terms of mitigation implementation.
*   **Data Access Layer:** If controllers use route parameters to construct database queries (especially in NoSQL databases), the data access layer becomes vulnerable to NoSQL injection.  This is relevant when using Egg.js database integrations like `egg-sequelize` or `egg-mongoose`.
*   **File System Operations:**  If controllers perform file system operations (reading, writing, including files) based on route parameters, these operations become vulnerable to path traversal and file inclusion attacks.

#### 4.4. Attack Vectors and Scenarios in Egg.js

**Scenario 1: Path Traversal and LFI via Filename Parameter**

*   **Route:** `/files/:filename`
*   **Controller Code (Vulnerable):**  (As shown in the example in 4.1)
*   **Attack Vector:**
    1.  Attacker crafts a request like `/files/../../../../etc/passwd`.
    2.  The vulnerable controller directly uses `ctx.params.filename` to construct the file path.
    3.  `fs.readFileSync` attempts to read `/app/data/../../../../etc/passwd`, which resolves to `/etc/passwd` due to path traversal.
    4.  If successful, the attacker can read the contents of `/etc/passwd`.

**Scenario 2: NoSQL Injection via Search Query Parameter**

*   **Route:** `/products/search` (using query parameter `query`)
*   **Controller Code (Vulnerable - using `egg-mongoose` conceptually):**

```javascript
// Vulnerable Egg.js Controller - DO NOT USE IN PRODUCTION
module.exports = class VulnerableProductController extends app.Controller {
  async searchProducts() {
    const { ctx } = this;
    const searchQuery = ctx.query.query; // Unsanitized query parameter

    try {
      const products = await ctx.model.Product.find({ name: searchQuery }); // Vulnerable NoSQL query
      ctx.body = products;
    } catch (error) {
      ctx.status = 500;
      ctx.body = 'Search error';
    }
  }
};
```

*   **Attack Vector:**
    1.  Attacker crafts a request like `/products/search?query[$ne]=null`.
    2.  The vulnerable controller uses `ctx.query.query` directly in the MongoDB query.
    3.  The query becomes `db.products.find({ name: { $ne: null } })`, which effectively returns all products because `$ne: null` means "not equal to null," and most `name` fields will not be null.
    4.  More sophisticated NoSQL injection payloads can be used to bypass authentication or extract more data.

**Scenario 3: Command Injection (Indirect - Less Common from Route Parameters Directly)**

*   **Route:** `/process/:command`
*   **Controller Code (Vulnerable - Highly Unlikely in Real-World, but Illustrative):**

```javascript
// Vulnerable Egg.js Controller - DO NOT USE IN PRODUCTION - HIGHLY UNLIKELY SCENARIO
const { exec } = require('child_process');

module.exports = class VulnerableProcessController extends app.Controller {
  async executeCommand() {
    const { ctx } = this;
    const command = ctx.params.command; // Unsanitized route parameter

    exec(command, (error, stdout, stderr) => { // Vulnerable command execution
      if (error) {
        ctx.status = 500;
        ctx.body = `Error: ${error.message}`;
        return;
      }
      ctx.body = stdout;
    });
  }
};
```

*   **Attack Vector:**
    1.  Attacker crafts a request like `/process/ls -al && cat /etc/passwd`.
    2.  The vulnerable controller directly executes the unsanitized command.
    3.  `exec` executes `ls -al && cat /etc/passwd`, potentially revealing directory listings and sensitive file contents.

**Note:** Direct command injection from route parameters is less common in typical web applications. However, if route parameters are used to indirectly influence command construction in other parts of the application, it remains a potential risk.

### 5. Mitigation Strategies (Detailed and Egg.js Specific)

To effectively mitigate Route Parameter Injection in Egg.js applications, implement the following strategies:

#### 5.1. Input Validation and Sanitization

This is the **most critical** mitigation.  Always validate and sanitize route parameters **within your Egg.js controllers** before using them in any application logic.

*   **Validation:**
    *   **Data Type Validation:** Ensure parameters are of the expected data type (e.g., integer, string, UUID). Use libraries like `parameter` (an official Egg.js plugin) or custom validation logic.
    *   **Format Validation:**  Validate parameter format using regular expressions or specific validation rules (e.g., email format, date format, allowed characters).
    *   **Allowed Values (Whitelisting):**  If possible, define a whitelist of allowed values for parameters. This is the most secure approach when applicable.
    *   **Length Limits:**  Enforce maximum length limits for string parameters to prevent buffer overflows or excessive resource consumption in certain scenarios.

*   **Sanitization:**
    *   **Encoding:**  Encode parameters appropriately for their intended use (e.g., URL encoding, HTML encoding). However, encoding alone is often insufficient for security and should be combined with validation.
    *   **Removing/Replacing Disallowed Characters:**  Remove or replace characters that are known to be dangerous in specific contexts (e.g., path traversal characters like `..`, `/`, `\` in filenames; special characters in NoSQL queries).
    *   **Type Casting:**  Cast parameters to the expected data type (e.g., `parseInt()` for integers) after validation. This can help prevent unexpected behavior.

**Egg.js Specific Implementation Examples:**

**Using `egg-parameter` for Validation:**

1.  **Install `egg-parameter`:** `npm install egg-parameter --save`
2.  **Enable plugin in `config/plugin.js`:**

    ```javascript
    exports.parameter = {
      enable: true,
      package: 'egg-parameter',
    };
    ```

3.  **Use in Controller:**

    ```javascript
    module.exports = class SafeController extends app.Controller {
      async readFile() {
        const { ctx } = this;
        const rules = {
          filename: { type: 'string', format: /^[a-zA-Z0-9_-]+$/, required: true }, // Whitelist allowed characters
        };

        try {
          ctx.validate(rules, ctx.params); // Validate ctx.params
          const filename = ctx.params.filename;
          const filePath = path.join('/app/data/', filename);
          // ... (rest of the code - file reading) ...
        } catch (error) {
          ctx.status = 400; // Bad Request
          ctx.body = error.errors; // Return validation errors
        }
      }
    };
    ```

**Manual Validation and Sanitization in Controller:**

```javascript
module.exports = class SafeController extends app.Controller {
  async searchProducts() {
    const { ctx } = this;
    let searchQuery = ctx.query.query;

    if (!searchQuery || typeof searchQuery !== 'string' || searchQuery.length > 100) { // Basic validation
      ctx.status = 400;
      ctx.body = { error: 'Invalid search query' };
      return;
    }

    searchQuery = searchQuery.replace(/[^a-zA-Z0-9\s]/g, ''); // Basic sanitization - remove special characters

    try {
      const products = await ctx.model.Product.find({ name: { $regex: searchQuery, $options: 'i' } }); // Using regex for search
      ctx.body = products;
    } catch (error) {
      ctx.status = 500;
      ctx.body = 'Search error';
    }
  }
};
```

#### 5.2. Parameter Encoding

Properly encode route parameters, especially when constructing URLs or embedding them in other contexts.

*   **URL Encoding:**  Use URL encoding (e.g., `encodeURIComponent()` in JavaScript) when constructing URLs that include route parameters. This helps prevent misinterpretation of special characters in URLs.
*   **HTML Encoding:** If route parameters are displayed in HTML content, use HTML encoding to prevent Cross-Site Scripting (XSS) vulnerabilities. While not directly related to Route Parameter Injection as defined, it's a good general security practice.

**Egg.js Context:** Egg.js handles URL encoding and decoding for route parameters automatically in most cases. However, when you are *constructing* URLs programmatically within your application that include user-provided parameters, ensure you are using URL encoding.

#### 5.3. Principle of Least Privilege (File Access)

Apply the principle of least privilege to file system access.

*   **Restrict File System Access:**  Limit the directories and files that the application process has access to.  Avoid running the Egg.js application process with overly permissive user accounts.
*   **Dedicated Directories:**  Store application data and files in dedicated directories with restricted permissions.  Avoid allowing the application to access the entire file system.
*   **Chroot Environments (Advanced):** In highly sensitive environments, consider using chroot jails or containerization to further isolate the application's file system access.

**Egg.js Context:**  When dealing with file operations in Egg.js, carefully consider the directory paths you are working with.  Avoid constructing file paths based on unsanitized route parameters that could lead to accessing files outside the intended directories.

#### 5.4. Prepared Statements/Parameterized Queries (Database)

For database interactions, **always use prepared statements or parameterized queries** to prevent SQL and NoSQL injection.

*   **Prepared Statements (SQL):**  Use parameterized queries provided by your SQL database driver. This separates the SQL query structure from user-supplied data, preventing injection.
*   **Parameterized Queries (NoSQL - MongoDB with `egg-mongoose`):**  Use query builders and object-based query syntax provided by your NoSQL database driver (e.g., Mongoose in `egg-mongoose`). Avoid constructing queries by directly concatenating strings with user input.

**Egg.js Specific Implementation Examples (using `egg-mongoose`):**

**Vulnerable (String Concatenation - DO NOT USE):**

```javascript
// Vulnerable - DO NOT USE
const searchQuery = ctx.query.query;
const products = await ctx.model.Product.find({ name: `"${searchQuery}"` }); // Vulnerable string concatenation
```

**Safe (Parameterized Query - Using Mongoose Query Builder):**

```javascript
const searchQuery = ctx.query.query;
const products = await ctx.model.Product.find({ name: searchQuery }); // Safe - Mongoose handles parameterization
```

**For more complex queries in `egg-mongoose`, use object-based syntax:**

```javascript
const searchName = ctx.query.name;
const searchCategory = ctx.query.category;

const query = {};
if (searchName) {
  query.name = searchName;
}
if (searchCategory) {
  query.category = searchCategory;
}

const products = await ctx.model.Product.find(query); // Safe - Object-based query
```

**Key Takeaway:**  Never directly embed unsanitized route parameters into database query strings. Always use the parameterized query mechanisms provided by your database driver or ORM/ODM (like Mongoose in `egg-mongoose` or Sequelize in `egg-sequelize`).

### 6. Conclusion

Route Parameter Injection is a significant threat to Egg.js applications, potentially leading to severe vulnerabilities like path traversal, file inclusion, NoSQL injection, and data breaches.  By understanding how route parameters are processed in Egg.js and implementing robust mitigation strategies, development teams can significantly reduce the risk.

**Key Recommendations for Egg.js Developers:**

*   **Prioritize Input Validation and Sanitization:** Make validation and sanitization of all route parameters a standard practice in every controller. Use libraries like `egg-parameter` to streamline validation.
*   **Adopt Secure Coding Practices:**  Avoid directly using unsanitized route parameters in file system operations, database queries, or system commands.
*   **Use Parameterized Queries:**  Always use prepared statements or parameterized queries for database interactions to prevent injection vulnerabilities.
*   **Apply Least Privilege:**  Restrict file system access and database permissions for the Egg.js application process.
*   **Regular Security Reviews:**  Conduct regular security reviews and penetration testing to identify and address potential Route Parameter Injection vulnerabilities and other security weaknesses in your Egg.js applications.

By diligently applying these mitigation strategies and fostering a security-conscious development culture, you can build more resilient and secure Egg.js applications.