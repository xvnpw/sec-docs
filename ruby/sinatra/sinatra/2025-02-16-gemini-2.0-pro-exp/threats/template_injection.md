Okay, let's create a deep analysis of the "Template Injection" threat for a Sinatra application.

## Deep Analysis: Template Injection in Sinatra Applications

### 1. Define Objective, Scope, and Methodology

**Objective:**

The primary objective of this deep analysis is to thoroughly understand the "Template Injection" threat within the context of a Sinatra application.  This includes understanding how the vulnerability manifests, the potential impact, and effective mitigation strategies beyond the high-level overview provided in the initial threat model. We aim to provide actionable guidance for developers to prevent this vulnerability.

**Scope:**

This analysis focuses specifically on Server-Side Template Injection (SSTI) vulnerabilities arising from the misuse of templating engines (like ERB, Haml, Slim, etc.) within a Sinatra application.  It covers:

*   Sinatra's built-in templating mechanisms and how they interact with user-supplied data.
*   Common patterns of vulnerable code.
*   Specific examples of exploit payloads.
*   Detailed explanation of mitigation techniques, including code examples and best practices.
*   Testing strategies to identify and confirm the presence or absence of SSTI.

This analysis *does not* cover:

*   Client-side template injection (which is a separate, though related, vulnerability).
*   Vulnerabilities in the templating engines themselves (we assume the templating engine is up-to-date and patched).
*   Other types of injection attacks (e.g., SQL injection, command injection) unless they directly relate to exploiting SSTI.

**Methodology:**

This analysis will follow a structured approach:

1.  **Vulnerability Explanation:**  Provide a detailed explanation of SSTI, including how it works in general and specifically within Sinatra.
2.  **Vulnerable Code Patterns:** Identify and illustrate common coding patterns that lead to SSTI vulnerabilities in Sinatra.
3.  **Exploit Examples:**  Demonstrate concrete examples of how an attacker could exploit SSTI in a Sinatra application, including specific payloads.
4.  **Mitigation Strategies (Deep Dive):**  Expand on the initial mitigation strategies, providing detailed explanations, code examples, and best practices.
5.  **Testing and Verification:**  Describe methods for testing Sinatra applications for SSTI vulnerabilities, including both manual and automated approaches.
6.  **References:**  Provide links to relevant documentation, security advisories, and further reading.

### 2. Deep Analysis of the Threat

#### 2.1 Vulnerability Explanation

Server-Side Template Injection (SSTI) occurs when an attacker can inject malicious code into a server-side template.  Templating engines are designed to generate dynamic content by combining static templates with data.  If user-supplied data is directly incorporated into the template *itself* (rather than being passed as *data* to the template), the attacker can control the template's structure and potentially execute arbitrary code on the server.

In Sinatra, this typically happens when user input is used to determine *which* template to render, or when user input is directly concatenated into the template string.  Sinatra's `erb`, `haml`, `slim`, etc., methods are vulnerable if misused.

**Example (Vulnerable):**

```ruby
require 'sinatra'

get '/hello/:template' do
  template_name = params[:template]
  erb template_name.to_sym  # VULNERABLE!
end
```

In this example, the `template_name` is taken directly from the URL parameter `:template`.  An attacker could craft a URL like `/hello/../../../../etc/passwd` (path traversal) or, more dangerously, `/hello/something;system('ls')` to attempt to execute arbitrary commands.  The `.to_sym` conversion is insufficient protection.

#### 2.2 Vulnerable Code Patterns

Besides the direct example above, here are other vulnerable patterns:

*   **Indirect Template Selection:**

    ```ruby
    get '/greet' do
      greeting_type = params[:type] || 'default'
      erb :"greetings/#{greeting_type}"  # VULNERABLE if 'type' is not strictly controlled
    end
    ```
    Even with a default value, if `params[:type]` can be manipulated to include malicious characters or paths, it's vulnerable.

*   **Concatenating User Input into Template Strings:**

    ```ruby
    get '/message' do
      message = params[:msg]
      erb "<h1>#{message}</h1>"  # VULNERABLE!  This is NOT how to pass data to a template.
    end
    ```
    This is a classic example of directly embedding user input into the template.  The correct way is to pass `message` as a variable to the template: `erb :message, locals: { msg: message }` and then use `<%= msg %>` in the `message.erb` template.

*   **Using `render` with Untrusted Input:**

    Sinatra's `render` method (which is used internally by `erb`, `haml`, etc.) is also vulnerable if the template name or content is derived from untrusted input.

#### 2.3 Exploit Examples

Let's assume the vulnerable code from section 2.1:

```ruby
get '/hello/:template' do
  template_name = params[:template]
  erb template_name.to_sym
end
```

*   **ERB Payload (Command Execution):**

    An attacker might try:
    `/hello/<%=`system('id')`%><%=`
    If successful, this would execute the `id` command on the server and display the output.  The backticks are crucial for command execution within ERB.

*   **ERB Payload (File Read):**

    `/hello/<%=`File.read('/etc/passwd')`%><%=`
    This attempts to read the contents of `/etc/passwd` and display it.

*   **Haml Payload (Command Execution):**

    Haml uses different syntax.  A possible payload:
    `/hello/-`x = `id`;`= x`
    The `-` indicates a Ruby code block, and `=` outputs the result.

*   **Path Traversal (leading to arbitrary template execution):**
    `/hello/../../views/admin/secret_template`
    If an `admin/secret_template.erb` exists, and the attacker knows (or guesses) its location, they could potentially render it, even if it's not intended to be publicly accessible.

#### 2.4 Mitigation Strategies (Deep Dive)

*   **1. Avoid User Input in Template Names (Preferred):**

    The best approach is to *never* use user input to construct template names or paths.  Instead, use a predefined set of templates and select them based on application logic, *not* directly on user input.

    ```ruby
    get '/greet/:type' do
      case params[:type]
      when 'formal'
        erb :formal_greeting
      when 'informal'
        erb :informal_greeting
      else
        erb :default_greeting
      end
    end
    ```
    This is safe because the template name is determined by a `case` statement, and the possible values are hardcoded.

*   **2. Whitelist Allowed Templates (If Dynamic Selection is Necessary):**

    If you *must* use user input to select a template, use a strict whitelist.

    ```ruby
    ALLOWED_TEMPLATES = ['greeting', 'farewell', 'introduction'].freeze

    get '/page/:name' do
      template_name = params[:name]
      if ALLOWED_TEMPLATES.include?(template_name)
        erb template_name.to_sym
      else
        halt 404, 'Template not found'
      end
    end
    ```
    This limits the attacker's options to the explicitly allowed templates.  The `.freeze` method makes the array immutable, preventing accidental modification.

*   **3. Sanitize and Validate (Least Preferred, Use with Caution):**

    If you absolutely cannot avoid using user input and a whitelist is insufficient, you *must* sanitize and validate the input *extremely* carefully.  This is the riskiest approach and is prone to errors.

    ```ruby
    get '/report/:type' do
      report_type = params[:type]
      # Sanitize: Remove any characters that are not alphanumeric.
      report_type = report_type.gsub(/[^a-zA-Z0-9]/, '')
      # Validate: Ensure the sanitized input matches a specific pattern.
      if report_type =~ /\A[a-z]{1,10}\z/
        erb :"reports/#{report_type}"
      else
        halt 400, 'Invalid report type'
      end
    end
    ```
    This example sanitizes by removing non-alphanumeric characters and then validates that the result is a lowercase string of 1 to 10 characters.  **This is still a fragile approach.**  It's very easy to miss a potential bypass.  Whitelisting is *always* preferred.

*   **4. Use `locals` to Pass Data:**

    Always pass data to templates using the `locals` option.  This ensures that the data is treated as *data*, not as part of the template itself.

    ```ruby
    get '/user/:id' do
      user = User.find(params[:id])
      erb :user_profile, locals: { user: user }
    end
    ```
    In the `user_profile.erb` template, you would then access the user data using `<%= user.name %>`, `<%= user.email %>`, etc.

*   **5. Principle of Least Privilege:**

    Run your Sinatra application with the least necessary privileges.  This limits the damage an attacker can do if they achieve code execution.  Don't run the application as root!

*   **6. Keep Sinatra and Gems Updated:**

    Regularly update Sinatra and all your application's dependencies (including the templating engine) to the latest versions.  This ensures you have the latest security patches.

#### 2.5 Testing and Verification

*   **Manual Testing:**

    *   Try injecting common SSTI payloads (like those in section 2.3) into any parameters that might influence template selection or content.
    *   Use a proxy (like Burp Suite or OWASP ZAP) to intercept and modify requests.
    *   Carefully review the application's source code for any instances where user input is used to construct template names or is directly embedded in template strings.

*   **Automated Testing:**

    *   **Static Analysis:** Use static analysis tools (like Brakeman for Ruby) to scan your code for potential SSTI vulnerabilities.  Brakeman specifically has checks for template injection.
    *   **Dynamic Analysis:**  Use a web application vulnerability scanner (like OWASP ZAP or Burp Suite's scanner) to automatically test for SSTI.  These tools can send a variety of payloads and analyze the responses for signs of vulnerability.
    *   **Fuzzing:**  Use a fuzzer to send a large number of mutated inputs to the application and monitor for unexpected behavior.

*   **Code Review:** Incorporate SSTI checks into your code review process.  Ensure that all developers are aware of the risks and the proper mitigation techniques.

#### 2.6 References

*   **Sinatra Documentation:** [http://sinatrarb.com/](http://sinatrarb.com/)
*   **OWASP Server Side Template Injection:** [https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection)
*   **PortSwigger Web Security Academy - Server-Side Template Injection:** [https://portswigger.net/web-security/server-side-template-injection](https://portswigger.net/web-security/server-side-template-injection)
*   **Brakeman (Static Analysis Tool):** [https://brakemanscanner.org/](https://brakemanscanner.org/)

### 3. Conclusion

Template injection is a critical vulnerability that can lead to complete server compromise.  By understanding the underlying mechanisms, common vulnerable patterns, and effective mitigation strategies, developers can build Sinatra applications that are secure against this threat.  The most important takeaway is to avoid using user input to determine which template to render.  If dynamic template selection is unavoidable, a strict whitelist is the best defense.  Regular security testing and code reviews are essential to ensure that SSTI vulnerabilities are identified and addressed promptly.