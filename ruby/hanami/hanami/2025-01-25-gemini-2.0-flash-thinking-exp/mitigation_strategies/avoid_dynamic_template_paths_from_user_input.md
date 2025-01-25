## Deep Analysis: Avoid Dynamic Template Paths from User Input - Mitigation Strategy for Hanami Application

### 1. Define Objective of Deep Analysis

The objective of this deep analysis is to thoroughly evaluate the "Avoid Dynamic Template Paths from User Input" mitigation strategy in the context of a Hanami web application. This analysis aims to:

*   **Understand the threat landscape:** Clearly define Template Injection and Local File Inclusion (LFI) vulnerabilities and their relevance to Hanami applications.
*   **Assess the effectiveness of the mitigation strategy:** Determine how effectively this strategy prevents Template Injection and LFI attacks in Hanami.
*   **Identify strengths and weaknesses:** Analyze the advantages and potential limitations of this mitigation approach.
*   **Provide implementation guidance:** Offer practical recommendations for implementing this strategy within a Hanami development workflow.
*   **Suggest improvements and further considerations:** Explore potential enhancements and related security practices to complement this mitigation.

### 2. Scope

This deep analysis will focus on the following aspects of the "Avoid Dynamic Template Paths from User Input" mitigation strategy:

*   **Detailed explanation of Template Injection and LFI vulnerabilities** in the context of Hanami template rendering.
*   **Analysis of how dynamic template paths can introduce these vulnerabilities** within Hanami applications.
*   **Evaluation of the proposed mitigation steps** and their effectiveness in addressing the identified threats.
*   **Discussion of the impact** of implementing this mitigation strategy on application security and development practices.
*   **Exploration of potential edge cases and limitations** of the mitigation.
*   **Recommendations for practical implementation** within a Hanami project, including code examples and workflow considerations.
*   **Suggestions for complementary security measures** to enhance the overall security posture.

This analysis will primarily consider the security implications related to template rendering within Hanami and will not delve into other potential vulnerabilities or broader application security aspects unless directly relevant to the discussed mitigation strategy.

### 3. Methodology

This deep analysis will be conducted using the following methodology:

*   **Literature Review:** Review documentation related to Hanami framework, template engines commonly used with Hanami (e.g., ERB, Haml, Slim), and general web application security best practices, specifically focusing on Template Injection and LFI vulnerabilities.
*   **Threat Modeling:** Analyze how Template Injection and LFI vulnerabilities can manifest in Hanami applications due to dynamic template paths, considering the framework's architecture and template rendering process.
*   **Mitigation Strategy Analysis:**  Critically examine each step of the proposed mitigation strategy, evaluating its logic, effectiveness, and potential drawbacks.
*   **Impact Assessment:**  Assess the positive impact of implementing this mitigation on reducing the risk of Template Injection and LFI, as well as any potential negative impacts on development flexibility or performance.
*   **Best Practices Integration:**  Align the mitigation strategy with established secure coding practices and industry standards for web application security.
*   **Practical Recommendations:**  Formulate actionable recommendations for implementing and verifying the mitigation strategy within a Hanami development environment, considering developer workflows and code review processes.

### 4. Deep Analysis of Mitigation Strategy: Avoid Dynamic Template Paths from User Input

#### 4.1. Understanding the Threat Landscape in Hanami Templates

Hanami, like many web frameworks, relies on template engines to dynamically generate HTML or other output. These templates often contain embedded code that is executed during rendering.  If an attacker can control the path to the template being rendered, they can potentially exploit two significant vulnerabilities:

*   **Template Injection (High Severity):**  This vulnerability arises when user-controlled input is directly used to construct or influence the template content *or* the template path itself, and the template engine interprets this input as code. In the context of *dynamic template paths*, if an attacker can manipulate the path, they might be able to force the application to render a template they control, which contains malicious code. This code could then be executed on the server, leading to severe consequences like:
    *   **Remote Code Execution (RCE):**  The attacker can execute arbitrary commands on the server.
    *   **Data Breach:**  Access to sensitive data stored on the server.
    *   **Server Compromise:**  Full control over the web server.

*   **Local File Inclusion (LFI) (Medium to High Severity):**  LFI occurs when an attacker can manipulate file paths to include arbitrary files from the server's filesystem into the application's output. In the context of *dynamic template paths*, if the application uses user input to determine the template path without proper validation, an attacker could potentially provide paths like `../../../../etc/passwd` (for Linux systems) or similar paths to access sensitive files outside the intended template directory. This can lead to:
    *   **Information Disclosure:**  Exposure of sensitive configuration files, source code, or other confidential data.
    *   **Potential for RCE (in some scenarios):**  If the included file is interpreted as code (depending on server configuration and application logic), it could lead to remote code execution.

**Relevance to Hanami:**

Hanami views are responsible for rendering templates. While Hanami itself doesn't inherently encourage dynamic template paths based on user input, developers might introduce this pattern unintentionally or due to specific application requirements. For example, a developer might try to dynamically select templates based on user roles or preferences, potentially using user input to construct the template path. This is where the vulnerability can be introduced.

#### 4.2. How Dynamic Template Paths Enable Vulnerabilities

The core issue lies in trusting user input to determine which template to render.  Consider a hypothetical (and insecure) Hanami view code snippet:

```ruby
# In a Hanami view
def render
  template_name = params[:template] # User input from query parameter 'template'
  render "app/templates/#{template_name}" # Constructing template path dynamically
end
```

In this flawed example, the `template_name` is directly taken from the `params[:template]` (user input). An attacker could then make requests like:

*   `/?template=../../../../etc/passwd`  (Attempting LFI)
*   `/?template=malicious_template` (If they can upload or create a `malicious_template` in the template directory or a reachable location, attempting Template Injection)

Even if direct file system access is restricted, template engines might have their own vulnerabilities if they process user-controlled paths.  Furthermore, even if the attacker cannot directly include arbitrary files, they might be able to manipulate the path to render unexpected templates within the application, potentially leading to information disclosure or unexpected application behavior.

#### 4.3. Evaluation of the Mitigation Strategy Steps

The proposed mitigation strategy outlines three key steps:

1.  **Review Code for Dynamic Template Path Construction:** This is a crucial first step. Proactive code review is essential to identify any existing instances where template paths are dynamically constructed based on user input within Hanami views. This step emphasizes vigilance and awareness of this potential vulnerability.

    *   **Effectiveness:** Highly effective as a preventative measure. Identifying and addressing vulnerable code early in the development lifecycle is significantly more efficient than fixing vulnerabilities discovered in production.
    *   **Considerations:** Requires developers to be aware of this vulnerability and actively look for it during code reviews. Automated static analysis tools could potentially assist in identifying dynamic path constructions, although they might require specific configuration to detect template path manipulation patterns.

2.  **Refactor Code to Avoid Dynamic Construction:** This is the core of the mitigation. Hardcoding template paths or using safe mapping mechanisms are excellent approaches.

    *   **Hardcoding:**  If template selection is based on a limited set of predefined options, hardcoding paths is the most secure and straightforward solution. This eliminates user input from influencing the path entirely.
    *   **Safe Mapping:**  Using a mapping (e.g., a Hash or a `case` statement) to translate user-provided keys to predefined, safe template paths is a robust approach for scenarios where dynamic selection is needed based on user choices.  This ensures that user input only acts as an *index* into a safe set of options, rather than directly constructing the path.

    ```ruby
    # Example of Safe Mapping in a Hanami view
    TEMPLATE_MAPPING = {
      "profile" => "app/templates/users/profile",
      "settings" => "app/templates/users/settings",
      # ... other safe mappings
    }

    def render
      template_key = params[:page] # User input for page selection
      template_path = TEMPLATE_MAPPING[template_key]

      if template_path
        render template_path
      else
        # Handle invalid template key (e.g., render a default template or error)
        render "app/templates/errors/not_found"
      end
    end
    ```

    *   **Effectiveness:** Highly effective in preventing Template Injection and LFI by eliminating or significantly restricting user control over template paths. Safe mapping is particularly effective as it decouples user input from direct path construction.
    *   **Considerations:** Requires careful planning of the mapping mechanism and ensuring that the mapping itself is secure and doesn't introduce new vulnerabilities.  It might require more upfront design effort compared to simply using dynamic paths, but the security benefits are substantial.

3.  **Strict Validation and Sanitization (If Absolutely Necessary):** This step is a fallback for situations where dynamic template selection is deemed unavoidable. However, it is strongly discouraged and should be approached with extreme caution.

    *   **Validation:**  Input validation should strictly enforce allowed template names. Use whitelisting to only permit predefined, safe template names. Regular expressions can be used to enforce allowed characters and formats.
    *   **Sanitization:**  Sanitization should focus on preventing path traversal attacks.  Techniques like removing `..` sequences and ensuring the path remains within the intended template directory are crucial. However, even with sanitization, there's always a risk of bypass or overlooking subtle vulnerabilities.

    ```ruby
    # Example of (Discouraged) Validation and Sanitization - Still risky!
    ALLOWED_TEMPLATE_NAMES = ["profile", "settings", "dashboard"] # Whitelist

    def render
      template_name = params[:template]

      if ALLOWED_TEMPLATE_NAMES.include?(template_name)
        # Path Sanitization (Basic - still potentially bypassable)
        sanitized_template_name = template_name.gsub(/\.\./, '') # Remove ".."
        template_path = "app/templates/#{sanitized_template_name}"
        render template_path
      else
        # Handle invalid template name
        render "app/templates/errors/invalid_template"
      end
    end
    ```

    *   **Effectiveness:**  Less effective and significantly more complex to implement securely compared to avoiding dynamic paths altogether. Validation and sanitization are prone to bypasses and human error.  It adds complexity and maintenance overhead.
    *   **Considerations:**  Should be considered a last resort.  Requires deep security expertise to implement correctly.  Regular security audits and penetration testing are essential if this approach is used.  It's generally better to refactor the application logic to avoid dynamic paths if possible.

#### 4.4. Impact of Mitigation

*   **Template Injection:**  This mitigation strategy effectively eliminates or significantly reduces the risk of Template Injection by preventing attackers from controlling the template path. By hardcoding paths or using safe mappings, the application dictates which templates are rendered, regardless of user input.
*   **Local File Inclusion (LFI):**  Similarly, this mitigation drastically reduces the risk of LFI. By preventing user-controlled path construction, attackers cannot manipulate the template path to access files outside the intended template directory.

**Overall Impact:** Implementing this mitigation strategy has a high positive impact on the security of the Hanami application. It directly addresses two critical vulnerabilities and significantly strengthens the application's resistance to attacks targeting template rendering.

#### 4.5. Strengths of the Mitigation Strategy

*   **Simplicity and Effectiveness:** The core principle of avoiding dynamic template paths is simple to understand and highly effective in preventing the targeted vulnerabilities.
*   **Proactive Security:**  This is a proactive security measure that focuses on preventing vulnerabilities at the design and implementation stages, rather than relying on reactive measures like intrusion detection.
*   **Reduced Attack Surface:**  By eliminating user control over template paths, the attack surface related to template rendering is significantly reduced.
*   **Improved Code Maintainability:** Hardcoding or using safe mappings can often lead to cleaner and more maintainable code compared to complex validation and sanitization logic.
*   **Alignment with Security Best Practices:**  This strategy aligns with fundamental security principles of least privilege and input validation (by limiting user input's influence on critical application components like template paths).

#### 4.6. Limitations and Edge Cases

*   **Over-reliance on Developer Discipline:** The "Currently Implemented" section correctly points out that while dynamic template paths might not be common, vigilance is needed. The effectiveness of this mitigation relies heavily on developer awareness and consistent adherence to secure coding practices during development and maintenance.
*   **Potential for Accidental Introduction:**  Developers might inadvertently introduce dynamic template paths in future code changes if they are not fully aware of the security implications or if project requirements evolve in unforeseen ways.
*   **Complexity in Highly Dynamic Applications (Rare):** In extremely rare and complex applications where template selection *must* be highly dynamic and based on very diverse user criteria, completely avoiding dynamic paths might be perceived as overly restrictive. However, even in such cases, safe mapping or very strict, well-audited validation is still preferable to direct dynamic path construction.
*   **False Sense of Security (If Validation is Chosen):** If developers opt for validation and sanitization instead of avoiding dynamic paths, there's a risk of creating a false sense of security.  Validation and sanitization are complex and can be bypassed if not implemented perfectly.

#### 4.7. Implementation Details in Hanami

Implementing this mitigation in a Hanami application involves the following:

1.  **Code Review Process:** Establish a mandatory code review process that specifically checks for dynamic template path construction in Hanami views.  Educate developers on the risks and best practices.
2.  **Developer Training:**  Provide training to developers on secure coding practices related to template rendering, emphasizing the dangers of dynamic template paths and the importance of using hardcoded paths or safe mappings.
3.  **Static Analysis Tools (Optional):** Explore using static analysis tools that can be configured to detect patterns of dynamic path construction, although this might require custom rules or configurations specific to Hanami and the chosen template engine.
4.  **Refactoring Existing Code:**  If existing code uses dynamic template paths, refactor it to use hardcoded paths or safe mapping mechanisms. Prioritize refactoring over validation and sanitization if possible.
5.  **Secure Template Selection Logic:** When implementing template selection logic, always favor safe mapping over direct user input. Design the mapping to be comprehensive and cover all legitimate template choices.
6.  **Error Handling:** Implement robust error handling for cases where user input does not match any valid template in the mapping or if validation fails.  Avoid revealing sensitive information in error messages.

**Example of Refactoring (Before - Insecure):**

```ruby
# Insecure Hanami View (Example - DO NOT USE)
def render
  template_name = params[:view] # User input
  render "app/templates/#{template_name}"
end
```

**Example of Refactoring (After - Secure - Using Safe Mapping):**

```ruby
# Secure Hanami View (Example - USE THIS APPROACH)
VIEW_TEMPLATE_MAP = {
  "home" => "app/templates/pages/home",
  "products" => "app/templates/pages/products",
  "contact" => "app/templates/pages/contact"
}

def render
  view_key = params[:view]
  template_path = VIEW_TEMPLATE_MAP[view_key]

  if template_path
    render template_path
  else
    # Handle invalid view key - render default or error
    render "app/templates/pages/home" # Or render an error page
  end
end
```

#### 4.8. Verification and Testing

To verify the effectiveness of this mitigation:

*   **Manual Code Review:** Conduct thorough manual code reviews to ensure no dynamic template paths are present in the codebase.
*   **Static Analysis:** Utilize static analysis tools (if configured) to automatically scan for potential dynamic path constructions.
*   **Penetration Testing:** Perform penetration testing, specifically targeting template rendering vulnerabilities. Attempt to exploit Template Injection and LFI by manipulating parameters that might influence template selection.
*   **Unit/Integration Tests:** Write unit or integration tests that specifically check the template rendering logic and ensure that user input cannot be used to render unintended templates or access unauthorized files.

#### 4.9. Recommendations

*   **Prioritize Avoiding Dynamic Paths:**  Make it a strict policy to avoid dynamic template paths based on user input in Hanami applications.
*   **Implement Safe Mapping by Default:**  Adopt safe mapping as the standard approach for template selection when dynamic choices are needed.
*   **Mandatory Code Reviews:**  Enforce mandatory code reviews with a specific focus on template rendering security and dynamic path detection.
*   **Developer Security Training:**  Provide regular security training to developers, covering Template Injection, LFI, and secure template rendering practices in Hanami.
*   **Regular Security Audits:**  Conduct periodic security audits and penetration testing to identify and address any potential vulnerabilities, including those related to template rendering.
*   **Consider Content Security Policy (CSP):**  While not directly related to dynamic template paths, implementing a strong Content Security Policy can provide an additional layer of defense against certain types of attacks that might be facilitated by template injection (e.g., cross-site scripting).

#### 4.10. Conclusion

The "Avoid Dynamic Template Paths from User Input" mitigation strategy is a highly effective and essential security measure for Hanami applications. By preventing user control over template paths, it directly addresses the risks of Template Injection and Local File Inclusion vulnerabilities, significantly enhancing the application's security posture.  While vigilance and consistent implementation are crucial, the simplicity and effectiveness of this strategy make it a cornerstone of secure Hanami development.  Prioritizing hardcoded paths or safe mapping mechanisms, combined with robust code review and developer training, will ensure that Hanami applications are resilient against these critical web application vulnerabilities.