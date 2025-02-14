# Attack Tree Analysis for abi/screenshot-to-code

Objective: Exfiltrate Data OR Execute Arbitrary Code via screenshot-to-code

## Attack Tree Visualization

```
                                     Attacker Goal:
                    Exfiltrate Data OR Execute Arbitrary Code via screenshot-to-code
                                              |
          -------------------------------------------------------------------------------------
          |                                                   |                                   |
  1. Manipulate Screenshot Input                  2. Exploit Backend Processing          3.  Exploit Frontend Code Generation/Execution
          |                                                   |                                   |
  ------------------------                      ---------------------------------       ------------------------------------------------
  |                                                |                                       |                      |                       |
1.1  Inject Malicious                             2.1  Prompt Injection in LLM             3.1 Inject Malicious   3.2  Over-reliance on    3.3  Bypass Frontend
     UI Elements                 [CRITICAL]         Code via Generated    Generated Code        Security Mechanisms
                                                                                                   HTML/JS/CSS
  |                                                |                                       |                      |
1.1.1  Craft a UI                               2.1.1  Craft a prompt to                   3.1.1  Craft a UI       3.2.1  Trust that the    3.3.1  If frontend uses
       that looks like                                 reveal internal data/                      that causes the      generated code is     eval() or similar on
       sensitive data                                  instructions. [HIGH RISK]                    LLM to generate     safe without         generated code, inject
       (e.g., API key    [HIGH RISK]                                                              malicious code.      further checks.      malicious code. [HIGH RISK]
       field).                                                                                  [HIGH RISK]          [CRITICAL]

```

## Attack Tree Path: [1. Manipulate Screenshot Input](./attack_tree_paths/1__manipulate_screenshot_input.md)

*   **1.1 Inject Malicious UI Elements:**
    *   **1.1.1 Craft a UI that looks like sensitive data (e.g., API key field). [HIGH RISK]**
        *   **Description:** The attacker creates a screenshot of a fabricated UI that mimics a legitimate interface displaying sensitive information, such as API keys, passwords, or personal data. The goal is to trick the LLM into extracting and processing this fake data.
        *   **Likelihood:** Medium
        *   **Impact:** High (if successful, could lead to data exfiltration)
        *   **Effort:** Low (creating a fake UI is relatively easy)
        *   **Skill Level:** Novice
        *   **Detection Difficulty:** Medium (requires image analysis and anomaly detection)
        *   **Mitigations:**
            *   Robust Input Validation (Beyond Basic Sanitization): Implement checks to detect obviously fake UI elements. Consider using a secondary image analysis model.
            *   Rate Limiting: Limit screenshot submissions per user.
            *   User Input Restrictions (If Applicable): Restrict file types and sizes.
            *   Image Similarity Checks: Compare against known-good UI layouts.

## Attack Tree Path: [2. Exploit Backend Processing](./attack_tree_paths/2__exploit_backend_processing.md)

*   **2.1 Prompt Injection in LLM (Backend) [CRITICAL]**
    *   **Description:** The attacker crafts the screenshot and/or accompanying text input to inject malicious instructions into the LLM's prompt, manipulating its behavior.
    *   **Mitigations (General for 2.1):**
        *   Prompt Hardening: Use clear system instructions, input delimiters, and output validation.
        *   Least Privilege: Run the LLM interaction in a sandboxed environment.
        *   Consider using a smaller, fine-tuned LLM.
        *   Monitor LLM Output: Log and monitor for anomalies.

    *   **2.1.1 Craft a prompt to reveal internal data/instructions. [HIGH RISK]**
        *   **Description:** The attacker designs the screenshot to include text or visual elements that, when processed by OCR and fed to the LLM, act as a prompt injection, instructing the LLM to reveal sensitive data or execute unintended actions.
        *   **Likelihood:** High
        *   **Impact:** Very High (could lead to complete system compromise)
        *   **Effort:** Medium (requires understanding of LLM prompting)
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Hard (requires monitoring LLM output and detecting anomalous behavior)
        *   **Mitigations:** (Same as general 2.1 mitigations, with emphasis on *very* strict output validation).

## Attack Tree Path: [3. Exploit Frontend Code Generation/Execution](./attack_tree_paths/3__exploit_frontend_code_generationexecution.md)

*   **3.1 Inject Malicious Code via Generated HTML/JS/CSS:**
    *   **3.1.1 Craft a UI that causes the LLM to generate malicious code. [HIGH RISK]**
        *   **Description:** The attacker designs the screenshot to include elements that resemble code snippets or HTML tags, influencing the LLM to generate malicious JavaScript, CSS, or HTML that will be executed in the user's browser.
        *   **Likelihood:** Medium
        *   **Impact:** High (could lead to XSS or other client-side attacks)
        *   **Effort:** Medium (requires understanding of web vulnerabilities and LLM code generation)
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Medium (requires code analysis and vulnerability scanning)
        *   **Mitigations:**
            *   Strict Content Security Policy (CSP): Prevent execution of inline/external scripts.
            *   Code Review (Automated and Manual): Scan for known vulnerabilities.
            *   Sandboxing (Frontend): Execute generated code in a restricted environment.

*   **3.2 Over-reliance on Generated Code:**
    *   **3.2.1 Trust that the generated code is safe without further checks. [CRITICAL]**
        *   **Description:** Developers mistakenly assume the LLM-generated code is inherently secure and fail to implement adequate security checks and validation. This is a *vulnerability* arising from a lack of security awareness, not a specific attack action.
        *   **Likelihood:** High (common developer mistake)
        *   **Impact:** High (could lead to various vulnerabilities)
        *   **Effort:** Very Low (passive vulnerability)
        *   **Skill Level:** Novice
        *   **Detection Difficulty:** Easy (requires code review and security audits)
        *   **Mitigations:**
            *   Treat Generated Code as Untrusted Input: Apply all standard security checks.
            *   Education and Training: Educate developers about the risks.

*   **3.3 Bypass Frontend Security Mechanisms:**
    *   **3.3.1 If frontend uses eval() or similar on generated code, inject malicious code. [HIGH RISK]**
        *   **Description:** If the application uses `eval()` or similar functions to execute the generated code, the attacker can inject arbitrary JavaScript, leading to complete control over the client-side application.
        *   **Likelihood:** Low (using `eval()` is bad practice)
        *   **Impact:** Very High (allows arbitrary code execution)
        *   **Effort:** Low (trivial if `eval()` is present)
        *   **Skill Level:** Novice
        *   **Detection Difficulty:** Easy (static code analysis detects `eval()`)
        *   **Mitigations:**
            *   Avoid `eval()` and similar functions: Use safer alternatives.

