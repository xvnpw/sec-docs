Okay, here's a deep analysis of the provided attack tree path, focusing on the `asciinema-player` library, formatted as Markdown:

```markdown
# Deep Analysis of asciinema-player Attack Tree Path: Malicious Cast File

## 1. Objective, Scope, and Methodology

### 1.1 Objective

The primary objective of this deep analysis is to thoroughly investigate the "Malicious Cast File" attack path for applications utilizing the `asciinema-player` library.  We aim to identify specific vulnerabilities, assess their exploitability, and propose concrete mitigation strategies.  The ultimate goal is to provide actionable recommendations to developers to enhance the security posture of their applications against attacks leveraging malicious `.cast` files.

### 1.2 Scope

This analysis focuses exclusively on the "Malicious Cast File" attack path, encompassing the following sub-paths:

*   **Escape Sequence Injection (CSI, OSC, etc.)**
*   **VT Sequence Manipulation**
*   **Data URI in `src` (Critical Node)**

The analysis will consider:

*   The `asciinema-player` library's handling of `.cast` file data.
*   Potential interactions with the browser's DOM and JavaScript engine.
*   The application's implementation context (how it uses `asciinema-player`).
*   Known vulnerabilities and attack techniques related to ANSI escape sequences, VT sequences, and data URIs.

This analysis *does not* cover:

*   Attacks unrelated to `.cast` files (e.g., server-side vulnerabilities).
*   Attacks targeting the operating system or terminal emulator directly (outside the browser context).
*   Denial-of-Service (DoS) attacks, unless they directly contribute to code execution.

### 1.3 Methodology

The analysis will employ the following methodologies:

1.  **Code Review:**  We will examine the `asciinema-player` source code (available on GitHub) to understand how it parses and processes `.cast` files, handles escape sequences, and interacts with the DOM.  We will pay close attention to sanitization routines, input validation, and any areas where user-supplied data might influence execution flow.

2.  **Vulnerability Research:** We will research known vulnerabilities related to ANSI escape sequences, VT sequences, and data URIs.  This includes searching vulnerability databases (CVE, NVD), security advisories, and relevant blog posts/articles.

3.  **Proof-of-Concept (PoC) Development (Hypothetical):**  While we won't be actively exploiting a live system, we will *hypothetically* construct PoC `.cast` files and `data:` URIs to demonstrate the potential for exploitation.  This will help us understand the practical limitations and requirements for successful attacks.

4.  **Threat Modeling:** We will use the attack tree as a basis for threat modeling, considering the attacker's capabilities, motivations, and potential attack vectors.

5.  **Mitigation Analysis:** For each identified vulnerability, we will propose specific mitigation strategies, prioritizing those that are most effective and easiest to implement.

## 2. Deep Analysis of Attack Tree Path

### 2.1 Escape Sequence Injection (CSI, OSC, etc.)

*   **Description (Detailed):**  ANSI escape sequences (CSI - Control Sequence Introducer, OSC - Operating System Command) are special character sequences used to control terminal behavior (e.g., cursor positioning, text color, etc.).  `asciinema-player` must parse these sequences to accurately render the recorded terminal session.  An attacker can craft a malicious `.cast` file containing carefully designed escape sequences that, if not properly sanitized, could trigger unexpected behavior within the player's internal logic.  The goal is to manipulate the player's state or internal data structures in a way that ultimately leads to JavaScript execution (e.g., through DOM manipulation).  This is an *indirect* attack, as the escape sequences themselves don't directly execute JavaScript.

*   **Code Review Focus:**
    *   Identify the code responsible for parsing and handling CSI and OSC sequences.
    *   Look for any lack of input validation or sanitization.
    *   Examine how the parsed sequences are used to update the player's internal state and the DOM.
    *   Check for any potential buffer overflows or other memory corruption vulnerabilities.
    *   Specifically look for how `asciinema-player` handles OSC sequences that can interact with the system (e.g., setting the window title, which could be abused for XSS).

*   **Vulnerability Research:**
    *   Research known vulnerabilities in terminal emulators and libraries related to escape sequence handling.
    *   Look for examples of escape sequence injection attacks leading to XSS or other security issues.
    *   Investigate any reported vulnerabilities specifically targeting `asciinema-player`.

*   **Hypothetical PoC:**  A PoC might involve crafting a `.cast` file with an OSC sequence designed to manipulate the window title in a way that injects JavaScript.  For example:
    ```
    \x1b]0;javascript:alert(1)\x07
    ```
    This *should* be sanitized by the player, but if not, it could trigger an alert box.  More complex sequences could be used to achieve more sophisticated XSS attacks.

*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Implement rigorous validation of all escape sequences, allowing only a whitelisted set of known-safe sequences and parameters.
    *   **Output Encoding:**  Ensure that any output derived from escape sequences is properly encoded before being inserted into the DOM.
    *   **Context-Aware Sanitization:**  Sanitize escape sequences based on their context and intended use.  For example, sequences that modify the window title should be treated with extra caution.
    *   **Regular Expression Filtering:** Use carefully crafted regular expressions to filter out potentially dangerous escape sequences.  However, be aware that overly complex regular expressions can be prone to bypasses.
    *   **Content Security Policy (CSP):**  Use a strong CSP to restrict the sources from which JavaScript can be executed, mitigating the impact of XSS even if an escape sequence injection is successful.  Specifically, `script-src` and `object-src` directives should be carefully configured.

### 2.2 VT Sequence Manipulation

*   **Description (Detailed):**  VT (Virtual Terminal) sequences are a broader category of control sequences that encompass ANSI escape sequences.  This attack vector is similar to escape sequence injection but focuses on a wider range of sequences, including those that might not be strictly considered ANSI escape sequences.  The attacker aims to exploit vulnerabilities in the player's handling of these sequences to achieve code execution.

*   **Code Review Focus:**  Similar to escape sequence injection, but with a broader scope, examining the handling of all VT sequences.

*   **Vulnerability Research:**  Research vulnerabilities related to VT sequence handling in terminal emulators and libraries.

*   **Hypothetical PoC:**  A PoC would involve crafting a `.cast` file with malformed or unusual VT sequences that are not properly handled by the player, potentially leading to unexpected behavior or memory corruption.

*   **Mitigation Strategies:**  Similar to escape sequence injection, with a focus on comprehensive validation and sanitization of all VT sequences.

### 2.3 Data URI in `src` (Critical Node)

*   **Description (Detailed):**  This is the most direct and potentially dangerous attack vector.  The `src` attribute of the `asciinema-player` HTML element specifies the location of the `.cast` file.  If the application allows user-supplied input to directly control the `src` attribute *without proper validation*, an attacker can provide a `data:` URI instead of a URL to a `.cast` file.  A `data:` URI allows embedding data directly within the URI itself.  The attacker can craft a `data:` URI that contains malicious JavaScript disguised as a `.cast` file.  When the `asciinema-player` attempts to load this "file," the browser will execute the embedded JavaScript.

*   **Code Review Focus:**
    *   Examine how the application sets the `src` attribute of the `asciinema-player` element.
    *   Check for any input validation or sanitization of the `src` value.
    *   Determine if user input can directly or indirectly influence the `src` attribute.

*   **Vulnerability Research:**
    *   Research vulnerabilities related to `data:` URI abuse in web applications.
    *   Look for examples of XSS attacks using `data:` URIs.

*   **Hypothetical PoC:**
    ```html
    <asciinema-player src="data:text/plain;base64,ZGF0YTp0ZXh0L2h0bWw7YmFzZTY0LFBEOHZhVjBuWDI1bGRDa2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lpSUhSb1pTQjFiR3h2WVhWc2JWOXpkR0ZzSUhkcGRHZ2djbVZ6WTI5dEp5QjNhV1lp