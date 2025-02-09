# Attack Tree Analysis for fmtlib/fmt

Objective: Achieve Arbitrary Code Execution, Information Disclosure, or Denial of Service via fmtlib/fmt

## Attack Tree Visualization

```
                                      Attacker's Goal:
                                Achieve Arbitrary Code Execution,
                                Information Disclosure, or Denial of Service
                                      via fmtlib/fmt
                                              |
                      -----------------------------------------------------------------
                      |
      1.  Exploit Format String Vulnerabilities [HIGH RISK]
                      |
      ---------------------------------
      |
1.1. User-Controlled Format String [CRITICAL]
      |
      |
1.1.1.  `%n` Specifier (Write) [HIGH RISK]
      |
      |
1.1.1.1. Overwrite Return Address [HIGH RISK]
      |
      |
1.1.1.2. Overwrite GOT Entry [HIGH RISK]
      |
      |
1.1.2.  `%s`, `%x`, etc. (Read) [HIGH RISK]
      |
      |
1.1.2.1. Read Stack Contents
      |
      |
1.1.2.2. Read Heap Contents
      |
      |
1.1.2.3. Information Disclosure (Addresses, etc.)

```

## Attack Tree Path: [1. Exploit Format String Vulnerabilities [HIGH RISK]](./attack_tree_paths/1__exploit_format_string_vulnerabilities__high_risk_.md)

*   **Description:** This is the overarching category for attacks that leverage vulnerabilities in how the `fmtlib/fmt` library handles format strings.  The core issue is when the format string itself is not a constant, compile-time string, but is instead influenced by external input, particularly user-supplied data.
*   **Why High Risk:** Format string vulnerabilities are notoriously dangerous because they can often lead to arbitrary code execution, giving the attacker complete control over the compromised system. They are also relatively easy to exploit with readily available tools and techniques.

## Attack Tree Path: [1.1. User-Controlled Format String [CRITICAL]](./attack_tree_paths/1_1__user-controlled_format_string__critical_.md)

*   **Description:** This is the root cause and enabling factor for most format string exploits.  If an attacker can control, even partially, the format string passed to `fmt::format`, `fmt::print`, or related functions, they can inject malicious format specifiers.
*   **Why Critical:** This is the single most important vulnerability to prevent.  Without user control over the format string, the subsequent attack steps are impossible.  This is the gateway to all other format string exploits.
*   **Mitigation:**
    *   *Primary:* Use compile-time format strings with `FMT_STRING` whenever possible. This provides compile-time checking and prevents the injection of malicious specifiers.
    *   *Secondary (if user input is absolutely necessary):* Implement extremely strict input sanitization and whitelisting.  Allow *only* a very limited set of characters, and *never* allow format specifiers (like `%`) to be passed through from user input.  Consider alternative approaches to formatting if user-controlled formatting is required.

## Attack Tree Path: [1.1.1. `%n` Specifier (Write) [HIGH RISK]](./attack_tree_paths/1_1_1___%n__specifier__write___high_risk_.md)

*   **Description:** The `%n` format specifier is particularly dangerous.  It *writes* the number of bytes written so far to a memory location specified by a corresponding argument (which is treated as a pointer).
*   **Why High Risk:** This allows an attacker to write arbitrary data to arbitrary memory locations, which is a direct path to controlling program execution.
*   **Exploitation:**
    *   The attacker crafts a format string with `%n` and carefully controls the number of bytes written before the `%n` to write a specific value (e.g., the address of malicious code) to a target memory location.
*   **Mitigation:**
    *   Prevent user-controlled format strings (as above).
    *   If user input is unavoidable, *absolutely* prevent `%n` from being used.

## Attack Tree Path: [1.1.1.1. Overwrite Return Address [HIGH RISK]](./attack_tree_paths/1_1_1_1__overwrite_return_address__high_risk_.md)

*   **Description:** A classic exploitation technique.  The attacker uses `%n` to overwrite the return address stored on the stack.  When the current function returns, execution jumps to the attacker-controlled address.
*   **Why High Risk:** This is a direct path to arbitrary code execution.
*   **Mitigation:**
    *   Prevent user-controlled format strings.
    *   Stack canaries (if present) can help detect stack buffer overflows, but format string vulnerabilities can often bypass them.
    *   Address Space Layout Randomization (ASLR) makes it harder to predict the location of the return address, but can often be bypassed with information leaks.

## Attack Tree Path: [1.1.1.2. Overwrite GOT Entry [HIGH RISK]](./attack_tree_paths/1_1_1_2__overwrite_got_entry__high_risk_.md)

*   **Description:** The Global Offset Table (GOT) contains pointers to the actual locations of dynamically linked functions.  By overwriting a GOT entry with the address of malicious code, the attacker can redirect a function call to their code.
*   **Why High Risk:** Another direct path to arbitrary code execution.
*   **Mitigation:**
    *   Prevent user-controlled format strings.
    *   Full RELRO (Relocation Read-Only) can make the GOT read-only, preventing this attack.

## Attack Tree Path: [1.1.2. `%s`, `%x`, etc. (Read) [HIGH RISK]](./attack_tree_paths/1_1_2___%s____%x___etc___read___high_risk_.md)

*   **Description:**  Format specifiers like `%s` (read a string), `%x` (read an integer as hexadecimal), `%p` (read a pointer), etc., can be used to read data from the stack or heap.
*   **Why High Risk:**  While not directly leading to code execution, these specifiers can leak sensitive information, such as:
    *   Stack contents (local variables, function arguments)
    *   Heap contents (dynamically allocated data)
    *   Addresses of code and data (used to bypass ASLR)
    *   Security tokens, keys, or other confidential data
*   **Exploitation:**
    *   The attacker provides a format string with multiple `%x` or `%p` specifiers to read consecutive memory locations.
    *   `%s` can be particularly dangerous if it reads from an unintended location, potentially causing a crash or revealing a large amount of data.
*   **Mitigation:**
    *   Prevent user-controlled format strings.

## Attack Tree Path: [1.1.2.1. Read Stack Contents](./attack_tree_paths/1_1_2_1__read_stack_contents.md)

* **Description:** Using format specifiers to read values from the program's stack.

## Attack Tree Path: [1.1.2.2. Read Heap Contents](./attack_tree_paths/1_1_2_2__read_heap_contents.md)

* **Description:** Using format specifiers to read values from the program's heap.

## Attack Tree Path: [1.1.2.3. Information Disclosure (Addresses, etc.)](./attack_tree_paths/1_1_2_3__information_disclosure__addresses__etc__.md)

* **Description:** Leaking memory addresses, which can be used to bypass security mechanisms like ASLR.

