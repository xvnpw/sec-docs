# Attack Surface Analysis for nodemcu/nodemcu-firmware

## Attack Surface: [1. Lua Code Injection](./attack_surfaces/1__lua_code_injection.md)

*   **Description:**  Attackers inject malicious Lua code into the device, gaining full control.  This is the *primary* attack vector against NodeMCU.
*   **NodeMCU Contribution:**  NodeMCU's core functionality is executing Lua scripts.  Any vulnerability that allows arbitrary code execution in the Lua interpreter is a direct attack on the firmware's design and purpose.  The interpreter and its exposed APIs are the attack surface.
*   **Example:**  A web configuration interface with a text field for entering a Wi-Fi SSID.  If the input isn't sanitized, an attacker could enter: `"; os.execute("rm -rf /") --`. This would attempt to delete the entire filesystem *because NodeMCU provides the `os.execute` function*.
*   **Impact:**  Complete device compromise, data loss, potential control of connected hardware (indirectly, through further Lua code execution).
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Strict Input Validation:**  Implement rigorous input validation and sanitization *everywhere* user-supplied data is used, especially before passing it to `dofile()`, `loadstring()`, or any function that executes Lua code.  Use whitelisting (allowing only known-good characters) instead of blacklisting.
    *   **Avoid `loadstring()`:**  Prefer `dofile()` for loading scripts from files.  Avoid `loadstring()` if at all possible.
    *   **Sandboxing (Limited):** Explore techniques like limiting global variable access or pre-compiling Lua code to bytecode.
    *   **Code Review:**  Thoroughly review all Lua scripts for potential injection vulnerabilities.  Automated static analysis tools can help.

## Attack Surface: [2. Unauthenticated/Weakly Authenticated OTA Updates](./attack_surfaces/2__unauthenticatedweakly_authenticated_ota_updates.md)

*   **Description:**  Attackers upload malicious firmware to the device via the Over-the-Air (OTA) update mechanism, replacing the legitimate NodeMCU firmware.
*   **NodeMCU Contribution:**  NodeMCU provides built-in OTA functionality (often using the `node.flashreload()` function or similar).  The *implementation* of this functionality within NodeMCU, and how developers *use* it, creates the attack surface.  If authentication and integrity checks are missing or weak, it's a direct vulnerability in the firmware's update process.
*   **Example:**  An OTA update endpoint that accepts any firmware image without verifying a digital signature or requiring a strong password.  The *lack* of these checks within the NodeMCU-based update handler is the vulnerability.
*   **Impact:**  Complete device compromise, permanent bricking, potential for widespread compromise of multiple devices.
*   **Risk Severity:**  Critical
*   **Mitigation Strategies:**
    *   **Strong Authentication:**  Require strong authentication (e.g., a robust password, API key, or cryptographic challenge-response) before allowing an OTA update. This authentication must be handled *within* the NodeMCU code.
    *   **Digital Signatures:**  Digitally sign all firmware images.  The NodeMCU firmware *must* verify the signature before installing the update.
    *   **HTTPS:**  Use HTTPS for all OTA update communication.  The NodeMCU code *must* verify the server's certificate.
    *   **Version Control:** The NodeMCU firmware *must* implement version control to prevent rollback attacks.
    *   **Rollback Protection:** If a rollback is necessary, the NodeMCU firmware *must* ensure it's also authenticated and signed.

## Attack Surface: [3. Filesystem Access (via Lua)](./attack_surfaces/3__filesystem_access__via_lua_.md)

*   **Description:** Attackers use injected Lua code to read, write, or delete files on the device's flash filesystem, leveraging NodeMCU's file API.
*   **NodeMCU Contribution:** NodeMCU provides the `file` module, giving Lua scripts direct access to the filesystem. The *existence* of this module and its capabilities are the direct contribution to the attack surface.
*   **Example:** An attacker injects Lua code that uses `file.open("init.lua", "w")` to overwrite the main startup script, replacing it with malicious code.  Or, reading Wi-Fi credentials stored in a plain text file using `file.open()` and `file.read()`.  This is possible *because* NodeMCU exposes these functions.
*   **Impact:** Data theft (e.g., Wi-Fi credentials), device configuration modification, potential for persistent compromise (by modifying startup scripts).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Least Privilege:** Store sensitive data as securely as possible. Avoid storing credentials in plain text files accessible to Lua.
    *   **Encryption:** Encrypt sensitive data stored on the filesystem. This requires implementing encryption/decryption *within* the NodeMCU environment (likely using a custom C module or a Lua library).
    *   **Secure Configuration Storage:** If possible, use alternative storage mechanisms that are less directly exposed to Lua scripts.
    *   **Code Review:** Carefully review any Lua code that interacts with the filesystem, looking for potential misuse of the `file` module.

## Attack Surface: [4. Network Service Vulnerabilities (in Lua Modules)](./attack_surfaces/4__network_service_vulnerabilities__in_lua_modules_.md)

*   **Description:** Vulnerabilities in NodeMCU's network-related modules (e.g., `net`, `http`, `mqtt`) or custom modules written in Lua, *specifically* vulnerabilities within the Lua code itself or how it interacts with the underlying network stack.
*   **NodeMCU Contribution:** NodeMCU provides these modules as part of its standard library. The *implementation* of these modules in Lua, and the APIs they expose, are the direct contribution to the attack surface.
*   **Example:** A buffer overflow in the `http` module's handling of HTTP headers (written in Lua), allowing an attacker to crash the device or potentially inject code. Or, a custom MQTT client (written in Lua) that doesn't properly validate server certificates. The vulnerability lies within the *Lua code* of these modules.
*   **Impact:** Denial-of-service (DoS), potential code execution (if the vulnerability allows for it), data leakage, Man-in-the-Middle (MitM) attacks.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Keep Modules Updated:** Use the latest version of NodeMCU and its modules. This is crucial as vulnerabilities are often patched in newer releases.
    *   **Secure Coding Practices:** Follow secure coding practices *within* the Lua code of network modules. Validate all input, handle errors gracefully, and avoid common vulnerabilities like buffer overflows (even in Lua).
    *   **Use Secure Protocols:** Use secure protocols (e.g., HTTPS, MQTTS) whenever possible. The Lua code *must* verify server certificates.
    *   **Input Validation (Again):** Even within network modules, rigorously validate all data received from the network *before* processing it within the Lua environment.

