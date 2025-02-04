# Attack Surface Analysis for korlibs/korge

## Attack Surface: [Malicious Asset Loading](./attack_surfaces/malicious_asset_loading.md)

*   **Description:** Loading assets (images, sounds, fonts, etc.) from untrusted or unverified sources can introduce malicious content, exploiting vulnerabilities in asset processing or the underlying platform.
*   **Korge Contribution:** Korge provides `ResourcesRoot` and asset loading APIs (`resourcesVfs`, `readBitmap`, `readSoundBuffer`, etc.) which, if used to load assets from untrusted sources without validation, directly expose the application to this risk. Korge itself doesn't inherently sanitize loaded assets.
*   **Example:** A Korge game uses `resourcesVfs["http://untrusted-server.com/level1_textures.zip"].readZip()` to load level textures. An attacker compromises `untrusted-server.com` and replaces `level1_textures.zip` with a malicious zip containing crafted images that exploit a buffer overflow in the platform's image decoding library when Korge attempts to render them. This leads to arbitrary code execution.
*   **Impact:** Arbitrary code execution, Denial of Service (DoS), data corruption, information disclosure.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Restrict Asset Sources:** Load assets exclusively from trusted and controlled sources, ideally bundled within the application or served from secure, internally managed servers.
    *   **Content Security Policy (CSP) (JS Target):** Implement CSP to strictly limit the origins from which assets can be loaded, preventing loading from arbitrary external URLs.
    *   **Asset Integrity Verification:** Implement mechanisms to verify the integrity and authenticity of loaded assets (e.g., digital signatures, checksums) before processing them.
    *   **Input Validation (File Type & Basic Checks):** Validate asset file types and perform basic sanity checks (e.g., file size limits) before attempting to load and decode them.
    *   **Regularly Update Dependencies:** Ensure Korge and the underlying platform's libraries (especially image/sound decoders) are kept up-to-date to patch known vulnerabilities that could be exploited by malicious assets.

## Attack Surface: [Insecure Deserialization of Game State](./attack_surfaces/insecure_deserialization_of_game_state.md)

*   **Description:** Deserializing game state or other application data from untrusted sources without proper validation can lead to arbitrary code execution if vulnerabilities exist in the deserialization process or the classes being deserialized.
*   **Korge Contribution:** While Korge doesn't enforce a specific serialization method, developers might use Kotlin serialization or other libraries within their Korge applications to save/load game progress or exchange data. If insecure deserialization practices are employed in conjunction with Korge's application logic, it becomes a Korge-contextual vulnerability.
*   **Example:** A Korge RPG saves game state using Kotlin serialization, including player character objects. An attacker modifies a saved game file, injecting a maliciously crafted serialized object that, when deserialized by the game's loading routine (integrated within the Korge application), executes arbitrary code due to a vulnerability in a custom class or a weakness in the deserialization process itself.
*   **Impact:** Arbitrary code execution, application state manipulation, privilege escalation, complete application compromise.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid Deserializing Untrusted Data:**  The most secure approach is to avoid deserializing data from untrusted sources entirely. If necessary, carefully consider alternative data formats and processing methods.
    *   **Input Validation and Sanitization (Deserialized Data):**  Thoroughly validate and sanitize all deserialized data to ensure it conforms to expected formats, types, and value ranges *after* deserialization but *before* using it in game logic.
    *   **Use Secure Serialization Libraries and Practices:** If serialization is essential, choose serialization libraries known for security and follow secure deserialization best practices. Consider data formats like JSON or Protocol Buffers, which are generally less prone to deserialization vulnerabilities than more complex binary serialization formats (like Java serialization, if applicable in your Korge context).
    *   **Integrity Checks (Serialization Data):** Implement robust integrity checks (e.g., HMAC, digital signatures) on serialized data to detect tampering. Only deserialize data that passes integrity verification.

## Attack Surface: [Client-Side Input Injection via Custom Events for Logic Exploitation](./attack_surfaces/client-side_input_injection_via_custom_events_for_logic_exploitation.md)

*   **Description:**  Improper handling of custom events within Korge's event system, particularly lacking validation of event data, can allow attackers to inject malicious data or event sequences to bypass game logic and gain unfair advantages or cause unintended application behavior.
*   **Korge Contribution:** Korge's powerful event dispatching and handling system (`Stage.dispatch`, `EventDispatcher.on`) allows developers to create complex custom event flows. If event handlers within Korge applications don't rigorously validate event data, attackers can exploit this system.
*   **Example:** In a Korge fighting game, a custom event `SpecialAttackEvent(attackType: String, powerLevel: Int)` is used.  If the event handler for `SpecialAttackEvent` in the game logic doesn't validate `attackType` and `powerLevel`, an attacker could inject events like `SpecialAttackEvent(attackType: "instant_win", powerLevel: 9999)` to bypass normal game mechanics and instantly win, or trigger unintended game states by manipulating event parameters.
*   **Impact:** Logic flaws, game manipulation, unfair advantages, unintended application behavior, potentially leading to Denial of Service if logic errors cause crashes or resource exhaustion.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Input Validation in Event Handlers:** Implement rigorous input validation within all custom event handlers. Validate all data fields within events against expected types, formats, and value ranges.
    *   **Secure Event Design:** Design event structures and handling logic with security in mind. Minimize the amount of data carried in events and carefully consider the potential impact of manipulated event data.
    *   **Principle of Least Privilege (Event Handlers):**  Grant event handlers only the necessary permissions and access to application resources. Avoid giving event handlers overly broad capabilities that could be abused if event data is manipulated.
    *   **Rate Limiting (Event Processing):** While primarily for DoS prevention, rate limiting event processing can also mitigate the impact of rapid-fire logic exploitation attempts via event injection.

## Attack Surface: [Path Traversal during Asset Loading (If User Input is Involved)](./attack_surfaces/path_traversal_during_asset_loading__if_user_input_is_involved_.md)

*   **Description:** If asset paths are constructed dynamically within a Korge application based on user input or external data without proper sanitization, attackers might be able to manipulate these paths to access files outside the intended asset directory, potentially leading to information disclosure or other vulnerabilities.
*   **Korge Contribution:** Korge's asset loading mechanisms rely on file paths. If developers within their Korge applications construct these paths by directly incorporating unsanitized user input (e.g., from UI elements or external configuration), they introduce a path traversal vulnerability.
*   **Example:** A Korge application allows users to select a custom background image. The application uses user-provided input to construct the asset path like `resourcesVfs["assets/backgrounds/" + userInput + ".png"].readBitmap()`. If `userInput` is not sanitized, an attacker could input "../../../sensitive_data/config" to attempt to access files outside the "assets/backgrounds/" directory, potentially reading sensitive configuration files if permissions allow.
*   **Impact:** Information disclosure, access to sensitive files, potential for further exploitation depending on the nature of accessed files.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Input Sanitization (Path Construction):**  Thoroughly sanitize any user input or external data used to construct file paths within Korge asset loading operations. Remove or escape characters like "..", "/", and "\".
    *   **Path Whitelisting and Validation:**  Validate that constructed paths remain within the allowed asset directory. Implement checks to ensure the final path resolves to a location within the intended asset storage area.
    *   **Use Safe Path APIs:**  Utilize platform-specific or Korge-provided APIs for path manipulation that inherently prevent path traversal vulnerabilities, if available.
    *   **Principle of Least Privilege (File System Access):**  Grant the Korge application only the minimum necessary file system permissions required for its intended functionality. Avoid granting broad read access to the entire file system.

These refined points highlight the most critical and high-risk attack surfaces directly related to the use of Korge, focusing on vulnerabilities that can lead to significant security impacts like arbitrary code execution and logic exploitation. Remember to implement the recommended mitigation strategies to minimize these risks in your Korge applications.

