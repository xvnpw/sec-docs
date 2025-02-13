# Threat Model Analysis for korlibs/korge

## Threat: [Asset Spoofing (Images)](./threats/asset_spoofing__images_.md)

*   **Threat:** Asset Replacement - Image (Exploitable Decoder)
*   **Description:** An attacker replaces a legitimate image asset with a maliciously crafted one designed to exploit a vulnerability in KorGE's image decoding libraries (or the underlying platform's libraries).
*   **Impact:** Client-side code execution, potential for complete system compromise.
*   **Affected KorGE Component:** `korlibs.io.file.VfsFile`, `korlibs.image.format.*` (image format decoders), `korlibs.image.bitmap.Bitmap`.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Use HTTPS for all asset downloads. Implement checksum verification (e.g., SHA-256) for all loaded images. Use a Content Security Policy (CSP) to restrict image sources.  *Crucially*, keep image decoding libraries (including any platform-specific dependencies KorGE uses) up-to-date with the latest security patches.  Consider using a more secure image format (e.g., WebP with integrity checks) and potentially sandboxing image decoding.
    *   **User:** Ensure the game is downloaded from a trusted source.

## Threat: [Asset Spoofing (Fonts)](./threats/asset_spoofing__fonts_.md)

*   **Threat:** Asset Replacement - Font (Exploitable Renderer)
*   **Description:** Attackers replace legitimate font files with malicious ones designed to exploit vulnerabilities in KorGE's font rendering engine (or the underlying platform's). Font rendering has historically been a source of vulnerabilities.
*   **Impact:** Potential client-side code execution, system compromise.
*   **Affected KorGE Component:** `korlibs.io.file.VfsFile`, `korlibs.image.font.*` (font rendering classes), potentially underlying platform-specific font rendering libraries.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** HTTPS for downloads. Checksum verification. CSP. Use a *very* limited set of well-vetted fonts from trusted sources. Keep font rendering libraries (including underlying platform libraries) *absolutely up-to-date*. Consider sandboxing the font rendering process if feasible. Explore using system-provided fonts where possible and practical, relying on the OS vendor's patching process.
    *   **User:** Download from trusted sources.

## Threat: [KorGE API Misuse (File System)](./threats/korge_api_misuse__file_system_.md)

*   **Threat:**  Unsafe File Access (Path Traversal)
*   **Description:**  The game uses KorGE's file system APIs (`korlibs.io.file.*`) insecurely, allowing an attacker to craft input (e.g., a level name, a saved game filename) that results in a path traversal vulnerability. This could allow reading or writing arbitrary files outside the intended game directory.
*   **Impact:**  Data leakage (reading sensitive system files), potential for code execution (overwriting executable files or configuration files), denial of service (deleting critical files).
*   **Affected KorGE Component:** `korlibs.io.file.*` (VfsFile and related classes).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:**  *Thoroughly* sanitize all file paths received from user input or external sources.  *Never* directly construct file paths by concatenating user input with base directories. Use KorGE's `VfsFile` API *correctly* to resolve paths relative to a safe, sandboxed root directory.  Validate file extensions and contents before processing.  Implement strict checks to prevent any ".." sequences or absolute paths from being used.  Consider using a whitelist of allowed file paths/names.
    *   **User:**  None (primarily a developer responsibility).

## Threat: [KorGE API Misuse (Networking) - Missing Encryption](./threats/korge_api_misuse__networking__-_missing_encryption.md)

*   **Threat:** Unencrypted Communication
*   **Description:** The game uses KorGE's networking APIs (`korlibs.io.net.*`) to transmit sensitive data (player credentials, game state, etc.) without encryption (e.g., using plain HTTP instead of HTTPS, or WebSockets without TLS).
*   **Impact:** Data leakage (credentials, game data), man-in-the-middle attacks (allowing attackers to modify game data or impersonate players/server).
*   **Affected KorGE Component:** `korlibs.io.net.*` (especially `korlibs.io.net.http.*` and `korlibs.io.net.ws.*`).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** *Always* use HTTPS for all HTTP communication. *Always* use WebSockets with TLS (wss://). Validate server certificates properly to prevent MITM attacks. Use strong, modern cryptographic protocols and ciphers.
    *   **User:** None (primarily a developer responsibility).

## Threat: [Dependency Vulnerability (Critical Dependency)](./threats/dependency_vulnerability__critical_dependency_.md)

*   **Threat:** Compromised Critical Third-Party Library (Used by KorGE)
*   **Description:** A critical vulnerability is discovered and exploited in a library that KorGE *directly* depends on. This is distinct from a game-specific dependency.
*   **Impact:** Varies widely depending on the vulnerability, but could range from denial of service to complete system compromise.
*   **Affected KorGE Component:** Any KorGE component that relies on the vulnerable dependency. This requires careful analysis of KorGE's dependency tree.
*   **Risk Severity:** Potentially Critical (depending on the dependency and vulnerability).
*   **Mitigation Strategies:**
    *   **Developer:** Maintain an up-to-date Software Bill of Materials (SBOM) for KorGE itself. Monitor security advisories for *all* of KorGE's dependencies.  Use a dependency management system with vulnerability scanning (e.g., Gradle with dependency verification, Dependabot).  *Immediately* update KorGE and its dependencies when security patches are released.  Consider contributing to KorGE's security by auditing its dependencies.
    *   **User:** Ensure the game is downloaded from a trusted source and that the game developer promptly releases updates to address vulnerabilities in KorGE or its dependencies.

## Threat: [Network Input Spoofing (Multiplayer) - No Server Authority](./threats/network_input_spoofing__multiplayer__-_no_server_authority.md)

*   **Threat:** Fabricated Input Events, Lack of Server Validation
*   **Description:** In a multiplayer game built with KorGE, an attacker sends fake input events to the server, and the server, due to inadequate validation or lack of server-side authority, accepts these inputs as legitimate. This leverages KorGE's networking without proper security practices.
*   **Impact:** Unfair advantage, disruption of gameplay, potential for server instability or crashes if the server doesn't handle invalid input gracefully.
*   **Affected KorGE Component:** `korlibs.io.net.*` (networking libraries, e.g., `korlibs.io.net.ws.WebSocketClient`), and the game's custom networking code *interacting with* KorGE's networking.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Implement *strict* server-side authority for *all* game actions. The server *must* validate *all* client input and reject anything that is impossible, out-of-bounds, or violates game rules. Use secure communication (TLS/SSL via KorGE's networking). Authenticate players robustly. Implement rate-limiting to prevent flooding.
    *   **User:** None (primarily a developer responsibility).

## Threat: [Denial of Service (Network Flooding - Multiplayer)](./threats/denial_of_service__network_flooding_-_multiplayer_.md)

*   **Threat:** Network Packet Flood targeting KorGE networking
*   **Description:** An attacker floods the game server, specifically targeting the endpoints and protocols used by KorGE's networking libraries, with a large number of network packets.
*   **Impact:** Server slowdown or crash, denial of service for all players.
*   **Affected KorGE Component:** `korlibs.io.net.*` (networking libraries), and the server's networking infrastructure *as it interacts with* KorGE.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Developer:** Implement rate limiting and connection throttling on the server, specifically within the code that handles KorGE network events. Use a firewall and intrusion detection system. Consider DDoS mitigation services. Design the server-side networking code using KorGE to be resilient to high load and malformed packets.
    *   **User:** None (primarily a server-side issue).

