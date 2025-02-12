# Threat Model Analysis for mrdoob/three.js

## Threat: [Malicious Shader Injection](./threats/malicious_shader_injection.md)

*   **Description:** An attacker injects malicious GLSL (OpenGL Shading Language) code into a custom shader.  This is most likely if the application allows users to define or modify shaders, even indirectly through parameters that influence shader code generation. The injected code could perform unauthorized computations, attempt to read data from other parts of the scene, or cause rendering issues.
*   **Impact:**
    *   Denial of Service (DoS) by causing GPU hangs or crashes.
    *   Unauthorized computation (e.g., cryptocurrency mining using the user's GPU).
    *   Potential data exfiltration (limited by browser security, but still a risk).
    *   Visual corruption or glitches.
*   **Three.js Component Affected:**
    *   `THREE.ShaderMaterial`
    *   `THREE.RawShaderMaterial`
    *   Any material that allows custom shader code (including materials extended from built-in ones).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid User-Defined Shaders:** The best mitigation is to *avoid* allowing users to provide or modify shader code directly.
    *   **Strict Input Sanitization and Validation (If Unavoidable):** If user-defined shaders are absolutely necessary, implement *extremely* strict input sanitization and validation. Use a whitelist approach, allowing only a very limited set of GLSL constructs and functions.
    *   **GLSL Parser/Validator:** Use a GLSL parser and validator (ideally server-side) to analyze the user-provided code and reject any code that contains potentially dangerous operations.
    *   **Code Review:** Thoroughly review any code that handles user-provided shader input.

## Threat: [Exploitation of Three.js or WebGL Vulnerabilities](./threats/exploitation_of_three_js_or_webgl_vulnerabilities.md)

*   **Description:** An attacker exploits a known or zero-day vulnerability in the Three.js library itself or in the underlying WebGL implementation (which is part of the browser). These vulnerabilities are often complex and may be specific to certain browsers or graphics drivers.
*   **Impact:**
    *   Denial of Service (DoS).
    *   Arbitrary code execution (potentially, though browser sandboxing makes this difficult).
    *   Information disclosure.
*   **Three.js Component Affected:** Potentially any part of Three.js or the browser's WebGL implementation.
*   **Risk Severity:** Critical (if a zero-day exists), High (for known but unpatched vulnerabilities)
*   **Mitigation Strategies:**
    *   **Keep Three.js Updated:** Regularly update to the latest version of Three.js to get security patches.
    *   **Keep Browser Updated:** Ensure users are running the latest version of their web browser.
    *   **Monitor Security Advisories:** Stay informed about security advisories related to Three.js and WebGL.
    *   **Vulnerability Scanning:** Use vulnerability scanning tools to identify known vulnerabilities in your dependencies.

## Threat: [Malicious Model Substitution](./threats/malicious_model_substitution.md)

*   **Description:** An attacker replaces a legitimate 3D model file (e.g., .glb, .fbx, .obj) with a crafted malicious one. The attacker could upload this file directly if the application allows user uploads, or they could intercept and modify the model during transit (MITM attack, even with HTTPS if certificates are compromised). The malicious model might contain an extremely high polygon count, excessively large textures, or exploit a vulnerability in the model loader.
*   **Impact:**
    *   Denial of Service (DoS): The application or browser tab crashes or becomes unresponsive due to excessive resource consumption.
    *   Client-side resource exhaustion (CPU, GPU, memory).
    *   Potential for arbitrary code execution (if a loader vulnerability is exploited, though this is less common).
*   **Three.js Component Affected:**
    *   `THREE.Loader` (base class) and specific loader implementations like `GLTFLoader`, `OBJLoader`, `FBXLoader`, etc.
    *   `THREE.BufferGeometry` (if the malicious model manipulates geometry data directly).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Validate all uploaded models.  Check file size, polygon count, texture dimensions, and other relevant parameters against predefined limits.  Reject models that exceed these limits.
    *   **Subresource Integrity (SRI):** Use SRI for the Three.js library itself.  If possible, generate and use SRI hashes for *all* loaded assets, including models.
    *   **Content Security Policy (CSP):** Use CSP to restrict the origins from which models can be loaded.
    *   **Secure Transmission (HTTPS):** Ensure HTTPS is correctly configured with strong ciphers and a valid, trusted certificate.
    *   **Asset Post-Processing (Limited):** After loading, *before* adding the model to the scene, perform some basic checks (e.g., bounding box size, number of vertices). This is not a foolproof solution but can catch some obvious issues.

## Threat: [Malicious Texture Injection](./threats/malicious_texture_injection.md)

*   **Description:** Similar to model substitution, an attacker replaces a legitimate texture file (e.g., .jpg, .png) with a malicious one. This could be done through direct upload, MITM attack, or by exploiting a vulnerability in the image loading process. The malicious texture might be excessively large, contain crafted data to exploit a decoder vulnerability, or be designed to trigger a specific rendering bug.
*   **Impact:**
    *   Denial of Service (DoS).
    *   Client-side resource exhaustion.
    *   Potential for arbitrary code execution (if a decoder vulnerability is exploited – less likely, but possible).
    *   Visual artifacts or glitches.
*   **Three.js Component Affected:**
    *   `THREE.TextureLoader`
    *   `THREE.Texture`
    *   Materials that use textures (e.g., `MeshBasicMaterial`, `MeshStandardMaterial`).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Validate all uploaded textures. Check file size, dimensions, and image format against predefined limits.
    *   **Subresource Integrity (SRI):** Use SRI for the Three.js library and, if feasible, for loaded textures.
    *   **Content Security Policy (CSP):** Use CSP to restrict the origins from which textures can be loaded.
    *   **Secure Transmission (HTTPS):** Ensure HTTPS is correctly configured.
    *   **Image Library Validation:** Consider using a separate, well-vetted image processing library (server-side) to validate and potentially resize/re-encode uploaded textures *before* they are used by Three.js. This adds a layer of defense against image decoder exploits.

