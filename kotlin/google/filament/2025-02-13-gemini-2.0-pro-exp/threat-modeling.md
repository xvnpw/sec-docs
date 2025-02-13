# Threat Model Analysis for google/filament

## Threat: [Malicious glTF Model - Buffer Overflow](./threats/malicious_gltf_model_-_buffer_overflow.md)

*   **Threat:** Malicious glTF Model - Buffer Overflow

    *   **Description:** An attacker crafts a glTF/glb file containing malformed data (e.g., excessively long strings, invalid indices, corrupted animation data) designed to trigger a buffer overflow or underflow during parsing within Filament's glTF loader. The attacker could host this file on a website or deliver it through other means, tricking the application into loading it.
    *   **Impact:** Arbitrary code execution on the client machine, potentially leading to complete system compromise.
    *   **Affected Filament Component:** `gltfio` (glTF loader), specifically the parsing functions within `Source` (e.g., when handling buffers, accessors, and animation samplers). Potentially also lower-level libraries like `draco` (if Draco compression is used and the vulnerability is within Draco).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   **Strict glTF Validation:** Use a robust glTF validator (e.g., `gltf-validator`) *before* passing the data to Filament.  Reject any invalid files.  This is the most important mitigation.
        *   **Fuzz Testing:** Regularly fuzz test the `gltfio` component with a wide variety of malformed glTF files.
        *   **Memory Safety:** Filament's use of Rust helps mitigate this, but continuous vigilance is needed.
        *   **Input Size Limits:** Impose reasonable limits on the size of glTF files and individual data chunks within them.

## Threat: [Malicious glTF Model - Denial of Service (Resource Exhaustion)](./threats/malicious_gltf_model_-_denial_of_service__resource_exhaustion_.md)

*   **Threat:** Malicious glTF Model - Denial of Service (Resource Exhaustion)

    *   **Description:** An attacker creates a glTF model with an extremely high polygon count, excessive number of materials, deeply nested scene graph, or very large textures (that are still valid according to image format specifications, but excessively large). The attacker aims to overwhelm Filament's renderer, causing it to crash or become unresponsive.
    *   **Impact:** Denial of service (DoS) – the application becomes unusable. In severe cases, it could lead to system instability.
    *   **Affected Filament Component:** `filament::Engine`, `filament::Renderer`, `filament::View`, `filament::Scene`, `gltfio` (during loading), and potentially the underlying graphics API (Vulkan, OpenGL, Metal) *through* Filament's usage.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Resource Limits:** Set limits on the maximum number of polygons, materials, lights, and scene graph depth *within Filament*.
        *   **Texture Size Limits:** Enforce strict limits on texture dimensions and file sizes *before* passing them to Filament.
        *   **Progressive Loading (if applicable):** If possible, load models and textures progressively, allowing the application to remain responsive even with large assets. This would involve application-level logic interacting with Filament's API.
        *   **Timeout Mechanisms:** Implement timeouts for loading and rendering operations *within Filament or in the application code interacting with Filament* to prevent indefinite hangs.
        *   **Load in Background Thread:** Load large assets in a background thread to avoid blocking the main UI thread. This is application-level logic, but it directly impacts how Filament is used.

## Threat: [Malicious Shader - Infinite Loop (GPU Hang)](./threats/malicious_shader_-_infinite_loop__gpu_hang_.md)

*   **Threat:** Malicious Shader - Infinite Loop (GPU Hang)

    *   **Description:** If custom shaders are allowed *through Filament's material system*, an attacker provides a shader containing an infinite loop (e.g., a `while(true)` loop without a proper exit condition).
    *   **Impact:** GPU hang, potentially leading to system-wide instability and requiring a system reboot.
    *   **Affected Filament Component:** `filament::Material`, `filament::MaterialInstance`, and the underlying graphics API's shader compiler and runtime *as used by Filament*.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid Custom Shaders:** If possible, do *not* allow users to provide custom shaders *to Filament*. Use only pre-built, trusted materials provided by Filament or carefully vetted by the application developers.
        *   **Shader Validation (if custom shaders are unavoidable):**
            *   **Static Analysis:** Use static analysis tools to detect potential infinite loops and other problematic code patterns *before* passing the shader to Filament.
            *   **Timeout Mechanisms:** Implement timeouts for shader compilation and execution *within Filament or in the application's interaction with Filament*.
            *   **Restricted Shader Language:** Use a restricted subset of the shading language that limits the potential for malicious code, and ensure Filament's material system enforces this restriction.
            *   **Code Review:** Manually review all custom shader code before allowing it to be used *by Filament*.

## Threat: [Dependency Vulnerability - Arbitrary Code Execution (Directly Affecting Filament)](./threats/dependency_vulnerability_-_arbitrary_code_execution__directly_affecting_filament_.md)

* **Threat:** Dependency Vulnerability - Arbitrary Code Execution (Directly Affecting Filament)

    *   **Description:** A vulnerability is discovered in a *core* dependency of Filament that is *directly* involved in Filament's rendering pipeline (e.g., a vulnerability in Filament's `image` library, or a vulnerability in a low-level graphics library that Filament directly uses and exposes through its API). An attacker exploits this vulnerability through a crafted input file that triggers the vulnerability *within Filament's processing*.
    *   **Impact:** Arbitrary code execution, potentially leading to system compromise.
    *   **Affected Filament Component:** The affected dependency, and the Filament components that directly interact with it (e.g., `image`, `filament::Engine`, `filament::Texture` if the vulnerability is in the image library).
    *   **Risk Severity:** Critical (depending on the dependency vulnerability)
    *   **Mitigation Strategies:**
        *   **Dependency Scanning:** Regularly scan Filament's *direct* dependencies for known vulnerabilities using tools like Dependabot, Snyk, or OWASP Dependency-Check. Focus on dependencies that are part of Filament's core functionality.
        *   **Prompt Updates:** Update Filament and its *core* dependencies promptly when security patches are released.
        *   **Vendor Security Advisories:** Monitor security advisories from the vendors of Filament and its *core* dependencies.

