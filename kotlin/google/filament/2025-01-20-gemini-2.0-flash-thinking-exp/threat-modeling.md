# Threat Model Analysis for google/filament

## Threat: [Malicious 3D Model Loading](./threats/malicious_3d_model_loading.md)

*   **Threat:** Malicious 3D Model Loading
    *   **Description:** An attacker provides a specially crafted 3D model file (e.g., glTF, OBJ) to the application. This model could contain excessively complex geometry, an extremely large number of draw calls, or trigger vulnerabilities in the model parsing logic *within Filament*. The attacker might achieve this by compromising a content delivery mechanism or tricking a user into uploading a malicious file.
    *   **Impact:** Client-side Denial of Service (DoS) leading to application freeze or crash due to excessive resource consumption (CPU, GPU, memory) *within Filament's rendering pipeline*. Potentially, exploitation of parsing vulnerabilities *within Filament's model loading components* could lead to unexpected behavior or even code execution (though less likely in a sandboxed browser environment).
    *   **Which https://github.com/google/filament component is affected:**
        *   `Filament::gltfio` (for glTF models)
        *   `Filament::Geometry` (for mesh data processing)
        *   `Filament::Renderer` (when attempting to render the complex model)
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Implement strict validation and sanitization of 3D model files *before* loading them into Filament. This includes checking for excessive polygon counts, large texture sizes, and other resource-intensive properties.
        *   Set resource limits for model complexity (e.g., maximum number of triangles, vertices, draw calls) *within the application's Filament usage*.
        *   Consider using a separate process or worker thread for model loading and processing to prevent blocking the main application thread.
        *   Regularly update the Filament library to benefit from bug fixes and security patches in the model loading components.

## Threat: [Malicious Shader Injection/Exploitation](./threats/malicious_shader_injectionexploitation.md)

*   **Threat:** Malicious Shader Injection/Exploitation
    *   **Description:** An attacker provides or manipulates shader code (e.g., GLSL) used by Filament. This could involve exploiting vulnerabilities in the *Filament's* shader compiler or writing shaders that perform malicious operations *within Filament's rendering pipeline*. The attacker might achieve this if the application allows users to upload or define custom shaders.
    *   **Impact:** Client-side Denial of Service (DoS) by creating shaders with infinite loops or excessive computations that overload the GPU *through Filament's rendering*. Potentially, information disclosure by crafting shaders that attempt to access or leak data from the rendering context (though browser security models limit this). Unexpected or incorrect rendering behavior.
    *   **Which https://github.com/google/filament component is affected:**
        *   `Filament::ShaderCompiler`
        *   `Filament::Material` (when using custom shaders)
        *   `Filament::Renderer` (when executing the malicious shader)
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Avoid allowing users to upload or define arbitrary shader code if possible.
        *   If custom shaders are necessary, implement a strict review and auditing process for all shader code.
        *   Utilize shader compilers with security features and warnings enabled.
        *   Sanitize and validate any user-provided input that influences shader parameters.
        *   Consider using pre-compiled and validated shader libraries where feasible.

