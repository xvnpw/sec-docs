# Attack Surface Analysis for mrdoob/three.js

## Attack Surface: [Shader (GLSL) Injection](./attack_surfaces/shader__glsl__injection.md)

*   **Description:**  Attackers inject malicious GLSL code into WebGL shaders.
*   **How Three.js Contributes:** Three.js's core functionality relies on GLSL shaders.  Any user-provided data that influences shader code (directly or indirectly) creates a direct injection point *within* Three.js's rendering pipeline. This is inherent to how Three.js uses WebGL.
*   **Example:**  A user-customizable material allows direct input of a GLSL code snippet, or a seemingly safe parameter like a color is directly concatenated into shader source code without sanitization.
*   **Impact:**
    *   Denial of Service (browser/GPU crash).
    *   Information disclosure (reading pixel data, potentially cross-origin).
    *   GPU fingerprinting.
    *   Potential (rare) arbitrary code execution (via browser/driver exploits).
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Never** directly embed user input into shader code.
    *   Use **uniforms** exclusively to pass data to shaders.  Treat uniforms as the *only* safe way to parameterize shaders.
    *   **Strict input validation and sanitization:**  Validate *all* data that influences shader behavior, even if it's passed via uniforms. Use whitelists and strong typing.
    *   **Avoid dynamic shader compilation:** Pre-compile shaders whenever possible.
    * **Shader parameterization:** Design shaders to accept parameters (uniforms) rather than constructing them dynamically from user input.

## Attack Surface: [Malicious 3D Model Files](./attack_surfaces/malicious_3d_model_files.md)

*   **Description:**  Attackers upload or provide links to maliciously crafted 3D model files that exploit vulnerabilities in Three.js's *loaders*.
*   **How Three.js Contributes:** This is a direct attack on Three.js's provided loaders (e.g., `GLTFLoader`, `OBJLoader`, `FBXLoader`).  The vulnerability lies within the Three.js code responsible for parsing these model formats.
*   **Example:**  An attacker uploads a specially crafted glTF file designed to trigger a buffer overflow or other memory corruption vulnerability *within* the `GLTFLoader`'s parsing logic.
*   **Impact:**
    *   Denial of Service (application/browser crash).
    *   Potential (though less likely) arbitrary code execution by exploiting vulnerabilities *within the Three.js loader code*.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use the latest Three.js version:** This is paramount.  Security fixes for loaders are often included in updates.
    *   **Strict file type and size validation:** Enforce strict limits on allowed file types and sizes *before* Three.js processes them.
    *   **Server-side validation (pre-Three.js):** Ideally, perform validation and sanitization on the server *before* the model data ever reaches the client-side Three.js code. This adds a crucial layer of defense.
    * **Fuzz testing:** Use fuzz testing techniques on loaders.

## Attack Surface: [Resource Exhaustion (GPU)](./attack_surfaces/resource_exhaustion__gpu_.md)

*   **Description:**  Attackers provide input (models, textures, shader parameters) designed to consume excessive GPU resources.
*   **How Three.js Contributes:** Three.js is the direct interface to the GPU via WebGL.  The complexity of the scene rendered by Three.js directly impacts GPU resource usage.  User-provided data that controls scene complexity (e.g., model uploads, texture choices) directly affects this.
*   **Example:**  An attacker uploads a model with an extremely high polygon count and numerous large, uncompressed textures, causing Three.js to attempt to render a scene that overwhelms the user's GPU.
*   **Impact:**  Denial of Service (application/browser unresponsiveness, potential system instability).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Limit model complexity:** Enforce strict limits on the number of vertices, polygons, and materials in user-provided models *before* they are processed by Three.js.
    *   **Texture size and format restrictions:** Limit texture dimensions and enforce compressed texture formats *before* passing them to Three.js's texture loading mechanisms.
    *   **Shader complexity analysis:** Analyze shaders (especially those influenced by user input) for potential performance bottlenecks.  Simplify shaders where possible.  This is a Three.js-specific concern because Three.js uses these shaders.
    *   **Resource monitoring and throttling (within Three.js context):** Monitor GPU memory usage and frame rates *within your Three.js application*. Implement mechanisms to throttle or reject rendering updates that exceed predefined limits.

## Attack Surface: [Using Outdated Three.js Version](./attack_surfaces/using_outdated_three_js_version.md)

* **Description:** Using an old version of the library with known vulnerabilities.
* **How Three.js Contributes:** This is a direct vulnerability related to the Three.js library itself. Older versions may contain security flaws in loaders, renderers, or other components.
* **Example:** Using a version of Three.js with a known vulnerability in its `OBJLoader` that allows for arbitrary code execution.
* **Impact:** Varies depending on the specific vulnerability, but could range from DoS to code execution.
* **Risk Severity:** High (depending on the specific vulnerabilities)
* **Mitigation Strategies:**
    *   **Regularly update Three.js:** Keep Three.js up to date with the latest stable release. This is the *primary* mitigation.
    *   **Use a package manager:** Use npm, yarn, or a similar tool to manage Three.js as a dependency and easily update it.
    *   **Monitor security advisories:** Stay informed about security vulnerabilities in Three.js and its dependencies.

