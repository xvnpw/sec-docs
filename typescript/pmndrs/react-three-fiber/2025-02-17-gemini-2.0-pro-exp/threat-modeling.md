# Threat Model Analysis for pmndrs/react-three-fiber

## Threat: [Threat 1: Malicious Geometry Injection (via R3F Props)](./threats/threat_1_malicious_geometry_injection__via_r3f_props_.md)

*   **Description:** An attacker provides crafted input (e.g., through a form, URL, API) that is directly used to define the geometry of a 3D object *via R3F props*. The attacker creates a geometry with an extremely high vertex/face count, or uses degenerate geometry, aiming to overwhelm the renderer. This is *direct* because R3F is the mechanism by which the malicious data is passed to Three.js.
    *   **Impact:**
        *   **Denial of Service (DoS):** Browser unresponsiveness or crash due to excessive GPU/CPU load.
        *   **Application Freeze:** The React application freezes, blocking legitimate users.
    *   **Affected Component:**  `<mesh>` component (and any custom components that create geometries using `new THREE.BufferGeometry()` or similar, *when those constructors are used within the R3F render cycle and receive props derived from user input*). Specifically, props like `args` passed to geometry constructors, or custom hooks generating geometry data *within* the R3F component tree.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Strict Input Validation (Geometry Data):**
            *   **Vertex Count Limit:** Enforce a *hard* maximum on vertices/faces. This limit must be determined based on performance testing.
            *   **Bounding Box Check:** Reject geometries outside reasonable size limits.
            *   **Data Type Validation:** Ensure input data types are correct (numbers for positions, etc.).
        *   **Server-Side Validation:** Validate *before* sending geometry data to the client. This is a crucial defense.
        *   **Use of Simplified Geometries (When Possible):** Prefer pre-defined, simplified geometries over allowing arbitrary user-created shapes.
        *   **Progressive Loading (for Legitimate Complex Geometries):** Use techniques to avoid overwhelming the renderer with large, but valid, models.

## Threat: [Threat 2: Shader Code Injection (via R3F Material Props)](./threats/threat_2_shader_code_injection__via_r3f_material_props_.md)

*   **Description:** An attacker injects malicious GLSL code into a custom shader used by a material, *specifically through props passed to R3F components*. This exploits how R3F handles material creation and updates. The attacker might create a shader with an infinite loop, excessive texture lookups, or attempts at out-of-bounds memory access, directly targeting the GPU.
    *   **Impact:**
        *   **Denial of Service (DoS):** GPU hangs or crashes, rendering the application unusable.
        *   **(Rare) Information Disclosure:** In very specific, advanced scenarios, a crafted shader *might* leak information via side channels (e.g., subtle color changes).
    *   **Affected Component:**  `<mesh>` component (and any component that uses materials), *specifically when using `shaderMaterial` or custom materials where shader code or parameters are passed as props and derived from user input*. This includes any custom hooks that dynamically generate shader code based on user input *within* the R3F component tree.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Avoid User-Provided Shader Code:** The *primary* mitigation is to *completely avoid* allowing users to input raw GLSL.
        *   **Parameterized Shaders (Strictly Controlled):** Provide pre-defined shaders with a *very limited* set of parameters. *Rigorously* validate these parameters.
        *   **Shader Sandboxing (Not Feasible in Browsers):** True sandboxing is generally not possible in a web context.
        *   **GLSL Validator (Limited Help):** A validator can catch *some* syntax errors, but it's not a complete security solution.
        * **Strict Input Validation (Shader Parameters):** If using parameterized shaders, *thoroughly* validate *all* user-provided parameters (numbers, colors, texture names) to ensure they are within expected, safe ranges and formats. This validation must happen *before* the parameters are used in the R3F component.

