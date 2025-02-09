# Threat Model Analysis for embree/embree

## Threat: [Degenerate Geometry Crash/DoS](./threats/degenerate_geometry_crashdos.md)

*   **Description:** An attacker provides input geometry containing degenerate triangles (e.g., zero-area triangles, triangles with collinear vertices), invalid floating-point values (NaN, Inf), or other malformed geometric primitives. The attacker crafts this input specifically to trigger edge cases or errors within Embree's BVH (Bounding Volume Hierarchy) construction or traversal algorithms.
    *   **Impact:**
        *   Application crash due to unhandled exceptions or assertions within Embree.
        *   Denial of Service (DoS) due to excessive CPU consumption or infinite loops triggered by the invalid geometry.
        *   Potentially, undefined behavior that *could* lead to further exploitation, although this is less likely than a crash or DoS.
    *   **Embree Component Affected:**
        *   BVH builders (e.g., `rtcBuildBVH`, different builder types like `BVH4.bvh4`, `BVH8.bvh8`).
        *   Ray traversal functions (e.g., `rtcIntersect1`, `rtcOccluded1`).
        *   Geometry creation functions (e.g., `rtcNewTriangleMesh`, `rtcNewQuadMesh`, `rtcNewCurve`).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   **Input Validation:** Before passing geometry to Embree, rigorously validate the input:
            *   Check for degenerate triangles (zero area, collinear vertices).
            *   Check for invalid floating-point values (NaN, Inf) in vertex coordinates and other geometric data.
            *   Enforce reasonable limits on vertex coordinates to prevent extremely large or small values.
        *   **Sanitization:** If possible, attempt to "repair" slightly malformed geometry (e.g., by merging nearly coincident vertices) before passing it to Embree.  However, be cautious, as incorrect sanitization can introduce new issues.
        *   **Resource Limits:** Implement resource limits (CPU time, memory allocation) for Embree operations.  This prevents a single malicious input from consuming all available resources.
        *   **Fuzz Testing:** Use fuzzing tools to generate a wide variety of malformed and edge-case geometry inputs to test Embree's robustness.
        *   **Error Handling:** Wrap Embree calls in appropriate error handling (e.g., `try-catch` blocks in C++, or checking the `RTCError` returned by `rtcGetDeviceError`).  Gracefully handle errors reported by Embree, rather than allowing the application to crash.

