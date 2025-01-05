# Threat Model Analysis for gin-gonic/gin

## Threat: [Path Traversal via Parameter Manipulation](./threats/path_traversal_via_parameter_manipulation.md)

**Description:** An attacker manipulates URL path parameters that are directly processed by Gin's routing to access files or resources on the server's filesystem. They might use ".." sequences or absolute paths to navigate outside the intended directories.
*   **Impact:** Unauthorized access to sensitive files (e.g., configuration files, source code), potential for arbitrary code execution if accessed files can be executed.
*   **Affected Gin Component:** `gin.Context.Param()`, Gin's routing logic for extracting path parameters.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   Implement strict input validation and sanitization on all path parameters obtained using `c.Param()`.

