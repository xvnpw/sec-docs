* Vulnerability name: Infinite Recursion/Stack Overflow in $ref Resolution
* Description:
    1. An attacker crafts a Swagger/OpenAPI specification document (YAML or JSON) containing a circular or deeply nested chain of `$ref`s.
    2. The attacker submits this malicious specification document to the application that uses the `go-openapi/spec` library to parse and process it.
    3. When the `go-openapi/spec` library attempts to expand or resolve the `$ref`s in the malicious specification, it enters an infinite recursion or a very deep recursion.
    4. This deep or infinite recursion consumes excessive stack space, leading to a stack overflow and crashing the application, or causing significant performance degradation.

* Impact:
    - Application crash (stack overflow).
    - Denial of Service (DoS) due to resource exhaustion or application unresponsiveness.

* Vulnerability rank: high

* Currently implemented mitigations:
    - Circular reference detection: The `expander.go` file implements a `isCircular` function within the `schemaLoader` struct. This function tracks parent references during schema expansion to detect circular references. When a circular reference is detected, the expansion is short-circuited, and the `$ref` is left unresolved.
    - Mitigation Code Location: `code/expander.go: schemaLoader.isCircular` and `code/expander.go: expandSchemaRef`

* Missing mitigations:
    - While circular reference detection is implemented to prevent infinite loops, there is no explicit limit on the depth of `$ref` resolution. In cases of extremely deep but not strictly circular nesting, the recursion depth could still become excessive and lead to a stack overflow, even with circular reference detection in place.
    - No configuration option to limit the depth of recursion for `$ref` resolution.

* Preconditions:
    - The application must use the `go-openapi/spec` library to parse and process Swagger/OpenAPI specification documents.
    - The attacker must be able to submit a malicious Swagger/OpenAPI specification document to the application, either directly (e.g., by uploading a file) or indirectly (e.g., by controlling a URL from which the specification is fetched).

* Source code analysis:
    - The vulnerability lies in the recursive nature of the `$ref` expansion logic in `expander.go`.
    - The `expandSchema` function is recursive and calls itself to handle nested schemas, `allOf`, `anyOf`, `oneOf`, `not`, `properties`, `items`, etc.
    - The `expandSchemaRef` function is specifically responsible for handling `$ref`s. It calls `resolver.Resolve` to fetch the referenced schema and then recursively calls `expandSchema` on the resolved schema.
    - The `isCircular` function is used to detect direct circular dependencies. However, it might not prevent stack overflow in cases of extremely deep, non-circular nesting.

```go
// code/expander.go

func expandSchemaRef(target Schema, parentRefs []string, resolver *schemaLoader, basePath string) (*Schema, error) {
	// ... (omitted code for brevity)

	if resolver.isCircular(normalizedRef, basePath, parentRefs...) { // Circular check
		// ... (omitted code for brevity)
		return &target, nil // Short-circuit on circular ref
	}

	var t *Schema
	err := resolver.Resolve(&target.Ref, &t, basePath) // Resolve the $ref
	if resolver.shouldStopOnError(err) {
		return nil, err
	}

	// ... (omitted code for brevity)
	return expandSchema(*t, parentRefs, transitiveResolver, basePath) // Recursive call
}

func expandSchema(target Schema, parentRefs []string, resolver *schemaLoader, basePath string) (*Schema, error) {
    // ... (omitted code for brevity)

    if target.Ref.String() != "" {
		if !resolver.options.SkipSchemas {
			return expandSchemaRef(target, parentRefs, resolver, basePath) // Recursive call for $ref
		}
        // ... (omitted code for brevity)
    }

    // ... recursive calls for other schema components (allOf, properties, items, etc.) ...
    for i := range target.AllOf {
		t, err := expandSchema(target.AllOf[i], parentRefs, resolver, basePath) // Recursive call for allOf
        // ...
    }
    // ... and so on for other schema components ...

    return &target, nil
}
```
- Visualization of recursion:

```
expandSchema (Schema A)
  -> expandSchemaRef (Schema A, $ref: B)
    -> resolver.Resolve(B)
    -> expandSchema (Schema B)
      -> expandSchemaRef (Schema B, $ref: C)
        -> resolver.Resolve(C)
        -> expandSchema (Schema C)
          -> ... (and so on, potentially very deep)
```

* Security test case:
    1. Create a YAML file (e.g., `recursive_spec.yaml`) with a deeply nested, but not strictly circular, chain of `$ref`s in the definitions. For example:

```yaml
swagger: "2.0"
info:
  version: "1.0.0"
  title: Recursive Spec

paths:
  /test:
    get:
      responses:
        '200':
          description: OK
          schema:
            $ref: '#/definitions/Level1'

definitions:
  Level1:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level2'
  Level2:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level3'
  Level3:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level4'
  Level4:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level5'
  Level5:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level6'
  Level6:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level7'
  Level7:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level8'
  Level8:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level9'
  Level9:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level10'
  Level10:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level11'
  Level11:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level12'
  Level12:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level13'
  Level13:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level14'
  Level14:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level15'
  Level15:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level16'
  Level16:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level17'
  Level17:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level18'
  Level18:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level19'
  Level19:
    type: object
    properties:
      next:
        $ref: '#/definitions/Level20'
  Level20:
    type: object
    properties:
      name:
        type: string
```

    2. Write a Go test case that loads and expands this `recursive_spec.yaml` using `go-openapi/spec`.

```go
package spec_test

import (
	"testing"

	"github.com/go-openapi/spec"
	"github.com/stretchr/testify/require"
)

func TestDeeplyNestedRefExpansion(t *testing.T) {
	specPath := "fixtures/recursive_spec.yaml" // Path to the YAML file created in step 1

	swspec := loadOrFail(t, specPath)

	err := spec.ExpandSpec(swspec, &spec.ExpandOptions{RelativeBase: specPath})
	if err != nil {
		t.Errorf("Expansion failed: %v", err) // Check for error, might indicate stack overflow if the app crashes before this line
	} else {
		t.Log("Expansion completed without immediate error, check for stack overflow or performance issues.")
	}
}
```
    3. Run the test case. Observe if the application crashes due to stack overflow or experiences significant performance degradation during `$ref` expansion.  You might need to increase the recursion depth in `recursive_spec.yaml` to reliably trigger a stack overflow depending on the Go stack size limit.

    4. To further validate, monitor resource usage (CPU, memory, stack) during the test execution. A stack overflow will typically lead to a crash without a graceful error, while deep recursion might cause high CPU usage and memory consumption.

This test case aims to demonstrate that while direct circular references are handled, very deep nesting can still be problematic due to the limitations of recursion depth in Go.

**Missing Mitigations:**
- Implement a recursion depth limit during `$ref` resolution. This limit should be configurable to allow users to adjust it based on their application's needs and security requirements.
- Consider alternative, non-recursive algorithms for `$ref` expansion if performance and stack usage become a significant concern. Iterative approaches or techniques like trampolining could be explored.

**Example of Missing Mitigation (Recursion Depth Limit):**

Add a `MaxRecursionDepth` option to `ExpandOptions` and check for recursion depth in `expandSchemaRef` function:

```diff
--- a/code/expander.go
+++ b/code/expander.go
@@ -27,6 +27,7 @@
 	ContinueOnError     bool                                  // continue expanding even after and error is found
 	PathLoader          func(string) (json.RawMessage, error) `json:"-"` // the document loading method that takes a path as input and yields a json document
 	AbsoluteCircularRef bool                                  // circular $ref remaining after expansion remain absolute URLs
+	MaxRecursionDepth   int                                   // maximum recursion depth for $ref expansion
 }

 func optionsOrDefault(opts *ExpandOptions) *ExpandOptions {
@@ -47,6 +48,9 @@
 		if clone.RelativeBase != "" {
 			clone.RelativeBase = normalizeBase(clone.RelativeBase)
 		}
+		if clone.MaxRecursionDepth <= 0 {
+			clone.MaxRecursionDepth = 50 // Default recursion depth limit
+		}
 		// if the relative base is empty, let the schema loader choose a pseudo root document
 		return &clone
 	}
@@ -245,6 +249,11 @@
 	normalizedRef := normalizeRef(&target.Ref, basePath)
 	normalizedBasePath := normalizedRef.RemoteURI()

+	if len(parentRefs) >= resolver.options.MaxRecursionDepth {
+		debugLog("recursion depth limit reached: basePath: %s, normalizedPath: %s, normalized ref: %s", basePath, normalizedBasePath, normalizedRef.String())
+		return &target, fmt.Errorf("recursion depth limit reached at ref: %s", normalizedRef.String())
+	}
+
 	if resolver.isCircular(normalizedRef, basePath, parentRefs...) {
 		// this means there is a cycle in the recursion tree: return the Ref
 		// - circular refs cannot be expanded. We leave them as ref.

```

By implementing a recursion depth limit, you can prevent stack overflows caused by excessively deep `$ref` nesting. Users can configure this limit based on their specific needs and security considerations.