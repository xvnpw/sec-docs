# Attack Surface Analysis for fuellabs/sway

## Attack Surface: [Integer Overflow/Underflow](./attack_surfaces/integer_overflowunderflow.md)

*Description:* Arithmetic operations on integer types that result in a value exceeding the maximum or minimum representable value for that type.
*Sway Contribution:* Sway's type system and arithmetic operations are directly involved. While Sway aims for improved safety, implicit type conversions, casting, or edge cases in the standard library's arithmetic functions could still lead to overflows/underflows if not handled carefully.
*Example:*
```sway
let x: u64 = 0xFFFFFFFFFFFFFFFF; // Max u64
let y: u64 = 1;
let z: u64 = x + y; // z will wrap around to 0
//If z is used in security-critical logic, it can lead to vulnerability.
```
*Impact:* Unexpected program behavior, incorrect calculations, potential bypass of security checks, leading to unauthorized access or manipulation of funds.
*Risk Severity:* High
*Mitigation Strategies:*
    *   **Developers:** Use Sway's checked arithmetic operations (if available, e.g., `checked_add`, `checked_sub`). If not available, manually check for potential overflow/underflow *before* performing the operation.  Favor explicit type conversions with careful consideration of potential range issues.  Use libraries that provide safe math operations.  Fuzz test with a wide range of integer inputs, including boundary values.

## Attack Surface: [Reentrancy (Sway-Specific Context)](./attack_surfaces/reentrancy__sway-specific_context_.md)

*Description:*  A vulnerability where an attacker can recursively call a function before the previous invocation completes, potentially leading to unexpected state changes.  This is relevant to how Sway handles external calls and state.
*Sway Contribution:* Sway's mechanism for handling external calls and state updates is directly responsible for preventing or enabling reentrancy. The interaction between Sway contracts is key.
*Example:* A contract calls an external, untrusted contract, which in turn calls back into the original contract before the first call's state updates are finalized. This could manipulate the state in an unintended way.  A specific Sway example would depend on how external calls are implemented.
*Impact:*  Unauthorized manipulation of contract state, draining of funds, bypassing of security checks.
*Risk Severity:* High
*Mitigation Strategies:*
    *   **Developers:** Strictly adhere to the "checks-effects-interactions" pattern. Perform all checks (e.g., authorization, input validation) first, then update the contract's state, and *only then* make external calls.  If reentrancy guards are available and appropriate in Sway, use them.  Thoroughly analyze the call graph and potential interaction points.

## Attack Surface: [Logic Errors (Sway-Specific)](./attack_surfaces/logic_errors__sway-specific_.md)

*Description:*  Flaws in the contract's logic due to incorrect use of Sway's features, misunderstanding of its semantics, or general programming errors. This is directly tied to the Sway code itself.
*Sway Contribution:* Sway's unique features (type system, enums, standard library) introduce new possibilities for logic errors if not used correctly. The developer's understanding and use of Sway are paramount.
*Example:* Misusing a Sway enum variant in a conditional statement, leading to an unexpected execution path.  Incorrectly using a standard library function due to a misunderstanding of its behavior.
*Impact:*  Wide range of potential impacts, from minor bugs to critical vulnerabilities, depending on the nature of the logic error.  Severe logic errors can lead to complete contract compromise.
*Risk Severity:* High
*Mitigation Strategies:*
    *   **Developers:** Thoroughly understand Sway's language features and best practices.  Write extensive unit and integration tests, covering all possible execution paths and edge cases.  Conduct code reviews with experienced Sway developers.  Use static analysis tools and linters designed for Sway.  Formal verification, where feasible, can help prove the correctness of critical logic.

## Attack Surface: [Compiler (forc) Bugs](./attack_surfaces/compiler__forc__bugs.md)

*Description:* Vulnerabilities in the Sway compiler that introduce flaws into the compiled bytecode.
*Sway Contribution:* The `forc` compiler is specific to Sway and is responsible for translating Sway code into FuelVM bytecode. The bug is not in *your* Sway code, but it *affects* your Sway code directly.
*Example:* A compiler bug that incorrectly optimizes a loop, leading to an infinite loop or other unexpected behavior in the compiled contract. A flaw in the code generation process that introduces a vulnerability not present in the original Sway code.
*Impact:* Can introduce vulnerabilities into seemingly correct Sway code, making them difficult to detect.
*Risk Severity:* High
*Mitigation Strategies:*
    *   **Developers:** Use the latest stable version of the `forc` compiler. Report any suspected compiler bugs to the Fuel Labs team. Consider using multiple compiler versions (if available) to cross-check the generated bytecode. Examine the generated bytecode (if possible) for any anomalies.

