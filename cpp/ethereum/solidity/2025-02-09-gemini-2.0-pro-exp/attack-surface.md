# Attack Surface Analysis for ethereum/solidity

## Attack Surface: [Reentrancy](./attack_surfaces/reentrancy.md)

*   **Description:** An attacker's contract recursively calls back into the victim contract before the initial invocation completes, manipulating state in unexpected ways.
*   **Solidity Contribution:** Solidity's ability to make external calls to other contracts (using `call`, `.transfer()`, etc.) enables this attack. The EVM's single-threaded execution model makes it susceptible.  The language *allows* for external calls, which is the core enabler.
*   **Example:** The DAO hack. A contract allowed withdrawals, and the attacker's contract repeatedly called the withdraw function before the balance was updated.
*   **Impact:** Loss of funds, unauthorized state changes, contract bricking.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Checks-Effects-Interactions Pattern:** Perform all state changes *before* making external calls.
    *   **Reentrancy Guards (Mutexes):** Use a state variable to lock the contract during sensitive operations.
    *   **Pull over Push:** Have users withdraw funds instead of sending them directly.

## Attack Surface: [Integer Overflow/Underflow](./attack_surfaces/integer_overflowunderflow.md)

*   **Description:** Arithmetic operations exceeding the type's limits wrap around, leading to unexpected results.
*   **Solidity Contribution:**  While Solidity 0.8.0+ has built-in checks, developers can *explicitly disable* them using `unchecked { ... }` blocks.  This is a *direct* Solidity feature that introduces the vulnerability.  Pre-0.8.0, this was the default behavior.
*   **Example:** A token contract where subtracting from zero results in a maximum balance.
*   **Impact:** Loss of funds, incorrect accounting, broken logic.
*   **Risk Severity:** Critical (if `unchecked` is used or pre-0.8.0)
*   **Mitigation Strategies:**
    *   **Use Solidity 0.8.0 or later (and avoid `unchecked`):** Rely on the built-in protection.
    *   **Extreme Caution with `unchecked`:** Only use for gas optimization with rigorous auditing.
    *   **SafeMath (for older versions):** If using an older compiler, use a library like SafeMath.

## Attack Surface: [Gas Limit Issues / Denial of Service (DoS)](./attack_surfaces/gas_limit_issues__denial_of_service__dos_.md)

*   **Description:** Functions consuming excessive gas can cause reverts, blocking legitimate users.
*   **Solidity Contribution:** Solidity code execution *directly* consumes gas.  Features like loops and external calls, *provided by Solidity*, are the mechanisms by which gas limits can be exceeded. The EVM's gas mechanism is fundamental to how Solidity operates.
*   **Example:** A contract iterating over a user-controlled array, causing out-of-gas errors.
*   **Impact:** Denial of service, contract unusable, loss of funds (spent gas).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Limit Loop Sizes:** Avoid unbounded loops or those dependent on external input.
    *   **Gas Optimization:** Analyze and optimize code for gas efficiency.
    *   **Off-Chain Computation:** Move complex calculations off-chain.
    *   **User-Initiated Actions:** Design for individual user actions rather than global operations.

## Attack Surface: [Delegatecall Vulnerabilities](./attack_surfaces/delegatecall_vulnerabilities.md)

*   **Description:** `delegatecall` executes code from another contract *in the context of the calling contract*, allowing storage modification.
*   **Solidity Contribution:** `delegatecall` is a *specific, low-level Solidity function*.  It's a core language feature that, by its very nature, creates this risk.
*   **Example:** A contract using `delegatecall` to a compromised library, allowing the library to overwrite the contract's owner.
*   **Impact:** Complete contract takeover, loss of funds, arbitrary state changes.
*   **Risk Severity:** Critical
*   **Mitigation Strategies:**
    *   **Avoid Untrusted Contracts:** Never use `delegatecall` with untrusted code.
    *   **Understand Storage Layout:** Be extremely careful about storage collisions.
    *   **Use Well-Audited Proxy Patterns:** Employ established proxy patterns for upgrades.
    *   **Immutability:** If possible, make the delegatecalled contract immutable.

## Attack Surface: [Unhandled Exceptions](./attack_surfaces/unhandled_exceptions.md)

*   **Description:** If an external call throws an exception and it's not handled, state changes before the exception might persist.
*   **Solidity Contribution:** Solidity's exception handling (and the behavior of low-level calls like `call` which don't automatically revert on failure) *directly* contributes to this. The language's error-handling mechanisms are the key factor.
*   **Example:** A contract sending funds, failing, but still marking the funds as sent.
*   **Impact:** Double spending, inconsistent state, loss of funds.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use `try`/`catch`:** Wrap external calls to handle exceptions.
    *   **Check Return Values:** For low-level calls, check the return value for success.
    *   **Revert on Failure:** Explicitly revert if a failure should not be ignored.

## Attack Surface: [Incorrect Use of `tx.origin`](./attack_surfaces/incorrect_use_of__tx_origin_.md)

*   **Description:** Using `tx.origin` for authorization is vulnerable to phishing.
*   **Solidity Contribution:** Solidity *provides* `tx.origin` as a global variable. The language makes this value accessible, and its misuse is the vulnerability.
*   **Example:** A contract using `tx.origin` for withdrawal authorization, allowing a phished user's funds to be stolen.
*   **Impact:** Unauthorized access, loss of funds.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Use `msg.sender`:** Always use `msg.sender` for authorization checks.

