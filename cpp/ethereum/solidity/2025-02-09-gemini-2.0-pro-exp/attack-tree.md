# Attack Tree Analysis for ethereum/solidity

Objective: Illicit Financial Benefit or Disruption

## Attack Tree Visualization

```
                                      Attacker's Goal: Illicit Financial Benefit or Disruption
                                                      |
                                      -------------------------------------------------
                                      |                                               |
                      -----------------------------------               -----------------------------------
                      |                                 |               |
            1.  Exploit Logic Errors           2.  Exploit Gas Issues    4. Exploit External Calls
                      |                                 |               |
            --------------------------        --------------------------        --------------------------
            |        |       |       |        |        |               |        |       |
  1.1 Reentrancy 1.2  Arithmetic 1.3  Denial 1.4  Unexpected 2.1  Gas    2.4  Transaction 4.1  Untrusted 4.2  Reentrancy
  (Nested Calls) Overflow/ of Service State     Limit   Ordering  Contract  via External
  [CN][HR]       Underflow (DoS)     Changes  Exhaustion  Dependency  Call      Call
            [HR]     [HR]            [HR]               [HR]    (TOD/Front- [HR]      [CN][HR]
                                                                  Running)
                                                                  [HR]
                      -----------------------------------
                      |
            3. Exploit EVM/Solidity Features
                      |
            --------------------------
            |                   |
    3.3 Delegatecall    3.4 Selfdestruct
    (to same contract)  (with suicide())
    [CN][HR]            [HR]
```

## Attack Tree Path: [1. Exploit Logic Errors](./attack_tree_paths/1__exploit_logic_errors.md)

*   **1.1 Reentrancy (Nested Calls) `[CN][HR]`:**
    *   **Description:** An attacker exploits a function that makes an external call to the attacker's contract *before* updating its own state. The attacker's contract then calls the vulnerable function again (re-enters) before the first call completes. This can drain funds or manipulate state.
    *   **Likelihood:** Medium
    *   **Impact:** Very High
    *   **Effort:** Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

*   **1.2 Arithmetic Overflow/Underflow `[HR]`:**
    *   **(Pre Solidity 0.8.0):**
        *   **Description:** Calculations that result in values exceeding the maximum or minimum representable value wrap around, leading to unexpected results.
        *   **Likelihood:** Very Low (most contracts use 0.8.0+)
        *   **Impact:** Very High
        *   **Effort:** Low
        *   **Skill Level:** Intermediate
        *   **Detection Difficulty:** Easy
    *   **(Solidity 0.8.0+ with `unchecked`):**
        *   **Description:** Developers intentionally disable overflow/underflow checks for gas optimization, creating a potential vulnerability if not handled *extremely* carefully.
        *   **Likelihood:** Very Low
        *   **Impact:** Very High
        *   **Effort:** Very High
        *   **Skill Level:** Expert
        *   **Detection Difficulty:** Very Hard

*   **1.3 Denial of Service (DoS) `[HR]`:**
    *   **Description:** An attacker makes the contract unusable, either temporarily or permanently, by exploiting unbounded loops, excessive gas consumption, or unexpected reverts.
    *   **Likelihood:** Medium
    *   **Impact:** Medium-High
    *   **Effort:** Low-Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium-Hard

*   **1.4 Unexpected State Changes `[HR]`:**
    *   **Description:** The contract's state is altered in ways not anticipated by the developers, due to logic flaws, incorrect visibility settings, or improper modifier usage.
    *   **Likelihood:** Medium
    *   **Impact:** Medium-High
    *   **Effort:** Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium-Hard

## Attack Tree Path: [2. Exploit Gas Issues](./attack_tree_paths/2__exploit_gas_issues.md)

*   **2.1 Gas Limit Exhaustion `[HR]`:**
    *   **Description:** An attacker crafts transactions that consume excessive gas, causing them to fail or making the contract too expensive to use.
    *   **Likelihood:** Medium
    *   **Impact:** Medium
    *   **Effort:** Low
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

*   **2.4 Transaction Ordering Dependency (TOD/Front-Running) `[HR]`:**
    *   **Description:** An attacker observes pending transactions and submits their own with a higher gas price to be executed first, manipulating the outcome.
    *   **Likelihood:** High
    *   **Impact:** Medium-High
    *   **Effort:** Medium
    *   **Skill Level:** Advanced
    *   **Detection Difficulty:** Medium-Hard

## Attack Tree Path: [3. Exploit EVM/Solidity Features](./attack_tree_paths/3__exploit_evmsolidity_features.md)

*   **3.3 Delegatecall (to same contract) `[CN][HR]`:**
    *   **Description:** `delegatecall` executes code in the context of the *calling* contract.  If a contract `delegatecall`s to itself (or a malicious contract mimicking its interface), it can lead to unexpected state changes and vulnerabilities, potentially giving the attacker full control.
    *   **Likelihood:** Very Low
    *   **Impact:** Very High
    *   **Effort:** High
    *   **Skill Level:** Expert
    *   **Detection Difficulty:** Very Hard

*   **3.4 Selfdestruct (with suicide()) `[HR]`:**
    *   **Description:** `selfdestruct` sends the remaining ether in the contract to a specified address and removes the contract's code. An attacker might force a `selfdestruct` or use it to bypass logic.
    *   **Likelihood:** Low
    *   **Impact:** High
    *   **Effort:** Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

## Attack Tree Path: [4. Exploit External Calls](./attack_tree_paths/4__exploit_external_calls.md)

*   **4.1 Untrusted Contract Call `[HR]`:**
    *   **Description:** Calling an untrusted external contract introduces vulnerabilities. The external contract might be malicious or have its own vulnerabilities.
    *   **Likelihood:** Medium
    *   **Impact:** High
    *   **Effort:** Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

*   **4.2 Reentrancy via External Call `[CN][HR]`:**
    *   **Description:**  Identical to 1.1, but emphasizes the external call as the vector.  An attacker exploits a function that makes an external call, and the called contract re-enters the original function before it completes.
    *   **Likelihood:** Medium
    *   **Impact:** Very High
    *   **Effort:** Medium
    *   **Skill Level:** Intermediate
    *   **Detection Difficulty:** Medium

