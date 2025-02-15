# Mitigation Strategies Analysis for github/scientist

## Mitigation Strategy: [Data Sanitization within Scientist's Execution Flow](./mitigation_strategies/data_sanitization_within_scientist's_execution_flow.md)

**Mitigation Strategy:**  Custom Result Class or Publisher with Integrated Sanitization

**Description:**
1.  **Create Custom `Scientist::Result` (Recommended):** Subclass `Scientist::Result` (or the equivalent in your language's Scientist implementation) to override the methods responsible for capturing and storing observation data (e.g., `value`, `exception`).  Within these overridden methods, *before* storing the data, call your sanitization functions to redact, mask, or hash sensitive information.
2.  **Alternatively, Customize Publisher:** If subclassing `Scientist::Result` is not feasible, create a custom publisher (Scientist allows you to define how results are reported).  Within the `publish` method of your custom publisher, perform the sanitization *before* sending the data to any external system (logs, metrics, etc.).
3.  **Sanitization Functions:**  (As described previously) Develop robust functions to handle different types of sensitive data using redaction, masking, hashing (with unique salts), or tokenization.
4.  **Configuration:** Configure Scientist to use your custom `Scientist::Result` class or custom publisher. This ensures that *all* experiments automatically use the sanitization logic.

**Threats Mitigated:**
*   **Data Leakage (Severity: High):** Exposure of sensitive data through Scientist's reporting.
*   **Compliance Violations (Severity: High):** Non-compliance with data privacy regulations.

**Impact:**
*   **Data Leakage:** Risk significantly reduced (from High to Low).
*   **Compliance Violations:** Risk significantly reduced (from High to Low).

**Currently Implemented:**
*   None (Sanitization functions exist, but are *not* integrated with Scientist).

**Missing Implementation:**
*   Creation of a custom `Scientist::Result` class or custom publisher.
*   Integration of sanitization functions within the custom class/publisher.
*   Configuration of Scientist to use the custom implementation.

## Mitigation Strategy: [Transaction Rollbacks within Candidate Code (Scientist Context)](./mitigation_strategies/transaction_rollbacks_within_candidate_code__scientist_context_.md)

**Mitigation Strategy:**  Mandatory Transaction Rollbacks in Candidate Blocks

**Description:**
1.  **Identify Side Effects:**  Analyze the candidate code for *any* operations that modify persistent state (database writes, file system changes, etc.).
2.  **Wrap in Transactions:**  Within the `try` block of the Scientist experiment's candidate code, wrap *all* such operations in a database transaction.
3.  **`try...finally` Block:** Use a `try...finally` block (or the equivalent in your language) to ensure that the transaction is *always* rolled back, regardless of whether the candidate code succeeds or raises an exception.  The rollback should happen in the `finally` block.
4.  **Explicit Rollback:**  Do *not* rely on automatic transaction management.  Explicitly call the `rollback()` method of the transaction object.
5. **Scientist Context Awareness:** Ensure that the transaction management logic is aware that it's running within a Scientist experiment. This might involve checking a flag or using a different connection pool.

**Threats Mitigated:**
*   **Data Corruption (Severity: High):** Unintended data modifications due to flawed candidate code.

**Impact:**
*   **Data Corruption:** Risk significantly reduced (from High to Low).

**Currently Implemented:**
*   Inconsistent use of transactions in some parts of the codebase.

**Missing Implementation:**
*   Consistent and mandatory use of transaction rollbacks within *all* candidate code blocks that have side effects, specifically within the Scientist experiment's `try` block.
*   Use of `try...finally` to guarantee rollback.

## Mitigation Strategy: [Scientist-Specific Timeouts and Sampling](./mitigation_strategies/scientist-specific_timeouts_and_sampling.md)

**Mitigation Strategy:**  Configure Timeouts and Sampling within Scientist

**Description:**
1.  **Timeouts:**  Within the Scientist experiment configuration, set a timeout for *both* the control and candidate code paths.  Scientist libraries typically provide a mechanism for this (e.g., `timeout` option).  If either path exceeds the timeout, Scientist should automatically abort the experiment and record a failure.
2.  **Sampling:**  Use Scientist's built-in sampling capabilities to run experiments on a small percentage of requests.  Start with a low percentage (e.g., 1%) and gradually increase it based on performance monitoring.  Scientist usually provides a `run_if` or similar method to control sampling.
3. **Dynamic Sampling (Advanced):** If possible, dynamically adjust the sampling rate based on system load.  This might involve integrating with a monitoring system or using a custom function within Scientist's `run_if` method.

**Threats Mitigated:**
*   **Denial of Service (DoS) (Severity: High):** Resource exhaustion due to experiments.
*   **Performance Degradation (Severity: Medium):** Slow response times.

**Impact:**
*   **Denial of Service (DoS):** Risk significantly reduced (from High to Low).
*   **Performance Degradation:** Risk reduced (from Medium to Low).

**Currently Implemented:**
*   Sampling is set to 5%.

**Missing Implementation:**
*   Timeouts for control and candidate code paths *within* the Scientist configuration.
*   Dynamic sampling based on system load.

## Mitigation Strategy: [Context Passing via Scientist's `context`](./mitigation_strategies/context_passing_via_scientist's__context_.md)

**Mitigation Strategy:** Utilize Scientist's `context` for Isolation and Awareness

**Description:**
1. **Identify Contextual Needs:** Determine what information the candidate and control code need to be aware of when running within a Scientist experiment. This might include:
    * A flag indicating whether the code is running in an experiment.
    * The name of the experiment.
    * A unique identifier for the experiment run.
    * Information about whether the code is running as the control or candidate.
    * Any other relevant contextual data that might affect behavior.
2. **Pass Context:** Use Scientist's `context` method (or equivalent) to pass this information to both the control and candidate blocks. The `context` is typically a dictionary or hash.
3. **Use Context in Code:** Within both the control and candidate code, access the context information and use it to modify behavior as needed. For example:
    * The candidate code might skip certain side effects if it knows it's running in an experiment.
    * The control code might log additional information when running in an experiment.
    * The code might use different configurations based on the experiment context.

**Threats Mitigated:**
* **Logic Errors (Severity: Medium):** Incorrect results due to mismatched context.
* **Data Corruption (Severity: High):** (Indirectly) By allowing the candidate code to avoid certain actions, it can reduce the risk of data corruption.

**Impact:**
* **Logic Errors:** Risk reduced (from Medium to Low).
* **Data Corruption:** Risk indirectly reduced.

**Currently Implemented:**
* Not implemented.

**Missing Implementation:**
* Identification of relevant contextual information.
* Passing context using Scientist's `context` method.
* Using the context within the control and candidate code to modify behavior.

