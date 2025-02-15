# Attack Surface Analysis for dmlc/dgl

## Attack Surface: [Malicious Graph Construction (Adversarial Examples)](./attack_surfaces/malicious_graph_construction__adversarial_examples_.md)

*Description:* Attackers craft subtle, malicious modifications to the graph structure (nodes, edges, features) that DGL processes, causing the DGL-based model to produce incorrect outputs.
*How DGL Contributes:* DGL is the *direct target*. Its graph representation and processing capabilities are exploited to manipulate the model's behavior.  The attack is *on* DGL's core functionality.
*Example:* Altering connections in a DGL-represented social network graph to bypass fraud detection; modifying node features in a DGL-represented molecular graph to cause misclassification of a chemical compound.
*Impact:* Incorrect model predictions, leading to security breaches, incorrect analysis, or flawed decisions.
*Risk Severity:* **High** to **Critical**
*Mitigation Strategies:*
    *   **Adversarial Training:** Train the DGL model with adversarial examples generated *using DGL's graph manipulation functions*.
    *   **Input Validation:** Implement strict validation of graph structure and features *within the DGL processing pipeline*.
    *   **Graph Regularization:** Use DGL-compatible regularization techniques during model training.
    *   **Gradient Masking/Obfuscation:** Explore DGL-compatible techniques (if available) to hinder gradient-based adversarial attacks.

## Attack Surface: [Denial-of-Service (DoS) via Graph Size/Complexity](./attack_surfaces/denial-of-service__dos__via_graph_sizecomplexity.md)

*Description:* Attackers submit extremely large or densely connected graphs to overwhelm DGL's processing capabilities, causing the DGL-dependent application to crash or become unresponsive.
*How DGL Contributes:* The attack directly targets DGL's graph processing algorithms and resource management.  The vulnerability lies in how DGL handles large or complex graphs.
*Example:* Sending a massive graph to a DGL-powered recommendation system, causing DGL's processing to consume all available memory or CPU, leading to a crash.
*Impact:* Application downtime, service unavailability.
*Risk Severity:* **High**
*Mitigation Strategies:*
    *   **Input Size Limits:** Enforce strict limits on graph size (nodes, edges) *before* passing the graph to DGL.
    *   **Resource Quotas:** Set resource limits (CPU, memory, GPU memory) specifically for DGL operations, potentially using DGL's own configuration options if available.
    *   **Timeout Mechanisms:** Implement timeouts for DGL operations to prevent them from running indefinitely.
    *   **Graph Sampling/Subsampling:** If feasible, use DGL's functions to sample or subsample the input graph *before* performing computationally intensive operations.

## Attack Surface: [Feature Injection/Poisoning](./attack_surfaces/feature_injectionpoisoning.md)

*Description:* Attackers inject malicious feature values into nodes or edges within the DGL graph representation to influence the model's output or trigger vulnerabilities.
*How DGL Contributes:* DGL's handling of node and edge features is the direct target.  The attack exploits how DGL stores and processes these features.
*Example:* Injecting extreme numerical values or crafted strings into features of a DGL graph used for chemical property prediction, causing incorrect results or potentially exploiting vulnerabilities in DGL's feature handling routines.
*Impact:* Incorrect model predictions, *potential* code execution (if DGL's feature processing has vulnerabilities).
*Risk Severity:* **High** to **Critical** (depending on the presence of exploitable vulnerabilities in DGL's feature handling).
*Mitigation Strategies:*
    *   **Strict Feature Validation:** Implement rigorous validation of feature values *before* they are assigned to nodes/edges in the DGL graph.
    *   **Feature Sanitization:** Sanitize feature values *within the DGL context* to remove potentially harmful characters or patterns.
    *   **Input Normalization:** Normalize feature values *before* passing them to DGL's model training or inference functions.

## Attack Surface: [Insecure Deserialization of Graph Data](./attack_surfaces/insecure_deserialization_of_graph_data.md)

*Description:* Attackers provide a maliciously crafted serialized graph to exploit vulnerabilities in DGL's *own* deserialization process.
*How DGL Contributes:* This attack specifically targets DGL's functions for loading graphs from serialized data (e.g., `dgl.load_graphs`).  The vulnerability lies within DGL's implementation of these functions.
*Example:* An attacker provides a crafted file that, when loaded using `dgl.load_graphs`, triggers a buffer overflow or other memory corruption vulnerability *within DGL's code*, leading to arbitrary code execution.
*Impact:* Arbitrary code execution, complete system compromise.
*Risk Severity:* **Critical**
*Mitigation Strategies:*
    *   **Avoid Untrusted Deserialization:** Never use DGL's deserialization functions (`dgl.load_graphs` or similar) on data from untrusted sources.
    *   **Input Validation (Post-Deserialization):** Even after using `dgl.load_graphs`, treat the loaded graph as untrusted and apply all the input validation and sanitization steps described for other attack vectors. This is crucial.
    *   **Safer Serialization Formats:** If possible, avoid using DGL's built-in serialization if it relies on potentially unsafe formats.  Instead, construct the DGL graph programmatically from data loaded using safer methods (e.g., JSON with schema validation).
    * **Sandboxing:** If deserialization with DGL functions is unavoidable, perform it in a sandboxed environment.

