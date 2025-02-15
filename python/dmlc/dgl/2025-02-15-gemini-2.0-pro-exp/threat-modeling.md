# Threat Model Analysis for dmlc/dgl

## Threat: [Graph Structure Poisoning via Edge Injection](./threats/graph_structure_poisoning_via_edge_injection.md)

*   **Description:**
    *   **Attacker Action:** An attacker adds malicious edges to the input graph. They might connect unrelated nodes, create fake relationships, or link to attacker-controlled nodes. This is done through a compromised data source, a vulnerability in the data ingestion pipeline, or by directly manipulating user-submitted graph data.
    *   **How:** The attacker exploits a lack of input validation or sanitization to inject edges that alter the graph's topology in a way that benefits the attacker.
*   **Impact:**
    *   The trained GNN model produces incorrect predictions or classifications, favoring the attacker's goals. For example, in a recommendation system, the attacker could promote specific items. In a fraud detection system, the attacker could make fraudulent transactions appear legitimate.
*   **DGL Component Affected:**
    *   `dgl.DGLGraph`: The core graph data structure is directly manipulated.
    *   Message Passing Functions (e.g., `update_all`, custom message/reduce functions): These functions propagate information across the poisoned edges, leading to corrupted node representations.
    *   Graph-level readout functions (if used): The final graph-level prediction is affected by the altered node representations.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Input Validation:** Implement rigorous validation of incoming graph data, checking for valid node and edge types, expected connectivity patterns, and reasonable feature values.
    *   **Schema Enforcement:** Define a strict schema for the graph data and enforce it during data ingestion.
    *   **Data Provenance:** Track the origin and modification history of all graph data.
    *   **Anomaly Detection:** Employ graph anomaly detection techniques to identify and flag suspicious edges or subgraphs.
    *   **Robustness Training (Adversarial Training):** Train the model with adversarial examples of edge injections to improve its resilience.

## Threat: [Feature Poisoning via Node Feature Modification](./threats/feature_poisoning_via_node_feature_modification.md)

*   **Description:**
    *   **Attacker Action:** An attacker modifies the feature vectors associated with nodes in the graph.
    *   **How:** The attacker exploits a vulnerability in the data pipeline or a lack of input validation to alter node features. This could involve changing numerical values, text strings, or other feature representations.
*   **Impact:**
    *   Incorrect model predictions. The attacker can manipulate the model's output by subtly altering node features, leading to misclassifications or biased results.
*   **DGL Component Affected:**
    *   `dgl.DGLGraph.ndata`: The node feature dictionary is directly modified.
    *   Message Passing Functions: These functions use the poisoned node features to compute node representations.
    *   Any DGL module that uses node features (e.g., GCN, GAT, GraphSAGE layers).
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Input Validation and Sanitization:** Rigorously validate and sanitize all node features. Define allowed ranges, data types, and formats.
    *   **Feature Normalization:** Apply robust feature normalization techniques to reduce the impact of outliers or malicious modifications.
    *   **Data Provenance:** Track the origin and modification history of node features.
    *   **Adversarial Training:** Train the model with adversarial examples of feature modifications.

## Threat: [Exploiting Vulnerability in DGL's `apply_edges` with Custom UDF](./threats/exploiting_vulnerability_in_dgl's__apply_edges__with_custom_udf.md)

*   **Description:**
    *   **Attacker Action:** An attacker exploits a vulnerability in a user-defined function (UDF) used within DGL's `apply_edges` function.
    *   **How:** If the UDF has a vulnerability (e.g., allows for code injection or buffer overflows), the attacker can craft input data that triggers the vulnerability when `apply_edges` is called.
*   **Impact:**
    *   Varies depending on the UDF vulnerability. Could range from denial of service to arbitrary code execution.
*   **DGL Component Affected:**
    *   `dgl.DGLGraph.apply_edges`: The vulnerability is triggered through this function.
    *   The custom UDF passed to `apply_edges`.
*   **Risk Severity:** Critical (if the UDF allows code execution), High (otherwise)
*   **Mitigation Strategies:**
    *   **Secure Coding Practices:** Rigorously review and test any custom UDFs for security vulnerabilities. Avoid using unsafe functions or operations.
    *   **Input Validation (within UDF):** Validate the input data *within* the UDF itself, even if validation is also performed elsewhere.
    *   **Sandboxing:** Consider running UDFs in a sandboxed environment to limit the impact of potential exploits.
    *   **Use Built-in Functions:** Whenever possible, prefer DGL's built-in functions over custom UDFs, as the built-in functions are generally more thoroughly tested and reviewed.

## Threat: [Exploiting Vulnerability in DGL's Heterograph Handling](./threats/exploiting_vulnerability_in_dgl's_heterograph_handling.md)

*   **Description:**
    *   **Attacker Action:** An attacker exploits incorrect handling of different node and edge types in a heterogeneous graph.
    *   **How:** The attacker leverages inconsistencies or vulnerabilities in how DGL processes different node/edge types, potentially leading to type confusion or data leakage between different parts of the graph. This could involve providing unexpected input types or exploiting edge cases in the type handling logic.
*   **Impact:**
    *   Data leakage between different node/edge types.
    *   Incorrect model behavior due to type confusion.
    *   Potential for denial of service if the vulnerability leads to crashes.
*   **DGL Component Affected:**
    *   `dgl.heterograph`: The core function for creating heterogeneous graphs.
    *   Message passing functions that operate on heterogeneous graphs (e.g., `multi_update_all`).
    *   Any DGL module that specifically handles heterogeneous graphs.
*   **Risk Severity:** High
*   **Mitigation Strategies:**
    *   **Strict Type Checking:** Ensure rigorous type checking and validation when defining and using heterogeneous graphs.
    *   **Careful UDF Design:** If using custom UDFs with heterogeneous graphs, ensure they correctly handle different node and edge types.
    *   **Thorough Testing:** Extensively test the application with various heterogeneous graph structures and input data.
    *   **Follow DGL Best Practices:** Adhere to DGL's documentation and examples for handling heterogeneous graphs.

