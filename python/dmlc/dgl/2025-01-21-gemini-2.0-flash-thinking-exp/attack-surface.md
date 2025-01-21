# Attack Surface Analysis for dmlc/dgl

## Attack Surface: [Malicious Graph/Feature Data Input](./attack_surfaces/malicious_graphfeature_data_input.md)

**Description:** The application loads graph structure and/or node/edge feature data from external sources that could be controlled by an attacker.

**How DGL Contributes:** DGL provides functionalities to ingest graph data from various formats (e.g., CSV, JSON, custom formats) and in-memory data structures. If the source of this data is untrusted, malicious data can be injected.

**Example:** An attacker provides a specially crafted CSV file representing a graph with an extremely large number of nodes or edges, causing excessive memory consumption and a denial-of-service. Alternatively, malicious feature data could contain format string vulnerabilities if processed without proper sanitization.

**Impact:** Denial of service, resource exhaustion, potential for arbitrary code execution if feature data is mishandled in a vulnerable way.

**Risk Severity:** High

**Mitigation Strategies:**
* Validate and sanitize all graph and feature data loaded from external sources.
* Implement size limits and complexity checks for graph structures.
* Use well-defined and trusted data formats where possible.
* Avoid directly processing raw string data from untrusted sources as feature data without careful sanitization.

## Attack Surface: [Deserialization of Malicious Graph Objects](./attack_surfaces/deserialization_of_malicious_graph_objects.md)

**Description:** The application uses DGL's saving and loading mechanisms (potentially relying on libraries like `pickle`) to persist and retrieve graph objects.

**How DGL Contributes:** DGL allows saving and loading graph objects, often leveraging Python's serialization capabilities. If an attacker can provide a maliciously crafted serialized graph object, deserialization vulnerabilities in the underlying library could be exploited.

**Example:** An attacker provides a pickled DGL graph object containing malicious code that gets executed when the application loads the graph using `dgl.save_graphs()` and `dgl.load_graphs()`.

**Impact:** Remote code execution, data corruption, privilege escalation.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Avoid deserializing graph objects from untrusted sources.
* If deserialization from untrusted sources is necessary, explore safer serialization methods than `pickle` or implement robust sandboxing.
* Regularly update DGL and its dependencies to patch known deserialization vulnerabilities.

## Attack Surface: [Exploiting Custom Message Passing Functions](./attack_surfaces/exploiting_custom_message_passing_functions.md)

**Description:** DGL allows users to define custom message passing functions for graph neural networks. If the application allows users to provide or influence these functions, it opens a potential attack vector.

**How DGL Contributes:** DGL's flexibility in defining message passing logic allows for arbitrary Python code to be executed within the graph computation.

**Example:** An attacker provides a malicious custom message passing function that performs actions beyond the intended graph computation, such as accessing sensitive data or executing system commands. This could happen if the application dynamically loads or compiles user-provided code.

**Impact:** Arbitrary code execution, data exfiltration, system compromise.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Avoid allowing users to directly define or provide custom message passing functions.
* If custom functions are necessary, implement strict sandboxing and validation of the provided code.
* Use predefined and well-tested message passing functions whenever possible.

## Attack Surface: [Distributed Training Communication Vulnerabilities](./attack_surfaces/distributed_training_communication_vulnerabilities.md)

**Description:** If the application utilizes DGL's distributed training capabilities, the communication between training nodes can be a potential attack surface.

**How DGL Contributes:** DGL facilitates distributed training, which involves network communication between different processes or machines. If this communication is not secured, it can be vulnerable.

**Example:** An attacker intercepts communication between distributed training nodes and injects malicious data or manipulates the training process. This could happen if the communication uses unencrypted protocols or lacks proper authentication.

**Impact:** Data poisoning, model corruption, unauthorized access to training data or infrastructure.

**Risk Severity:** High

**Mitigation Strategies:**
* Use secure communication protocols (e.g., TLS/SSL) for inter-node communication.
* Implement authentication and authorization mechanisms for distributed training nodes.
* Isolate the distributed training environment from untrusted networks.

