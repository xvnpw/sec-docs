# Attack Tree Analysis for facebookresearch/faiss

Objective: Manipulate Search Results or Data Integrity via Faiss

## Attack Tree Visualization

```
Compromise Application Using Faiss **CRITICAL NODE**
├── OR Exploit Input Data Vulnerabilities **HIGH RISK PATH START**
│   ├── AND Poisoning Training Data (if applicable) **HIGH RISK PATH**
│   │   ├── Inject malicious vectors into the training dataset **CRITICAL NODE**
│   │   ├── Manipulate labels associated with training data **CRITICAL NODE**
│   └── AND Exploiting Input Validation Weaknesses **HIGH RISK PATH**
│       ├── Bypass input sanitization on vector data **CRITICAL NODE**
├── OR Exploit Search Query Vulnerabilities
│   ├── AND Bypassing Access Controls on Search Queries **HIGH RISK PATH START**
│       ├── Accessing search functionality without proper authorization **CRITICAL NODE**
├── OR Exploit Underlying Faiss Library Vulnerabilities **HIGH RISK PATH START**
│   ├── AND Exploiting Known Faiss Vulnerabilities
│   │   ├── Leverage publicly disclosed CVEs in Faiss **CRITICAL NODE**
│   ├── AND Exploiting Memory Corruption Vulnerabilities
│   │   ├── Trigger buffer overflows or other memory safety issues **CRITICAL NODE**
├── OR Exploit Dependencies of Faiss **HIGH RISK PATH START**
│   ├── AND Exploiting Vulnerabilities in BLAS/LAPACK Libraries
│   │   ├── Leverage known vulnerabilities in the underlying linear algebra libraries **CRITICAL NODE**
│   ├── AND Exploiting Vulnerabilities in Other Dependencies
│       ├── Target vulnerabilities in libraries Faiss relies on for I/O or other functionalities **CRITICAL NODE**
```


## Attack Tree Path: [Exploit Input Data Vulnerabilities](./attack_tree_paths/exploit_input_data_vulnerabilities.md)

Exploit Input Data Vulnerabilities **HIGH RISK PATH START**
├── AND Poisoning Training Data (if applicable) **HIGH RISK PATH**
│   ├── Inject malicious vectors into the training dataset **CRITICAL NODE**
│   ├── Manipulate labels associated with training data **CRITICAL NODE**
└── AND Exploiting Input Validation Weaknesses **HIGH RISK PATH**
    ├── Bypass input sanitization on vector data **CRITICAL NODE**

## Attack Tree Path: [Poisoning Training Data (if applicable)](./attack_tree_paths/poisoning_training_data__if_applicable_.md)

Poisoning Training Data (if applicable) **HIGH RISK PATH**
├── Inject malicious vectors into the training dataset **CRITICAL NODE**
├── Manipulate labels associated with training data **CRITICAL NODE**

## Attack Tree Path: [Inject malicious vectors into the training dataset](./attack_tree_paths/inject_malicious_vectors_into_the_training_dataset.md)

Inject malicious vectors into the training dataset **CRITICAL NODE**

## Attack Tree Path: [Manipulate labels associated with training data](./attack_tree_paths/manipulate_labels_associated_with_training_data.md)

Manipulate labels associated with training data **CRITICAL NODE**

## Attack Tree Path: [Exploiting Input Validation Weaknesses](./attack_tree_paths/exploiting_input_validation_weaknesses.md)

Exploiting Input Validation Weaknesses **HIGH RISK PATH**
├── Bypass input sanitization on vector data **CRITICAL NODE**

## Attack Tree Path: [Bypass input sanitization on vector data](./attack_tree_paths/bypass_input_sanitization_on_vector_data.md)

Bypass input sanitization on vector data **CRITICAL NODE**

## Attack Tree Path: [Bypassing Access Controls on Search Queries](./attack_tree_paths/bypassing_access_controls_on_search_queries.md)

Bypassing Access Controls on Search Queries **HIGH RISK PATH START**
├── Accessing search functionality without proper authorization **CRITICAL NODE**

## Attack Tree Path: [Accessing search functionality without proper authorization](./attack_tree_paths/accessing_search_functionality_without_proper_authorization.md)

Accessing search functionality without proper authorization **CRITICAL NODE**

## Attack Tree Path: [Exploit Underlying Faiss Library Vulnerabilities](./attack_tree_paths/exploit_underlying_faiss_library_vulnerabilities.md)

Exploit Underlying Faiss Library Vulnerabilities **HIGH RISK PATH START**
├── AND Exploiting Known Faiss Vulnerabilities
│   ├── Leverage publicly disclosed CVEs in Faiss **CRITICAL NODE**
├── AND Exploiting Memory Corruption Vulnerabilities
│   ├── Trigger buffer overflows or other memory safety issues **CRITICAL NODE**

## Attack Tree Path: [Exploiting Known Faiss Vulnerabilities](./attack_tree_paths/exploiting_known_faiss_vulnerabilities.md)

Exploiting Known Faiss Vulnerabilities
├── Leverage publicly disclosed CVEs in Faiss **CRITICAL NODE**

## Attack Tree Path: [Leverage publicly disclosed CVEs in Faiss](./attack_tree_paths/leverage_publicly_disclosed_cves_in_faiss.md)

Leverage publicly disclosed CVEs in Faiss **CRITICAL NODE**

## Attack Tree Path: [Exploiting Memory Corruption Vulnerabilities](./attack_tree_paths/exploiting_memory_corruption_vulnerabilities.md)

Exploiting Memory Corruption Vulnerabilities
├── Trigger buffer overflows or other memory safety issues **CRITICAL NODE**

## Attack Tree Path: [Trigger buffer overflows or other memory safety issues](./attack_tree_paths/trigger_buffer_overflows_or_other_memory_safety_issues.md)

Trigger buffer overflows or other memory safety issues **CRITICAL NODE**

## Attack Tree Path: [Exploit Dependencies of Faiss](./attack_tree_paths/exploit_dependencies_of_faiss.md)

Exploit Dependencies of Faiss **HIGH RISK PATH START**
├── AND Exploiting Vulnerabilities in BLAS/LAPACK Libraries
│   ├── Leverage known vulnerabilities in the underlying linear algebra libraries **CRITICAL NODE**
├── AND Exploiting Vulnerabilities in Other Dependencies
│   ├── Target vulnerabilities in libraries Faiss relies on for I/O or other functionalities **CRITICAL NODE**

## Attack Tree Path: [Exploiting Vulnerabilities in BLAS/LAPACK Libraries](./attack_tree_paths/exploiting_vulnerabilities_in_blaslapack_libraries.md)

Exploiting Vulnerabilities in BLAS/LAPACK Libraries
├── Leverage known vulnerabilities in the underlying linear algebra libraries **CRITICAL NODE**

## Attack Tree Path: [Leverage known vulnerabilities in the underlying linear algebra libraries](./attack_tree_paths/leverage_known_vulnerabilities_in_the_underlying_linear_algebra_libraries.md)

Leverage known vulnerabilities in the underlying linear algebra libraries **CRITICAL NODE**

## Attack Tree Path: [Exploiting Vulnerabilities in Other Dependencies](./attack_tree_paths/exploiting_vulnerabilities_in_other_dependencies.md)

Exploiting Vulnerabilities in Other Dependencies
├── Target vulnerabilities in libraries Faiss relies on for I/O or other functionalities **CRITICAL NODE**

## Attack Tree Path: [Target vulnerabilities in libraries Faiss relies on for I/O or other functionalities](./attack_tree_paths/target_vulnerabilities_in_libraries_faiss_relies_on_for_io_or_other_functionalities.md)

Target vulnerabilities in libraries Faiss relies on for I/O or other functionalities **CRITICAL NODE**

