# Attack Tree Analysis for fluxml/flux.jl

Objective: Exfiltrate Data or Manipulate Model Output

## Attack Tree Visualization

                                     Exfiltrate Data or Manipulate Model Output
                                                    /       |       \
                                                   /        |        \
                                                  /         |         \
                                                 /          |          \
-------------------------------------------------------------------------------------------------
|                                               |                                               |
|  1. Compromise Model Training/Inference      |  2. Exploit Flux.jl Library Vulnerabilities   |  3. Inject Malicious Model/Weights           |
-------------------------------------------------------------------------------------------------
|       /       |       \                      |       /               \                      |       /                                       |
|      /        |        \                     |      /                 \                     |      /                                        |
|     /         |         \                    |     /                   \                    |     /                                         |
-------------------------------------------------------------------------------------------------
| 1.1 |        | 1.3     |                     |     | 2.2              | 2.4                  | 3.1 |                                         |
|Data |        |Evasion  |                     |     |Deser-            |Untrusted            |Pre-  |                                         |
|Pois-|        |Attacks  |                     |     |ializ-            |Input                |trained|                                         |
|oning|        | [CRIT]  |                     |     |ation             |Handling             |Model  |                                         |
| [CRIT]        |         |                     |     | [CRIT]            | [CRIT]              | [CRIT]  |                                         |
-------------------------------------------------------------------------------------------------

## Attack Tree Path: [Data Poisoning -> Model Output Manipulation](./attack_tree_paths/data_poisoning_-_model_output_manipulation.md)

1 -> 1.1

## Attack Tree Path: [Evasion Attack -> Model Output Manipulation](./attack_tree_paths/evasion_attack_-_model_output_manipulation.md)

1 -> 1.3

## Attack Tree Path: [Pre-trained Malicious Model -> Data Exfiltration/Output Manipulation](./attack_tree_paths/pre-trained_malicious_model_-_data_exfiltrationoutput_manipulation.md)

3 -> 3.1

## Attack Tree Path: [Untrusted Input Handling -> Code Injection/Data Exfiltration/Output Manipulation](./attack_tree_paths/untrusted_input_handling_-_code_injectiondata_exfiltrationoutput_manipulation.md)

2 -> 2.4 -> (Further exploitation)

## Attack Tree Path: [Deserialization Vulnerability -> Code Injection/Data Exfiltration/Output Manipulation](./attack_tree_paths/deserialization_vulnerability_-_code_injectiondata_exfiltrationoutput_manipulation.md)

2 -> 2.2 -> (Further exploitation)

