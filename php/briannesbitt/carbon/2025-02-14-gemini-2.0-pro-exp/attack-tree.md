# Attack Tree Analysis for briannesbitt/carbon

Objective: Manipulate Application Logic/Data via Carbon Exploitation

## Attack Tree Visualization

                                      Attacker's Goal:
                    Manipulate Application Logic/Data via Carbon Exploitation
                                                |
          -------------------------------------------------------------------------
          |                                                                       |
  2.  Unsafe Deserialization/Parsing                                  (Other attack vectors omitted)
          |
  -----------------------------------
  |                 |
**2.1  `createFromFormat`** **2.3  `serialize`**
  |                 |
**2.1.1 ...**       **2.3.1 ... [CRITICAL]`**
**2.1.2 ...**
**2.1.3 ...**

## Attack Tree Path: [HIGH-RISK PATH](./attack_tree_paths/high-risk_path.md)

Attacker's Goal -> 2. Unsafe Deserialization/Parsing -> 2.3 `serialize` -> 2.3.1 PHP Object Injection [CRITICAL]

## Attack Tree Path: [HIGH-RISK PATH](./attack_tree_paths/high-risk_path.md)

Attacker's Goal -> 2. Unsafe Deserialization/Parsing -> 2.1 `createFromFormat` -> 2.1.1 Format String Injection

