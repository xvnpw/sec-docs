# Attack Tree Analysis for blockskit/blockskit

Objective: [[Manipulate/Disrupt Blockchain Transactions]]

## Attack Tree Visualization

                                      [[Manipulate/Disrupt Blockchain Transactions]]
                                                    /               \
                                                   /                 \
                                                  /                   \
                      -------------------------------------------------------------------
                      |                                                                   |
[Exploit Blockskit Client-Side]                                  [Exploit Blockskit Dependencies]
      |                                                                         |
      |
[[Improper Config]]                                                      [[Outdated Dependency]]

(If Server-Side Exists, add this branch:)
                      |
                      |
         [Exploit Blockskit Server-Side]
                      |
                      |
             [[Input Validation]]

## Attack Tree Path: [Path 1](./attack_tree_paths/path_1.md)

==Manipulate/Disrupt Blockchain Transactions== --> ==Exploit Blockskit Client-Side== --> ==Improper Config==

## Attack Tree Path: [Path 2](./attack_tree_paths/path_2.md)

==Manipulate/Disrupt Blockchain Transactions== --> ==Exploit Blockskit Dependencies== --> ==Outdated Dependency==

## Attack Tree Path: [Path 3](./attack_tree_paths/path_3.md)

(If Server-Side Exists) ==Manipulate/Disrupt Blockchain Transactions== --> ==Exploit Blockskit Server-Side== --> ==Input Validation==

