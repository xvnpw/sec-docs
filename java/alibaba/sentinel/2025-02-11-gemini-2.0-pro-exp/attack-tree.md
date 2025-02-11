# Attack Tree Analysis for alibaba/sentinel

Objective: Degrade/Disable Application, Bypass Flow Control, or Leak Config

## Attack Tree Visualization

                                     [[Attacker's Goal]]
                                                        |
                                                        |
                      [[1. Bypass Sentinel's Protection]]
                                        |
                -------------------------------------------------
                |						|
[[1.1 Rule Manipulation]]					[1.3 Client-Side Bypass] (If client-side is used)
                |						|
    ---------------------						|
    |				   |						|
[[1.1.1 Modify Rules]]	[[1.1.2 Delete Rules]]				   |
  via Dashboard/API]]	  via Dashboard/API]]			[1.3.1 Manipulate Client]

## Attack Tree Path: [Path 1](./attack_tree_paths/path_1.md)

Attacker's Goal ===> 1. Bypass Sentinel's Protection ===> 1.1 Rule Manipulation ===> 1.1.1 Modify Rules via Dashboard/API

## Attack Tree Path: [Path 2](./attack_tree_paths/path_2.md)

Attacker's Goal ===> 1. Bypass Sentinel's Protection ===> 1.1 Rule Manipulation ===> 1.1.2 Delete Rules via Dashboard/API

## Attack Tree Path: [Path 3](./attack_tree_paths/path_3.md)

Attacker's Goal ===> 1. Bypass Sentinel's Protection ===> 1.3 Client-Side Bypass ===> 1.3.1 Manipulate Client (If client-side is used)

