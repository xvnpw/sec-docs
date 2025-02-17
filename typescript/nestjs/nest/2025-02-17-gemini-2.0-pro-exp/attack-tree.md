# Attack Tree Analysis for nestjs/nest

Objective: Gain Unauthorized Privileged Access (CRITICAL NODE)

## Attack Tree Visualization

                                     [Gain Unauthorized Privileged Access] (CRITICAL NODE)
                                                    |
          -------------------------------------------------------------------------
          |																							|
  [Exploit Module System]												 [Compromise Interceptors/Guards/Pipes]
          |																							|
  --------------------												 ------------------------------------
  |																							|					 |
[Dynamic Module																						[Bypass		 [Tamper with
 Misconfig]																						Guards]		Pipes]
 (CRITICAL NODE)																					(CRITICAL NODE) (CRITICAL NODE)
																										 (AuthZ)		 (Validation)

## Attack Tree Path: [HIGH-RISK PATH 1](./attack_tree_paths/high-risk_path_1.md)

[Gain Unauthorized Privileged Access] -> [Compromise Interceptors/Guards/Pipes] -> [Bypass Guards]

## Attack Tree Path: [HIGH-RISK PATH 2](./attack_tree_paths/high-risk_path_2.md)

[Gain Unauthorized Privileged Access] -> [Exploit Module System] -> [Dynamic Module Misconfig]

## Attack Tree Path: [HIGH-RISK PATH 3](./attack_tree_paths/high-risk_path_3.md)

[Gain Unauthorized Privileged Access] -> [Compromise Interceptors/Guards/Pipes] -> [Tamper with Pipes]

