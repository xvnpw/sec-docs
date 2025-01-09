# Attack Tree Analysis for borgbackup/borg

Objective: Attacker's Goal: To compromise the application that uses Borg Backup by exploiting weaknesses or vulnerabilities within Borg itself or its integration (focusing on high-risk scenarios).

## Attack Tree Visualization

```
└── Compromise Application Using Borg (Goal)
    ├── **HIGH-RISK PATH** Compromise Backups
    │   ├── Access Backup Data
    │   │   ├── **CRITICAL NODE** Obtain Borg Repository Access Credentials (AND)
    │   │   │   ├── **HIGH-RISK PATH** Exploit Application Vulnerability to Leak Credentials
    │   │   │   └── **HIGH-RISK PATH** Compromise System Hosting Borg Repository
    │   ├── **HIGH-RISK PATH** Modify Backup Data
    │       ├── **CRITICAL NODE** Gain Write Access to Borg Repository (AND)
    │           ├── Obtain Borg Repository Write Credentials (Similar to Access)
    │           └── Compromise System Hosting Borg Repository (Similar to Access)
    ├── **HIGH-RISK PATH** Manipulate Application's Borg Usage
    │   ├── **HIGH-RISK PATH** Command Injection via Application
    │   │   ├── **CRITICAL NODE** Exploit Application Vulnerability in Borg Command Construction
    │   ├── **HIGH-RISK PATH** Delete Existing Backups
    │   │   ├── **CRITICAL NODE** Gain Repository Write Access (Similar to Modify)
    │   └── **HIGH-RISK PATH** Exfiltrate Data via Backups
        └── Access Backups (Similar to Access)
```


## Attack Tree Path: [Compromise Backups](./attack_tree_paths/compromise_backups.md)

├── Access Backup Data
│   ├── **CRITICAL NODE** Obtain Borg Repository Access Credentials (AND)
│   │   ├── **HIGH-RISK PATH** Exploit Application Vulnerability to Leak Credentials
│   │   └── **HIGH-RISK PATH** Compromise System Hosting Borg Repository
├── **HIGH-RISK PATH** Modify Backup Data
    ├── **CRITICAL NODE** Gain Write Access to Borg Repository (AND)
        ├── Obtain Borg Repository Write Credentials (Similar to Access)
        └── Compromise System Hosting Borg Repository (Similar to Access)

## Attack Tree Path: [Exploit Application Vulnerability to Leak Credentials](./attack_tree_paths/exploit_application_vulnerability_to_leak_credentials.md)



## Attack Tree Path: [Compromise System Hosting Borg Repository](./attack_tree_paths/compromise_system_hosting_borg_repository.md)



## Attack Tree Path: [Modify Backup Data](./attack_tree_paths/modify_backup_data.md)

├── **CRITICAL NODE** Gain Write Access to Borg Repository (AND)
    ├── Obtain Borg Repository Write Credentials (Similar to Access)
    └── Compromise System Hosting Borg Repository (Similar to Access)

## Attack Tree Path: [Manipulate Application's Borg Usage](./attack_tree_paths/manipulate_application's_borg_usage.md)

├── **HIGH-RISK PATH** Command Injection via Application
│   ├── **CRITICAL NODE** Exploit Application Vulnerability in Borg Command Construction
├── **HIGH-RISK PATH** Delete Existing Backups
│   ├── **CRITICAL NODE** Gain Repository Write Access (Similar to Modify)
└── **HIGH-RISK PATH** Exfiltrate Data via Backups
    └── Access Backups (Similar to Access)

## Attack Tree Path: [Command Injection via Application](./attack_tree_paths/command_injection_via_application.md)

├── **CRITICAL NODE** Exploit Application Vulnerability in Borg Command Construction

## Attack Tree Path: [Delete Existing Backups](./attack_tree_paths/delete_existing_backups.md)

├── **CRITICAL NODE** Gain Repository Write Access (Similar to Modify)

## Attack Tree Path: [Exfiltrate Data via Backups](./attack_tree_paths/exfiltrate_data_via_backups.md)

└── Access Backups (Similar to Access)

