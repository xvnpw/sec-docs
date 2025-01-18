# Attack Tree Analysis for filosottile/mkcert

Objective: Compromise application utilizing mkcert by exploiting weaknesses within mkcert itself.

## Attack Tree Visualization

```
*   ***Compromise Root CA*** [CRITICAL NODE]
    *   ***Gain Access to Root CA Private Key*** [CRITICAL NODE]
        *   ***Exploit File System Permissions*** [HIGH-RISK PATH]
            *   Insufficiently Restrict Access to Root CA Key File (L:M, I:C, E:L, S:B, D:L)
*   ***Compromise Application-Specific Certificate*** [HIGH-RISK PATH]
    *   ***Gain Access to Application Certificate Private Key***
        *   ***Exploit File System Permissions*** [HIGH-RISK PATH]
            *   Insufficiently Restrict Access to Application Certificate Key File (L:M, I:H, E:L, S:B, D:L)
*   Exploit Trust Relationship with Root CA
    *   Install Malicious Root CA on Target System
        *   ***Social Engineering*** [HIGH-RISK PATH]
            *   Trick User into Installing Malicious Root CA (L:M, I:H, E:L, S:B, D:M)
*   ***Compromise mkcert Repository or Distribution*** [CRITICAL NODE]
```


## Attack Tree Path: [***Compromise Root CA***](./attack_tree_paths/compromise_root_ca.md)

***Gain Access to Root CA Private Key***
        *   ***Exploit File System Permissions*** [HIGH-RISK PATH]
            *   Insufficiently Restrict Access to Root CA Key File (L:M, I:C, E:L, S:B, D:L)

## Attack Tree Path: [***Compromise Application-Specific Certificate***](./attack_tree_paths/compromise_application-specific_certificate.md)

***Gain Access to Application Certificate Private Key***
        *   ***Exploit File System Permissions*** [HIGH-RISK PATH]
            *   Insufficiently Restrict Access to Application Certificate Key File (L:M, I:H, E:L, S:B, D:L)

## Attack Tree Path: [Exploit Trust Relationship with Root CA](./attack_tree_paths/exploit_trust_relationship_with_root_ca.md)

Install Malicious Root CA on Target System
        *   ***Social Engineering*** [HIGH-RISK PATH]
            *   Trick User into Installing Malicious Root CA (L:M, I:H, E:L, S:B, D:M)

## Attack Tree Path: [***Compromise mkcert Repository or Distribution***](./attack_tree_paths/compromise_mkcert_repository_or_distribution.md)



