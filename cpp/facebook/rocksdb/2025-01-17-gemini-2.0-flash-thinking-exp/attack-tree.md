# Attack Tree Analysis for facebook/rocksdb

Objective: Compromise application using RocksDB by exploiting weaknesses or vulnerabilities within RocksDB itself.

## Attack Tree Visualization

```
Compromise Application Using RocksDB
* OR Exploit Data Corruption/Manipulation
    * AND Exploit Application Logic Flaws + RocksDB's Data Handling [HR]
        * CR Exploit Lack of Input Validation in Application
    * OR Corrupt Existing Data
        * AND Directly Manipulate SST Files (Requires File System Access) [HR]
            * CR Gain Unauthorized File System Access
            * CR Modify SST Files to Inject Malicious Data or Corrupt Metadata
* OR Exploit Native Interface Vulnerabilities [HR]
    * AND Exploit Memory Safety Issues (C++++) [HR]
        * CR Trigger Buffer Overflows in API Calls
        * CR Exploit Use-After-Free Vulnerabilities
* OR Exploit Configuration Weaknesses [HR]
    * AND Leverage Insecure Default Configurations
        * CR Exploit Insecure File Permissions on Database Files
    * AND Manipulate Configuration Files (Requires File System Access) [HR]
        * CR Gain Unauthorized File System Access
        * CR Modify Configuration Files to Disable Security Features or Introduce Vulnerabilities
* OR Exploit Dependencies [HR]
    * AND Exploit Vulnerabilities in Libraries Used by RocksDB [HR]
        * CR Trigger Code Paths that Utilize Vulnerable Dependencies
```


## Attack Tree Path: [Exploit Data Corruption/Manipulation](./attack_tree_paths/exploit_data_corruptionmanipulation.md)

* AND Exploit Application Logic Flaws + RocksDB's Data Handling [HR]
        * CR Exploit Lack of Input Validation in Application
    * OR Corrupt Existing Data
        * AND Directly Manipulate SST Files (Requires File System Access) [HR]
            * CR Gain Unauthorized File System Access
            * CR Modify SST Files to Inject Malicious Data or Corrupt Metadata

## Attack Tree Path: [Exploit Native Interface Vulnerabilities [HR]](./attack_tree_paths/exploit_native_interface_vulnerabilities__hr_.md)

* AND Exploit Memory Safety Issues (C++) [HR]
        * CR Trigger Buffer Overflows in API Calls
        * CR Exploit Use-After-Free Vulnerabilities

## Attack Tree Path: [Exploit Configuration Weaknesses [HR]](./attack_tree_paths/exploit_configuration_weaknesses__hr_.md)

* AND Leverage Insecure Default Configurations
        * CR Exploit Insecure File Permissions on Database Files
    * AND Manipulate Configuration Files (Requires File System Access) [HR]
        * CR Gain Unauthorized File System Access
        * CR Modify Configuration Files to Disable Security Features or Introduce Vulnerabilities

## Attack Tree Path: [Exploit Dependencies [HR]](./attack_tree_paths/exploit_dependencies__hr_.md)

* AND Exploit Vulnerabilities in Libraries Used by RocksDB [HR]
        * CR Trigger Code Paths that Utilize Vulnerable Dependencies

