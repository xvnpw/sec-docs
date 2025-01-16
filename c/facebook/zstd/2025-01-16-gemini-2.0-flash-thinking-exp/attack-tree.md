# Attack Tree Analysis for facebook/zstd

Objective: Achieve Arbitrary Code Execution or Cause Denial of Service by Exploiting zstd Vulnerabilities.

## Attack Tree Visualization

```
Compromise Application Using zstd **[CRITICAL NODE]**
* [AND] Exploit zstd Library Weaknesses **[CRITICAL NODE]**
    * [OR] Exploit Decompression Functionality **[HIGH-RISK PATH START]**
        * Buffer Overflow (Decompression) **[CRITICAL NODE]**
            * Craft Malicious Compressed Data **[CRITICAL NODE]**
                * Provide Compressed Data with Length Fields Exceeding Buffer Size **[HIGH-RISK PATH END]**
        * Integer Overflow Leading to Small Buffer Allocation **[CRITICAL NODE]**
            * Craft Compressed Data Causing Integer Overflow in Size Calculation **[HIGH-RISK PATH END]**
        * Resource Exhaustion (Decompression) **[HIGH-RISK PATH START]**
            * Decompression Bomb (Zip Bomb Equivalent) **[CRITICAL NODE]**
                * Provide Highly Compressed Data that Expands to Enormous Size **[HIGH-RISK PATH END]**
            * Infinite Loop/Hang in Decompression Logic
                * Provide Malformed Compressed Data Triggering Loop **[HIGH-RISK PATH END]**
* [AND] Application Vulnerabilities Exacerbate zstd Exploits **[CRITICAL NODE]**
    * Insufficient Input Validation **[CRITICAL NODE, HIGH-RISK PATH START]**
        * Directly Decompressing Untrusted User Input **[HIGH-RISK PATH END]**
    * Lack of Resource Limits **[CRITICAL NODE, HIGH-RISK PATH START]**
        * Allowing Unlimited Memory/CPU Usage During Compression/Decompression **[HIGH-RISK PATH END]**
    * Using Vulnerable zstd Library Version **[CRITICAL NODE, HIGH-RISK PATH START]**
        * Failing to Update to Latest Secure Version **[HIGH-RISK PATH END]**
```


## Attack Tree Path: [Provide Compressed Data with Length Fields Exceeding Buffer Size](./attack_tree_paths/provide_compressed_data_with_length_fields_exceeding_buffer_size.md)

Compromise Application Using zstd **[CRITICAL NODE]**
* [AND] Exploit zstd Library Weaknesses **[CRITICAL NODE]**
    * [OR] Exploit Decompression Functionality **[HIGH-RISK PATH START]**
        * Buffer Overflow (Decompression) **[CRITICAL NODE]**
            * Craft Malicious Compressed Data **[CRITICAL NODE]**
                * Provide Compressed Data with Length Fields Exceeding Buffer Size **[HIGH-RISK PATH END]**

## Attack Tree Path: [Craft Compressed Data Causing Integer Overflow in Size Calculation](./attack_tree_paths/craft_compressed_data_causing_integer_overflow_in_size_calculation.md)

Compromise Application Using zstd **[CRITICAL NODE]**
* [AND] Exploit zstd Library Weaknesses **[CRITICAL NODE]**
    * [OR] Exploit Decompression Functionality **[HIGH-RISK PATH START]**
        * Integer Overflow Leading to Small Buffer Allocation **[CRITICAL NODE]**
            * Craft Compressed Data Causing Integer Overflow in Size Calculation **[HIGH-RISK PATH END]**

## Attack Tree Path: [Provide Highly Compressed Data that Expands to Enormous Size](./attack_tree_paths/provide_highly_compressed_data_that_expands_to_enormous_size.md)

Compromise Application Using zstd **[CRITICAL NODE]**
* [AND] Exploit zstd Library Weaknesses **[CRITICAL NODE]**
    * [OR] Exploit Decompression Functionality **[HIGH-RISK PATH START]**
        * Resource Exhaustion (Decompression) **[HIGH-RISK PATH START]**
            * Decompression Bomb (Zip Bomb Equivalent) **[CRITICAL NODE]**
                * Provide Highly Compressed Data that Expands to Enormous Size **[HIGH-RISK PATH END]**

## Attack Tree Path: [Provide Malformed Compressed Data Triggering Loop](./attack_tree_paths/provide_malformed_compressed_data_triggering_loop.md)

Compromise Application Using zstd **[CRITICAL NODE]**
* [AND] Exploit zstd Library Weaknesses **[CRITICAL NODE]**
    * [OR] Exploit Decompression Functionality **[HIGH-RISK PATH START]**
        * Resource Exhaustion (Decompression) **[HIGH-RISK PATH START]**
            * Infinite Loop/Hang in Decompression Logic
                * Provide Malformed Compressed Data Triggering Loop **[HIGH-RISK PATH END]**

## Attack Tree Path: [Directly Decompressing Untrusted User Input](./attack_tree_paths/directly_decompressing_untrusted_user_input.md)

Compromise Application Using zstd **[CRITICAL NODE]**
* [AND] Application Vulnerabilities Exacerbate zstd Exploits **[CRITICAL NODE]**
    * Insufficient Input Validation **[CRITICAL NODE, HIGH-RISK PATH START]**
        * Directly Decompressing Untrusted User Input **[HIGH-RISK PATH END]**

## Attack Tree Path: [Allowing Unlimited Memory/CPU Usage During Compression/Decompression](./attack_tree_paths/allowing_unlimited_memorycpu_usage_during_compressiondecompression.md)

Compromise Application Using zstd **[CRITICAL NODE]**
* [AND] Application Vulnerabilities Exacerbate zstd Exploits **[CRITICAL NODE]**
    * Lack of Resource Limits **[CRITICAL NODE, HIGH-RISK PATH START]**
        * Allowing Unlimited Memory/CPU Usage During Compression/Decompression **[HIGH-RISK PATH END]**

## Attack Tree Path: [Failing to Update to Latest Secure Version](./attack_tree_paths/failing_to_update_to_latest_secure_version.md)

Compromise Application Using zstd **[CRITICAL NODE]**
* [AND] Application Vulnerabilities Exacerbate zstd Exploits **[CRITICAL NODE]**
    * Using Vulnerable zstd Library Version **[CRITICAL NODE, HIGH-RISK PATH START]**
        * Failing to Update to Latest Secure Version **[HIGH-RISK PATH END]**

