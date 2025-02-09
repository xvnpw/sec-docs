# Attack Surface Analysis for facebook/rocksdb

## Attack Surface: [Data Corruption via Direct File Manipulation](./attack_surfaces/data_corruption_via_direct_file_manipulation.md)

*   *Description:* Attackers with file system access bypass RocksDB's internal mechanisms to directly modify or delete SST files or WAL files, leading to data corruption.
    *   *How RocksDB Contributes:* RocksDB stores data in files on the file system. Its reliance on the underlying file system's security is a fundamental aspect.
    *   *Example:* An attacker with compromised user privileges on the server deletes or overwrites SST files, causing data loss or application crashes upon restart.
    *   *Impact:* Data loss, application instability, potential for arbitrary code execution (if crafted data is loaded).
    *   *Risk Severity:* **Critical** (if sensitive data is involved) or **High** (for non-sensitive data, but still causing significant disruption).
    *   *Mitigation Strategies:*
        *   **Strict File System Permissions:** Run the application under a dedicated user account with the *absolute minimum* necessary permissions on the RocksDB data directory. Use the principle of least privilege.
        *   **File Integrity Monitoring (FIM):** Implement FIM to detect unauthorized changes to SST and WAL files. Alert on any modifications.
        *   **Regular Backups:** Frequent, verified backups are essential for recovery from data corruption. Store backups in a separate, secure location.
        *   **Consider `use_direct_io_for_flush_and_compaction`:** This option (with careful performance testing) can reduce the window of vulnerability for buffered writes, but it's not a complete solution.

## Attack Surface: [Denial of Service via Resource Exhaustion (RocksDB-Specific Aspects)](./attack_surfaces/denial_of_service_via_resource_exhaustion__rocksdb-specific_aspects_.md)

*   *Description:* Attackers trigger RocksDB-specific operations that consume excessive CPU, memory, or disk I/O, making the application unresponsive. This focuses on aspects *directly* controllable within RocksDB's configuration and operation.
    *   *How RocksDB Contributes:* RocksDB's performance is highly dependent on configuration. Poorly tuned configurations or malicious workloads *interacting directly with RocksDB features* can lead to exhaustion.
    *   *Example:* An attacker, through a vulnerability that allows them to influence RocksDB options, sets extremely small write buffer sizes or triggers excessive compactions by manipulating internal settings (if exposed).  This differs from the previous DoS example, which focused on application-level interactions.
    *   *Impact:* Application slowdown or complete unavailability.
    *   *Risk Severity:* **High**
    *   *Mitigation Strategies:*
        *   **Careful Configuration:** Tune RocksDB's memory usage (block cache, write buffers) and compaction settings based on expected workloads and available resources. Use appropriate `BlockBasedTableOptions`. *Never expose raw configuration options to untrusted input.*
        *   **Monitoring:** Continuously monitor RocksDB's performance metrics (CPU, memory, I/O, compaction statistics) to detect anomalies. RocksDB provides extensive statistics.
        *   **RocksDB `RateLimiter`:** Consider using RocksDB's built-in `RateLimiter` for fine-grained control over I/O operations *within RocksDB itself*.
        *   **Disk Space Monitoring:** Monitor disk space usage and set alerts to prevent WAL or archive logs from filling the disk. Configure `WAL_ttl_seconds` and `WAL_size_limit_MB`.

## Attack Surface: [Data Exposure (Data at Rest)](./attack_surfaces/data_exposure__data_at_rest_.md)

*   *Description:* Sensitive data stored in RocksDB is exposed if the underlying storage is compromised.
    *   *How RocksDB Contributes:* RocksDB does not encrypt data at rest by default.
    *   *Example:* An attacker gains access to the server's hard drive or a backup of the database files and can read the unencrypted data.
    *   *Impact:* Data breach, potential violation of privacy regulations.
    *   *Risk Severity:* **Critical** (if sensitive data is stored)
    *   *Mitigation Strategies:*
        *   **Full-Disk Encryption:** Use full-disk encryption (e.g., LUKS, BitLocker).
        *   **File-System Level Encryption:** If full-disk encryption is not feasible.
        *   **RocksDB Encryption at Rest:** Utilize RocksDB's `Encryption` API. This requires integration with a Key Management Service (KMS). This is the preferred solution if application-level control over encryption is needed.

## Attack Surface: [Code Execution via RocksDB Vulnerabilities](./attack_surfaces/code_execution_via_rocksdb_vulnerabilities.md)

*   *Description:* Exploitation of vulnerabilities within RocksDB itself (e.g., buffer overflows) to achieve arbitrary code execution.
    *   *How RocksDB Contributes:* As a complex C++ codebase, RocksDB may contain undiscovered vulnerabilities.
    *   *Example:* A zero-day vulnerability in RocksDB's compaction process is exploited to inject malicious code.
    *   *Impact:* Complete system compromise.
    *   *Risk Severity:* **Critical**
    *   *Mitigation Strategies:*
        *   **Keep RocksDB Updated:** Apply security patches and updates promptly. Monitor security advisories.
        *   **Sandboxing/Containerization:** Isolate RocksDB using sandboxing or containerization.
        *   **Vulnerability Scanning:** Regularly scan RocksDB for known vulnerabilities.

## Attack Surface: [Denial of Service via Compaction Stall](./attack_surfaces/denial_of_service_via_compaction_stall.md)

*   *Description:* Attackers trigger a scenario where RocksDB's compaction process cannot keep up with the write rate, leading to a write stall.
    *   *How RocksDB Contributes:* RocksDB's compaction process is essential for performance, but it can be overwhelmed by specific write patterns *and internal configuration*.
    *   *Example:* An attacker, through a vulnerability allowing manipulation of RocksDB's internal state, forces a configuration that makes compactions extremely slow or inefficient.
    *   *Impact:* Writes to the database are blocked, leading to application unavailability.
    *   *Risk Severity:* **High**
    *   *Mitigation Strategies:*
        *   **Tune Compaction Settings:** Carefully configure compaction parameters.
        *   **Monitor Compaction Statistics:** Use RocksDB's statistics.
        *   **`level0_slowdown_writes_trigger` and `level0_stop_writes_trigger`:** Configure these options.

