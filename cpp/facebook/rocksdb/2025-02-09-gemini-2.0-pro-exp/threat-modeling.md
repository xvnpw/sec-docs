# Threat Model Analysis for facebook/rocksdb

## Threat: [Data Leakage via Unencrypted Storage](./threats/data_leakage_via_unencrypted_storage.md)

*   **Threat:** Data Leakage via Unencrypted Storage

    *   **Description:** An attacker gains physical or logical access to the server's storage. Since RocksDB doesn't encrypt data at rest by default, the attacker can directly read the contents of the SST files and WAL, exposing sensitive data.
    *   **Impact:** Data breach, exposing sensitive information stored in the database.
    *   **Affected Component:** SST files, WAL files (all persistent storage components).
    *   **Risk Severity:** Critical
    *   **Mitigation Strategies:**
        *   Use full-disk encryption (e.g., LUKS, dm-crypt) to encrypt the entire storage volume where RocksDB data is stored.
        *   If using cloud storage, utilize the provider's encryption-at-rest features (e.g., AWS KMS, Azure Disk Encryption, Google Cloud Storage encryption).
        *   Consider RocksDB's experimental encryption features (if available and thoroughly vetted).
        *   Implement strong access controls on the server and storage devices.

## Threat: [Denial of Service via Compaction Amplification](./threats/denial_of_service_via_compaction_amplification.md)

*   **Threat:** Denial of Service via Compaction Amplification

    *   **Description:** An attacker could intentionally insert a large number of small keys/values, or keys with a specific pattern, designed to trigger excessive and prolonged compaction cycles. This would consume significant CPU and I/O resources, making the database unresponsive or extremely slow for legitimate users.
    *   **Impact:** Denial of service, rendering the application unavailable or severely degraded.
    *   **Affected Component:** Compaction process (specifically, the background threads responsible for merging SST files). Level-based compaction is particularly susceptible.
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Carefully tune RocksDB's compaction settings (level style, target file sizes, number of compaction threads).
        *   Implement rate limiting on write operations (at the *application* level, but this mitigates a RocksDB-specific DoS).
        *   Monitor compaction statistics and dynamically adjust settings if necessary.
        *   Consider using universal compaction (with awareness of its trade-offs).
        *   Implement input validation (at the *application* level) to prevent excessively small or patterned keys/values.

## Threat: [Out-of-Memory (OOM) due to Unbounded Block Cache](./threats/out-of-memory__oom__due_to_unbounded_block_cache.md)

*   **Threat:** Out-of-Memory (OOM) due to Unbounded Block Cache

    *   **Description:** An attacker could trigger a large number of read operations for different keys, causing RocksDB to populate its block cache. If the block cache size is not properly limited, this can lead to excessive memory consumption, potentially causing the application or the entire system to crash due to OOM.
    *   **Impact:** Application crash, denial of service, potential system instability.
    *   **Affected Component:** Block Cache (in-memory data structure).
    *   **Risk Severity:** High
    *   **Mitigation Strategies:**
        *   Set a reasonable limit on the block cache size using the `BlockBasedTableOptions::block_cache` option.
        *   Monitor memory usage and adjust the block cache size as needed.
        *   Consider using a shared block cache.
        *   Use a memory-constrained environment (e.g., cgroups).

## Threat: [Improper Shutdown Leading to Data Loss](./threats/improper_shutdown_leading_to_data_loss.md)

* **Threat:** Improper Shutdown Leading to Data Loss

    * **Description:** The application using RocksDB is terminated abruptly (e.g., due to a crash, power outage, or forced kill) without allowing RocksDB to gracefully shut down. This can leave data in the memtable unflushed, or the WAL in an inconsistent state, leading to data loss upon restart.
    * **Impact:** Data loss of recently written data.
    * **Affected Component:** Memtable, WAL.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Implement proper signal handling (e.g., SIGTERM, SIGINT) in the application to gracefully shut down RocksDB.
        * Ensure that the `DB::~DB()` destructor (or equivalent close operation) is called before the application exits.
        * Use a process supervisor that can handle graceful shutdowns.
        * Configure RocksDB's WAL settings for durability (e.g., `sync` options), balancing performance and data safety.

