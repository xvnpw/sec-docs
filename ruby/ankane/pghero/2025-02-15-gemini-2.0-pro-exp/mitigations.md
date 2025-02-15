# Mitigation Strategies Analysis for ankane/pghero

## Mitigation Strategy: [Limit Query History Retention (Directly involves `pghero`)](./mitigation_strategies/limit_query_history_retention__directly_involves__pghero__.md)

*   **Description:**
    1.  **Determine Business Needs:** Assess the minimum time you need to retain query history for operational purposes (debugging, performance analysis).
    2.  **Configure `pghero`:** Use `pghero`'s configuration options.  This is *typically* done through:
        *   **Environment Variables:**  Set environment variables like `PGHERO_QUERY_STATS_RETENTION` (and potentially others related to different data types) to the desired retention period (e.g., `PGHERO_QUERY_STATS_RETENTION=7d` for 7 days).
        *   **Configuration File:** If `pghero` uses a configuration file (e.g., `config/pghero.yml`), set the retention settings within that file (e.g., `query_stats_retention: 7d`).  The exact setting names and file format will depend on `pghero`'s version and configuration options. Refer to the official `pghero` documentation.
        *   **`pghero` CLI (Less Common):** In some cases, `pghero` might offer command-line interface (CLI) options to configure retention, but this is less common for persistent settings.
    3.  **Verify Configuration:** After making changes, restart `pghero` (or your application) and verify that the new retention settings are in effect.  You might be able to do this through the `pghero` web interface or by querying the underlying database tables where `pghero` stores its data (but be cautious about directly modifying these tables).
    4. **Automated Purging (If Necessary and `pghero` supports it):** Some versions or configurations of `pghero` might require you to set up your own automated purging. If `pghero` *doesn't* automatically delete old data, and you've configured a short retention period, you'll need a separate mechanism (like a cron job) to delete old data. *However*, if `pghero` *does* handle purging automatically based on your configuration, this step is unnecessary. Check the `pghero` documentation.

*   **Threats Mitigated:**
    *   **Data Exposure via Query History (Severity: High):** Directly reduces the window of vulnerability by limiting the amount of historical query data stored.

*   **Impact:**
    *   **Data Exposure:** Risk reduction is directly proportional to the reduction in retention time.  Shorter retention periods significantly reduce risk.

*   **Currently Implemented:**
    *   Example: "`PGHERO_QUERY_STATS_RETENTION` is set to `3d` via an environment variable in our Kubernetes deployment."

*   **Missing Implementation:**
    *   Example: "We need to verify that `pghero` is *actually* purging data as expected. We haven't checked the underlying database tables to confirm this."

## Mitigation Strategy: [Disable Unnecessary Features (Directly involves `pghero`)](./mitigation_strategies/disable_unnecessary_features__directly_involves__pghero__.md)

*   **Description:**
    1.  **Review `pghero` Features:** Consult the `pghero` documentation to understand all the available features and their purposes (e.g., query stats, space analysis, index recommendations).
    2.  **Identify Unused Features:** Determine which features are *not* essential for your current needs.
    3.  **Disable via Configuration:**  `pghero` likely provides configuration options to disable specific features.  This is usually done through:
        *   **Environment Variables:**  Look for environment variables that control feature toggles (e.g., `PGHERO_DISABLE_SPACE_ANALYSIS=true`).
        *   **Configuration File:**  Check for settings in a `pghero` configuration file (e.g., `config/pghero.yml`) that allow you to disable features (e.g., `space_analysis: false`).
    4.  **Verify Disabled Features:** After making changes, restart `pghero` (or your application) and verify that the disabled features are no longer accessible or active in the `pghero` web interface.
    5. **Document Disabled Features:** Keep a record of which features have been disabled and why.

*   **Threats Mitigated:**
    *   **Unauthorized Access to Database Insights (Severity: Medium):** Reduces the attack surface by limiting the functionality available to an attacker, even if they gain some level of access.
    *   **Vulnerabilities in `pghero` or its Dependencies (Severity: Variable):** By disabling unused features, you reduce the likelihood of being affected by vulnerabilities within those specific features.

*   **Impact:**
    *   **Unauthorized Access:** Risk reduction depends on the number and sensitivity of the disabled features.
    *   **Vulnerabilities:** Risk reduction is moderate; it eliminates the risk from vulnerabilities in the disabled components.

*   **Currently Implemented:**
    *   Example: "We have disabled the 'Live Queries' feature by setting `PGHERO_DISABLE_LIVE_QUERIES=true` in our environment."

*   **Missing Implementation:**
    *   Example: "We haven't fully reviewed all `pghero` features to determine if there are others we can safely disable. We need to consult the latest `pghero` documentation."

