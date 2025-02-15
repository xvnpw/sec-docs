# Deep Analysis of PgHero Mitigation Strategy: Limit Query History Retention

## 1. Objective

This deep analysis aims to thoroughly evaluate the effectiveness, implementation, and potential gaps of the "Limit Query History Retention" mitigation strategy for PgHero, a performance dashboard for Postgres. The goal is to ensure that this strategy adequately reduces the risk of sensitive data exposure through historical query data and to identify any areas for improvement.

## 2. Scope

This analysis focuses specifically on the "Limit Query History Retention" strategy as applied to PgHero. It covers:

*   Configuration mechanisms for query history retention in PgHero.
*   Verification of the implemented configuration.
*   Assessment of the effectiveness of the strategy in mitigating data exposure threats.
*   Identification of any missing implementation details or potential weaknesses.
*   Review of automated purging mechanisms, if applicable.
*   Consideration of different PgHero deployment scenarios (e.g., Kubernetes, Docker, direct installation).

This analysis *does not* cover other PgHero features or mitigation strategies unrelated to query history retention.  It also assumes basic familiarity with PostgreSQL and database security concepts.

## 3. Methodology

The analysis will follow these steps:

1.  **Documentation Review:**  Thoroughly review the official PgHero documentation (including any relevant GitHub issues, discussions, and release notes) to understand the recommended practices for configuring query history retention. This includes identifying the specific configuration parameters, their expected behavior, and any known limitations.
2.  **Implementation Review:** Examine the current implementation details, including how the `PGHERO_QUERY_STATS_RETENTION` environment variable (or other configuration methods) is set and where it is applied (e.g., Kubernetes deployment files, Docker Compose files, application configuration).
3.  **Verification:**  Develop and execute a plan to verify that the configured retention policy is working as expected. This will involve:
    *   **Direct Database Inspection:**  Querying the PgHero-related tables (e.g., `pghero_query_stats`) in the PostgreSQL database to observe the actual data retention behavior.  This is crucial for confirming that data is being purged.
    *   **Time-Based Testing:**  Allowing sufficient time to pass (more than the configured retention period) and then re-checking the database to ensure that older data has been removed.
    *   **PgHero UI Verification (If Available):** Checking the PgHero web interface (if applicable) to see if it reflects the expected retention period.
4.  **Threat Modeling:**  Re-evaluate the "Data Exposure via Query History" threat in light of the implemented retention policy.  Consider various attack scenarios and how the shortened retention period mitigates them.
5.  **Gap Analysis:**  Identify any discrepancies between the intended configuration, the actual implementation, and the expected behavior.  This includes checking for:
    *   Misconfigurations.
    *   Unintended data retention.
    *   Lack of automated purging (if required).
    *   Potential bypasses of the retention policy.
6.  **Recommendations:**  Provide specific, actionable recommendations to address any identified gaps or weaknesses.

## 4. Deep Analysis of "Limit Query History Retention"

### 4.1. Documentation Review

The PgHero documentation (https://github.com/ankane/pghero) indicates that `PGHERO_QUERY_STATS_RETENTION` is the primary environment variable for controlling query statistics retention.  The documentation states that the value should be a duration string (e.g., `7d`, `1w`, `30d`).  It's crucial to note that PgHero *does* handle the purging automatically.  There is no need for a separate cron job or other external purging mechanism.  This is a significant advantage, as it simplifies the implementation and reduces the risk of errors.

Other relevant settings mentioned in the documentation (though less directly related to query *text* retention) include:

*   `PGHERO_SPACE_STATS_RETENTION`: Controls retention of space statistics.
*   `PGHERO_SYSTEM_STATS_RETENTION`: Controls retention of system statistics.
*   `PGHERO_CAPTURE_QUERIES`:  Can be set to `false` to disable query capture entirely (a more drastic, but potentially valid, mitigation).

### 4.2. Implementation Review

The current implementation uses `PGHERO_QUERY_STATS_RETENTION=3d` set as an environment variable within the Kubernetes deployment. This is a good practice, as it keeps configuration separate from the application code and allows for easy modification without redeploying the application.  The Kubernetes deployment ensures that this environment variable is available to the PgHero container.

### 4.3. Verification

To verify the implementation, we will perform the following:

1.  **Initial Data Check:** Connect to the PostgreSQL database and query the `pghero_query_stats` table:

    ```sql
    SELECT min(captured_at), max(captured_at) FROM pghero_query_stats;
    ```

    This will show the oldest and newest timestamps of captured queries.

2.  **Time-Based Test:** Wait for at least 4 days (longer than the 3-day retention period).

3.  **Post-Retention Check:** Re-run the query from step 1.  The `min(captured_at)` value should now be no older than 3 days from the current time.  If it is older, the retention policy is not working.

4.  **Count Check:**  Run a query to count the number of records older than 3 days:

    ```sql
    SELECT COUNT(*) FROM pghero_query_stats WHERE captured_at < NOW() - INTERVAL '3 days';
    ```

    This count should be zero (or very close to zero, allowing for a small window of time during the purging process).

5. **PgHero UI (Optional):** If accessible, check the PgHero UI to see if the displayed query history aligns with the 3-day retention period. This provides a visual confirmation, but the database checks are more definitive.

### 4.4. Threat Modeling

The "Data Exposure via Query History" threat is significantly mitigated by the 3-day retention policy.  An attacker gaining access to the PgHero database would only be able to see queries executed within the last 3 days, rather than potentially months or years of historical data. This reduces the impact of:

*   **Database Compromise:**  If the database itself is compromised, the attacker's access to sensitive data within queries is limited.
*   **PgHero Application Vulnerability:**  If a vulnerability in the PgHero application allows unauthorized access to query history, the scope of the exposure is reduced.
*   **Insider Threat:**  A malicious insider with access to PgHero would have a limited window to exfiltrate query data.

However, it's important to acknowledge that a 3-day window *still* presents some risk.  Highly sensitive queries executed within that window could still be exposed.  Therefore, this mitigation should be part of a layered defense strategy, combined with other security measures like:

*   **Principle of Least Privilege:**  Ensure that database users have only the necessary permissions.
*   **Query Parameterization:**  Use parameterized queries to prevent SQL injection vulnerabilities.
*   **Data Masking/Encryption:**  Consider masking or encrypting sensitive data at rest and in transit.
*   **Regular Security Audits:**  Conduct regular security audits to identify and address vulnerabilities.

### 4.5. Gap Analysis

Based on the "Missing Implementation" example, the primary gap is the lack of verification.  The steps outlined in section 4.3 (Verification) *must* be performed to confirm that PgHero is purging data as expected.  Without this verification, we are relying on an assumption that could be incorrect.

Other potential gaps (depending on the results of the verification):

*   **Incorrect `PGHERO_QUERY_STATS_RETENTION` Value:**  The value might be misspelled, have an invalid format, or be overridden by another configuration setting.
*   **PgHero Bug:**  There could be a bug in PgHero that prevents it from correctly purging data, even with the correct configuration.
*   **Database Permissions Issue:**  The database user that PgHero uses might not have the necessary permissions to delete data from the `pghero_query_stats` table.
* **Timezone issues**: Ensure that the timezone used by the application and the database are the same.

### 4.6. Recommendations

1.  **Immediate Verification:**  Perform the verification steps outlined in section 4.3 *immediately* to confirm that the retention policy is working.
2.  **Automated Monitoring:**  Implement automated monitoring to regularly check the `pghero_query_stats` table and ensure that the retention policy continues to function correctly.  This could involve:
    *   A script that runs periodically and alerts if the oldest query is older than expected.
    *   Integration with a monitoring system (e.g., Prometheus, Grafana) to track the age of the oldest query and trigger alerts based on thresholds.
3.  **Documentation:**  Document the verification process and the results.  This documentation should be kept up-to-date and readily available.
4.  **Regular Review:**  Periodically review the retention policy and adjust it as needed based on business requirements and evolving threat landscapes.
5.  **Consider Shorter Retention:** If feasible, consider reducing the retention period further (e.g., to 1 day or even a few hours) if the business needs allow. This would further reduce the risk of data exposure.
6. **Timezone Check:** Verify that the application server and the database server are using the same timezone. Inconsistent timezones can lead to unexpected behavior with time-based data purging.
7. **Database User Permissions:** Double-check that the database user PgHero uses has the necessary `DELETE` privileges on the `pghero_query_stats` table.

By addressing these gaps and implementing these recommendations, the "Limit Query History Retention" strategy can be significantly strengthened, providing a robust defense against data exposure through PgHero's query history.