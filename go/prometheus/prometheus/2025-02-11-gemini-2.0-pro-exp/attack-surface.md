# Attack Surface Analysis for prometheus/prometheus

## Attack Surface: [1. Unauthenticated Metrics Exposure](./attack_surfaces/1__unauthenticated_metrics_exposure.md)

*   **Description:** Sensitive application and infrastructure data exposed via the `/metrics` endpoint without authentication.
    *   **Prometheus Contribution:** Prometheus, by default, exposes all scraped metrics on the `/metrics` endpoint. This is its core functionality.
    *   **Example:** An attacker accesses `http://<prometheus-server>:<port>/metrics` and obtains database connection strings, internal IP addresses, and request rates.
    *   **Impact:** Information disclosure, leading to potential further attacks, data breaches, or competitive disadvantage.
    *   **Risk Severity:** **High** (Can be Critical if highly sensitive data is exposed).
    *   **Mitigation Strategies:**
        *   **Network Policies:** Restrict access to the `/metrics` endpoint to only authorized clients (e.g., the Prometheus server, monitoring dashboards) using firewall rules or network segmentation.
        *   **Authentication:** Implement authentication (basic auth, TLS client certificates) on the `/metrics` endpoint.  This requires configuring Prometheus and any clients that scrape metrics.
        *   **Reverse Proxy:** Use a reverse proxy (e.g., Nginx, Apache) to handle authentication and authorization before forwarding requests to Prometheus.
        *   **Metric Review:** Regularly review the metrics being exposed and minimize the inclusion of sensitive data in custom metrics.

## Attack Surface: [2. Unauthenticated Prometheus Web UI Access](./attack_surfaces/2__unauthenticated_prometheus_web_ui_access.md)

*   **Description:** Access to the Prometheus Web UI (typically `/graph` and other paths) without authentication, allowing querying and visualization of metrics.
    *   **Prometheus Contribution:** Prometheus provides a built-in web UI for exploring and querying metrics.
    *   **Example:** An attacker accesses `http://<prometheus-server>:<port>/graph` and uses the query interface to explore all collected metrics, including sensitive information.
    *   **Impact:** Information disclosure, similar to unauthenticated `/metrics` exposure, but with a more user-friendly interface for data exploration.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Network Policies:** Restrict access to the Prometheus Web UI using firewall rules or network segmentation.
        *   **Authentication:** Implement authentication (basic auth, TLS client certificates, or via a reverse proxy) to protect the UI.
        *   **Disable UI:** If the UI is not strictly needed (e.g., in production environments using Grafana), disable it entirely in the Prometheus configuration (`--web.enable-ui=false`).

## Attack Surface: [3. High Cardinality Metric DoS](./attack_surfaces/3__high_cardinality_metric_dos.md)

*   **Description:** An attacker intentionally or unintentionally causes a large number of unique time series to be created, overwhelming Prometheus's storage and processing capabilities.
    *   **Prometheus Contribution:** Prometheus's time-series database is susceptible to performance degradation with excessively high cardinality metrics.
    *   **Example:** An attacker sends requests with rapidly changing, unique label values (e.g., a UUID per request) to a monitored application, causing Prometheus to create a massive number of time series.
    *   **Impact:** Denial of service (DoS) of the Prometheus server, rendering monitoring and alerting unavailable.
    *   **Risk Severity:** **High**
    *   **Mitigation Strategies:**
        *   **Relabeling:** Use `relabel_configs` and `metric_relabel_configs` in the Prometheus configuration to drop or aggregate high-cardinality labels before they are stored.
        *   **Metric Design:** Educate developers on best practices for metric labeling to avoid unintentional cardinality explosions.  Avoid using unbounded values (e.g., user IDs, request IDs) as labels.
        *   **Limits:** Set limits on the number of time series per target (`sample_limit`) and globally (`global.scrape_sample_limit`).
        *   **`honor_labels` configuration:** Use it carefully, as it can be abused.

