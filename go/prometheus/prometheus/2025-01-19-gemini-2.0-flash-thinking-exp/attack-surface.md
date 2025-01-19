# Attack Surface Analysis for prometheus/prometheus

## Attack Surface: [Unauthenticated HTTP API Access](./attack_surfaces/unauthenticated_http_api_access.md)

**Description:** Prometheus's HTTP API is exposed by default without any authentication or authorization mechanisms.

**How Prometheus Contributes:** The default configuration of Prometheus does not enforce authentication on its API endpoints.

**Example:** An attacker on the same network can access `/metrics`, `/graph`, or `/targets` endpoints to view sensitive operational data, query metrics, or see the list of monitored targets.

**Impact:** Information disclosure (sensitive metrics, target information), potential for data manipulation via remote write (if enabled and unsecured), and potential for denial of service by triggering expensive queries or reloading configurations.

**Risk Severity:** High

**Mitigation Strategies:**
* Implement authentication and authorization using a reverse proxy (e.g., Nginx, Apache) in front of Prometheus.
* Utilize Prometheus's built-in `--web.enable-lifecycle` flag and configure authentication using `--web.auth-users` and `--web.auth-password-files`.
* Restrict network access to the Prometheus server to trusted networks or hosts using firewalls.

## Attack Surface: [Denial of Service via Resource Exhaustion (High Cardinality Metrics)](./attack_surfaces/denial_of_service_via_resource_exhaustion__high_cardinality_metrics_.md)

**Description:** Scraping targets that expose metrics with a large number of unique label combinations (high cardinality) can overwhelm Prometheus's memory and storage.

**How Prometheus Contributes:** Prometheus stores all unique time series, and high cardinality leads to a massive increase in the number of series.

**Example:** An application exposes a metric `http_requests_total` with a label `user_id` that has a unique value for every user. Over time, this will create an enormous number of time series, potentially crashing Prometheus.

**Impact:** Denial of service (Prometheus becomes unresponsive or crashes), impacting monitoring capabilities.

**Risk Severity:** High

**Mitigation Strategies:**
* Design metrics carefully to avoid unbounded labels.
* Relabel metrics at the exporter or Prometheus level to reduce cardinality (e.g., aggregate or drop high-cardinality labels).
* Implement limits on the number of time series Prometheus can ingest.
* Monitor Prometheus's resource usage (memory, CPU, disk I/O).

## Attack Surface: [Exposure of Sensitive Information in Metrics](./attack_surfaces/exposure_of_sensitive_information_in_metrics.md)

**Description:** Applications might inadvertently expose sensitive data (e.g., API keys, passwords, internal IDs) as metric labels or values, which Prometheus then stores and exposes.

**How Prometheus Contributes:** Prometheus scrapes and stores all exposed metrics without inherent filtering of sensitive data.

**Example:** An application exposes a metric `api_request_duration_seconds` with a label `api_key` containing actual API keys.

**Impact:** Confidentiality breach, potential compromise of other systems if exposed credentials are used elsewhere.

**Risk Severity:** Critical

**Mitigation Strategies:**
* Thoroughly review the metrics being exposed by applications and ensure no sensitive information is included.
* Use relabeling rules in Prometheus to drop or mask sensitive labels or values.
* Implement secure logging practices and avoid including sensitive data in logs that are then exposed as metrics.

