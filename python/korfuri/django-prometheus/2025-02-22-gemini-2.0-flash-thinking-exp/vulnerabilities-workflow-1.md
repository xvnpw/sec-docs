## Combined Vulnerability List:

### Unprotected Metrics Endpoint

- **Description:**
    - The django-prometheus library, when enabled in a Django project, exposes a `/metrics` endpoint by default through its `django_prometheus.urls`.
    - This endpoint, implemented in `django_prometheus.exports.ExportToDjangoView`, is designed to provide detailed internal metrics about the Django application in Prometheus format.
    - An external, unauthenticated attacker can access this endpoint simply by sending an HTTP GET request to the `/metrics` path of the deployed application.
    - Upon accessing `/metrics`, the application responds with a large text-based output containing a wide range of operational metrics. This includes sensitive information such as:
        - HTTP request and response counts
        - Response latencies for different views and methods
        - Database query counts and durations
        - Cache hit and miss ratios
        - Exception counts
        - Potentially custom application-specific metrics
    - This publicly accessible metrics data allows attackers to gain significant insights into the application's performance, internal architecture, and operational characteristics, which can be leveraged for reconnaissance and planning further attacks.

    - *Triggering Steps:*
        1. Deploy a Django application with `django-prometheus` enabled, ensuring `django_prometheus.urls` are included in the project's `urls.py` to expose the `/metrics` endpoint.
        2. Ensure the deployed application is accessible over the internet or an untrusted network.
        3. As an external attacker, use a web browser or a command-line tool like `curl` or `wget` to send a GET request to the `/metrics` endpoint of the application (e.g., `http://<target-host>/metrics`).
        4. Observe the HTTP response, which should contain a large text output in Prometheus format, filled with various application metrics.

- **Impact:** Information Disclosure
    - The primary impact of this vulnerability is information disclosure. By exposing internal application metrics without authentication, the application reveals sensitive operational details to unauthorized parties.
    - This disclosed information can be used by attackers to:
        - **Fingerprint the system:** Understand the application's technology stack, architecture, and dependencies.
        - **Identify performance bottlenecks:** Pinpoint slow endpoints or resource-intensive operations.
        - **Infer business logic:** Deduce application behavior and data structures from query patterns and usage metrics.
        - **Detect abnormal error patterns:** Recognize unusual error rates or performance degradations that could indicate vulnerabilities or ongoing attacks.
        - **Plan further attacks:** Utilize gathered intelligence to target specific weaknesses or plan more sophisticated attacks, although DoS is out of scope, information can aid in other attack vectors.
    - The exposure of these internal details significantly aids attackers in reconnaissance, increasing the risk of further compromise of the application and its underlying infrastructure.

- **Vulnerability Rank:** High

- **Currently implemented mitigations:** None
    - The django-prometheus library, in its default configuration, does not implement any access control, authentication, or authorization mechanisms for the `/metrics` endpoint.
    - The provided code and documentation focus solely on enabling and configuring metrics export, without addressing the security implications of public exposure.
    - The endpoint is directly mapped to a Django view function (`ExportToDjangoView`) that generates and returns metrics data to any unauthenticated request.

- **Missing mitigations:**
    - **Implement Access Control:** Access to the `/metrics` endpoint must be restricted to authorized users or systems only.
    - **Recommended Mitigations:**
        - **Django Permission Classes:** Utilize Django's built-in permission classes to restrict access to the `ExportToDjangoView` based on user authentication and authorization.
        - **Middleware Authentication/Authorization:** Implement custom middleware to enforce authentication (e.g., API key, basic auth) or authorization (e.g., IP address whitelisting) before requests reach the `ExportToDjangoView`.
        - **Reverse Proxy Authentication:** Configure a reverse proxy (like Nginx or Apache) in front of the Django application to handle authentication and authorization, filtering requests to the `/metrics` endpoint before they reach the application server.
        - **Configuration Options:** Provide configuration settings to easily enable or disable the `/metrics` endpoint and to integrate custom authentication/authorization mechanisms.
        - **Security Documentation:** Clearly document the security implications of exposing the `/metrics` endpoint publicly and provide explicit guidance and best practices on how to secure it in production deployments.

- **Preconditions:**
    - django-prometheus is installed and enabled in a Django project.
    - `django_prometheus` is added to `INSTALLED_APPS` in `settings.py`.
    - `django_prometheus.middleware.PrometheusBeforeMiddleware` and `django_prometheus.middleware.PrometheusAfterMiddleware` are included in `MIDDLEWARE` in `settings.py`.
    - The `django_prometheus.urls` are included in the project's `urls.py`, typically using `path('', include('django_prometheus.urls'))` or similar, which exposes the `/metrics` endpoint at `/metrics` (or under a specified prefix).
    - The Django application is deployed and publicly accessible over the internet or an untrusted network, allowing external access to the `/metrics` endpoint.

- **Source code analysis:**
    - **`django_prometheus/urls.py`:**
        ```python
        from django.urls import path
        from django_prometheus import exports

        urlpatterns = [path("metrics", exports.ExportToDjangoView, name="prometheus-django-metrics")]
        ```
        This code snippet from `django_prometheus/urls.py` defines the URL pattern for the metrics endpoint. It maps the path `/metrics` to the `ExportToDjangoView` function, which is responsible for serving the metrics. Notably, there are no authentication or authorization mechanisms implemented directly within these URL configurations.

    - **`django_prometheus/exports.py`:**
        ```python
        from django.http import HttpResponse
        from prometheus_client import multiprocess, generate_latest, CollectorRegistry
        import os

        def ExportToDjangoView(request):
            """Exports /metrics as a Django view."""
            if "PROMETHEUS_MULTIPROC_DIR" in os.environ or "prometheus_multiproc_dir" in os.environ:
                registry = CollectorRegistry()
                multiprocess.MultiProcessCollector(registry)
            else:
                registry = prometheus_client.REGISTRY
            metrics_page = generate_latest(registry)
            return HttpResponse(metrics_page, content_type=prometheus_client.CONTENT_TYPE_LATEST)
        ```
        The `ExportToDjangoView` function in `django_prometheus/exports.py` is the core of the vulnerability. This function retrieves metrics from the Prometheus registry and returns them directly in an `HttpResponse`.
        - **Absence of Authentication:**  Crucially, there is no code within `ExportToDjangoView` or in the URL configuration in `urls.py` that performs any authentication or authorization checks on the incoming request.
        - **Direct Metric Exposure:** The function directly calls `generate_latest(registry)` to format the metrics and returns them. Any request reaching this view will successfully receive the metrics data, regardless of the requester's identity or permissions.
        - **Code Flow Visualization:**
            ```mermaid
            graph LR
                A[Incoming Request to /metrics] --> B(urls.py: path("metrics", ExportToDjangoView));
                B --> C(exports.py: ExportToDjangoView(request));
                C --> D{Authentication/Authorization?};
                D -- No --> E[Collect Metrics from Registry];
                E --> F[Generate Metrics Page];
                F --> G[HttpResponse with Metrics];
                G --> H[Response to Attacker];
                D -- Yes --> I[Access Denied];
                I --> J[403/401 Response];
            ```
            The diagram illustrates the request flow. The critical point is the missing "Authentication/Authorization?" step, leading directly to metric collection and response generation for any incoming request.

    - **Review of other files and documentation:**  Analysis of other files within the `django-prometheus` library (middleware, models, database/cache integrations, configuration) and documentation (README, export documentation) confirms that there are no built-in features or warnings related to securing the `/metrics` endpoint. The documentation focuses on enabling and using the endpoint, not securing it.

- **Security test case:**
    1. **Environment Setup:** Deploy a Django application with `django-prometheus` enabled in a publicly accessible environment (e.g., development server exposed to the internet or a staging/production deployment). Ensure the application is configured as follows:
        - `django_prometheus` is added to `INSTALLED_APPS` in `settings.py`.
        - `django_prometheus.middleware.PrometheusBeforeMiddleware` and `django_prometheus.middleware.PrometheusAfterMiddleware` are added to `MIDDLEWARE` in `settings.py`.
        - `path('', include('django_prometheus.urls'))` (or similar inclusion of `django_prometheus.urls`) is present in the project's `urls.py`.
    2. **Attacker Action - Access Metrics Endpoint:** As an external attacker, open a web browser or use a command-line tool like `curl` to access the `/metrics` endpoint of the deployed application. For example, if the application is hosted at `http://example.com`, access `http://example.com/metrics`.
        ```bash
        curl http://example.com/metrics
        ```
    3. **Observe Response:** Examine the HTTP response received from the server.
    4. **Verify Metrics Data:** Confirm that the response is a large text output in Prometheus format. Inspect the content and verify that it contains detailed metrics about the Django application, including but not limited to:
        - `django_http_requests_total` (Request counts)
        - `django_http_latency_seconds_bucket` (Request latencies)
        - `django_db_query_total` (Database query counts)
        - `django_cache_hits_total`, `django_cache_misses_total` (Cache statistics)
        - `django_exceptions_total` (Exception counts)
        - Potentially custom application metrics if implemented.
    5. **Authentication Bypass Confirmation:** Verify that the metrics data was successfully retrieved without any authentication prompt, login requirement, or access restriction. The successful retrieval of metrics data without authentication confirms the presence of the unprotected metrics endpoint vulnerability.