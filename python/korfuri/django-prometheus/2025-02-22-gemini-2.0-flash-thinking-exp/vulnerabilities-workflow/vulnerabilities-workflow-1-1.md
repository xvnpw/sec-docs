## Vulnerability List:

- Vulnerability Name: Unprotected metrics endpoint

- Description:
    - The django-prometheus library exposes a `/metrics` endpoint that, when enabled, provides detailed internal metrics about the Django application.
    - An external attacker can access this endpoint without authentication if it is exposed publicly.
    - By accessing `/metrics`, the attacker can gain insights into the application's performance, internal workings, and potentially sensitive information like database query patterns, cache usage, request rates, and response times.
    - This information can be used for reconnaissance to identify potential vulnerabilities or plan more targeted attacks.
    - To trigger this vulnerability, an attacker simply needs to send an HTTP GET request to the `/metrics` endpoint of a vulnerable Django application.

- Impact: Information Disclosure
    - Exposure of internal application metrics can lead to significant information disclosure.
    - Attackers can use these metrics to understand the application's architecture, identify bottlenecks, and potentially infer business logic.
    - This information can facilitate further attacks, such as identifying slow endpoints for targeted denial-of-service attempts (although DoS vulnerabilities are excluded from this list, the information gathered can still aid in other attack vectors).
    - Sensitive data might be indirectly revealed through metrics, for example, patterns in database queries might reveal data structures or business processes.

- Vulnerability Rank: High

- Currently implemented mitigations: None
    - The django-prometheus library itself does not implement any access control or authentication mechanisms for the `/metrics` endpoint.
    - The provided code and documentation focus on enabling and configuring the metrics export but do not include security considerations for protecting the endpoint.

- Missing mitigations:
    - Access control should be implemented on the `/metrics` endpoint to restrict access to authorized users or systems only.
    - Recommended mitigations include:
        - Implementing Django's permission classes to restrict access to specific users or groups.
        - Using middleware to enforce IP address whitelisting or other forms of authentication.
        - Configuring a reverse proxy (like Nginx or Apache) in front of the Django application to handle authentication and authorization before requests reach the application.
        - Documenting clearly the security implications of exposing the `/metrics` endpoint publicly and providing guidance on implementing access control.

- Preconditions:
    - django-prometheus is installed and enabled in a Django project.
    - The `django_prometheus.urls` are included in the project's `urls.py`, exposing the `/metrics` endpoint.
    - The Django application is deployed and publicly accessible over the internet or an untrusted network.

- Source code analysis:
    - `django_prometheus/urls.py`:
        ```python
        from django.urls import path

        from django_prometheus import exports

        urlpatterns = [path("metrics", exports.ExportToDjangoView, name="prometheus-django-metrics")]
        ```
        This file defines the URL pattern `/metrics` and maps it to the `ExportToDjangoView` view function.
    - `django_prometheus/exports.py`:
        ```python
        def ExportToDjangoView(request):
            """Exports /metrics as a Django view.

            You can use django_prometheus.urls to map /metrics to this view.
            """
            if "PROMETHEUS_MULTIPROC_DIR" in os.environ or "prometheus_multiproc_dir" in os.environ:
                registry = prometheus_client.CollectorRegistry()
                multiprocess.MultiProcessCollector(registry)
            else:
                registry = prometheus_client.REGISTRY
            metrics_page = prometheus_client.generate_latest(registry)
            return HttpResponse(metrics_page, content_type=prometheus_client.CONTENT_TYPE_LATEST)
        ```
        The `ExportToDjangoView` function is responsible for generating the Prometheus metrics. It retrieves the metrics registry and uses `prometheus_client.generate_latest()` to format the metrics for export.
        **Crucially, there is no authentication or authorization logic within this view function or in the URL configuration.** Any request to `/metrics` will be served, regardless of the requester's identity or permissions.
    - Review of other files (`middleware.py`, `models.py`, `db/*`, `cache/*`, `conf/__init__.py`): These files are responsible for collecting and defining the metrics that are exposed. They do not contain any code related to access control for the `/metrics` endpoint.
    - Documentation (`README.md`, `documentation/exports.md`): The documentation guides users on how to enable the `/metrics` endpoint by including `django_prometheus.urls` in their project's `urls.py`. It does not highlight the security implications of publicly exposing this endpoint or provide explicit instructions on how to secure it.

- Security test case:
    1. Deploy a Django application with django-prometheus enabled, ensuring the following configurations are in place:
        - `django_prometheus` is added to `INSTALLED_APPS` in `settings.py`.
        - `django_prometheus.middleware.PrometheusBeforeMiddleware` and `django_prometheus.middleware.PrometheusAfterMiddleware` are added to `MIDDLEWARE` in `settings.py`.
        - `path('prometheus/', include('django_prometheus.urls'))` or `path('', include('django_prometheus.urls'))` is added to `urls.py`.
        - Ensure the application is accessible over the internet or a network from which an attack can be simulated.
    2. As an external attacker, open a web browser or use a tool like `curl` or `wget`.
    3. Access the `/metrics` endpoint of the deployed application. For example, if the application is running at `http://example.com`, access `http://example.com/prometheus/metrics` (if using prefix `prometheus/`) or `http://example.com/metrics` (if using no prefix).
    4. Observe the response. If the vulnerability exists, the server will respond with a large text-based output in Prometheus format, containing various metrics about the Django application.
    5. Examine the content of the metrics output. Confirm that it contains sensitive information such as:
        - Request counts and latencies for different views and methods.
        - Database query counts and durations.
        - Cache hit and miss ratios.
        - Exception counts.
        - Potentially other application-specific metrics if custom metrics are implemented.
    6. Successful retrieval and analysis of these metrics without any authentication confirms the presence of the unprotected metrics endpoint vulnerability.