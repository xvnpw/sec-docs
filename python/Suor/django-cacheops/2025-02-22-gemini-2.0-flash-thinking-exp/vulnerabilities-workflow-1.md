Here is the combined list of vulnerabilities, formatted in markdown as requested:

### Vulnerability List

- **Vulnerability Name:** Insecure Deserialization via Pickle Serializer
  **Description:**
    1. The project uses Python’s built‑in pickle module as the default serializer (configured in the cacheops settings and used in functions such as `settings.CACHEOPS_SERIALIZER.loads` in multiple modules).
    2. If an attacker can inject arbitrary data into the cache (for example, by exploiting a misconfigured or externally accessible Redis instance), the application will deserialize that data without validation.
    3. An attacker could craft a malicious pickle payload so that when it is loaded, arbitrary code is executed in the application’s process.
  **Impact:**
    - An attacker who successfully injects a malicious payload may achieve remote code execution.
    - This can compromise the entire host.
    - It can lead to the theft of sensitive data.
    - It can allow tampering with application behavior.
  **Vulnerability Rank:** Critical
  **Currently Implemented Mitigations:**
    - Redis connection calls are wrapped by a generic “handle_connection_failure” decorator that catches connection problems, but no serialization‐level sanitization is in place.
    - The default configuration sets `CACHEOPS_SERIALIZER` to “pickle” without additional safeguards.
  **Missing Mitigations:**
    - Use a safe serializer (e.g., JSON) or an explicitly secured serializer in production.
    - Enforce that the cache store (Redis) is only accessible from trusted backends by requiring authentication and binding to localhost (or another secure interface).
  **Preconditions:**
    - The Redis instance must be misconfigured to be accessible externally and allow unauthenticated writes.
    - The application must use the default pickle serializer.
    - An attacker must be able to inject a crafted payload into the cache.
  **Source Code Analysis:**
    - In **/code/cacheops/serializers.py**, the `PickleSerializer` simply wraps `pickle.dumps` and `pickle.loads`.
    - In **/code/cacheops/conf.py**, the default `CACHEOPS_SERIALIZER` is set to the string “pickle”.
    - In several modules (e.g., **/code/cacheops/getset.py**), data read from Redis is processed using `settings.CACHEOPS_SERIALIZER.loads`.
    - This creates a deserialization “sink” that can be exploited if an attacker controls the stored data.
  **Security Test Case:**
    1. Identify or simulate a scenario where Redis is accessible with no authentication (for example, by overriding the `CACHEOPS_REDIS` settings).
    2. Using a Redis client, inject a malicious pickle payload under a key that the application would later read. For example, craft a pickle object that runs an arbitrary command when deserialized.
    3. Trigger a cache read from the application (via an HTTP GET request that causes a query cache hit).
    4. Verify that the payload is executed (for example, by checking for file creation or other side effects).

---

- **Vulnerability Name:** Insecure Redis Configuration Allowing External Access
  **Description:**
    1. The Redis connection settings (from **/code/tests/settings.py**) default to connecting to “127.0.0.1” on port 6379 without specifying a password.
    2. Although “127.0.0.1” is a localhost address, if—through misconfiguration or container/network setup—Redis becomes exposed on a public interface, an attacker will be able to connect without credentials.
    3. This exposure, in conjunction with the use of the insecure pickle serializer, significantly increases the risk that an attacker may modify cache entries or inject malicious payloads.
  **Impact:**
    - If an attacker gains direct access to Redis, they can poison the cache (inject malicious serialized objects).
    - This can result in arbitrary code execution upon deserialization.
    - It can lead to interference with application data integrity.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
    - The default configuration enforces “127.0.0.1” as the host if no `REDIS_HOST` environment variable is provided.
    - However, no authentication (password) or additional network restrictions are enforced by code.
  **Missing Mitigations:**
    - Configure Redis to require authentication and restrict its network exposure (bind only to localhost or use proper firewall rules).
    - Consider using TLS to secure connections if Redis must be accessible over a network.
  **Preconditions:**
    - The Redis instance is misconfigured to be publicly accessible (for example, if environment variables override the defaults so that Redis binds to 0.0.0.0).
    - No password is required for Redis access.
  **Source Code Analysis:**
    - In **/code/tests/settings.py**, the `CACHEOPS_REDIS` setting is defined as:
      ```python
      {'host': os.getenv('REDIS_HOST') or '127.0.0.1', 'port': 6379, 'db': 13, 'socket_timeout': 3}
      ```
    - There is no password parameter, meaning that if an attacker can route to Redis, no barrier prevents access.
  **Security Test Case:**
    1. Verify (in a test environment) that Redis is accessible from a remote machine (simulate misconfiguration by binding Redis to a public IP address).
    2. Connect using a standard Redis client (e.g. `redis-cli`) without supplying a password.
    3. Attempt to read keys (including those used by cacheops) and modify or inject a malicious cache entry.
    4. Confirm that these operations succeed, demonstrating the insecure configuration.

---

- **Vulnerability Name:** Conjunctive Key Injection
  **Description:**
    1. An attacker can create or modify a database record in a Django model that is cached by Cacheops.
    2. The fields of this model are used to generate a conjunctive key for cache invalidation.
    3. If a field value contains special characters like '=' or '&', these characters are not properly escaped when constructing the conjunctive key in the Lua script `invalidate.lua`.
    4. This allows an attacker to inject additional conditions or manipulate the conjunctive key structure.
    5. When the `invalidate_dict` function is called (e.g., on model save or delete), the Lua script `invalidate.lua` will generate incorrect conjunctive keys based on the injected characters.
    6. This can lead to unexpected cache invalidation behavior, potentially causing cache invalidation bypass or incorrect invalidation.
  **Impact:**
    - Cache invalidation bypass: An attacker might be able to manipulate data in such a way that associated cache entries are not properly invalidated, leading to serving stale data.
    - Cache poisoning: Although less direct, incorrect invalidation could in some scenarios contribute to cache poisoning by making it harder to manage cache consistency.
    - Information disclosure (indirect): Serving stale data could indirectly lead to information disclosure if outdated information is presented to users due to cache invalidation failures.
  **Vulnerability Rank:** High
  **Currently Implemented Mitigations:**
    - None. The code does not currently escape or sanitize field names or values before constructing conjunctive keys in Lua.
  **Missing Mitigations:**
    - **Input Sanitization/Escaping:** In the Lua script `invalidate.lua`, properly escape or encode field names and values before concatenating them to form conjunctive keys. A robust approach would be to use URL-encoding or a similar mechanism to ensure that '=' and '&' characters within field names or values are treated as literal characters and not as delimiters in the conjunctive key structure. Alternatively, consider using a more structured data format (like JSON within Redis sets) for conjunctive keys instead of simple string concatenation.
  **Preconditions:**
    - Cacheops is enabled and caching Django models.
    - An attacker has the ability to create or modify records in a model that is being cached.
  **Source Code Analysis:**
    1. `/code/cacheops/invalidation.py:invalidate_dict`: This function calls `load_script('invalidate')` and passes `model._meta.db_table` and `json.dumps(obj_dict, default=str)` as arguments to the Lua script. The `obj_dict` contains model field names and values.
    2. `/code/cacheops/lua/invalidate.lua:generate_conjs`: This Lua function constructs conjunctive keys by iterating through the `obj_dict` and concatenating `field .. '=' .. value` with '&' as a separator. There is no escaping or encoding of `field` or `value` before concatenation.
    3. **Vulnerable Code Snippet (`/code/cacheops/lua/invalidate.lua`):**
    ```lua
    local function generate_conjs(obj_dict, prefix, table)
        local conjs = {}
        local conj_parts = {}
        for field, value in pairs(obj_dict) do
            table.insert(conj_parts, field .. '=' .. value)
        end
        table.sort(conj_parts)
        table.insert(conjs, table.concat(conj_parts, '&'))
        return conjs
    end
    ```
    4. **Vulnerability:** The `generate_conjs` function in `invalidate.lua` directly concatenates field names and values with `=` and `&` without any encoding. If a field value contains these characters, it can lead to the creation of malformed conjunctive keys, causing incorrect cache invalidation.
  **Security Test Case:**
    1. **Setup:**
        - Define a Django model in `tests/models.py`:
        ```python
        class VulnerableModel(models.Model):
            data = models.CharField(max_length=255)
        ```
        - Add Cacheops configuration in `tests/settings.py` to cache `VulnerableModel`:
        ```python
        CACHEOPS = {
            'tests.vulnerablemodel': {'ops': 'all', 'timeout': 60},
            'tests.*': {},
            'auth.*': {},
        }
        ```
        - Create a test case in `tests/tests.py`:
        ```python
        class ConjunctiveKeyInjectionTest(BaseTestCase):
            def test_conjunctive_key_injection(self):
                from .models import VulnerableModel

                # Create and cache an object with a safe value
                safe_obj = VulnerableModel.objects.create(data="safe_value")
                list(VulnerableModel.objects.cache().filter(data="safe_value")) # Cache it

                # Create an object with a malicious value containing '&' and '='
                malicious_obj = VulnerableModel.objects.create(data="malicious=value&extra=condition")

                # Trigger invalidation by saving the malicious object (or could be delete)
                malicious_obj.save()

                # Attempt to retrieve the originally cached safe object.
                # If injection is successful, the cache for 'safe_value' might be incorrectly invalidated.
                with self.assertNumQueries(1): # Expect cache miss due to potential incorrect invalidation
                    list(VulnerableModel.objects.cache().filter(data="safe_value"))
        ```
    2. **Run Test:** Execute the test case.
    3. **Expected Result:** The test `test_conjunctive_key_injection` should fail, showing that when the malicious object is saved, it incorrectly invalidates the cache for the safe object due to the conjunctive key injection vulnerability. The `assertNumQueries(1)` should actually result in more queries (0) if the cache was correctly used, indicating a cache miss and thus incorrect invalidation.