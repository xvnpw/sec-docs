**Vulnerability Name:** Unsafe Deserialization via PickleSerializer

- **Description:**  
  The package uses a serializer based on Python’s built‐in pickle protocol by default (see the class `PickleSerializer` in *django_redis/serializers/pickle.py*). Its `loads` method directly calls `pickle.loads(value)` on data retrieved from the cache without any additional verification. An external attacker who can either directly access the Redis instance or poison the cache (for example, by injecting specially crafted payloads via an untrusted input channel) can supply a malicious pickle payload. When that payload is later retrieved by the application (for example, via a regular cache lookup using methods like `get()` in *django_redis/client/default.py*), the unsafe deserialization process will execute the embedded object’s malicious code, potentially resulting in remote code execution and complete compromise of the hosting server.

- **Impact:**  
  An attacker who can inject a malicious serialized payload into the Redis cache could force the application to execute arbitrary code. This may lead to remote code execution, data leakage, full system takeover, and lateral movement within the network.

- **Vulnerability Rank:** Critical

- **Currently Implemented Mitigations:**  
  - The project itself does not enforce a safe serialization strategy by default.  
  - It allows configuration of an alternative serializer via the `SERIALIZER` option (for example choosing JSON or msgpack) but the default remains the pickle-based serializer.

- **Missing Mitigations:**  
  - The package does not enforce or recommend a safer default like JSON serialization that avoids arbitrary code execution.  
  - There is no built-in check (or signature/validation mechanism) to ensure that data being deserialized comes only from trusted sources.  
  - No runtime warning or flag is raised when using pickle in environments where the Redis instance might be accessible to untrusted actors.

- **Preconditions:**  
  - The Redis cache must be reachable by an external attacker (for example, if it is misconfigured or exposed on a public network without proper authentication/firewalling).  
  - The application must store data that could later be influenced by external input (i.e. allow cache poisoning) or be running in an environment where input from untrusted sources is used as cache content.
  
- **Source Code Analysis:**  
  - In *django_redis/serializers/pickle.py*, the `PickleSerializer` class defines:
    - `dumps(value)` which calls `pickle.dumps(value, self._pickle_version)`.
    - `loads(value)` which directly calls `pickle.loads(value)`.
  - In *django_redis/client/default.py* (and similarly in other parts of the client code), when a cache value is fetched the following occurs:  
    1. The raw data is obtained from the underlying Redis connection.  
    2. The data is passed to a call such as `self._serializer.loads(value)` (after possible decompression).  
    3. Since no additional validation is done, any malicious payload stored in Redis will be deserialized blindly.
  - If an attacker can inject a crafted payload into Redis, then during a normal `get()` call (which does not perform any signature or safe-guard checks) the unsafe deserialization is triggered.

- **Security Test Case:**  
  1. **Setup:**  
     - Deploy the application using the default configuration so that the cache backend uses the `PickleSerializer`.  
     - Ensure that the Redis instance is accessible to an external attacker (simulate this in a test environment).  
  2. **Payload Creation:**  
     - Create a benign—but clearly non‐native—pickle payload that, when deserialized, performs an observable action (for example, writing a known message to a file or modifying a global flag). A safe test payload can be constructed using Python’s `pickle` module in a controlled environment.
  3. **Injection:**  
     - Manually insert the malicious pickle payload into the Redis store under a key that the application later retrieves. This could be done by using a Redis command line client or a simple script. For example:
       - Connect to Redis and set a key (matching the application’s key format) with the crafted payload.
  4. **Trigger:**  
     - Cause the application to call its normal cache retrieval method (for example, by visiting a URL that in turn calls `cache.get("target_key")`).
  5. **Verification:**  
     - Verify that the payload is deserialized and that the observable action takes place (for example, check that the file was created or the flag was modified).  
     - If the payload executes, this demonstrates that malicious pickle payloads are being deserialized without proper safeguards.

---

_Recommendation:_  
Administrators should consider configuring a safer serializer (such as JSON or MSGPack) via the `SERIALIZER` option when using django-redis in environments with any possibility of external attacker access to the cache. In addition, ensure that the Redis instance is properly secured (e.g. bound to internal networks and protected by strong authentication) to minimize the risk of cache poisoning attacks.

This vulnerability is critical due to its potential to allow remote code execution and complete system compromise if both preconditions are met.