# Threat Model Analysis for apollographql/apollo-android

## Threat: [Cache Poisoning](./threats/cache_poisoning.md)

**Description:** An attacker compromises the GraphQL server or performs a man-in-the-middle attack to inject malicious GraphQL responses. Apollo Android's caching mechanism stores this poisoned data. When the application retrieves data from the cache, it receives the malicious data. An attacker might manipulate data displayed to the user, cause application malfunction, or potentially exploit vulnerabilities if the poisoned data is processed unsafely by the application.
**Impact:** Data corruption, application malfunction, potential exploitation leading to unauthorized actions or information disclosure.
**Affected Apollo Android Component:** `ApolloClient` caching mechanism, specifically the `normalized cache` or `http cache` depending on configuration.
**Risk Severity:** High
**Mitigation Strategies:**
* Implement robust server-side input validation and sanitization.
* Utilize cache invalidation strategies to refresh data regularly.
* Implement client-side data validation after cache retrieval.
* Enforce HTTPS to prevent man-in-the-middle attacks.

## Threat: [Insecure Deserialization of GraphQL Responses](./threats/insecure_deserialization_of_graphql_responses.md)

**Description:** An attacker crafts malicious GraphQL responses designed to exploit deserialization vulnerabilities in Apollo Android's underlying libraries (e.g., Gson, Moshi). If successful, this could lead to remote code execution on the user's device.
**Impact:** Remote code execution, complete compromise of the application and potentially the device.
**Affected Apollo Android Component:**  Data parsing and deserialization within `ApolloClient`, potentially related to libraries like Gson or Moshi used for JSON processing.
**Risk Severity:** Critical
**Mitigation Strategies:**
* Keep Apollo Android and its dependencies updated to the latest versions.
* Monitor for and promptly address any reported deserialization vulnerabilities in used libraries.
* Implement strong server-side input validation to prevent malicious data from reaching the client.

