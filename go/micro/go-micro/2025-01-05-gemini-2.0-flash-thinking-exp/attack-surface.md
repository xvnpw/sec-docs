# Attack Surface Analysis for micro/go-micro

## Attack Surface: [Insecure Transport Configuration](./attack_surfaces/insecure_transport_configuration.md)

* **Attack Surface: Insecure Transport Configuration**
    * **Description:** Communication between microservices or between clients and services is not adequately secured, exposing data in transit.
    * **How go-micro Contributes:** `go-micro` allows developers to choose different transports (gRPC, HTTP). If not explicitly configured for security (e.g., using TLS), communication defaults to insecure channels.
    * **Example:** Two microservices communicate using the default gRPC transport without TLS enabled. An attacker on the network can intercept and read the data exchanged between them.
    * **Impact:** Confidential data leakage, potential for data manipulation in transit.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Enforce TLS for all inter-service and client-service communication by configuring `go-micro` transport options.
        * Consider Mutual TLS (mTLS) for stronger authentication between services, leveraging `go-micro`'s mTLS configuration.

## Attack Surface: [Codec Deserialization Vulnerabilities](./attack_surfaces/codec_deserialization_vulnerabilities.md)

* **Attack Surface: Codec Deserialization Vulnerabilities**
    * **Description:** Flaws in the data serialization/deserialization process can be exploited by sending malicious payloads that trigger vulnerabilities in the codec library.
    * **How go-micro Contributes:** `go-micro` uses codecs (like Protocol Buffers, JSON) to serialize and deserialize messages. Vulnerabilities in these codecs or improper handling of deserialization can lead to issues.
    * **Example:** A service using the JSON codec receives a specially crafted JSON payload that exploits a known vulnerability in the underlying JSON parsing library, leading to a denial of service or even remote code execution.
    * **Impact:** Denial of service, remote code execution, information disclosure.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * Use well-vetted and up-to-date codec libraries.
        * Implement input validation *after* deserialization.

## Attack Surface: [Unsecured Broker Communication (for asynchronous messaging)](./attack_surfaces/unsecured_broker_communication__for_asynchronous_messaging_.md)

* **Attack Surface: Unsecured Broker Communication (for asynchronous messaging)**
    * **Description:** Communication with the message broker used for asynchronous communication is not secured, allowing unauthorized access or manipulation of messages.
    * **How go-micro Contributes:** `go-micro` integrates with various message brokers (e.g., NATS, RabbitMQ). If these brokers are not configured with proper authentication and encryption, they become an attack vector within the `go-micro` ecosystem.
    * **Example:** A `go-micro` service uses a NATS broker without authentication. An attacker can connect to the broker and publish malicious messages or consume sensitive data from the queues, impacting the `go-micro` application.
    * **Impact:** Data breaches, message manipulation, unauthorized access to system functionalities within the `go-micro` application.
    * **Risk Severity:** High
    * **Mitigation Strategies:**
        * Enable authentication and authorization on the message broker.
        * Use TLS for communication between `go-micro` services and the message broker.

## Attack Surface: [Registry Manipulation](./attack_surfaces/registry_manipulation.md)

* **Attack Surface: Registry Manipulation**
    * **Description:** The service registry, which `go-micro` uses for service discovery, is compromised, allowing attackers to register malicious services or manipulate existing service entries.
    * **How go-micro Contributes:** `go-micro` relies on a service registry (like Consul, etcd, or Kubernetes DNS) for dynamic service discovery. If this registry is insecure, it directly impacts how `go-micro` services find and interact with each other.
    * **Example:** An attacker gains access to the Consul registry and registers a malicious service with the same name as a legitimate service. When other `go-micro` services attempt to discover and communicate, they are redirected to the attacker's service.
    * **Impact:** Service disruption within the `go-micro` application, man-in-the-middle attacks, potential for data breaches or further system compromise.
    * **Risk Severity:** Critical
    * **Mitigation Strategies:**
        * Secure the service registry with strong authentication and authorization.
        * Use secure communication protocols for `go-micro` services' access to the registry.

