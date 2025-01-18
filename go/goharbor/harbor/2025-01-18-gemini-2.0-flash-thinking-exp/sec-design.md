# Project Design Document: Harbor - Cloud Native Registry

**Version:** 1.1
**Date:** October 26, 2023
**Author:** AI Software Architect

## 1. Introduction

This document provides an enhanced and more detailed design overview of the Harbor project, an open-source cloud-native registry that stores, signs, and scans container images and other cloud-native artifacts. This document is specifically tailored to serve as a robust foundation for subsequent threat modeling activities, providing a comprehensive understanding of the system's components, architecture, data flows, and deployment considerations.

## 2. Project Overview

Harbor is a trusted, enterprise-class cloud-native registry designed for storing and managing various cloud-native artifacts, including container images, Helm charts, and OCI artifacts. It extends the core functionalities of a standard container registry by incorporating essential enterprise-grade features such as fine-grained role-based access control (RBAC), integrated vulnerability scanning, image signing and content trust, robust replication capabilities, comprehensive auditing, and flexible authentication options.

**Key Features:**

*   **Secure Role-Based Access Control (RBAC):**  Provides granular control over access to projects, repositories, and artifacts.
*   **Vulnerability Scanning Integration:** Supports integration with various vulnerability scanners (e.g., Trivy, Clair) to identify security weaknesses in container images.
*   **Image Signing and Content Trust (using Notary):** Enables the signing of images to ensure their integrity and authenticity, preventing tampering.
*   **Image Replication:** Facilitates the replication of images across multiple Harbor instances for high availability and disaster recovery. Supports various replication modes and filters.
*   **Auditing:** Logs user actions and system events for compliance and security monitoring.
*   **Multiple Authentication Methods:** Supports local user accounts, LDAP/Active Directory integration, and OIDC (OpenID Connect) for seamless integration with existing identity providers.
*   **Web UI:** Offers an intuitive web-based interface for managing projects, repositories, users, and system configurations.
*   **RESTful API:** Provides a comprehensive RESTful API for automation, integration with CI/CD pipelines, and programmatic management.
*   **Garbage Collection:**  Automates the removal of unused image layers and manifests to optimize storage utilization.
*   **Support for Multiple Artifact Types:**  Manages container images, Helm charts, and other OCI (Open Container Initiative) artifacts within the same platform.
*   **Quota Management:** Allows administrators to set storage quotas at the project level.

## 3. Architecture Overview

Harbor employs a microservices-oriented architecture, where distinct components collaborate to deliver its comprehensive feature set. Understanding the interactions between these components is crucial for effective threat modeling.

-   **Core Services:** The central orchestrator responsible for authentication, authorization, project and repository management, API routing, and overall system coordination.
-   **Database (PostgreSQL):**  The persistent data store for metadata related to users, projects, repositories, images, vulnerabilities, replication policies, audit logs, and system configurations.
-   **Registry (Distribution):** The core component based on the Docker Distribution project, handling the actual storage and retrieval of container image layers and manifests. Harbor acts as a secure proxy, enforcing access control policies.
-   **Job Service:**  Manages and executes asynchronous tasks, including image replication, vulnerability scanning jobs, garbage collection, and webhook event processing.
-   **Notary:**  Provides the functionality for signing and verifying the authenticity and integrity of container images, ensuring content trust.
-   **Vulnerability Scanner (Clair/Trivy/Others):** Analyzes container image layers for known security vulnerabilities based on vulnerability databases. Supports pluggable scanner adapters.
-   **UI (User Interface):**  The web-based interface providing a user-friendly way to interact with and manage Harbor.
-   **Log Collector:**  Aggregates logs from all Harbor components into a centralized location for monitoring, analysis, and auditing. Often integrates with external logging systems.
-   **Exporter (Optional):**  Provides metrics in Prometheus format for monitoring Harbor's performance and health.

## 4. Key Components and their Functionality

-   **Core Services:**
    -   **Authentication:** Verifies user credentials against configured authentication backends (local, LDAP, OIDC).
    -   **Authorization:** Enforces RBAC policies to control access to projects, repositories, and operations.
    -   **Project Management:**  Handles the creation, deletion, and management of projects (namespaces).
    -   **Repository Management:** Manages repositories within projects, including creation, deletion, and listing.
    -   **Image Management:**  Provides APIs for managing image tags, manifests, and configurations.
    -   **API Gateway:** Routes incoming API requests to the appropriate internal services.
    -   **Webhook Management:**  Handles the configuration and triggering of webhooks for events within Harbor.
-   **Database (PostgreSQL):**
    -   Stores user accounts, roles, and permissions.
    -   Persists project and repository metadata.
    -   Stores image metadata, including tags, manifests, and associated vulnerabilities.
    -   Maintains replication policies and job execution status.
    -   Stores audit logs of user and system activities.
    -   Stores vulnerability scan reports and metadata.
    -   Stores Notary signing information.
-   **Registry (Distribution):**
    -   **Storage Backend:** Stores container image layers in a content-addressable manner (typically on the local filesystem or cloud storage like S3).
    -   **Push and Pull Handling:**  Receives and processes requests to push and pull container image layers and manifests.
    -   **Manifest Management:**  Handles the storage and retrieval of image manifests, which describe the image layers.
    -   **Blob Management:** Manages the storage and retrieval of individual image layers (blobs).
-   **Job Service:**
    -   **Task Queue:**  Manages a queue of asynchronous tasks to be executed.
    -   **Replication Controller:**  Executes replication jobs based on configured policies, pulling images from source registries and pushing them to target registries.
    -   **Scanner Controller:**  Triggers vulnerability scans for newly pushed images or on a scheduled basis.
    -   **Garbage Collection Controller:**  Identifies and removes unused image layers and manifests.
    -   **Webhook Dispatcher:**  Sends webhook notifications to configured endpoints when events occur in Harbor.
-   **Notary:**
    -   **Signing Service:** Allows image publishers to sign their images using cryptographic keys.
    -   **Verification Service:** Enables clients to verify the signatures of images before pulling, ensuring their integrity and authenticity.
    -   **Metadata Storage:** Stores signature metadata associated with container images.
-   **Vulnerability Scanner (Clair/Trivy/Others):**
    -   **Image Analysis:** Pulls image layers from the Registry and analyzes their contents against known vulnerability databases.
    -   **Vulnerability Reporting:** Generates reports detailing identified vulnerabilities, including severity levels and Common Vulnerabilities and Exposures (CVE) identifiers.
    -   **Scanner Adapter Interface:** Provides a pluggable interface for integrating different vulnerability scanners.
-   **UI (User Interface):**
    -   **Authentication and Authorization:**  Integrates with Core Services for user authentication and authorization.
    -   **Project and Repository Browsing:** Allows users to view and manage projects and repositories.
    -   **Image Management:** Provides tools for viewing image tags, vulnerability scan results, and signing information.
    -   **User and Permission Management:** Enables administrators to manage users, groups, and permissions.
    -   **System Configuration:**  Provides access to configure various Harbor settings, such as authentication methods, replication policies, and vulnerability scanners.
    -   **Monitoring and Logging:** Displays basic system metrics and links to log data.
-   **Log Collector:**
    -   **Log Aggregation:** Collects logs from all Harbor components (Core Services, Registry, Job Service, Notary, Scanner, UI).
    -   **Centralized Storage:** Stores logs in a central location, often using technologies like Fluentd, rsyslog, or the logging capabilities of the deployment platform (e.g., Kubernetes logging).
    -   **Integration with Monitoring Tools:**  Facilitates integration with log analysis and monitoring tools like Elasticsearch and Kibana (EFK stack).
-   **Exporter (Optional):**
    -   **Metrics Collection:** Collects performance and health metrics from Harbor components.
    -   **Prometheus Endpoint:** Exposes metrics in the Prometheus exposition format, allowing Prometheus to scrape and store the data.

## 5. Data Flow

Understanding how data flows through the Harbor system is critical for identifying potential attack vectors and vulnerabilities.

-   **Image Push:**
    -   "User/System" authenticates with "Core Services" via API or UI.
    -   "Core Services" authenticates the user against the configured backend ("Database", LDAP, OIDC).
    -   "Core Services" authorizes the push request based on RBAC policies stored in the "Database".
    -   "User/System" pushes image layers to the "Registry".
    -   "Registry" stores the image layers in the "Image Storage".
    -   "User/System" pushes the image manifest to the "Registry".
    -   "Registry" stores the image manifest in the "Image Storage".
    -   "Core Services" updates image metadata in the "Database".
    -   "Job Service" is notified of the new image.
    -   "Job Service" triggers a vulnerability scan by communicating with the "Vulnerability Scanner".
    -   Optionally, the user can sign the image using "Notary".
-   **Image Pull:**
    -   "User/System" authenticates with "Core Services" via API or UI.
    -   "Core Services" authenticates the user against the configured backend ("Database", LDAP, OIDC).
    -   "Core Services" authorizes the pull request based on RBAC policies stored in the "Database".
    -   "User/System" requests the image manifest from the "Registry".
    -   "Registry" retrieves the manifest from the "Image Storage".
    -   "Registry" returns the manifest to the "User/System".
    -   "User/System" requests image layers from the "Registry".
    -   "Registry" retrieves the requested layers from the "Image Storage".
    -   "Registry" streams the image layers to the "User/System".
    -   Optionally, the user can verify the image signature using "Notary".
-   **Vulnerability Scan:**
    -   "Job Service" schedules or triggers a scan for a specific image.
    -   "Job Service" communicates with the "Vulnerability Scanner" via its API.
    -   "Vulnerability Scanner" pulls the image layers from the "Registry".
    -   "Vulnerability Scanner" analyzes the image layers for vulnerabilities.
    -   "Vulnerability Scanner" reports the scan results to "Core Services".
    -   "Core Services" stores the vulnerability information in the "Database".
    -   Vulnerability information is displayed in the "UI".
-   **User Authentication (UI/API):**
    -   "User" attempts to log in via the "UI" or API.
    -   The request is routed to "Core Services".
    -   "Core Services" authenticates the user against the configured authentication backend ("Database", LDAP, OIDC).
    -   Upon successful authentication, "Core Services" issues a session token or API key.
-   **Replication:**
    -   A replication policy is configured in "Core Services" and stored in the "Database".
    -   "Job Service" periodically checks for images matching the replication policy.
    -   "Job Service" pulls the image from the source Harbor instance's "Registry".
    -   "Job Service" pushes the image to the target Harbor instance's "Registry".
    -   "Core Services" on the target instance updates its metadata in its "Database".

## 6. Deployment Options

The chosen deployment method significantly impacts the security posture of the Harbor instance.

-   **Docker Compose:**
    -   Suitable for development and testing environments.
    -   All components run as Docker containers, typically on a single host.
    -   **Security Considerations:** Network isolation between containers relies on Docker's networking capabilities. Security updates require manual intervention. Single point of failure if the host fails.
-   **Kubernetes:**
    -   Recommended for production deployments, providing scalability, resilience, and self-healing capabilities.
    -   Harbor components are deployed as Kubernetes Deployments, Services, and other resources.
    -   **Security Considerations:** Leverages Kubernetes' security features like Network Policies for network segmentation, RBAC for access control within the cluster, and Secrets management for sensitive data. Requires careful configuration of these features. Benefits from Kubernetes' rolling updates and health checks.
-   **Helm Chart:**
    -   Simplifies deployment and management of Harbor on Kubernetes.
    -   Provides configurable options for customizing the deployment.
    -   **Security Considerations:** Inherits the security considerations of the underlying Kubernetes deployment. Properly configuring the Helm chart values is crucial for security.
-   **Operator:**
    -   A Kubernetes-native method for managing the lifecycle of Harbor deployments, including installation, upgrades, scaling, and backups.
    -   Provides automated management and ensures consistent configuration.
    -   **Security Considerations:**  Relies on the security of the Operator itself. Provides a more opinionated and managed approach to security configuration.

## 7. Security Considerations (Detailed)

This section expands on the high-level security considerations, providing more specific examples and categories relevant for threat modeling.

-   **Authentication and Authorization:**
    -   **Authentication Strength:**  Ensure strong password policies and consider multi-factor authentication (MFA).
    -   **Authorization Granularity:**  Implement fine-grained RBAC to restrict access based on the principle of least privilege.
    -   **API Token Security:** Securely manage and rotate API tokens.
    -   **Session Management:** Implement secure session management practices to prevent session hijacking.
-   **Data Security:**
    -   **Data at Rest Encryption:** Encrypt sensitive data stored in the "Database" and "Image Storage".
    -   **Data in Transit Encryption:** Enforce HTTPS (TLS) for all communication between Harbor components and external clients.
    -   **Secret Management:** Securely store and manage secrets (e.g., database credentials, API keys) using Kubernetes Secrets or dedicated secret management solutions.
-   **Application Security:**
    -   **Input Validation:**  Thoroughly validate all user inputs to prevent injection attacks (e.g., SQL injection, command injection).
    -   **Output Encoding:** Encode output data to prevent cross-site scripting (XSS) vulnerabilities.
    -   **Dependency Management:** Regularly update dependencies to patch known vulnerabilities.
    -   **Vulnerability Scanning:**  Integrate and regularly run vulnerability scans on container images and Harbor components.
    -   **Content Trust:**  Enforce image signing and verification using Notary to ensure image integrity.
-   **Infrastructure Security:**
    -   **Network Segmentation:**  Use network policies or firewalls to restrict network access between Harbor components and external networks.
    -   **Operating System Security:**  Harden the underlying operating system of the hosts running Harbor.
    -   **Container Security:**  Follow container security best practices, such as running containers as non-root users.
    -   **Resource Limits:**  Set appropriate resource limits for containers to prevent resource exhaustion attacks.
-   **Logging and Auditing:**
    -   **Comprehensive Logging:**  Ensure all significant events are logged with sufficient detail.
    -   **Secure Log Storage:**  Store logs securely and protect them from unauthorized access or modification.
    -   **Audit Trail:** Maintain an auditable record of user actions and system events for compliance and security investigations.
-   **Availability and Resilience:**
    -   **High Availability:**  Deploy Harbor in a highly available configuration (e.g., using Kubernetes) to minimize downtime.
    -   **Disaster Recovery:**  Implement backup and recovery procedures for the "Database" and "Image Storage".
    -   **Replication for DR:** Utilize Harbor's replication capabilities for disaster recovery across multiple regions or availability zones.
-   **Rate Limiting:**
    -   Implement rate limiting on API endpoints to prevent denial-of-service (DoS) attacks.

## 8. Diagrams

### 8.1. Detailed Architecture Diagram

```mermaid
graph LR
    subgraph "Harbor Instance"
        direction LR
        A["User/System"] -->|API/UI Requests| B("Core Services");
        B -->|Database Access| C("Database (PostgreSQL)");
        B -->|Registry API| D("Registry (Distribution)");
        B -->|Job Queue/API Calls| E("Job Service");
        B -->|Notary API| F("Notary");
        B -->|Scanner API| G("Vulnerability Scanner (Clair/Trivy/...)");
        D -->|Storage Access| H("Image Storage (Filesystem/Cloud)");
        E -->|Scanner API| G;
        E -->|Registry API (Target)| D_target("Registry (Target Harbor)");
        F -->|Database Access| C;
        G -->|Report Results| B;
        I("Log Collector") -->|Collect Logs| B;
        I -->|Collect Logs| D;
        I -->|Collect Logs| E;
        I -->|Collect Logs| F;
        I -->|Collect Logs| G;
        J("Exporter (Prometheus)") -->|Expose Metrics| B;
        J -->|Expose Metrics| D;
        J -->|Expose Metrics| E;
        B -->|UI Data| K("UI (User Interface)");
    end
    style A fill:#f9f,stroke:#333,stroke-width:2px
```

### 8.2. Enhanced Image Push Data Flow

```mermaid
graph TD
    A["User/System"] -->|Push Request| B("Core Services");
    B -->|Authenticate User| C{Authentication Backend (DB/LDAP/OIDC)};
    C -- "Credentials Verified" --> B;
    B -->|Authorize Push| D("Database (RBAC)");
    D -- "Authorization Granted" --> B;
    B -->|Initiate Blob Upload| E("Registry");
    E -->|Store Blob| F("Image Storage");
    A -->|Upload Blob(s)| E;
    B -->|Initiate Manifest Upload| E;
    A -->|Upload Manifest| E;
    E -->|Store Manifest| F;
    B -->|Update Image Metadata| D;
    B -->|Enqueue Scan Job| G("Job Service");
    G -->|Request Scan| H("Vulnerability Scanner");
    H -->|Pull Layers from Registry| E;
    H -->|Analyze Layers| I("Vulnerability DB");
    H -->|Report Results| B;
    B -->|Store Scan Results| D;
    J["Notary (Optional)"] -- "Sign Image" --> K("Notary Storage");
    style A fill:#ccf,stroke:#333,stroke-width:2px
```

### 8.3. Enhanced Image Pull Data Flow

```mermaid
graph TD
    A["User/System"] -->|Pull Request| B("Core Services");
    B -->|Authenticate User| C{Authentication Backend (DB/LDAP/OIDC)};
    C -- "Credentials Verified" --> B;
    B -->|Authorize Pull| D("Database (RBAC)");
    D -- "Authorization Granted" --> B;
    B -->|Request Manifest| E("Registry");
    E -->|Retrieve Manifest| F("Image Storage");
    E -->|Send Manifest| B;
    B -->|Request Blob(s)| E;
    E -->|Retrieve Blob(s)| F;
    E -->|Send Blob(s)| A;
    G["Notary (Optional)"] -- "Verify Signature" --> H("Notary Storage");
    style A fill:#ddf,stroke:#333,stroke-width:2px
```

## 9. Conclusion

This enhanced design document provides a more granular and comprehensive overview of the Harbor project, specifically tailored for threat modeling purposes. By detailing the architecture, key components, data flows, and deployment options, along with a more in-depth discussion of security considerations, this document serves as a valuable resource for identifying potential vulnerabilities and designing appropriate security mitigations. The included diagrams offer visual aids for understanding the system's complex interactions.