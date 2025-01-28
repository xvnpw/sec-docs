# BUSINESS POSTURE

This project, TiDB, aims to provide a horizontally scalable, distributed SQL database that is compatible with MySQL. The primary business priorities and goals are to offer a database solution that can handle massive amounts of data and high transaction volumes while maintaining strong consistency and ease of use for applications already built for MySQL.

Key business priorities include:
- Scalability:  Enable users to scale their database infrastructure linearly to accommodate growing data and traffic demands without significant application changes.
- High Availability: Ensure continuous database service availability even in the face of hardware failures or network disruptions.
- MySQL Compatibility: Minimize the migration effort for existing MySQL users by providing a high degree of protocol and feature compatibility.
- Performance: Deliver competitive query performance for both transactional and analytical workloads.
- Open Source: Foster a community-driven development model and wider adoption through an open-source license.

Most important business risks that need to be addressed:
- Data Loss: Risk of losing critical business data due to system failures, software bugs, or operational errors.
- Data Breach: Risk of unauthorized access to sensitive data, leading to financial loss, reputational damage, and regulatory penalties.
- Service Disruption: Risk of database downtime impacting business operations, revenue, and customer satisfaction.
- Performance Degradation: Risk of slow query performance affecting application responsiveness and user experience.
- Complexity of Operation: Risk associated with managing a distributed database system, potentially leading to operational errors and increased costs.
- Security Vulnerabilities: Risk of undiscovered security flaws in the database software that could be exploited by attackers.

# SECURITY POSTURE

Existing security controls:
- security control Authentication: TiDB supports various authentication methods including MySQL native authentication, passwordless authentication, and integration with external authentication systems like LDAP and OpenID Connect. Implemented in TiDB Server and PD Server. Described in TiDB documentation.
- security control Authorization: TiDB implements a role-based access control (RBAC) system to manage user permissions and access to database objects. Implemented in TiDB Server and PD Server. Described in TiDB documentation.
- security control Encryption in Transit: TiDB supports TLS encryption for communication between TiDB components and between clients and TiDB. Configurable in TiDB Server, PD Server, TiKV Server, and TiFlash Server. Described in TiDB documentation.
- security control Encryption at Rest: TiDB supports encryption at rest for data stored in TiKV using encryption keys managed by an external Key Management Service (KMS) or locally. Configurable in TiKV Server. Described in TiDB documentation.
- security control Auditing: TiDB provides audit logging to track database activities, including user logins, query execution, and data modifications. Configurable in TiDB Server. Described in TiDB documentation.
- security control SQL Injection Prevention: TiDB uses parameterized queries and input validation techniques to mitigate SQL injection vulnerabilities. Implemented in TiDB Server. Described in TiDB documentation and best practices.
- security control Security Hardening: TiDB components are designed with security hardening in mind, following secure coding practices and minimizing the attack surface. Implemented across all TiDB components. Described in TiDB documentation and security guidelines.
- accepted risk Open Source Nature: Being an open-source project, the source code is publicly accessible, which could potentially expose vulnerabilities to malicious actors. This risk is mitigated by a strong security development lifecycle, active community security reviews, and timely patching.
- accepted risk Complexity of Distributed System: The inherent complexity of a distributed database system can introduce configuration errors or misconfigurations that could lead to security vulnerabilities. This risk is mitigated by comprehensive documentation, automation tools, and best practice guides.

Recommended security controls:
- security control Vulnerability Scanning: Implement automated vulnerability scanning of TiDB components and dependencies to proactively identify and address potential security weaknesses. Integrate with CI/CD pipeline.
- security control Penetration Testing: Conduct regular penetration testing by external security experts to simulate real-world attacks and identify vulnerabilities that may not be caught by automated scanning.
- security control Security Awareness Training: Provide security awareness training to developers, operators, and users of TiDB to promote secure practices and reduce the risk of human error.
- security control Incident Response Plan: Develop and maintain a comprehensive incident response plan to effectively handle security incidents, minimize damage, and ensure timely recovery.
- security control Security Code Review: Implement mandatory security code reviews for all code changes to identify and address security vulnerabilities before they are introduced into production.

Security requirements:
- Authentication:
    - Requirement: Securely authenticate users and applications accessing TiDB.
    - Details: Support strong password policies, multi-factor authentication (MFA) integration, and integration with enterprise identity providers.
- Authorization:
    - Requirement: Implement fine-grained access control to restrict user and application access to only necessary data and operations.
    - Details: Role-based access control (RBAC) with granular permissions on database objects, row-level security, and column-level security.
- Input Validation:
    - Requirement: Validate all user inputs to prevent injection attacks and other input-related vulnerabilities.
    - Details: Implement input sanitization, parameterized queries, and use of prepared statements to prevent SQL injection. Validate data types, formats, and ranges to prevent other types of input manipulation.
- Cryptography:
    - Requirement: Protect sensitive data in transit and at rest using strong encryption algorithms.
    - Details: Use TLS for all network communication between TiDB components and clients. Implement encryption at rest for data stored in TiKV. Support key rotation and secure key management practices.

# DESIGN

## C4 CONTEXT

```mermaid
graph LR
    subgraph "TiDB System"
        center "TiDB"
    end

    u1 "Users"
    u2 "Applications"
    s1 "Monitoring System"
    s2 "Backup System"
    s3 "Cloud Providers"
    s4 "Clients (e.g., MySQL CLI)"

    u1 -- Uses --> center
    u2 -- Uses --> center
    center -- Sends Metrics to --> s1
    center -- Sends Backup Data to --> s2
    center -- Deploys on --> s3
    s4 -- Connects to --> center

    style TiDB fill:#f9f,stroke:#333,stroke-width:2px
```

### Context Diagram Elements

- Element:
    - Name: Users
    - Type: Person
    - Description: Database administrators, developers, and operators who interact with TiDB for management, development, and monitoring purposes.
    - Responsibilities: Manage TiDB clusters, develop applications using TiDB, monitor TiDB performance and health.
    - Security controls: Role-based access control to TiDB management interfaces, strong authentication for administrative access, audit logging of administrative actions.

- Element:
    - Name: Applications
    - Type: Software System
    - Description: Various applications (web applications, microservices, data analytics tools, etc.) that use TiDB as their data storage backend.
    - Responsibilities: Read and write data to TiDB, perform business logic operations using data stored in TiDB.
    - Security controls: Application-level authentication and authorization, secure coding practices to prevent SQL injection, input validation, and secure handling of database credentials.

- Element:
    - Name: Monitoring System
    - Type: Software System
    - Description: External monitoring systems like Prometheus and Grafana used to collect metrics from TiDB and visualize performance and health.
    - Responsibilities: Collect, store, and visualize TiDB metrics, provide alerts for performance issues and anomalies.
    - Security controls: Secure communication channels for metric collection (e.g., TLS), access control to monitoring dashboards, secure storage of monitoring data.

- Element:
    - Name: Backup System
    - Type: Software System
    - Description: Tools like BR (Backup & Restore) and Dumpling used to back up and restore TiDB data for disaster recovery and data protection.
    - Responsibilities: Perform full and incremental backups of TiDB data, restore data from backups in case of failures.
    - Security controls: Secure storage of backup data (encryption at rest), access control to backup data and backup tools, secure transfer of backup data.

- Element:
    - Name: Cloud Providers
    - Type: Infrastructure
    - Description: Cloud platforms like AWS, GCP, and Azure where TiDB can be deployed and run.
    - Responsibilities: Provide infrastructure resources (compute, storage, network) for TiDB deployment, manage underlying infrastructure security.
    - Security controls: Cloud provider security controls (firewalls, network security groups, IAM), secure configuration of cloud resources, compliance certifications of cloud providers.

- Element:
    - Name: Clients (e.g., MySQL CLI)
    - Type: Software System
    - Description: Command-line tools and other clients that connect to TiDB for direct interaction and administration, often using the MySQL protocol.
    - Responsibilities: Execute SQL queries, manage database objects, perform administrative tasks.
    - Security controls: Client-side authentication, secure communication channels (TLS), secure handling of database credentials on client machines.

## C4 CONTAINER

```mermaid
graph LR
    subgraph "TiDB System"
        subgraph "TiDB Server"
            ts("TiDB Server")
        end
        subgraph "PD Server"
            pd("PD Server")
        end
        subgraph "TiKV Server"
            tkv("TiKV Server")
        end
        subgraph "TiFlash Server"
            tf("TiFlash Server")
        end
    end

    u2 "Applications"
    s1 "Monitoring System"
    s2 "Backup System"

    u2 -- SQL Queries --> ts
    ts -- Metadata Requests --> pd
    ts -- Data Read/Write --> tkv
    ts -- Analytical Queries --> tf
    pd -- Cluster Metadata --> tkv
    pd -- Cluster Metadata --> tf
    tkv -- Metrics --> s1
    tf -- Metrics --> s1
    ts -- Metrics --> s1
    pd -- Metrics --> s1
    s2 -- Backup/Restore --> tkv
    s2 -- Backup/Restore --> tf

    style "TiDB System" fill:#ccf,stroke:#333,stroke-width:2px
    style TiDB Server fill:#fcf,stroke:#333,stroke-width:1px
    style PD Server fill:#fcf,stroke:#333,stroke-width:1px
    style TiKV Server fill:#fcf,stroke:#333,stroke-width:1px
    style TiFlash Server fill:#fcf,stroke:#333,stroke-width:1px
```

### Container Diagram Elements

- Element:
    - Name: TiDB Server
    - Type: Container
    - Description: The SQL layer of TiDB, responsible for parsing SQL queries, optimizing query execution plans, and routing requests to the underlying storage layers. It is stateless and horizontally scalable.
    - Responsibilities: SQL query processing, query optimization, transaction management, user authentication and authorization, MySQL protocol compatibility.
    - Security controls: SQL injection prevention, input validation, authentication and authorization mechanisms, TLS encryption for client connections, audit logging of SQL queries and user activities.

- Element:
    - Name: PD Server
    - Type: Container
    - Description: The Placement Driver (PD) server is the cluster manager of TiDB. It is responsible for storing cluster metadata, managing TiKV and TiFlash nodes, and making scheduling decisions for data placement and load balancing.
    - Responsibilities: Cluster metadata management, TiKV and TiFlash node management, data placement and scheduling, leader election, cluster configuration management.
    - Security controls: Access control to PD API, secure storage of cluster metadata, TLS encryption for inter-component communication, authentication for inter-component communication.

- Element:
    - Name: TiKV Server
    - Type: Container
    - Description: TiKV is a distributed key-value storage engine that stores the actual data in TiDB. It is built on top of RocksDB and provides transactional key-value operations with strong consistency.
    - Responsibilities: Data storage and retrieval, transactional key-value operations, data replication for high availability, data encryption at rest, data compaction and garbage collection.
    - Security controls: Encryption at rest, access control to TiKV data, TLS encryption for inter-component communication, data integrity checks.

- Element:
    - Name: TiFlash Server
    - Type: Container
    - Description: TiFlash is a columnar storage extension for TiDB, designed for analytical workloads. It replicates data from TiKV and stores it in a columnar format optimized for fast analytical queries.
    - Responsibilities: Columnar data storage for analytical queries, data replication from TiKV, fast query processing for analytical workloads.
    - Security controls: Access control to TiFlash data, TLS encryption for inter-component communication, data integrity checks, potentially encryption at rest (depending on configuration and version).

## DEPLOYMENT

TiDB can be deployed in various environments, including:
- On-premises (bare metal servers, virtual machines)
- Kubernetes
- Cloud platforms (AWS, GCP, Azure)

For detailed description, we will focus on Kubernetes deployment, which is a common and recommended approach for deploying TiDB in production environments due to its scalability, resilience, and ease of management.

```mermaid
graph LR
    subgraph "Kubernetes Cluster"
        subgraph "Nodes"
            subgraph "Node 1"
                pod1["Pod: tidb-server-0"]
                pod2["Pod: pd-server-0"]
            end
            subgraph "Node 2"
                pod3["Pod: tikv-server-0"]
                pod4["Pod: tiflash-server-0"]
            end
            subgraph "Node 3"
                pod5["Pod: tidb-server-1"]
                pod6["Pod: pd-server-1"]
            end
        end
        svc["Service: tidb-service"]
        ingress["Ingress: tidb-ingress"]
    end
    lb["Load Balancer"]
    users["Users/Applications"]

    users -- Access via --> lb
    lb -- Routes to --> ingress
    ingress -- Routes to --> svc
    svc -- Load Balances to --> pod1 & pod5

    pod1 -- Interacts with --> pod2
    pod1 -- Interacts with --> pod3
    pod1 -- Interacts with --> pod4
    pod2 -- Interacts with --> pod3
    pod2 -- Interacts with --> pod4

    style "Kubernetes Cluster" fill:#efe,stroke:#333,stroke-width:2px
    style Nodes fill:#eee,stroke:#333,stroke-width:1px
    style "Node 1" fill:#eee,stroke:#333,stroke-width:1px
    style "Node 2" fill:#eee,stroke:#333,stroke-width:1px
    style "Node 3" fill:#eee,stroke:#333,stroke-width:1px
    style "Pod: tidb-server-0" fill:#fcf,stroke:#333,stroke-width:1px
    style "Pod: pd-server-0" fill:#fcf,stroke:#333,stroke-width:1px
    style "Pod: tikv-server-0" fill:#fcf,stroke:#333,stroke-width:1px
    style "Pod: tiflash-server-0" fill:#fcf,stroke:#333,stroke-width:1px
    style "Pod: tidb-server-1" fill:#fcf,stroke:#333,stroke-width:1px
    style "Pod: pd-server-1" fill:#fcf,stroke:#333,stroke-width:1px
    style svc fill:#eee,stroke:#333,stroke-width:1px
    style ingress fill:#eee,stroke:#333,stroke-width:1px
    style lb fill:#eee,stroke:#333,stroke-width:1px
```

### Deployment Diagram Elements

- Element:
    - Name: Kubernetes Cluster
    - Type: Infrastructure
    - Description: A Kubernetes cluster provides the container orchestration platform for deploying and managing TiDB.
    - Responsibilities: Container orchestration, resource management, service discovery, scaling, and high availability for TiDB components.
    - Security controls: Kubernetes RBAC, network policies, pod security policies/admission controllers, secrets management, security updates for Kubernetes components.

- Element:
    - Name: Nodes
    - Type: Infrastructure
    - Description: Worker nodes in the Kubernetes cluster that host TiDB pods.
    - Responsibilities: Run TiDB containers, provide compute and storage resources, network connectivity.
    - Security controls: Operating system hardening, security updates, network segmentation, access control to nodes.

- Element:
    - Name: Pods (tidb-server, pd-server, tikv-server, tiflash-server)
    - Type: Container
    - Description: Kubernetes pods encapsulate TiDB containers (TiDB Server, PD Server, TiKV Server, TiFlash Server). Each pod runs one or more TiDB containers and related sidecar containers if needed.
    - Responsibilities: Run individual TiDB components, provide isolated runtime environment, manage container lifecycle.
    - Security controls: Container image security scanning, least privilege container configurations, resource limits, network policies to restrict pod-to-pod communication.

- Element:
    - Name: Service (tidb-service)
    - Type: Network
    - Description: Kubernetes service provides a stable endpoint for accessing TiDB Server pods. It load balances traffic across multiple TiDB Server pods.
    - Responsibilities: Service discovery, load balancing, providing a stable access point for applications.
    - Security controls: Network policies to restrict access to the service, service account security.

- Element:
    - Name: Ingress (tidb-ingress)
    - Type: Network
    - Description: Kubernetes ingress controller manages external access to the TiDB service, typically handling TLS termination and routing based on hostnames or paths.
    - Responsibilities: External access management, TLS termination, routing, load balancing (optional).
    - Security controls: TLS configuration, ingress controller security hardening, access control to ingress configuration.

- Element:
    - Name: Load Balancer
    - Type: Network
    - Description: External load balancer provided by the cloud provider or on-premises infrastructure, distributing traffic to the Kubernetes ingress controller or directly to Kubernetes nodes.
    - Responsibilities: External load balancing, high availability for ingress, DDoS protection (optional).
    - Security controls: Load balancer security configuration, access control to load balancer management, DDoS protection mechanisms.

## BUILD

The TiDB project uses GitHub Actions for its Continuous Integration and Continuous Delivery (CI/CD) pipeline. The build process involves compiling Go code, running tests, building Docker images, and publishing artifacts.

```mermaid
graph LR
    dev["Developer"] --> commit["Git Commit"]
    commit --> github["GitHub Repository"]
    github --> workflow["GitHub Workflow (CI/CD)"]
    subgraph "GitHub Workflow (CI/CD)"
        build["Build Stage (Go Compile, Tests)"] --> scan["Security Scan (SAST, Linters)"]
        scan --> containerize["Containerize (Docker Build)"]
        containerize --> publish["Publish Artifacts (Docker Registry, Binaries)"]
    end
    publish --> artifacts["Build Artifacts (Docker Images, Binaries)"]

    style "GitHub Workflow (CI/CD)" fill:#efe,stroke:#333,stroke-width:2px
    style build fill:#eee,stroke:#333,stroke-width:1px
    style scan fill:#eee,stroke:#333,stroke-width:1px
    style containerize fill:#eee,stroke:#333,stroke-width:1px
    style publish fill:#eee,stroke:#333,stroke-width:1px
```

### Build Diagram Elements

- Element:
    - Name: Developer
    - Type: Person
    - Description: Software developers who write and contribute code to the TiDB project.
    - Responsibilities: Code development, bug fixing, feature implementation, code review.
    - Security controls: Secure coding practices, code review process, access control to code repository, developer workstations security.

- Element:
    - Name: Git Commit
    - Type: Code Change
    - Description: Code changes committed by developers to the Git repository.
    - Responsibilities: Represent code modifications, trigger CI/CD pipeline.
    - Security controls: Commit signing, branch protection, access control to Git repository.

- Element:
    - Name: GitHub Repository
    - Type: Code Repository
    - Description: The central Git repository hosted on GitHub that stores the TiDB source code.
    - Responsibilities: Version control, code collaboration, source code management.
    - Security controls: Access control to repository, branch protection, audit logging of repository activities.

- Element:
    - Name: GitHub Workflow (CI/CD)
    - Type: Automation System
    - Description: GitHub Actions workflows automate the build, test, security scan, and release processes for TiDB.
    - Responsibilities: Automated build, testing, security scanning, containerization, artifact publishing.
    - Security controls: Secure workflow definitions, secrets management for CI/CD pipeline, access control to workflow configurations, audit logging of workflow executions.

- Element:
    - Name: Build Stage (Go Compile, Tests)
    - Type: Build Process
    - Description: Compiles the Go source code of TiDB and runs unit and integration tests to ensure code quality and functionality.
    - Responsibilities: Code compilation, unit testing, integration testing, build artifact generation.
    - Security controls: Dependency management, build environment security, secure build scripts.

- Element:
    - Name: Security Scan (SAST, Linters)
    - Type: Security Tool
    - Description: Static Application Security Testing (SAST) tools and linters are used to automatically scan the codebase for potential security vulnerabilities and code quality issues.
    - Responsibilities: Static code analysis, vulnerability detection, code quality checks.
    - Security controls: Regularly updated security rules and vulnerability databases, secure configuration of scanning tools, vulnerability reporting and tracking.

- Element:
    - Name: Containerize (Docker Build)
    - Type: Build Process
    - Description: Builds Docker images for TiDB components, packaging the compiled binaries and dependencies into container images.
    - Responsibilities: Docker image creation, image tagging, image signing (optional).
    - Security controls: Base image security scanning, minimal container image design, vulnerability scanning of container images, image signing and verification.

- Element:
    - Name: Publish Artifacts (Docker Registry, Binaries)
    - Type: Artifact Repository
    - Description: Publishes the build artifacts, including Docker images to container registries (e.g., Docker Hub, GitHub Container Registry) and binaries to release repositories.
    - Responsibilities: Artifact storage, artifact distribution, versioning, release management.
    - Security controls: Access control to artifact repositories, secure artifact storage, artifact integrity verification, vulnerability scanning of published artifacts.

- Element:
    - Name: Build Artifacts (Docker Images, Binaries)
    - Type: Software Artifacts
    - Description: The final output of the build process, including Docker images and binary distributions of TiDB components.
    - Responsibilities: Deployable software packages for TiDB.
    - Security controls: Vulnerability scanning of artifacts, integrity verification (checksums, signatures).

# RISK ASSESSMENT

Critical business processes we are trying to protect:
- Data Storage and Retrieval: Ensuring the reliable and secure storage and retrieval of business-critical data.
- Transaction Processing: Maintaining the integrity and consistency of transactions, which are fundamental to many business operations.
- Database Availability: Ensuring continuous availability of the database service to support business applications and operations.
- Data Analytics: Providing reliable data for analytical workloads to support business intelligence and decision-making.

Data we are trying to protect and their sensitivity:
- Customer Data: Potentially includes personally identifiable information (PII), contact details, purchase history, and other sensitive customer-related data. Sensitivity: High. Requires strong confidentiality, integrity, and availability controls to comply with privacy regulations (e.g., GDPR, CCPA).
- Financial Data: Transaction records, financial reports, and other financial information. Sensitivity: High. Requires strong confidentiality, integrity, and availability controls to ensure financial accuracy and regulatory compliance.
- Business Operations Data: Data related to internal business processes, supply chain, inventory, and other operational data. Sensitivity: Medium to High. Sensitivity depends on the specific data and its impact on business operations if compromised.
- Application Data: Data generated and used by applications running on TiDB. Sensitivity: Varies. Sensitivity depends on the nature of the application and the data it handles.

# QUESTIONS & ASSUMPTIONS

Questions:
- BUSINESS POSTURE:
    - What are the specific compliance requirements (e.g., GDPR, HIPAA, PCI DSS) that TiDB deployments need to adhere to?
    - What is the target user base for TiDB (e.g., startups, enterprises, specific industries)?
    - What are the key performance indicators (KPIs) for TiDB deployments from a business perspective?
- SECURITY POSTURE:
    - Is there existing security documentation or security policies for TiDB deployments within the organization?
    - What is the frequency of security testing (penetration testing, vulnerability scanning) for TiDB deployments?
    - Is there a dedicated security team responsible for TiDB security?
    - What is the incident response process for security incidents related to TiDB?
- DESIGN:
    - What is the specific deployment environment (cloud provider, on-premises, Kubernetes distribution)?
    - What monitoring tools are currently in use or planned for TiDB deployments?
    - What backup and disaster recovery strategy is planned for TiDB?
    - Are there specific network security requirements or constraints for TiDB deployments?

Assumptions:
- BUSINESS POSTURE:
    - TiDB is intended for production use and will handle sensitive business data.
    - High availability and data durability are critical business requirements.
    - Compliance with industry security standards and regulations is important.
- SECURITY POSTURE:
    - Basic security controls like authentication, authorization, and encryption are expected to be implemented.
    - Security is a high priority for TiDB deployments.
    - Regular security updates and patching will be applied.
- DESIGN:
    - Kubernetes is a likely deployment platform for production environments.
    - Standard monitoring and logging practices will be implemented.
    - Backup and restore procedures will be in place.
    - Network security measures (firewalls, network segmentation) will be used to protect TiDB deployments.