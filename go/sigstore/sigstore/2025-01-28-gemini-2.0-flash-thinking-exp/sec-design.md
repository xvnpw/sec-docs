# BUSINESS POSTURE

The Sigstore project aims to improve the security of the software supply chain by providing free and easy-to-use code signing and verification tools. The primary business priority is to increase trust and transparency in software distribution, making it harder for malicious actors to inject compromised software into the supply chain. This is crucial for both software developers and consumers.

- Business priorities:
 - Increase adoption of code signing across the software ecosystem.
 - Provide a free and open-source solution for code signing and verification.
 - Enhance trust in software provenance and integrity.
 - Reduce the risk of software supply chain attacks.

- Business goals:
 - Establish Sigstore as a widely adopted standard for code signing.
 - Create a robust and reliable infrastructure for signing and verification.
 - Foster a community around secure software supply chain practices.
 - Integrate Sigstore with popular development tools and platforms.

- Most important business risks:
 - Risk of slow adoption if the system is too complex or difficult to use.
 - Risk of vulnerabilities in Sigstore infrastructure itself being exploited, undermining trust.
 - Risk of key compromise in Sigstore's root of trust.
 - Risk of dependency on external services (like OIDC providers and transparency logs) impacting availability.
 - Risk of misuse of the system by malicious actors if not properly secured.

# SECURITY POSTURE

- Security control: Secure software development lifecycle (SSDLC) is likely followed by the Sigstore project, given its security-sensitive nature. This includes practices like threat modeling, security code reviews, and vulnerability scanning. (Location: Project documentation and development practices, not explicitly stated in the provided input but assumed for a security-focused project).
- Security control: Use of GitHub for source code management, which provides access control, audit logging, and vulnerability scanning capabilities. (Location: GitHub repository itself).
- Security control: Automated testing and CI/CD pipelines are likely in place to ensure code quality and security. (Location: GitHub Workflows in the repository).
- Security control: Public transparency logs (Rekor and CTLog) are used to record signing events, providing auditability and non-repudiation. (Location: Sigstore architecture documentation).
- Security control: Reliance on established OIDC providers for identity verification, leveraging their existing security infrastructure. (Location: Sigstore architecture documentation).

- Accepted risk: Dependence on the security of external OIDC providers. If an OIDC provider is compromised, it could potentially impact Sigstore.
- Accepted risk: Initial adoption phase might expose unforeseen vulnerabilities as the system is used at scale.
- Accepted risk: Complexity of the system might lead to configuration errors or misconfigurations by users.

- Recommended security controls:
 - Security control: Implement regular penetration testing and security audits by external security experts.
 - Security control: Establish a formal incident response plan to handle security incidents effectively.
 - Security control: Implement rate limiting and abuse prevention mechanisms to protect against denial-of-service attacks and misuse.
 - Security control: Enhance monitoring and logging of Sigstore components for security-relevant events.
 - Security control: Provide comprehensive security guidelines and best practices for users of Sigstore tools.

- Security requirements:
 - Authentication:
  - Requirement: Users (developers and systems) interacting with Sigstore for signing and verification must be strongly authenticated.
  - Requirement: Sigstore components must authenticate each other when communicating.
  - Requirement: Leverage existing identity providers (OIDC) for user authentication where possible.
 - Authorization:
  - Requirement: Access to signing keys and signing operations must be strictly authorized based on roles and policies.
  - Requirement: Verification processes must ensure that only authorized signatures are accepted.
  - Requirement: Access to audit logs and transparency logs should be restricted to authorized personnel.
 - Input validation:
  - Requirement: All inputs to Sigstore components (e.g., code artifacts, signatures, metadata) must be thoroughly validated to prevent injection attacks and other input-related vulnerabilities.
  - Requirement: Input validation should be performed at multiple layers of the system.
  - Requirement: Use secure coding practices to avoid common input validation errors.
 - Cryptography:
  - Requirement: Use strong cryptographic algorithms and protocols for signing, verification, and secure communication.
  - Requirement: Properly manage cryptographic keys, including secure generation, storage, and rotation.
  - Requirement: Adhere to cryptographic best practices and standards.
  - Requirement: Ensure cryptographic operations are performed in a secure environment.

# DESIGN

## C4 CONTEXT

```mermaid
flowchart LR
    subgraph "Software Developer"
        A[Software Developer]
    end
    subgraph "Package Manager"
        B[Package Manager]
    end
    subgraph "Sigstore Project"
        C[Sigstore System]
    end
    subgraph "OIDC Provider"
        D[OIDC Provider]
    end
    subgraph "Transparency Log (Rekor)"
        E[Transparency Log (Rekor)]
    end
    subgraph "Certificate Transparency Log (CTLog)"
        F[Certificate Transparency Log (CTLog)]
    end
    A -->|Signs software artifacts| C
    C -->|Verifies signatures| B
    A -->|Authenticates identity| D
    C -->|Retrieves identity information| D
    C -->|Logs signing events| E
    C -->|Logs certificate information| F
    B -->|Verifies signatures| C
    style C fill:#f9f,stroke:#333,stroke-width:2px
```

- Context Diagram Elements:
 - Element:
  - Name: Software Developer
  - Type: Person
  - Description: Developers who build and sign software artifacts using Sigstore tools.
  - Responsibilities: Develop software, sign software artifacts using Sigstore, and publish signed artifacts to package managers or distribution channels.
  - Security controls: Local key management, secure development environment, adherence to signing best practices.
 - Element:
  - Name: Package Manager
  - Type: Software System
  - Description: Systems that distribute software packages, such as npm, PyPI, Maven Central, container registries, etc. They integrate with Sigstore to verify signatures.
  - Responsibilities: Distribute software packages, verify Sigstore signatures before installation or use, and potentially display signature verification status to users.
  - Security controls: Signature verification logic, secure storage of software packages, access control to package repositories.
 - Element:
  - Name: Sigstore System
  - Type: Software System
  - Description: The core Sigstore infrastructure, providing services for signing, verification, certificate issuance, and transparency logging.
  - Responsibilities: Issue short-lived certificates for signing, verify signatures, record signing events in transparency logs, and provide APIs for clients to interact with these services.
  - Security controls: Authentication, authorization, input validation, cryptography, secure key management, audit logging, monitoring, rate limiting.
 - Element:
  - Name: OIDC Provider
  - Type: External System
  - Description: OpenID Connect Identity Providers (e.g., Google, GitHub, Microsoft) used by Sigstore to authenticate software developers.
  - Responsibilities: Authenticate users, issue identity tokens, and provide user identity information to Sigstore.
  - Security controls: Account security, multi-factor authentication, secure token issuance, and compliance with OIDC standards.
 - Element:
  - Name: Transparency Log (Rekor)
  - Type: External System
  - Description: A tamper-proof transparency log that records metadata about software signing events.
  - Responsibilities: Store and provide verifiable records of signing events, ensuring non-repudiation and auditability.
  - Security controls: Cryptographic integrity, append-only data structure, public auditability, and replication for durability.
 - Element:
  - Name: Certificate Transparency Log (CTLog)
  - Type: External System
  - Description: A public log of TLS certificates, used by Sigstore to enhance the transparency of the certificate issuance process.
  - Responsibilities: Publicly record issued certificates, allowing for monitoring and detection of mis-issuance.
  - Security controls: Cryptographic integrity, append-only data structure, public auditability, and compliance with CT standards.

## C4 CONTAINER

```mermaid
flowchart LR
    subgraph "Sigstore System"
        subgraph "Fulcio"
            C1[Fulcio API]
        end
        subgraph "Rekor"
            C2[Rekor API]
            C3[Rekor Database]
        end
        subgraph "ctlog"
            C4[ctlog API]
        end
        subgraph "Cosign Client"
            C5[Cosign CLI]
            C6[Cosign Libraries]
        end
    end
    subgraph "OIDC Provider"
        D[OIDC Provider]
    end
    subgraph "Transparency Log (Rekor)"
        E[Transparency Log (Rekor)]
    end
    subgraph "Certificate Transparency Log (CTLog)"
        F[Certificate Transparency Log (CTLog)]
    end
    C5 -->|Requests certificate| C1
    C1 -->|Verifies identity| D
    C1 -->|Issues short-lived certificate| C5
    C5 -->|Submits signing event| C2
    C2 -->|Stores signing event| C3
    C5 -->|Submits certificate to CTLog| C4
    C2 -->|Writes to Transparency Log| E
    C4 -->|Writes to Certificate Transparency Log| F
    style C fill:#f9f,stroke:#333,stroke-width:2px
```

- Container Diagram Elements:
 - Element:
  - Name: Fulcio API
  - Type: Web Application
  - Description: The certificate authority component of Sigstore. It issues short-lived certificates based on OIDC identity.
  - Responsibilities: Receive certificate requests, authenticate users via OIDC, issue short-lived certificates, and interact with CTLog.
  - Security controls: Authentication (OIDC), authorization, input validation, secure key management for CA keys, TLS encryption, audit logging.
 - Element:
  - Name: Rekor API
  - Type: Web Application
  - Description: The transparency log component of Sigstore. It stores and serves verifiable records of signing events.
  - Responsibilities: Receive signing event submissions, validate submissions, store signing events in a tamper-proof log, and provide APIs for querying and verifying log entries.
  - Security controls: Authentication, authorization, input validation, cryptographic integrity of the log, TLS encryption, audit logging, database security.
 - Element:
  - Name: Rekor Database
  - Type: Database
  - Description: Persistent storage for Rekor log entries.
  - Responsibilities: Store signing event data reliably and durably.
  - Security controls: Access control, encryption at rest, regular backups, database hardening.
 - Element:
  - Name: ctlog API
  - Type: Web Application
  - Description: Interface to interact with Certificate Transparency Logs.
  - Responsibilities: Submit certificates to CTLogs.
  - Security controls: Authentication, authorization, input validation, TLS encryption, audit logging.
 - Element:
  - Name: Cosign CLI
  - Type: Command-Line Interface
  - Description: A command-line tool for signing and verifying container images and other artifacts using Sigstore.
  - Responsibilities: Allow users to sign and verify artifacts, interact with Fulcio to obtain certificates, interact with Rekor to submit and verify signing events, and interact with CTLog.
  - Security controls: Secure key management (ephemeral keys), input validation, secure communication with Sigstore APIs, and local security best practices on the user's machine.
 - Element:
  - Name: Cosign Libraries
  - Type: Software Library
  - Description: Libraries that provide core Sigstore functionality for integration into other tools and applications.
  - Responsibilities: Provide signing and verification functionalities, abstracting the interaction with Sigstore APIs.
  - Security controls: Secure coding practices, input validation, and adherence to security best practices for software libraries.
 - Element:
  - Name: OIDC Provider
  - Type: External System
  - Description: OpenID Connect Identity Providers (e.g., Google, GitHub, Microsoft).
  - Responsibilities: Authenticate users and provide identity information to Fulcio.
  - Security controls: Managed by external providers, Sigstore relies on their security controls.
 - Element:
  - Name: Transparency Log (Rekor)
  - Type: External System
  - Description: Tamper-proof transparency log for signing events.
  - Responsibilities: Store and provide verifiable records of signing events.
  - Security controls: Managed by the Rekor project, Sigstore integrates with their service.
 - Element:
  - Name: Certificate Transparency Log (CTLog)
  - Type: External System
  - Description: Public log of TLS certificates.
  - Responsibilities: Publicly record issued certificates.
  - Security controls: Managed by CTLog operators, Sigstore integrates with their service.

## DEPLOYMENT

Sigstore components are typically deployed in a cloud environment for scalability and availability. A possible deployment architecture is described below, focusing on a cloud-based deployment using Kubernetes.

```mermaid
flowchart LR
    subgraph "Cloud Provider Infrastructure"
        subgraph "Kubernetes Cluster"
            subgraph "Fulcio Namespace"
                D1[Fulcio Pod (API)]
            end
            subgraph "Rekor Namespace"
                D2[Rekor Pod (API)]
                D3[Rekor Database (Persistent Volume)]
            end
            subgraph "ctlog Namespace"
                D4[ctlog Pod (API)]
            end
            subgraph "Ingress Controller"
                D5[Ingress Controller]
            end
        end
        subgraph "Cloud Services"
            D6[Managed Database Service (Optional for Rekor)]
            D7[Object Storage (for backups)]
            D8[Monitoring & Logging Service]
        end
    end
    subgraph "Internet"
        D9[Internet]
    end
    D9 --> D5
    D5 --> D1
    D5 --> D2
    D5 --> D4
    D2 --> D3
    D2 --> D6
    D1 --> D8
    D2 --> D8
    D4 --> D8
    D3 --> D7
    style "Cloud Provider Infrastructure" fill:#e0f7fa,stroke:#333,stroke-width:1px
```

- Deployment Diagram Elements:
 - Element:
  - Name: Kubernetes Cluster
  - Type: Infrastructure
  - Description: A managed Kubernetes cluster in a cloud provider environment. Provides orchestration and management for Sigstore components.
  - Responsibilities: Container orchestration, scaling, health monitoring, and resource management for Sigstore applications.
  - Security controls: Network policies, RBAC, pod security policies/admission controllers, regular security updates, and cluster hardening.
 - Element:
  - Name: Fulcio Pod (API)
  - Type: Container
  - Description: Instances of the Fulcio API application running as containers within Kubernetes pods.
  - Responsibilities: Serve Fulcio API requests, issue certificates.
  - Security controls: Container image security scanning, resource limits, network policies, application-level security controls (authentication, authorization, input validation).
 - Element:
  - Name: Rekor Pod (API)
  - Type: Container
  - Description: Instances of the Rekor API application running as containers within Kubernetes pods.
  - Responsibilities: Serve Rekor API requests, manage the transparency log.
  - Security controls: Container image security scanning, resource limits, network policies, application-level security controls (authentication, authorization, input validation).
 - Element:
  - Name: Rekor Database (Persistent Volume)
  - Type: Persistent Storage
  - Description: Persistent volume within Kubernetes for storing Rekor database data. Alternatively, a managed database service can be used.
  - Responsibilities: Persistent storage for Rekor data.
  - Security controls: Access control, encryption at rest, regular backups, and potentially database-level security controls.
 - Element:
  - Name: ctlog Pod (API)
  - Type: Container
  - Description: Instances of the ctlog API application running as containers within Kubernetes pods.
  - Responsibilities: Serve ctlog API requests.
  - Security controls: Container image security scanning, resource limits, network policies, application-level security controls (authentication, authorization, input validation).
 - Element:
  - Name: Ingress Controller
  - Type: Load Balancer/Reverse Proxy
  - Description: Kubernetes Ingress controller to route external traffic to Sigstore services.
  - Responsibilities: Load balancing, TLS termination, routing traffic to backend services (Fulcio, Rekor, ctlog).
  - Security controls: TLS configuration, rate limiting, web application firewall (WAF) if needed, and regular security updates.
 - Element:
  - Name: Managed Database Service (Optional for Rekor)
  - Type: Managed Service
  - Description: Cloud provider's managed database service (e.g., PostgreSQL, Cloud SQL) as an alternative to in-cluster database.
  - Responsibilities: Managed database service for Rekor data.
  - Security controls: Security controls provided by the cloud provider (access control, encryption, backups, patching).
 - Element:
  - Name: Object Storage (for backups)
  - Type: Cloud Storage
  - Description: Cloud object storage (e.g., AWS S3, Google Cloud Storage) for storing backups of the Rekor database.
  - Responsibilities: Secure and durable storage for backups.
  - Security controls: Access control, encryption at rest, versioning, and lifecycle policies.
 - Element:
  - Name: Monitoring & Logging Service
  - Type: Managed Service
  - Description: Cloud provider's monitoring and logging service (e.g., Prometheus, Grafana, ELK stack) for monitoring Sigstore components.
  - Responsibilities: Collect logs and metrics, provide dashboards and alerts for monitoring system health and security events.
  - Security controls: Access control, secure data storage, and integration with security incident response systems.
 - Element:
  - Name: Internet
  - Type: Network
  - Description: Public internet through which users and systems access Sigstore services.
  - Responsibilities: Public network connectivity.
  - Security controls: TLS encryption for all public-facing services, DDoS protection, and network security best practices.

## BUILD

The Sigstore project likely uses GitHub Actions for its CI/CD pipeline. The build process should incorporate security checks to ensure the integrity and security of the released artifacts.

```mermaid
flowchart LR
    subgraph "Developer Workstation"
        B1[Developer]
        B2[Source Code (GitHub)]
    end
    subgraph "GitHub Actions CI/CD"
        B3[Build Environment]
        B4[Automated Tests]
        B5[SAST Scanners]
        B6[Dependency Check]
        B7[Container Image Build & Scan]
        B8[Artifact Signing]
        B9[Release Artifacts]
    end
    B1 --> B2
    B2 --> B3
    B3 --> B4
    B3 --> B5
    B3 --> B6
    B3 --> B7
    B7 --> B8
    B8 --> B9
    style "GitHub Actions CI/CD" fill:#ffe0b2,stroke:#333,stroke-width:1px
```

- Build Process Elements:
 - Element:
  - Name: Developer
  - Type: Person
  - Description: Software developers contributing to the Sigstore project.
  - Responsibilities: Write code, commit code to the repository, and trigger build pipelines.
  - Security controls: Secure development environment, code review process, and adherence to secure coding practices.
 - Element:
  - Name: Source Code (GitHub)
  - Type: Code Repository
  - Description: GitHub repository hosting the Sigstore project's source code.
  - Responsibilities: Version control, source code management, and trigger for CI/CD pipelines.
  - Security controls: Access control, branch protection, audit logging, and vulnerability scanning by GitHub.
 - Element:
  - Name: Build Environment
  - Type: CI/CD Environment (GitHub Actions)
  - Description: Automated build environment provided by GitHub Actions.
  - Responsibilities: Execute build steps, run tests, perform security checks, and build release artifacts.
  - Security controls: Secure build agents, isolated build environments, access control to secrets and credentials, and audit logging.
 - Element:
  - Name: Automated Tests
  - Type: Automated Testing
  - Description: Unit tests, integration tests, and end-to-end tests to ensure code quality and functionality.
  - Responsibilities: Verify code correctness and prevent regressions.
  - Security controls: Test coverage for security-relevant functionalities, and secure test data management.
 - Element:
  - Name: SAST Scanners
  - Type: Security Tool
  - Description: Static Application Security Testing (SAST) tools to scan source code for potential vulnerabilities.
  - Responsibilities: Identify potential security flaws in the code before deployment.
  - Security controls: Regularly updated vulnerability rules, and integration with vulnerability management systems.
 - Element:
  - Name: Dependency Check
  - Type: Security Tool
  - Description: Tools to check for known vulnerabilities in project dependencies.
  - Responsibilities: Identify vulnerable dependencies and ensure the use of secure dependency versions.
  - Security controls: Regularly updated vulnerability databases, and automated dependency updates.
 - Element:
  - Name: Container Image Build & Scan
  - Type: Build & Security Tool
  - Description: Tools to build container images and scan them for vulnerabilities.
  - Responsibilities: Create container images for deployment and ensure they are free of known vulnerabilities.
  - Security controls: Base image selection, minimal image construction, vulnerability scanning of container images, and image signing.
 - Element:
  - Name: Artifact Signing
  - Type: Security Process
  - Description: Signing release artifacts (binaries, container images, etc.) using Sigstore itself or other signing mechanisms.
  - Responsibilities: Ensure the integrity and authenticity of release artifacts.
  - Security controls: Secure key management for signing keys, and use of Sigstore for signing.
 - Element:
  - Name: Release Artifacts
  - Type: Software Artifacts
  - Description: Binaries, container images, and other artifacts ready for release and distribution.
  - Responsibilities: Distribute software to users and package managers.
  - Security controls: Secure storage and distribution channels, and signature verification mechanisms for users.

# RISK ASSESSMENT

- Critical business process we are trying to protect:
 - Software supply chain integrity: Ensuring that software distributed to users is not compromised and originates from trusted sources. This protects against supply chain attacks and ensures user trust in software.

- Data we are trying to protect and their sensitivity:
 - Signing keys (private keys): Highly sensitive. Compromise would allow unauthorized signing of software. Sigstore uses short-lived certificates and keyless signing to mitigate this risk.
 - Signing certificates (public keys and associated metadata): Public but sensitive in terms of integrity. Tampering could lead to trust issues. Protected by transparency logs.
 - Signing events metadata (hashes of artifacts, signer identities, timestamps): Public but sensitive in terms of integrity and auditability. Protected by transparency logs (Rekor).
 - Audit logs of Sigstore components: Sensitive for security monitoring and incident response. Need to be protected for confidentiality and integrity.

# QUESTIONS & ASSUMPTIONS

- Questions:
 - What specific OIDC providers are officially supported and recommended for production use?
 - What is the key rotation policy for the root CA used by Fulcio?
 - What are the disaster recovery and business continuity plans for Sigstore infrastructure?
 - Are there specific rate limits or usage quotas for the public Sigstore services?
 - What is the process for reporting and handling security vulnerabilities in Sigstore?

- Assumptions:
 - Assumption: Sigstore project prioritizes security and follows security best practices in development and operations.
 - Assumption: The deployment environment is assumed to be a secure cloud environment with appropriate security controls in place.
 - Assumption: Users of Sigstore tools are expected to follow security best practices in their own environments, such as secure key management for any long-term keys they might use (though Sigstore aims to minimize the need for long-term keys).
 - Assumption: The provided GitHub repository represents the core components of the Sigstore project.
 - Assumption: The project is intended for broad public use and adoption within the software development community.