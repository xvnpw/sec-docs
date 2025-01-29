# BUSINESS POSTURE

- Business priorities and goals:
  - Provide a robust, efficient, and widely applicable set of core Java libraries.
  - Enhance developer productivity by offering well-tested and reliable utility functions.
  - Promote code quality and best practices within the Java ecosystem.
  - Maintain backwards compatibility and stability for existing users.
  - Ensure the library is performant and resource-efficient.
- Business risks:
  - Security vulnerabilities in Guava could have a widespread impact on numerous Java applications.
  - Performance regressions or inefficiencies could negatively affect the performance of applications using Guava.
  - Breaking changes in new versions could cause significant disruption and require extensive code modifications for users.
  - Availability issues with Guava (e.g., distribution platform outage) could hinder Java development projects.
  - Negative reputation impact if the library is perceived as unreliable or insecure.

# SECURITY POSTURE

- Existing security controls:
  - security control: Open source code, allowing for community review and scrutiny. Implemented in: GitHub repository.
  - security control: Comprehensive unit and integration testing. Implemented in: Guava's build and testing infrastructure.
  - security control: Code review process for all contributions. Implemented in: Guava's development workflow on GitHub.
  - security control: Public vulnerability reporting and disclosure process. Described in: Guava project documentation and security policies (if available).
  - security control: Use of memory-safe language (Java). Implemented in: Language choice for Guava development.
- Accepted risks:
  - accepted risk: Reliance on community and external researchers for vulnerability discovery.
  - accepted risk: Potential for undiscovered vulnerabilities in complex and widely used code.
  - accepted risk: Risk of supply chain attacks through dependencies (though Guava aims to minimize dependencies).
- Recommended security controls:
  - security control: Implement automated Static Application Security Testing (SAST) in the CI/CD pipeline to detect potential vulnerabilities in code changes.
  - security control: Integrate Dependency Scanning to identify and manage vulnerabilities in third-party libraries used by Guava (if any).
  - security control: Conduct periodic security audits and penetration testing by external security experts to proactively identify and address security weaknesses.
  - security control: Implement a Software Bill of Materials (SBOM) generation process to track components and dependencies for better vulnerability management.
- Security requirements:
  - Authentication: Not directly applicable to a library. Guava itself does not authenticate users.
  - Authorization: Not directly applicable to a library. Guava does not enforce authorization.
  - Input validation:
    - Requirement: Guava methods that accept external input (e.g., from user applications) must perform thorough input validation to prevent injection attacks and unexpected behavior.
    - Requirement: Validation should cover data type, format, and range, as appropriate for each method.
  - Cryptography:
    - Requirement: Cryptographic functionalities provided by Guava (if any) must be implemented using secure algorithms and best practices.
    - Requirement: Ensure proper key management and avoid hardcoding sensitive cryptographic keys.
    - Requirement: Regularly review and update cryptographic implementations to address newly discovered vulnerabilities and algorithm weaknesses.

# DESIGN

## C4 CONTEXT

```mermaid
flowchart LR
    subgraph "Organization"
        style "Organization" fill:transparent,stroke:#999,stroke-dasharray:5 5
        Guava["Guava Library"]
    end
    JavaDeveloper["Java Developer"]
    MavenCentral["Maven Central"]
    JRE["Java Runtime Environment"]

    JavaDeveloper --> Guava
    Guava --> MavenCentral
    Guava --> JRE
    JavaDeveloper -- "Uses" --> JRE
    JavaDeveloper -- "Downloads from" --> MavenCentral

    classDef external stroke-dasharray: 5 5
    class MavenCentral,JRE external
```

- Context Diagram Elements:
  - - Name: Java Developer
    - Type: Person
    - Description: Software developers who use the Guava library in their Java projects.
    - Responsibilities: Develop Java applications, integrate and utilize Guava library functionalities, report issues and contribute to the Guava project.
    - Security controls: Follow secure coding practices when using Guava, properly handle exceptions and potential vulnerabilities reported in Guava.
  - - Name: Guava Library
    - Type: Software System
    - Description: A core Java library providing collections, caching, primitives support, concurrency libraries, common annotations, string processing, I/O, and more.
    - Responsibilities: Provide reliable and efficient utility functions for Java developers, maintain backwards compatibility, address reported issues and security vulnerabilities, release new versions.
    - Security controls: Secure development lifecycle, code reviews, testing, vulnerability scanning, secure build and release process.
  - - Name: Maven Central
    - Type: External System
    - Description: A central repository for Java libraries, used for distributing and managing Guava library releases.
    - Responsibilities: Host and distribute Guava library artifacts, ensure availability and integrity of hosted libraries.
    - Security controls: Access controls, integrity checks, vulnerability scanning of hosted artifacts, DDoS protection.
  - - Name: Java Runtime Environment (JRE)
    - Type: External System
    - Description: The runtime environment required to execute Java applications that depend on the Guava library.
    - Responsibilities: Provide a platform to run Java code, manage memory and resources, enforce security policies at the runtime level.
    - Security controls: Security patches and updates, sandboxing, access controls, memory management security features.

## C4 CONTAINER

```mermaid
flowchart LR
    subgraph "Organization"
        style "Organization" fill:transparent,stroke:#999,stroke-dasharray:5 5
        subgraph "Guava Library System"
            style "Guava Library System" fill:transparent,stroke:#ddd
            GuavaJAR["Guava JAR File"]
            GuavaSourceCode["Guava Source Code"]
            BuildSystem["Build System"]
        end
    end
    JavaDeveloper["Java Developer"]
    MavenCentral["Maven Central"]
    JRE["Java Runtime Environment"]
    GitHub["GitHub Repository"]

    JavaDeveloper --> GuavaJAR
    GuavaJAR --> JRE
    GuavaJAR --> MavenCentral

    JavaDeveloper --> GitHub
    GitHub --> BuildSystem
    BuildSystem --> GuavaJAR
    BuildSystem --> MavenCentral
    GitHub --> GuavaSourceCode

    classDef external stroke-dasharray: 5 5
    class MavenCentral,JRE,GitHub external
```

- Container Diagram Elements:
  - - Name: Guava JAR File
    - Type: Container - Library
    - Description: The compiled and packaged Guava library, distributed as a JAR (Java Archive) file. Contains all the classes and resources of the Guava library.
    - Responsibilities: Provide the runtime implementation of Guava's functionalities, be included as a dependency in Java applications.
    - Security controls: Code signing of JAR file, vulnerability scanning of compiled code, protection against tampering.
  - - Name: Guava Source Code
    - Type: Container - Code Repository
    - Description: The source code of the Guava library, managed in a version control system (GitHub).
    - Responsibilities: Store the source code, track changes, facilitate collaboration among developers, serve as the basis for building the library.
    - Security controls: Access controls to the repository, code review process, branch protection, audit logging of changes.
  - - Name: Build System
    - Type: Container - Build Tool
    - Description: Automated system (e.g., Maven, Bazel) used to compile, test, package, and release the Guava library from the source code.
    - Responsibilities: Automate the build process, run tests, perform static analysis, package the library into JAR files, publish releases to Maven Central.
    - Security controls: Secure build environment, access controls to build system, dependency scanning, SAST integration, secure artifact signing and publishing.
  - - Name: GitHub Repository
    - Type: External System
    - Description: External system hosting the Guava source code repository.
    - Responsibilities: Provide version control, issue tracking, pull request management, and collaboration platform for Guava development.
    - Security controls: Access controls, audit logs, vulnerability scanning of the platform, security features provided by GitHub (e.g., branch protection).
  - - Name: Maven Central
    - Type: External System
    - Description: External system serving as the central repository for distributing Java libraries, including Guava JAR files.
    - Responsibilities: Host and distribute Guava JAR files, ensure availability and integrity of hosted artifacts.
    - Security controls: Access controls, integrity checks, vulnerability scanning of hosted artifacts, DDoS protection.
  - - Name: Java Developer
    - Type: Person
    - Description: Software developers who use the Guava library in their Java projects.
    - Responsibilities: Develop Java applications, integrate and utilize Guava library functionalities, report issues and contribute to the Guava project.
    - Security controls: Follow secure coding practices when using Guava, properly handle exceptions and potential vulnerabilities reported in Guava.
  - - Name: Java Runtime Environment (JRE)
    - Type: External System
    - Description: The runtime environment required to execute Java applications that depend on the Guava library.
    - Responsibilities: Provide a platform to run Java code, manage memory and resources, enforce security policies at the runtime level.
    - Security controls: Security patches and updates, sandboxing, access controls, memory management security features.

## DEPLOYMENT

- Deployment Scenarios:
  - Scenario 1: Java Desktop Application - Guava library is packaged within a desktop application and deployed to end-user machines.
  - Scenario 2: Java Web Application - Guava library is included in a web application deployed to application servers (e.g., Tomcat, Jetty, WildFly).
  - Scenario 3: Java Microservice - Guava library is part of a microservice deployed in containerized environments (e.g., Docker, Kubernetes).
  - Scenario 4: Java Backend Service - Guava library is used in backend services deployed on virtual machines or cloud platforms.

- Detailed Deployment Scenario (Scenario 3: Java Microservice in Kubernetes):

```mermaid
flowchart LR
    subgraph "Kubernetes Cluster"
        style "Kubernetes Cluster" fill:transparent,stroke:#999,stroke-dasharray:5 5
        subgraph "Namespace: Application"
            style "Namespace: Application" fill:transparent,stroke:#ddd
            Pod["Pod: Microservice Instance"]
        end
        KubernetesNode["Kubernetes Node"]
    end
    ContainerRegistry["Container Registry"]
    LoadBalancer["Load Balancer"]
    User["User"]

    Pod -- "Runs" --> KubernetesNode
    Pod -- "Pulls Image from" --> ContainerRegistry
    LoadBalancer -- "Routes traffic to" --> Pod
    User -- "Accesses via" --> LoadBalancer

    classDef external stroke-dasharray: 5 5
    class ContainerRegistry,LoadBalancer external
```

- Deployment Diagram Elements (Scenario 3: Java Microservice in Kubernetes):
  - - Name: Kubernetes Cluster
    - Type: Infrastructure - Cluster
    - Description: A Kubernetes cluster providing container orchestration and management.
    - Responsibilities: Manage container deployments, scaling, networking, and resource allocation.
    - Security controls: Network policies, RBAC (Role-Based Access Control), security audits, vulnerability scanning of cluster components, secrets management.
  - - Name: Namespace: Application
    - Type: Infrastructure - Kubernetes Namespace
    - Description: A Kubernetes namespace dedicated to the application using the Guava library. Provides isolation within the cluster.
    - Responsibilities: Isolate application resources, manage access control within the namespace.
    - Security controls: Network policies, RBAC within the namespace, resource quotas.
  - - Name: Pod: Microservice Instance
    - Type: Deployment Unit - Kubernetes Pod
    - Description: A pod in Kubernetes running an instance of the Java microservice that utilizes the Guava library. Contains the application container and Guava JAR.
    - Responsibilities: Execute the microservice application code, utilize Guava library functionalities, handle requests.
    - Security controls: Container security (image scanning, security context), resource limits, network policies, application-level security controls.
  - - Name: Kubernetes Node
    - Type: Infrastructure - Compute Node
    - Description: A worker node in the Kubernetes cluster, providing compute resources for running pods.
    - Responsibilities: Execute containers, manage local resources, communicate with the Kubernetes control plane.
    - Security controls: OS hardening, security patches, access controls, monitoring, container runtime security.
  - - Name: Container Registry
    - Type: External System
    - Description: A registry (e.g., Docker Hub, Google Container Registry) storing container images for the microservice.
    - Responsibilities: Store and serve container images, ensure image integrity and availability.
    - Security controls: Access controls, vulnerability scanning of images, image signing, audit logging.
  - - Name: Load Balancer
    - Type: External System
    - Description: A load balancer distributing incoming traffic to the microservice instances running in the Kubernetes cluster.
    - Responsibilities: Distribute traffic, provide high availability, expose the service externally.
    - Security controls: DDoS protection, TLS termination, access controls, security monitoring.
  - - Name: User
    - Type: Person/System
    - Description: End-user or another system that interacts with the Java microservice.
    - Responsibilities: Consume the services provided by the microservice.
    - Security controls: Authentication and authorization to access the microservice, secure communication protocols (HTTPS).

## BUILD

```mermaid
flowchart LR
    Developer["Developer"] --> CodeRepository["Code Repository (GitHub)"]
    CodeRepository --> BuildSystem["Build System (Maven/Bazel)"]
    BuildSystem --> ArtifactRepository["Artifact Repository (Maven Central)"]
    BuildSystem --> BuildArtifacts["Build Artifacts (JAR)"]

    subgraph "Build System Security Controls"
        style "Build System Security Controls" fill:transparent,stroke:#ddd
        SAST["SAST Scanner"]
        DependencyCheck["Dependency Check"]
        CodeSigning["Code Signing"]
    end
    BuildSystem --> SAST
    BuildSystem --> DependencyCheck
    BuildSystem --> CodeSigning
    SAST --> BuildArtifacts
    DependencyCheck --> BuildArtifacts
    CodeSigning --> BuildArtifacts
```

- Build Process Elements:
  - - Name: Developer
    - Type: Person
    - Description: A software developer contributing to the Guava project.
    - Responsibilities: Write code, commit changes to the code repository, participate in code reviews.
    - Security controls: Secure development environment, strong authentication, code review participation.
  - - Name: Code Repository (GitHub)
    - Type: System - Version Control
    - Description: GitHub repository hosting the Guava source code.
    - Responsibilities: Store source code, manage versions, track changes, facilitate collaboration.
    - Security controls: Access controls, branch protection, audit logging, vulnerability scanning of the platform.
  - - Name: Build System (Maven/Bazel)
    - Type: System - Build Automation
    - Description: Automated build system used to compile, test, and package Guava.
    - Responsibilities: Automate build process, run tests, perform security checks, package artifacts, publish releases.
    - Security controls: Secure build environment, access controls, SAST integration, dependency scanning, code signing, build reproducibility.
  - - Name: Artifact Repository (Maven Central)
    - Type: System - Artifact Repository
    - Description: Maven Central repository for hosting and distributing Guava JAR files.
    - Responsibilities: Host and distribute build artifacts, ensure artifact integrity and availability.
    - Security controls: Access controls, integrity checks, vulnerability scanning of hosted artifacts, DDoS protection.
  - - Name: Build Artifacts (JAR)
    - Type: Data - Software Artifact
    - Description: Compiled and packaged Guava JAR files produced by the build system.
    - Responsibilities: Contain the distributable Guava library, be consumed by Java applications.
    - Security controls: Code signing, vulnerability scanning, integrity checks.
  - - Name: SAST Scanner
    - Type: Tool - Security Scanner
    - Description: Static Application Security Testing tool integrated into the build process to detect potential vulnerabilities in the source code.
    - Responsibilities: Analyze source code for security weaknesses, report findings to developers.
    - Security controls: Regular updates of scanner rules, secure configuration, access control to scanner results.
  - - Name: Dependency Check
    - Type: Tool - Security Scanner
    - Description: Tool used to scan project dependencies for known vulnerabilities.
    - Responsibilities: Identify vulnerable dependencies, report findings to developers.
    - Security controls: Regularly updated vulnerability database, secure configuration, access control to scan results.
  - - Name: Code Signing
    - Type: Process - Security Measure
    - Description: Process of digitally signing the build artifacts (JAR files) to ensure integrity and authenticity.
    - Responsibilities: Verify the origin and integrity of the artifacts, prevent tampering.
    - Security controls: Secure key management, secure signing process, verification of signatures by consumers.

# RISK ASSESSMENT

- Critical business process we are trying to protect:
  - Secure and reliable development and execution of Java applications that depend on the Guava library.
  - Maintaining the integrity and availability of the Guava library itself as a foundational component of the Java ecosystem.
- Data we are trying to protect and their sensitivity:
  - Guava library code: Sensitivity - High. Integrity and confidentiality of the source code are important to prevent malicious modifications and maintain trust.
  - Guava library build artifacts (JAR files): Sensitivity - High. Integrity and authenticity of the JAR files are crucial to ensure users are using a safe and untampered library.
  - Vulnerability information: Sensitivity - Medium to High. Responsible disclosure of vulnerabilities is important, but public disclosure before patching can increase risk.
  - Build system credentials and signing keys: Sensitivity - Critical. Compromise could lead to malicious releases of Guava.

# QUESTIONS & ASSUMPTIONS

- Questions:
  - What specific SAST and dependency scanning tools are currently used in the Guava build process?
  - Is there a formal security audit process for Guava, and if so, how frequently are audits conducted?
  - What is the process for handling and disclosing security vulnerabilities in Guava? Is there a security contact or dedicated security team?
  - Are Guava JAR files digitally signed? If so, what key management practices are in place?
  - What are the criteria and process for accepting third-party contributions, especially from a security perspective?
- Assumptions:
  - Assumption: The Guava project prioritizes security and aims to produce a secure and reliable library.
  - Assumption: The Guava development team follows secure coding practices and is responsive to reported security issues.
  - Assumption: The infrastructure used for building and distributing Guava (GitHub, Maven Central, build systems) has reasonable security controls in place.
  - Assumption: Users of the Guava library are expected to use it responsibly and follow secure coding practices in their own applications.