# BUSINESS POSTURE

- Business priorities and goals:
  - Provide a declarative and flexible policy engine for authorization and validation.
  - Enable users to define and enforce policies as code.
  - Support validation of JSON and YAML documents against defined policies.
  - Offer a command-line interface for ease of use and integration.
  - Ensure performance and reliability for policy evaluation.
  - Facilitate integration into various environments and workflows, such as CI/CD pipelines, configuration management, and application runtime.

- Most important business risks:
  - Risk of policy misconfiguration leading to unintended access or denial of service.
  - Risk of vulnerabilities in the policy engine allowing policy bypass or unauthorized actions.
  - Risk of unauthorized access or modification of policies, compromising security posture.
  - Risk of performance issues impacting critical applications or workflows relying on policy evaluation.
  - Risk of integration challenges hindering adoption and effectiveness in diverse environments.

# SECURITY POSTURE

- Existing security controls:
  - security control: Source code hosted on GitHub (https://github.com/guard/guard) - provides version control and transparency.
  - security control: Open source project - allows community review and contributions, potentially improving security through wider scrutiny.
  - security control: Written in Rust - benefits from Rust's memory safety features, reducing the risk of certain types of vulnerabilities like buffer overflows.
  - security control: Command-line interface - limits network exposure compared to always-on services.

- Accepted risks:
  - accepted risk: Reliance on user-provided policies - the security of the system heavily depends on the correctness and security of the policies defined by users.
  - accepted risk: Dependency on third-party libraries - potential vulnerabilities in dependencies could affect the project.
  - accepted risk: Lack of built-in authentication and authorization for policy management within the tool itself - assumes external mechanisms manage access to policy files.

- Recommended security controls:
  - security control: Implement automated security scanning (SAST, DAST, dependency scanning) in the CI/CD pipeline.
  - security control: Introduce policy validation and testing frameworks to help users create secure and effective policies.
  - security control: Provide guidance and best practices for writing secure policies, including common pitfalls and mitigations.
  - security control: Consider providing mechanisms for policy versioning and rollback to manage policy changes securely.
  - security control: Implement input validation and sanitization for both policies and data being validated to prevent injection attacks.

- Security requirements:
  - Authentication:
    - Requirement: The tool itself does not require authentication as it's a command-line utility. However, access to policy files and the environment where `guard` is executed needs to be controlled via operating system level permissions and potentially version control systems.
  - Authorization:
    - Requirement: Authorization is the core function of `guard`. Policies must be defined in a way that accurately reflects the desired authorization logic. The policy language should be expressive enough to cover required authorization scenarios and prevent unintended access.
    - Requirement: Access to policy files should be restricted to authorized personnel to prevent unauthorized modification or deletion of policies.
  - Input validation:
    - Requirement: `guard` must validate both policy files and the data being evaluated against policies to prevent injection attacks and ensure data integrity. Policy syntax should be strictly validated. Data provided for validation should be validated against expected schemas or formats.
  - Cryptography:
    - Requirement: Cryptography might be relevant if policies need to handle sensitive data or secrets.  While `guard` itself might not directly implement cryptography, it should be able to integrate with systems that manage and provide secrets securely.  Policy language might need to support referencing or retrieving secrets securely.

# DESIGN

## C4 CONTEXT

```mermaid
flowchart LR
    subgraph "Organization Context"
      style "Organization Context" fill:transparent,stroke-dasharray: 5 5
      User[/"User"/]
      Admin[/"Administrator"/]
      Dev[/"Developer"/]
      Ops[/"Operations"/]
    end
    Guard[/"Guard"/]
    ConfigMgmt[/"Configuration Management System"/]
    CICD[/"CI/CD Pipeline"/]
    App[/"Application"/]

    User --> Guard: Uses to validate data or policies
    Admin --> Guard: Manages policies
    Dev --> Guard: Integrates into development workflows, writes policies
    Ops --> Guard: Integrates into deployment and operational workflows
    Guard --> ConfigMgmt: Reads policies from repository
    Guard --> CICD: Used in CI/CD for policy checks
    Guard --> App: Used as library for authorization
    CICD --> ConfigMgmt: Deploys policies
    App --> ConfigMgmt: May retrieve policies

    style Guard fill:#f9f,stroke:#333,stroke-width:2px
```

- Context Diagram Elements:
  - Element:
    - Name: User
    - Type: Person
    - Description: End-user who might use `guard` directly for ad-hoc policy validation or indirectly through applications.
    - Responsibilities: Uses `guard` to validate data or policies against defined rules.
    - Security controls: User authentication and authorization to access the system where `guard` is used.
  - Element:
    - Name: Administrator
    - Type: Person
    - Description:  Responsible for managing and maintaining policies used by `guard`.
    - Responsibilities: Creates, updates, and manages authorization policies. Ensures policies are aligned with security and business requirements.
    - Security controls: Role-Based Access Control (RBAC) to policy repositories and policy management tools. Audit logging of policy changes.
  - Element:
    - Name: Developer
    - Type: Person
    - Description: Developers who write and integrate policies into applications and infrastructure as code.
    - Responsibilities: Develops and tests authorization policies. Integrates `guard` into development workflows and applications.
    - Security controls: Access control to policy repositories. Code review of policies. Secure coding practices when integrating `guard`.
  - Element:
    - Name: Operations
    - Type: Person
    - Description: Operations teams responsible for deploying and running systems that use `guard`.
    - Responsibilities: Deploys and configures `guard` in various environments. Monitors policy enforcement and performance.
    - Security controls: Secure deployment practices. Monitoring and logging of `guard` execution. Access control to production environments.
  - Element:
    - Name: Guard
    - Type: Software System
    - Description: Command-line tool and library for declarative policy definition and enforcement.
    - Responsibilities: Reads and evaluates policies. Validates JSON/YAML data against policies. Provides authorization decisions.
    - Security controls: Input validation, secure policy parsing, robust policy evaluation engine, logging of policy decisions.
  - Element:
    - Name: Configuration Management System
    - Type: Software System
    - Description: Systems like Git repositories, HashiCorp Vault, or similar, used to store and manage authorization policies.
    - Responsibilities: Stores and versions policies. Provides access control to policies. May distribute policies to systems using `guard`.
    - Security controls: Access control lists (ACLs), version control, encryption at rest and in transit, audit logging.
  - Element:
    - Name: CI/CD Pipeline
    - Type: Software System
    - Description: Automated pipelines for building, testing, and deploying software and infrastructure.
    - Responsibilities: Uses `guard` to validate policies as part of the deployment process. Ensures policies are deployed consistently.
    - Security controls: Secure pipeline configuration, access control to pipeline resources, vulnerability scanning of pipeline components.
  - Element:
    - Name: Application
    - Type: Software System
    - Description: Applications that use `guard` as a library to enforce authorization policies at runtime.
    - Responsibilities: Integrates `guard` library. Provides data to `guard` for policy evaluation. Enforces authorization decisions made by `guard`.
    - Security controls: Secure integration of `guard` library. Proper handling of authorization decisions. Application-level security controls.

## C4 CONTAINER

```mermaid
flowchart LR
    subgraph "Guard System"
      style "Guard System" fill:#f9f,stroke:#333,stroke-width:2px
      CLI[/"Command-Line Interface"/]
      PolicyEngine[/"Policy Engine"/]
      PolicyParser[/"Policy Parser"/]
      InputValidator[/"Input Validator"/]
      OutputFormatter[/"Output Formatter"/]
    end
    ConfigMgmt[/"Configuration Management System"/]
    App[/"Application"/]

    CLI --> PolicyParser: Parses policy files
    CLI --> InputValidator: Validates input data
    CLI --> PolicyEngine: Evaluates policies against data
    CLI --> OutputFormatter: Formats output
    PolicyParser --> PolicyEngine: Provides parsed policy
    InputValidator --> PolicyEngine: Provides validated data
    PolicyEngine --> OutputFormatter: Provides policy evaluation results
    ConfigMgmt --> PolicyParser: Reads policy files
    App --> PolicyEngine: Uses Policy Engine as library

    style CLI fill:#ccf,stroke:#333,stroke-width:1px
    style PolicyEngine fill:#ccf,stroke:#333,stroke-width:1px
    style PolicyParser fill:#ccf,stroke:#333,stroke-width:1px
    style InputValidator fill:#ccf,stroke:#333,stroke-width:1px
    style OutputFormatter fill:#ccf,stroke:#333,stroke-width:1px
```

- Container Diagram Elements:
  - Element:
    - Name: Command-Line Interface (CLI)
    - Type: Container
    - Description: Provides a command-line interface for users to interact with `guard`.
    - Responsibilities: Accepts user commands, reads policy files and input data, invokes policy engine, and displays results.
    - Security controls: Input validation of command-line arguments. Secure handling of credentials if passed via command line (though discouraged).
  - Element:
    - Name: Policy Parser
    - Type: Container
    - Description: Parses policy files written in `guard`'s declarative syntax.
    - Responsibilities: Reads policy files from various sources (e.g., local file system, remote repositories). Validates policy syntax. Converts policy files into an internal representation usable by the policy engine.
    - Security controls: Input validation to prevent policy injection attacks. Secure parsing logic to avoid vulnerabilities.
  - Element:
    - Name: Policy Engine
    - Type: Container
    - Description: The core component that evaluates policies against input data.
    - Responsibilities: Receives parsed policies and validated input data. Executes policy evaluation logic. Makes authorization decisions based on policy rules.
    - Security controls: Robust and secure policy evaluation logic. Protection against policy bypass vulnerabilities. Performance optimization to prevent denial of service.
  - Element:
    - Name: Input Validator
    - Type: Container
    - Description: Validates input data against expected schemas or formats before policy evaluation.
    - Responsibilities: Validates JSON/YAML data against defined schemas or expected structures. Prevents processing of malformed or malicious input data.
    - Security controls: Input validation rules and sanitization techniques. Protection against injection attacks through input data.
  - Element:
    - Name: Output Formatter
    - Type: Container
    - Description: Formats the output of policy evaluation results for user consumption.
    - Responsibilities: Presents policy evaluation results in a user-friendly format (e.g., JSON, YAML, plain text). Provides clear and concise output indicating policy compliance or violations.
    - Security controls: Output sanitization to prevent information leakage or injection attacks in output.

## DEPLOYMENT

- Deployment Options:
  - Option 1: Local command-line execution - User directly executes `guard` on their local machine.
  - Option 2: CI/CD Pipeline integration - `guard` is integrated into CI/CD pipelines to validate policies as part of the deployment process.
  - Option 3: Library integration - `guard` is used as a library within applications to enforce authorization at runtime.

- Detailed Deployment (CI/CD Pipeline Integration):

```mermaid
flowchart LR
    subgraph "Developer Workstation"
      style "Developer Workstation" fill:transparent,stroke-dasharray: 5 5
      Dev[/"Developer"/]
      PolicyFiles[/"Policy Files"/]
    end
    subgraph "CI/CD Pipeline Environment"
      style "CI/CD Pipeline Environment" fill:transparent,stroke-dasharray: 5 5
      CIPipeline[/"CI/CD Pipeline"/]
      GuardCLI[/"Guard CLI"/]
      ArtifactRepo[/"Artifact Repository"/]
    end
    subgraph "Target Environment"
      style "Target Environment" fill:transparent,stroke-dasharray: 5 5
      TargetSystem[/"Target System"/]
      PolicyStore[/"Policy Store"/]
    end

    Dev --> PolicyFiles: Writes/Updates Policies
    PolicyFiles --> CIPipeline: Policy Files Source
    CIPipeline --> GuardCLI: Executes Guard for Policy Validation
    GuardCLI --> PolicyStore: Reads Policies for Validation
    CIPipeline --> ArtifactRepo: Stores Build Artifacts (including validated policies)
    ArtifactRepo --> TargetSystem: Deploys Artifacts and Policies

    style GuardCLI fill:#f9f,stroke:#333,stroke-width:2px
```

- Deployment Diagram Elements:
  - Element:
    - Name: Developer Workstation
    - Type: Environment
    - Description: Developer's local machine where policies are created and modified.
    - Responsibilities: Policy development and initial testing.
    - Security controls: Access control to developer workstations. Secure coding practices.
  - Element:
    - Name: Policy Files
    - Type: Artifact
    - Description: Files containing authorization policies written in `guard`'s syntax.
    - Responsibilities: Storage of policy definitions. Version control of policies.
    - Security controls: Access control to policy repositories. Version control history. Encryption at rest and in transit if policies contain sensitive information.
  - Element:
    - Name: CI/CD Pipeline Environment
    - Type: Environment
    - Description: Automated environment for building, testing, and deploying software and policies.
    - Responsibilities: Automated policy validation using `guard`. Integration testing. Deployment orchestration.
    - Security controls: Secure CI/CD pipeline configuration. Access control to pipeline resources. Audit logging of pipeline activities.
  - Element:
    - Name: CI/CD Pipeline
    - Type: Software System
    - Description: Orchestrates the build, test, and deployment process, including policy validation using `guard`.
    - Responsibilities: Executes `guard` CLI for policy validation. Manages deployment workflows.
    - Security controls: Pipeline security hardening. Input validation for pipeline configurations.
  - Element:
    - Name: Guard CLI
    - Type: Software Component
    - Description: `guard` command-line interface executed within the CI/CD pipeline.
    - Responsibilities: Policy parsing and validation within the pipeline. Provides feedback on policy compliance.
    - Security controls: Secure execution environment within the pipeline. Access control to policy files.
  - Element:
    - Name: Artifact Repository
    - Type: Software System
    - Description: Repository for storing build artifacts, including validated policies.
    - Responsibilities: Secure storage of artifacts. Versioning of artifacts. Access control to artifacts.
    - Security controls: Access control lists (ACLs). Encryption at rest and in transit. Integrity checks for artifacts.
  - Element:
    - Name: Target Environment
    - Type: Environment
    - Description: The environment where applications and systems using `guard` are deployed.
    - Responsibilities: Runtime environment for applications and policy enforcement.
    - Security controls: Environment hardening. Access control to target systems. Monitoring and logging.
  - Element:
    - Name: Policy Store
    - Type: Software System
    - Description: Storage location for policies in the target environment, accessible to `guard` or applications using `guard`.
    - Responsibilities: Provides policies to `guard` for runtime evaluation.
    - Security controls: Access control to policy store. Encryption at rest and in transit. Integrity checks for policies.

## BUILD

```mermaid
flowchart LR
    subgraph "Developer Workstation"
      style "Developer Workstation" fill:transparent,stroke-dasharray: 5 5
      Dev[/"Developer"/]
      SourceCode[/"Source Code"/]
    end
    subgraph "CI/CD Build Environment"
      style "CI/CD Build Environment" fill:transparent,stroke-dasharray: 5 5
      CodeRepo[/"Code Repository (GitHub)"/]
      CIBuilder[/"CI Builder (GitHub Actions)"/]
      DependencyScanner[/"Dependency Scanner"/]
      SASTScanner[/"SAST Scanner"/]
      ArtifactSigner[/"Artifact Signer"/]
      ArtifactRepo[/"Artifact Repository"/]
    end

    Dev --> SourceCode: Writes Code
    SourceCode --> CodeRepo: Commits Code
    CodeRepo --> CIBuilder: Triggers Build
    CIBuilder --> DependencyScanner: Scans Dependencies
    CIBuilder --> SASTScanner: Performs Static Analysis
    CIBuilder --> ArtifactSigner: Signs Artifacts
    CIBuilder --> ArtifactRepo: Publishes Artifacts
    CIBuilder --> CodeRepo: Version Tagging

    style CIBuilder fill:#f9f,stroke:#333,stroke-width:2px
    style DependencyScanner fill:#ccf,stroke:#333,stroke-width:1px
    style SASTScanner fill:#ccf,stroke:#333,stroke-width:1px
    style ArtifactSigner fill:#ccf,stroke:#333,stroke-width:1px
```

- Build Process Description:
  - Developer writes code on their workstation and commits it to the GitHub repository.
  - GitHub Actions (CI Builder) is triggered upon code changes.
  - The CI pipeline performs the following security checks:
    - Dependency Scanning: Scans project dependencies for known vulnerabilities using tools like `cargo audit` or similar.
    - SAST Scanner: Performs Static Application Security Testing using linters and SAST tools to identify potential code-level vulnerabilities.
  - The CI pipeline builds the `guard` binary.
  - Artifact Signing: The build artifacts (binaries) are signed using a code signing key to ensure integrity and authenticity.
  - Artifact Publishing: Signed artifacts are published to an artifact repository (e.g., GitHub Releases, crates.io for Rust crates).
  - Version Tagging: The code repository is tagged with the release version.

- Build Process Security Controls:
  - security control: Secure code repository (GitHub) with access controls and audit logging.
  - security control: Automated CI/CD pipeline (GitHub Actions) to ensure consistent and repeatable builds.
  - security control: Dependency scanning to identify and mitigate vulnerable dependencies.
  - security control: Static Application Security Testing (SAST) to detect code-level vulnerabilities.
  - security control: Code signing of build artifacts to ensure integrity and authenticity.
  - security control: Secure artifact repository with access controls to protect build artifacts.
  - security control: Principle of least privilege for CI/CD pipeline service accounts and credentials.
  - security control: Regular security audits of the build process and CI/CD configurations.

# RISK ASSESSMENT

- Critical business processes we are trying to protect:
  - Authorization decisions within applications and systems.
  - Validation of configurations and data against defined policies.
  - Ensuring compliance with security policies and regulations.
  - Maintaining the integrity and confidentiality of data and systems protected by policies.

- Data we are trying to protect and their sensitivity:
  - Policies themselves: Policies define the security posture and access controls. They might contain sensitive information depending on the authorization logic they implement. Policies should be treated as sensitive configuration data.
  - Data being validated: The data being validated by `guard` can vary widely depending on the use case. It could include:
    - Configuration data (e.g., infrastructure as code, application configurations) - Sensitivity depends on the system being configured.
    - User data (e.g., attributes for access control decisions) - Can be highly sensitive personal or confidential information.
    - Audit logs and security events - Contain sensitive information about system activity and security incidents.
  - Sensitivity levels should be determined based on the specific use case and the type of data being handled by `guard`. Generally, policies and data being validated should be treated with at least medium sensitivity, and potentially high sensitivity depending on the context.

# QUESTIONS & ASSUMPTIONS

- Questions:
  - What are the primary use cases for `guard` in the user's organization? (e.g., infrastructure as code validation, application authorization, data validation).
  - What type of data will be validated using `guard` and what is its sensitivity level?
  - Where will policies be stored and managed? (e.g., Git repository, dedicated policy management system).
  - How will `guard` be deployed and integrated into existing systems? (e.g., command-line tool, library, CI/CD pipeline).
  - Are there any specific compliance requirements that need to be addressed by `guard`? (e.g., GDPR, HIPAA, PCI DSS).
  - What are the performance requirements for policy evaluation?

- Assumptions:
  - BUSINESS POSTURE:
    - The primary goal is to enhance security and compliance through policy-as-code.
    - Ease of use and integration are important for adoption.
    - Reliability and performance are critical for operational use.
  - SECURITY POSTURE:
    - Security of policies is paramount.
    - Input validation is crucial to prevent attacks.
    - Secure software development lifecycle practices are followed.
    - External systems will manage access to policy files and environments where `guard` is used.
  - DESIGN:
    - `guard` will be used in various deployment scenarios, including local command-line execution, CI/CD pipelines, and library integration.
    - Policies will be stored and managed in a configuration management system like Git.
    - The build process will leverage standard CI/CD practices and security checks.