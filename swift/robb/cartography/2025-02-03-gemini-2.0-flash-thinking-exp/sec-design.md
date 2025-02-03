# BUSINESS POSTURE

Cartography is an open-source tool designed to improve cloud infrastructure visibility and security posture management. It aims to help organizations understand their cloud assets and relationships between them, enabling better security analysis, compliance auditing, and resource management.

Business Priorities and Goals:
- Improve cloud security posture management.
- Enhance visibility into cloud infrastructure assets and relationships.
- Facilitate security analysis and threat detection.
- Support compliance auditing and reporting.
- Optimize cloud resource management.

Business Risks:
- Data breaches due to misconfigurations or vulnerabilities in collected infrastructure data.
- Unauthorized access to sensitive cloud inventory data.
- Inaccurate or incomplete data collection leading to flawed security assessments.
- Operational disruptions due to Cartography malfunctions or dependencies.
- Supply chain vulnerabilities in Cartography dependencies or build process.

# SECURITY POSTURE

Existing Security Controls:
- security control: Open-source project with community review (partially implemented, relies on community contributions and code reviews).
- security control: Use of standard Python security practices (partially implemented, depends on developers' adherence to secure coding practices).
- security control: Dependency scanning (assumed, common practice in software development, but needs explicit confirmation).
- security control: HTTPS for web interfaces if exposed (partially applicable, depends on deployment configuration).
- accepted risk: Reliance on underlying cloud provider security for data storage and access control.
- accepted risk: Potential vulnerabilities in third-party libraries used by Cartography.
- accepted risk: Security of deployment environment is the responsibility of the user.

Recommended Security Controls:
- security control: Implement automated security scanning in CI/CD pipeline (SAST, DAST, dependency scanning).
- security control: Regularly update dependencies to patch known vulnerabilities.
- security control: Follow least privilege principles for Cartography service accounts and IAM roles.
- security control: Implement robust input validation and sanitization to prevent injection attacks.
- security control: Secure storage of collected data, considering encryption at rest and in transit.
- security control: Implement access control mechanisms for Cartography UI and API, if exposed.
- security control: Conduct regular security audits and penetration testing.

Security Requirements:
- Authentication:
    - Requirement: Secure authentication mechanism for accessing Cartography UI and API (if exposed).
    - Requirement: Support for integration with existing organizational identity providers (e.g., LDAP, SAML, OIDC).
- Authorization:
    - Requirement: Role-based access control (RBAC) to manage user permissions within Cartography.
    - Requirement: Granular authorization policies to control access to sensitive data and functionalities.
- Input Validation:
    - Requirement: Strict validation of all inputs from cloud providers and users to prevent injection attacks.
    - Requirement: Sanitization of data before storing and displaying to prevent cross-site scripting (XSS).
- Cryptography:
    - Requirement: Encryption of sensitive data at rest in the database.
    - Requirement: Encryption of data in transit between Cartography components and cloud providers.
    - Requirement: Secure handling of API keys and credentials used to access cloud providers.

# DESIGN

## C4 CONTEXT

```mermaid
graph LR
    subgraph "Organization Cloud Environment"
        style "Organization Cloud Environment" fill:#f9f,stroke:#333,stroke-width:2px
        CloudProvider1[/"Cloud Provider 1"/]
        CloudProvider2[/"Cloud Provider 2"/]
        CloudProviderN[/"Cloud Provider N"/]
    end
    User[/"Security/Compliance Team"/]
    Cartography[/"Cartography"/]
    SecurityTools[/"Security/Compliance Tools"/]

    User --> Cartography: "Uses to visualize cloud inventory and relationships"
    Cartography --> CloudProvider1: "Collects inventory data via APIs"
    Cartography --> CloudProvider2: "Collects inventory data via APIs"
    Cartography --> CloudProviderN: "Collects inventory data via APIs"
    Cartography --> SecurityTools: "Provides data for analysis and reporting"
    SecurityTools --> User: "Uses Cartography data for security analysis and compliance"
```

Context Diagram Elements:

- Element:
    - Name: Security/Compliance Team
    - Type: User
    - Description: Security and compliance professionals who use Cartography to gain visibility into their cloud infrastructure, analyze security posture, and ensure compliance.
    - Responsibilities:
        - Utilize Cartography to understand cloud inventory and relationships.
        - Analyze security risks and compliance gaps based on Cartography data.
        - Generate reports and dashboards for security and compliance monitoring.
    - Security controls:
        - Authentication to access Cartography UI/API.
        - Authorization based on roles to access specific features and data.

- Element:
    - Name: Cartography
    - Type: System
    - Description: Open-source tool that consolidates cloud infrastructure assets and their relationships from multiple cloud providers into a graph database.
    - Responsibilities:
        - Collect inventory data from various cloud providers via APIs.
        - Transform and store collected data in a graph database.
        - Provide a UI and API for users and other systems to access and visualize the data.
    - Security controls:
        - Input validation for data received from cloud providers.
        - Secure storage of collected data (encryption at rest).
        - Access control for UI and API.
        - Secure handling of cloud provider credentials.

- Element:
    - Name: Cloud Provider 1, Cloud Provider 2, Cloud Provider N
    - Type: System
    - Description: Various cloud service providers (e.g., AWS, Azure, GCP) where the organization's infrastructure is hosted.
    - Responsibilities:
        - Host and manage cloud resources (compute, storage, network, etc.).
        - Provide APIs for accessing inventory and configuration data.
        - Implement security controls for their respective platforms.
    - Security controls:
        - Cloud provider's native security controls (IAM, network security groups, encryption, etc.).
        - API authentication and authorization mechanisms.

- Element:
    - Name: Security/Compliance Tools
    - Type: System
    - Description: Other security and compliance tools within the organization's ecosystem that can integrate with Cartography data for enhanced analysis and reporting. Examples include SIEM, SOAR, GRC platforms.
    - Responsibilities:
        - Consume data from Cartography via API or data exports.
        - Integrate Cartography data into security analysis and compliance workflows.
        - Correlate Cartography data with other security information.
    - Security controls:
        - Authentication and authorization to access Cartography API.
        - Secure data transfer mechanisms.

## C4 CONTAINER

```mermaid
graph LR
    subgraph "Cartography System"
        style "Cartography System" fill:#ccf,stroke:#333,stroke-width:2px
        WebUI[/"Web UI"/]
        API[/"API Server"/]
        GraphDatabase[/"Graph Database"/]
        DataCollection[/"Data Collection Service"/]
        TaskQueue[/"Task Queue"/]
    end
    User[/"Security/Compliance Team"/]
    CloudProviderAPIs[/"Cloud Provider APIs"/]
    SecurityTools[/"Security/Compliance Tools"/]

    User --> WebUI: "Uses Web Interface"
    WebUI --> API: "API Requests"
    API --> GraphDatabase: "Read/Write Data"
    API --> DataCollection: "Triggers Data Collection"
    DataCollection --> TaskQueue: "Enqueues Data Collection Tasks"
    TaskQueue --> DataCollection: "Data Collection Tasks"
    DataCollection --> CloudProviderAPIs: "Collects Inventory Data"
    DataCollection --> GraphDatabase: "Writes Data"
    SecurityTools --> API: "API Requests"
```

Container Diagram Elements:

- Element:
    - Name: Web UI
    - Type: Container
    - Description: Web-based user interface for visualizing and interacting with the cloud inventory data stored in the graph database.
    - Responsibilities:
        - Provide a user-friendly interface for browsing and querying cloud assets and relationships.
        - Visualize data in graphs and tables.
        - Allow users to trigger data collection and manage Cartography settings.
    - Security controls:
        - security control: Authentication and authorization for user access.
        - security control: Input validation and output encoding to prevent XSS.
        - security control: HTTPS for secure communication.

- Element:
    - Name: API Server
    - Type: Container
    - Description: REST API server that provides programmatic access to Cartography's functionalities and data.
    - Responsibilities:
        - Expose API endpoints for data retrieval, querying, and management.
        - Handle authentication and authorization for API requests.
        - Serve data to the Web UI and other systems.
    - Security controls:
        - security control: API authentication and authorization (e.g., API keys, OAuth 2.0).
        - security control: Input validation and output encoding to prevent injection attacks.
        - security control: Rate limiting and request throttling to prevent abuse.
        - security control: HTTPS for secure communication.

- Element:
    - Name: Graph Database
    - Type: Container
    - Description: Database (e.g., Neo4j) used to store cloud inventory data as a graph, representing assets and their relationships.
    - Responsibilities:
        - Persist cloud inventory data in a graph format.
        - Provide efficient querying and traversal of graph data.
        - Ensure data integrity and availability.
    - Security controls:
        - security control: Access control to the database (authentication and authorization).
        - security control: Encryption at rest for sensitive data.
        - security control: Regular backups and disaster recovery mechanisms.

- Element:
    - Name: Data Collection Service
    - Type: Container
    - Description: Service responsible for collecting inventory data from cloud provider APIs.
    - Responsibilities:
        - Authenticate with cloud provider APIs using provided credentials.
        - Query cloud provider APIs to retrieve inventory data.
        - Transform and normalize data for storage in the graph database.
        - Handle API rate limits and errors.
        - Schedule and manage data collection tasks.
    - Security controls:
        - security control: Secure storage and handling of cloud provider credentials.
        - security control: Input validation for data received from cloud provider APIs.
        - security control: Logging and monitoring of data collection activities.

- Element:
    - Name: Task Queue
    - Type: Container
    - Description: Message queue (e.g., Redis, RabbitMQ) used to manage asynchronous data collection tasks.
    - Responsibilities:
        - Queue data collection tasks.
        - Ensure reliable delivery of tasks to the Data Collection Service.
        - Manage task concurrency and prioritization.
    - Security controls:
        - security control: Access control to the task queue.
        - security control: Secure communication between components and the task queue.

## DEPLOYMENT

Deployment Solution: Cloud-based Deployment (AWS ECS)

```mermaid
graph LR
    subgraph "AWS Cloud"
        style "AWS Cloud" fill:#efe,stroke:#333,stroke-width:2px
        subgraph "ECS Cluster"
            style "ECS Cluster" fill:#eee,stroke:#555,stroke-width:2px
            WebUIInstance[/"Web UI Container Instance"/]
            APIInstance[/"API Server Container Instance"/]
            DataCollectionInstance[/"Data Collection Container Instance"/]
        end
        GraphDatabaseService[/"Graph Database Service (e.g., AWS Neptune)"/]
        TaskQueueService[/"Task Queue Service (e.g., AWS SQS or Redis on EC2)"/]
        LoadBalancer[/"Load Balancer"/]
    end
    User[/"Security/Compliance Team"/]

    User --> LoadBalancer: "HTTPS Requests"
    LoadBalancer --> WebUIInstance: "Forwards Requests"
    LoadBalancer --> APIInstance: "Forwards API Requests"
    WebUIInstance --> APIInstance: "API Calls"
    APIInstance --> GraphDatabaseService: "Database Queries"
    APIInstance --> TaskQueueService: "Enqueues Tasks"
    DataCollectionInstance --> TaskQueueService: "Receives Tasks"
    DataCollectionInstance --> CloudProviderAPIs: "Collects Data"
    DataCollectionInstance --> GraphDatabaseService: "Writes Data"
```

Deployment Diagram Elements:

- Element:
    - Name: AWS ECS Cluster
    - Type: Deployment Environment
    - Description: Amazon Elastic Container Service (ECS) cluster used to run Cartography containerized services.
    - Responsibilities:
        - Orchestrate and manage container instances.
        - Provide compute resources for Cartography services.
        - Ensure scalability and availability of services.
    - Security controls:
        - security control: AWS IAM roles for container instances with least privilege access.
        - security control: Network security groups to control traffic to and from container instances.
        - security control: Container image scanning for vulnerabilities.

- Element:
    - Name: Web UI Container Instance
    - Type: Container Instance
    - Description: Instance of the Web UI container running within the ECS cluster.
    - Responsibilities:
        - Serve the Cartography Web UI to users.
        - Handle user requests and interact with the API Server.
    - Security controls:
        - security control: Same as Web UI Container security controls.

- Element:
    - Name: API Server Container Instance
    - Type: Container Instance
    - Description: Instance of the API Server container running within the ECS cluster.
    - Responsibilities:
        - Handle API requests from the Web UI and other systems.
        - Interact with the Graph Database and Task Queue.
    - Security controls:
        - security control: Same as API Server Container security controls.

- Element:
    - Name: Data Collection Container Instance
    - Type: Container Instance
    - Description: Instance of the Data Collection Service container running within the ECS cluster.
    - Responsibilities:
        - Execute data collection tasks from the Task Queue.
        - Collect data from cloud provider APIs.
        - Write data to the Graph Database.
    - Security controls:
        - security control: Same as Data Collection Service Container security controls.
        - security control: Securely managed cloud provider credentials (e.g., AWS Secrets Manager).

- Element:
    - Name: Graph Database Service (e.g., AWS Neptune)
    - Type: Managed Service
    - Description: Managed graph database service provided by AWS (Neptune) or similar cloud provider.
    - Responsibilities:
        - Host and manage the graph database.
        - Provide scalability, availability, and performance for graph data storage and querying.
    - Security controls:
        - security control: Cloud provider's managed database security controls (encryption, access control, backups).
        - security control: Network isolation within VPC.

- Element:
    - Name: Task Queue Service (e.g., AWS SQS or Redis on EC2)
    - Type: Managed Service/Infrastructure
    - Description: Managed message queue service (SQS) or self-managed Redis on EC2 for task queuing.
    - Responsibilities:
        - Provide a reliable task queue for asynchronous data collection.
        - Ensure message durability and delivery.
    - Security controls:
        - security control: Access control to the task queue service.
        - security control: Encryption in transit and at rest (if applicable).

- Element:
    - Name: Load Balancer
    - Type: Network Component
    - Description: AWS Elastic Load Balancer (ELB) or similar service to distribute traffic to Web UI and API Server instances.
    - Responsibilities:
        - Distribute incoming traffic across container instances.
        - Provide SSL termination and HTTPS support.
        - Enhance availability and scalability.
    - Security controls:
        - security control: HTTPS termination and SSL certificate management.
        - security control: Security groups to control inbound and outbound traffic.

## BUILD

```mermaid
graph LR
    subgraph "Developer Workstation"
        style "Developer Workstation" fill:#eee,stroke:#555,stroke-width:2px
        Developer[/"Developer"/]
        CodeChanges[/"Code Changes"/]
    end
    GitHub[/"GitHub Repository"/]
    subgraph "CI/CD Pipeline (GitHub Actions)"
        style "CI/CD Pipeline (GitHub Actions)" fill:#eee,stroke:#555,stroke-width:2px
        BuildStep[/"Build and Test"/]
        SecurityScan[/"Security Scanning (SAST, Dependency Check)"/]
        Containerize[/"Containerize"/]
        PublishArtifacts[/"Publish Artifacts (Container Registry)"/]
    end
    ContainerRegistry[/"Container Registry (e.g., GitHub Container Registry, Docker Hub)"/]

    Developer --> CodeChanges: "Develops Code"
    CodeChanges --> GitHub: "Commits and Pushes Code"
    GitHub --> BuildStep: "Triggers Build"
    BuildStep --> SecurityScan: "Runs Security Scans"
    SecurityScan --> Containerize: "Builds Container Image"
    Containerize --> PublishArtifacts: "Publishes Container Image"
    PublishArtifacts --> ContainerRegistry: "Stores Container Image"
```

Build Process Description:

1. Developer develops code changes on their workstation.
2. Code changes are committed and pushed to the GitHub repository.
3. GitHub Actions CI/CD pipeline is triggered upon code changes (e.g., push, pull request).
4. Build Step: The pipeline builds the Cartography application, runs unit tests and integration tests.
5. Security Scan: Static Application Security Testing (SAST) tools and dependency vulnerability scanners are executed to identify potential security issues in the code and dependencies.
6. Containerize: If security scans pass, the application is containerized (Docker image is built).
7. Publish Artifacts: The container image is tagged and pushed to a container registry (e.g., GitHub Container Registry, Docker Hub).

Build Diagram Elements:

- Element:
    - Name: Developer
    - Type: Actor
    - Description: Software developer contributing to the Cartography project.
    - Responsibilities:
        - Write and maintain Cartography code.
        - Perform local testing and code reviews.
        - Commit and push code changes to the GitHub repository.
    - Security controls:
        - security control: Secure development practices.
        - security control: Code review process.

- Element:
    - Name: GitHub Repository
    - Type: Code Repository
    - Description: GitHub repository hosting the Cartography source code.
    - Responsibilities:
        - Version control for source code.
        - Collaboration platform for developers.
        - Trigger CI/CD pipeline.
    - Security controls:
        - security control: Access control to the repository (authentication and authorization).
        - security control: Branch protection rules.
        - security control: Audit logging of repository activities.

- Element:
    - Name: CI/CD Pipeline (GitHub Actions)
    - Type: Automation System
    - Description: GitHub Actions workflow automating the build, test, security scan, and publishing process.
    - Responsibilities:
        - Automate the software build and release process.
        - Run security scans and quality checks.
        - Publish build artifacts.
    - Security controls:
        - security control: Secure configuration of CI/CD pipeline.
        - security control: Secrets management for credentials used in the pipeline.
        - security control: Audit logging of pipeline execution.

- Element:
    - Name: Build and Test
    - Type: CI/CD Step
    - Description: Step in the CI/CD pipeline that compiles the code, runs unit tests and integration tests.
    - Responsibilities:
        - Compile source code.
        - Execute automated tests to ensure code quality and functionality.
        - Generate build artifacts.
    - Security controls:
        - security control: Secure build environment.

- Element:
    - Name: Security Scanning (SAST, Dependency Check)
    - Type: CI/CD Step
    - Description: Step in the CI/CD pipeline that performs static application security testing and dependency vulnerability scanning.
    - Responsibilities:
        - Identify potential security vulnerabilities in the code.
        - Detect vulnerable dependencies.
        - Generate security scan reports.
    - Security controls:
        - security control: Regularly updated security scanning tools and rulesets.
        - security control: Fail the build pipeline on critical security findings (policy enforcement).

- Element:
    - Name: Containerize
    - Type: CI/CD Step
    - Description: Step in the CI/CD pipeline that builds the Docker container image for Cartography.
    - Responsibilities:
        - Create a container image based on the application code and dependencies.
        - Optimize container image size and security.
    - Security controls:
        - security control: Base image selection and hardening.
        - security control: Minimize container image layers and dependencies.

- Element:
    - Name: Publish Artifacts (Container Registry)
    - Type: CI/CD Step
    - Description: Step in the CI/CD pipeline that publishes the built container image to a container registry.
    - Responsibilities:
        - Tag and push container image to the registry.
        - Manage container image versions.
    - Security controls:
        - security control: Access control to the container registry.
        - security control: Container image signing and verification (if applicable).

- Element:
    - Name: Container Registry (e.g., GitHub Container Registry, Docker Hub)
    - Type: Artifact Repository
    - Description: Registry for storing and distributing container images.
    - Responsibilities:
        - Store container images.
        - Provide access to container images for deployment.
    - Security controls:
        - security control: Access control to the container registry.
        - security control: Vulnerability scanning of container images in the registry.

# RISK ASSESSMENT

Critical Business Processes:
- Cloud Security Posture Management: Cartography directly supports this process by providing visibility and data for analysis.
- Compliance Auditing: Cartography data is used to verify compliance with security and regulatory standards.
- Incident Response: Cartography can aid in incident response by providing context about affected cloud assets.

Data Sensitivity:
- Cloud Inventory Data: This data includes metadata about cloud resources, configurations, and relationships. It can contain sensitive information such as:
    - Resource names and IDs (potentially revealing application names or environments).
    - Security group rules and network configurations (revealing network architecture and security policies).
    - IAM roles and permissions (revealing access control policies).
    - Metadata tags (potentially containing business-sensitive information).
    - Secrets and credentials (if misconfigured or inadvertently collected - high sensitivity).

Data Sensitivity Level: Moderate to High. While not directly containing customer PII, cloud inventory data can reveal significant information about an organization's infrastructure and security posture, which could be exploited by attackers. Mismanagement or breaches of this data can lead to security incidents and compliance violations.

# QUESTIONS & ASSUMPTIONS

Questions:
- What type of graph database is recommended or supported by Cartography? (Assumption: Neo4j is a common choice, but needs confirmation).
- What are the specific authentication and authorization mechanisms supported by Cartography API and UI? (Assumption: API keys, potentially OAuth 2.0 for API, and username/password or integration with identity providers for UI).
- How are cloud provider credentials managed and secured by Cartography? (Assumption: Secure storage, potentially using secrets management services).
- What are the data retention policies for collected cloud inventory data?
- Are there any built-in data masking or anonymization features for sensitive data?
- What are the performance and scalability considerations for Cartography in large cloud environments?

Assumptions:
- BUSINESS POSTURE: The primary business goal is to improve cloud security posture management and compliance.
- SECURITY POSTURE: The project currently relies on basic open-source security practices. Additional security controls are needed for production deployments.
- DESIGN: Cartography follows a typical three-tier architecture with a Web UI, API server, and database. Deployment is envisioned in a cloud environment using containerization and managed services. Build process includes basic CI/CD with security scanning.