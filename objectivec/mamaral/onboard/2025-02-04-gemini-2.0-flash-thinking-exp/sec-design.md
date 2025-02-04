# BUSINESS POSTURE

This project, named 'onboard', aims to streamline and enhance the user onboarding process for a product. The primary business goal is to efficiently onboard new users, leading to quicker product adoption and increased user engagement. This can translate to improved customer satisfaction, reduced support costs associated with onboarding issues, and ultimately, higher user retention and revenue.

Key business priorities are:
- User Experience: Providing a smooth and intuitive onboarding experience is crucial for positive first impressions and user success.
- Efficiency: Reducing the time and effort required for users to become proficient with the product.
- Scalability: The onboarding process should be able to handle a growing number of new users without performance degradation.
- Measurable Improvement: Tracking onboarding metrics to understand effectiveness and identify areas for optimization.

Most important business risks to address:
- Failure to onboard users effectively: Leading to user churn and lost revenue.
- Security breaches compromising user data during onboarding: Damaging user trust and brand reputation, potentially leading to legal and financial repercussions.
- Service unavailability during onboarding: Preventing new users from accessing the product and creating a negative first experience.
- Compliance violations related to data privacy during onboarding: Resulting in legal penalties and reputational damage.

# SECURITY POSTURE

Existing security controls:
- security control: HTTPS is enforced for web traffic, as indicated by typical web application configurations. (Assumed based on standard practices for web applications, not explicitly stated in the repository).
- security control: Potentially basic input validation on the client-side for form fields. (Assumed based on standard web development practices, not explicitly visible in the repository without code inspection).

Accepted risks:
- accepted risk: Lack of comprehensive security testing and code reviews. (Common in sample projects and initial development phases).
- accepted risk: Basic authentication and authorization mechanisms might be in place, but potentially not robust enough for production environments. (Inferred from the nature of sample projects).
- accepted risk: Limited security monitoring and logging. (Typical for early-stage projects).

Recommended security controls:
- security control: Implement robust server-side input validation and sanitization to prevent injection attacks.
- security control: Implement strong authentication and authorization mechanisms, such as multi-factor authentication and role-based access control.
- security control: Encrypt sensitive data at rest and in transit.
- security control: Integrate security scanning tools (SAST/DAST) into the CI/CD pipeline.
- security control: Conduct regular security audits and penetration testing.
- security control: Implement comprehensive security logging and monitoring.
- security control: Establish a secure software development lifecycle (SSDLC) incorporating security best practices at each stage.

Security requirements:
- Authentication:
  - Requirement: Securely authenticate users accessing the onboarding application.
  - Requirement: Implement session management to maintain user authentication state.
  - Requirement: Consider multi-factor authentication for enhanced security, especially for administrative access.
- Authorization:
  - Requirement: Implement role-based access control to manage user permissions within the onboarding application.
  - Requirement: Ensure that users can only access resources and functionalities they are authorized to use.
- Input Validation:
  - Requirement: Validate all user inputs on both the client-side and server-side to prevent injection attacks (e.g., SQL injection, cross-site scripting).
  - Requirement: Sanitize user inputs before storing them in the database or displaying them to other users.
- Cryptography:
  - Requirement: Encrypt sensitive data at rest in the database.
  - Requirement: Use HTTPS to encrypt data in transit between the client and the server.
  - Requirement: Securely store and manage cryptographic keys.

# DESIGN

## C4 CONTEXT

```mermaid
flowchart LR
  subgraph "Onboarding System Context"
    center "Onboarding Application"
  end

  NewUser("New User")
  AdminUser("Admin User")
  EmailService("Email Service")
  ProductDatabase("Product Database")

  NewUser -->> center : Uses
  AdminUser -->> center : Manages
  center -->> EmailService : Sends emails
  center -->> ProductDatabase : Reads/Writes user data

  style center fill:#f9f,stroke:#333,stroke-width:2px
```

Context Diagram Elements:

- Name: Onboarding Application
  - Type: Software System
  - Description: The core system responsible for guiding new users through the product onboarding process. It provides interactive guides, tutorials, and progress tracking.
  - Responsibilities:
    - Presenting onboarding steps to new users.
    - Tracking user progress through onboarding.
    - Storing user onboarding data.
    - Triggering onboarding related emails.
    - Providing administrative interface to manage onboarding content and users.
  - Security controls:
    - Input validation on user provided data.
    - Authorization checks to control access to features and data.
    - Session management to maintain user authentication.
    - Logging of security-relevant events.

- Name: New User
  - Type: Person
  - Description: Individuals who are new to the product and are going through the onboarding process.
  - Responsibilities:
    - Completing the onboarding steps provided by the application.
    - Providing necessary information during onboarding.
  - Security controls:
    - Strong password management for their accounts.
    - Awareness of phishing and social engineering attacks.

- Name: Admin User
  - Type: Person
  - Description: Internal users who manage the onboarding application, including content creation, user management, and monitoring.
  - Responsibilities:
    - Creating and managing onboarding content.
    - Managing user accounts and roles within the onboarding system.
    - Monitoring onboarding progress and system performance.
  - Security controls:
    - Multi-factor authentication for administrative access.
    - Role-based access control to limit administrative privileges.
    - Audit logging of administrative actions.

- Name: Email Service
  - Type: External System
  - Description: A third-party service used to send emails related to the onboarding process, such as welcome emails, progress updates, and completion notifications.
  - Responsibilities:
    - Sending emails as requested by the Onboarding Application.
    - Ensuring reliable email delivery.
  - Security controls:
    - Secure API communication with the Onboarding Application (e.g., API keys, HTTPS).
    - Data encryption in transit.
    - Compliance with email sending regulations (e.g., SPF, DKIM, DMARC).

- Name: Product Database
  - Type: External System
  - Description: The main database of the product, which stores user data, product information, and potentially onboarding progress data.
  - Responsibilities:
    - Storing and retrieving user data and onboarding information.
    - Ensuring data integrity and availability.
  - Security controls:
    - Access control to the database.
    - Data encryption at rest.
    - Regular backups and disaster recovery mechanisms.
    - Database activity monitoring and auditing.

## C4 CONTAINER

```mermaid
flowchart LR
  subgraph "Onboarding System Containers"
    WebUI("Web Application")
    API("API Service")
    Database("Onboarding Database")
  end

  NewUser("New User")
  AdminUser("Admin User")
  EmailService("Email Service")
  ProductDatabase("Product Database")

  NewUser -->> WebUI : Uses
  AdminUser -->> WebUI : Manages
  WebUI -->> API : API calls (HTTPS)
  API -->> Database : Reads/Writes (JDBC/ORM)
  API -->> EmailService : Sends emails (SMTP/API)
  API -->> ProductDatabase : Reads/Writes user data (JDBC/ORM)

  style WebUI fill:#f9f,stroke:#333,stroke-width:2px
  style API fill:#f9f,stroke:#333,stroke-width:2px
  style Database fill:#f9f,stroke:#333,stroke-width:2px
```

Container Diagram Elements:

- Name: Web Application
  - Type: Web Application
  - Description: The front-end user interface of the onboarding system, built using web technologies (e.g., React, Angular, Vue.js). It provides the user interface for new users to go through onboarding steps and for admins to manage the system.
  - Responsibilities:
    - Presenting the user interface to users.
    - Handling user interactions and input.
    - Communicating with the API Service to fetch and update data.
    - Rendering onboarding content and progress indicators.
  - Security controls:
    - Client-side input validation.
    - Protection against cross-site scripting (XSS) vulnerabilities.
    - Secure handling of user sessions and cookies.
    - HTTPS enforcement for all communication.

- Name: API Service
  - Type: Application Service
  - Description: The back-end API service that handles business logic, data processing, and communication with other systems. It is likely built using a framework like Node.js, Python/Flask, Java/Spring, etc.
  - Responsibilities:
    - Handling API requests from the Web Application.
    - Implementing business logic for onboarding workflows.
    - Authenticating and authorizing users.
    - Interacting with the Database to store and retrieve data.
    - Communicating with the Email Service to send emails.
    - Interacting with the Product Database to access user information.
  - Security controls:
    - Server-side input validation and sanitization.
    - Authentication and authorization mechanisms (e.g., JWT, OAuth 2.0).
    - Protection against injection attacks (e.g., SQL injection, command injection).
    - Secure API design and implementation.
    - Rate limiting and request throttling to prevent abuse.
    - Logging and monitoring of API requests and errors.

- Name: Onboarding Database
  - Type: Database
  - Description: A dedicated database to store onboarding specific data, such as onboarding steps, user progress, onboarding content, and admin configurations. This could be a relational database (e.g., PostgreSQL, MySQL) or a NoSQL database.
  - Responsibilities:
    - Storing onboarding data persistently.
    - Providing efficient data retrieval and storage.
    - Ensuring data integrity and availability.
  - Security controls:
    - Database access control and authentication.
    - Data encryption at rest.
    - Regular database backups.
    - Database vulnerability scanning and patching.
    - Monitoring database activity and performance.

## DEPLOYMENT

Deployment Solution: Cloud Deployment (AWS)

```mermaid
flowchart LR
  subgraph "AWS Deployment Environment"
    subgraph "Virtual Private Cloud (VPC)"
      subgraph "Public Subnet"
        LoadBalancer("Load Balancer")
      end
      subgraph "Private Subnet"
        WebServer("Web Server Instance")
        APIServer("API Server Instance")
        DatabaseServer("Database Instance")
      end
    end
    Internet("Internet")
  end

  Internet -->> LoadBalancer
  LoadBalancer -->> WebServer
  LoadBalancer -->> APIServer
  WebServer -->> APIServer
  APIServer -->> DatabaseServer

  style LoadBalancer fill:#f9f,stroke:#333,stroke-width:2px
  style WebServer fill:#f9f,stroke:#333,stroke-width:2px
  style APIServer fill:#f9f,stroke:#333,stroke-width:2px
  style DatabaseServer fill:#f9f,stroke:#333,stroke-width:2px
```

Deployment Diagram Elements:

- Name: Load Balancer
  - Type: Infrastructure (AWS ELB)
  - Description: Distributes incoming traffic across multiple Web Server and API Server instances for high availability and scalability.
  - Responsibilities:
    - Load balancing incoming HTTP/HTTPS requests.
    - SSL termination.
    - Health checks for backend instances.
  - Security controls:
    - DDoS protection (AWS Shield).
    - Security groups to control inbound and outbound traffic.
    - Access logging.

- Name: Web Server Instance
  - Type: Infrastructure (AWS EC2)
  - Description: Hosts the Web Application container. Multiple instances can be deployed for redundancy and scalability.
  - Responsibilities:
    - Serving static web assets.
    - Running the Web Application container.
  - Security controls:
    - Security groups to restrict access.
    - Regular patching and updates.
    - Hardened operating system configuration.
    - Instance-level monitoring and logging.

- Name: API Server Instance
  - Type: Infrastructure (AWS EC2)
  - Description: Hosts the API Service container. Multiple instances can be deployed for redundancy and scalability.
  - Responsibilities:
    - Running the API Service container.
    - Processing API requests.
  - Security controls:
    - Security groups to restrict access.
    - Regular patching and updates.
    - Hardened operating system configuration.
    - Instance-level monitoring and logging.

- Name: Database Instance
  - Type: Infrastructure (AWS RDS)
  - Description: Managed database service for the Onboarding Database. Provides scalability, reliability, and security features.
  - Responsibilities:
    - Storing and managing onboarding data.
    - Ensuring database availability and performance.
    - Automated backups and recovery.
  - Security controls:
    - Database access control lists (ACLs).
    - Data encryption at rest and in transit.
    - Regular security patching and updates managed by AWS.
    - Database monitoring and auditing.

- Name: Virtual Private Cloud (VPC)
  - Type: Infrastructure (AWS VPC)
  - Description: Isolated network environment in AWS for deploying the Onboarding System. Provides network security and control.
  - Responsibilities:
    - Network isolation.
    - Defining network topology and subnets.
    - Routing and network security rules.
  - Security controls:
    - Network Access Control Lists (NACLs).
    - Security groups.
    - VPC flow logs for network traffic monitoring.

## BUILD

```mermaid
flowchart LR
  subgraph "Build Process"
    Developer["Developer"]
    CodeRepository["Code Repository (GitHub)"]
    CI_CD["CI/CD Pipeline (GitHub Actions)"]
    BuildArtifacts["Build Artifacts (Docker Image)"]
  end

  Developer -->> CodeRepository : Code Commit
  CodeRepository -->> CI_CD : Triggered on Commit/Push
  CI_CD --> BuildArtifacts : Build & Push Image

  subgraph "CI/CD Pipeline Steps"
    direction TB
    Checkout["Checkout Code"]
    Linting["Linting & Code Analysis"]
    SAST["SAST Scanning"]
    UnitTest["Unit Tests"]
    BuildImage["Build Docker Image"]
    PushImage["Push Docker Image to Registry"]
  end

  CI_CD --> Checkout
  Checkout --> Linting
  Linting --> SAST
  SAST --> UnitTest
  UnitTest --> BuildImage
  BuildImage --> PushImage

  style Developer fill:#f9f,stroke:#333,stroke-width:2px
  style CodeRepository fill:#f9f,stroke:#333,stroke-width:2px
  style CI_CD fill:#f9f,stroke:#333,stroke-width:2px
  style BuildArtifacts fill:#f9f,stroke:#333,stroke-width:2px
  style Checkout fill:#ccf,stroke:#333,stroke-width:1px
  style Linting fill:#ccf,stroke:#333,stroke-width:1px
  style SAST fill:#ccf,stroke:#333,stroke-width:1px
  style UnitTest fill:#ccf,stroke:#333,stroke-width:1px
  style BuildImage fill:#ccf,stroke:#333,stroke-width:1px
  style PushImage fill:#ccf,stroke:#333,stroke-width:1px
```

Build Process Description:

The build process is automated using a CI/CD pipeline, likely GitHub Actions, triggered by code commits to the Code Repository (GitHub).

Build Process Steps:
1. Developer commits code changes to the Code Repository.
2. CI/CD pipeline is triggered automatically.
3. Checkout Code: The pipeline checks out the latest code from the repository.
4. Linting & Code Analysis: Code is analyzed for style consistency and potential code quality issues using linters and static analysis tools.
5. SAST Scanning: Static Application Security Testing (SAST) tools are used to scan the code for potential security vulnerabilities.
6. Unit Tests: Automated unit tests are executed to ensure code functionality and prevent regressions.
7. Build Docker Image: A Docker image is built containing the application code and dependencies.
8. Push Docker Image to Registry: The built Docker image is pushed to a container registry (e.g., Docker Hub, AWS ECR).

Security Controls in Build Process:
- security control: Code Repository Access Control: Restricting access to the code repository to authorized developers.
- security control: Branch Protection: Enforcing code reviews and checks before merging code into main branches.
- security control: Automated Linting and Code Analysis: Identifying and preventing code quality and style issues.
- security control: SAST Scanning: Identifying potential security vulnerabilities early in the development lifecycle.
- security control: Unit Testing: Ensuring code functionality and preventing regressions, including security-related tests.
- security control: Secure Build Environment: Using secure and hardened build agents.
- security control: Dependency Scanning: Checking for vulnerabilities in third-party dependencies. (Not explicitly shown in diagram, but recommended).
- security control: Image Scanning: Scanning Docker images for vulnerabilities before deployment. (Not explicitly shown in diagram, but recommended).
- security control: Immutable Infrastructure: Building Docker images as immutable artifacts to ensure consistency and prevent drift.
- security control: Audit Logging: Logging build process activities for auditing and troubleshooting.

# RISK ASSESSMENT

Critical business process: User Onboarding. Disruption or failure of this process directly impacts user adoption and business growth.

Data we are trying to protect:
- User Data:
  - Sensitivity: Moderate to High. Depending on the data collected during onboarding (e.g., name, email, company information, potentially product usage data). Personal data is subject to privacy regulations (e.g., GDPR, CCPA).
  - Types: Personally Identifiable Information (PII), onboarding progress data, user preferences.
- Application Configuration Data:
  - Sensitivity: Low to Moderate. Configuration data for the onboarding application itself.
  - Types: Onboarding steps, content, admin user credentials (if stored in the database).

Data Sensitivity Levels:
- User PII (Name, Email): High sensitivity due to privacy regulations and potential for identity theft. Requires strong protection measures.
- Onboarding Progress Data: Moderate sensitivity. Loss or unauthorized access could impact user experience and onboarding effectiveness.
- Application Configuration: Moderate sensitivity. Unauthorized modification could disrupt the onboarding process.

# QUESTIONS & ASSUMPTIONS

Questions:
- What is the target deployment environment (cloud provider, on-premise)?
- Are there any specific security compliance requirements (e.g., GDPR, HIPAA, SOC 2)?
- What is the expected scale of the onboarding application (number of users, transactions)?
- What is the sensitivity level of the user data collected during onboarding?
- Are there any existing security policies or guidelines that need to be followed?
- What Email Service and Product Database are being used?
- What are the performance requirements for the onboarding process?

Assumptions:
- BUSINESS POSTURE: The primary business goal is efficient and user-friendly onboarding to drive product adoption. Security is important to maintain user trust and comply with basic data privacy principles.
- SECURITY POSTURE: Current security controls are basic, typical for an initial project stage. There is an understanding that more robust security measures are needed for production deployment.
- DESIGN: The application follows a standard three-tier web architecture (Web UI, API Service, Database). Deployment is assumed to be in a cloud environment (AWS) for scalability and manageability. Build process is automated using CI/CD principles.