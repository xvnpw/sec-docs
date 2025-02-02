# BUSINESS POSTURE

This project, represented by the GitHub repository `friendly_id`, provides a Ruby gem that allows for the creation of human-friendly URLs by using descriptive slugs instead of numeric IDs.

## Business Priorities and Goals

- Enhance User Experience: By using readable and memorable URLs, the project aims to improve the user experience, making it easier for users to understand and share links.
- Improve SEO: Human-friendly URLs are beneficial for search engine optimization (SEO), potentially leading to better search engine rankings and increased organic traffic.
- Mask Internal IDs:  Using slugs can obscure internal database IDs, which can be a minor security benefit by preventing direct enumeration of resources in some cases.
- Developer Productivity: The gem simplifies the process of implementing slug generation and management, increasing developer productivity by reducing boilerplate code.

## Business Risks

- Dependency Risk: Relying on an external library introduces a dependency risk. Issues in the library, such as bugs or security vulnerabilities, could impact projects using it.
- Compatibility Risk:  Updates to the library or changes in the application's environment could lead to compatibility issues, requiring maintenance and potential rework.
- Slug Collision Risk: If not properly managed, there's a risk of slug collisions, where different resources end up with the same slug, leading to routing conflicts and data integrity issues.
- Performance Risk:  Slug generation and lookup can introduce performance overhead, especially if not optimized or if slugs become excessively long or complex.

# SECURITY POSTURE

## Existing Security Controls

- security control: Code hosted on GitHub - Provides version control, issue tracking, and collaboration features. (Implemented: GitHub repository)
- security control: Open Source - Allows for community review and contribution, potentially leading to faster identification and resolution of security issues. (Implemented: Open Source nature of the project)
- accepted risk: Reliance on RubyGems - The gem is distributed via RubyGems, introducing a dependency on the security of the RubyGems platform and its packages.
- accepted risk: Community Maintained - Security updates and maintenance depend on the maintainers and community contributions, which can vary in timeliness and responsiveness.

## Recommended Security Controls

- security control: Dependency Scanning - Implement automated dependency scanning to identify known vulnerabilities in the gem's dependencies.
- security control: Static Application Security Testing (SAST) - Integrate SAST tools into the development process to automatically analyze the gem's code for potential security flaws.
- security control: Software Composition Analysis (SCA) - Use SCA tools to gain visibility into the gem's components and dependencies, and to manage open source risks.
- security control: Regular Security Audits - Conduct periodic security audits of the gem's codebase to proactively identify and address potential vulnerabilities.

## Security Requirements

- Authentication: Not directly applicable to this library itself, as it's a utility gem. Authentication is the responsibility of the application using `friendly_id`.
- Authorization: Not directly applicable to this library itself. Authorization is the responsibility of the application using `friendly_id` to control access to resources based on slugs.
- Input Validation: The gem should perform input validation to prevent injection attacks and ensure data integrity when generating and using slugs. This includes validating input strings used to generate slugs and when querying slugs.
- Cryptography: Not directly applicable to the core functionality of slug generation. However, if the gem were to handle sensitive data in the future (which is not its current purpose), cryptographic measures would be necessary. For now, ensure no sensitive data is processed or stored by the gem itself.

# DESIGN

## C4 CONTEXT

```mermaid
flowchart LR
    subgraph "Application Context"
    A["Application User"]:::person
    B["Web Application"]:::software_system
    C["Database"]:::database_system
    end
    D["friendly_id Gem"]:::software_system

    A --> B: Uses
    B --> D: Uses
    B --> C: Stores data in

    style A person
    classDef person fill:#8dd1fc,stroke:#333,stroke-width:2px
    style B,D software_system
    classDef software_system fill:#ffffb3,stroke:#333,stroke-width:2px
    style C database_system
    classDef database_system fill:#bebada,stroke:#333,stroke-width:2px
```

### Context Diagram Elements

- Name: Application User
  - Type: Person
  - Description: End-users who interact with the web application.
  - Responsibilities: Accessing and using the web application through a web browser.
  - Security controls: User authentication and session management implemented by the Web Application.

- Name: Web Application
  - Type: Software System
  - Description: The web application that utilizes the `friendly_id` gem to generate and manage human-friendly URLs.
  - Responsibilities:
    - Serving web pages and content to users.
    - Handling user requests and interactions.
    - Utilizing the `friendly_id` gem for slug generation and resolution.
    - Interacting with the Database to store and retrieve data.
  - Security controls:
    - security control: Web Application Firewall (WAF) - to protect against common web attacks.
    - security control: Input validation - to prevent injection vulnerabilities.
    - security control: Output encoding - to prevent cross-site scripting (XSS).
    - security control: Authentication and Authorization - to control user access.
    - security control: Secure session management.

- Name: Database
  - Type: Database System
  - Description: The database system used by the web application to store application data, including data related to slugs generated by `friendly_id`.
  - Responsibilities:
    - Persistently storing application data.
    - Providing data access and retrieval for the Web Application.
  - Security controls:
    - security control: Database access controls - to restrict access to authorized users and applications.
    - security control: Data encryption at rest and in transit - to protect data confidentiality.
    - security control: Regular database backups - for data recovery and disaster recovery.

- Name: friendly_id Gem
  - Type: Software System
  - Description: The Ruby gem that provides functionality for generating human-friendly slugs from model attributes and resolving models based on slugs.
  - Responsibilities:
    - Generating slugs from given strings.
    - Finding records based on slugs.
    - Managing slug history and uniqueness.
  - Security controls:
    - security control: Input validation within the gem - to prevent unexpected behavior and potential vulnerabilities.
    - security control: Code review - to ensure code quality and security.
    - security control: Dependency scanning - to identify vulnerabilities in dependencies.

## C4 CONTAINER

```mermaid
flowchart LR
    subgraph "Web Application Container"
    A["Web Server"]:::container
    B["Application Logic"]:::container
    C["Database"]:::database_system
    D["friendly_id Gem"]:::library
    end

    A --> B: Requests
    B --> D: Uses
    B --> C: Data Access

    style A,B container
    classDef container fill:#c4ffd7,stroke:#333,stroke-width:2px
    style D library
    classDef library fill:#f9f7cf,stroke:#333,stroke-width:2px
    style C database_system
    classDef database_system fill:#bebada,stroke:#333,stroke-width:2px
```

### Container Diagram Elements

- Name: Web Server
  - Type: Container
  - Description:  Handles HTTP requests and responses, serving static content and proxying requests to the Application Logic. Examples: Nginx, Apache.
  - Responsibilities:
    - Receiving and routing HTTP requests.
    - Serving static assets.
    - TLS termination.
    - Basic request filtering (e.g., rate limiting, basic WAF rules).
  - Security controls:
    - security control: TLS configuration - for secure communication.
    - security control: Web server hardening - to minimize attack surface.
    - security control: Rate limiting - to prevent denial-of-service attacks.

- Name: Application Logic
  - Type: Container
  - Description:  Contains the core application code, including the business logic, controllers, and models that utilize the `friendly_id` gem.  Written in Ruby, likely using a framework like Ruby on Rails.
  - Responsibilities:
    - Implementing application business logic.
    - Handling user authentication and authorization.
    - Interacting with the Database.
    - Utilizing the `friendly_id` gem for slug management.
  - Security controls:
    - security control: Framework security features - leveraging built-in security features of the chosen framework (e.g., Rails security defaults).
    - security control: Secure coding practices - following secure development guidelines.
    - security control: Input validation and output encoding - implemented within the application code.
    - security control: Authorization logic - to control access to application features and data.

- Name: Database
  - Type: Database System
  - Description:  The relational database system (e.g., PostgreSQL, MySQL) used to persist application data, including slug information.
  - Responsibilities:
    - Data persistence and retrieval.
    - Data integrity and consistency.
  - Security controls: (Same as in Context Diagram)
    - security control: Database access controls.
    - security control: Data encryption at rest and in transit.
    - security control: Regular database backups.

- Name: friendly_id Gem
  - Type: Library
  - Description: The `friendly_id` Ruby gem, integrated into the Application Logic container.
  - Responsibilities: (Same as in Context Diagram)
    - Generating slugs.
    - Finding records by slugs.
    - Managing slug history.
  - Security controls: (Same as in Context Diagram + Build process security controls described later)
    - security control: Input validation within the gem.
    - security control: Code review.
    - security control: Dependency scanning.
    - security control: SAST during development.

## DEPLOYMENT

Deployment architecture can vary greatly depending on the application using `friendly_id`. A common deployment scenario for a web application using Ruby on Rails and `friendly_id` is described below, using a cloud-based infrastructure.

```mermaid
flowchart LR
    subgraph "Cloud Environment (e.g., AWS, GCP, Azure)"
        subgraph "Load Balancer"
            A["Load Balancer"]:::deployment_node
        end
        subgraph "Application Servers"
            B1["Application Server 1"]:::deployment_node
            B2["Application Server 2"]:::deployment_node
        end
        subgraph "Database Server"
            C["Database Server"]:::deployment_node
        end
    end

    A --> B1 & B2: Distributes traffic
    B1 & B2 --> C: Database access

    style A,B1,B2,C deployment_node
    classDef deployment_node fill:#fde0dd,stroke:#333,stroke-width:2px
```

### Deployment Diagram Elements

- Name: Load Balancer
  - Type: Deployment Node
  - Description: Distributes incoming traffic across multiple Application Servers for scalability and high availability. Examples: AWS ELB, GCP Load Balancer, Azure Load Balancer.
  - Responsibilities:
    - Traffic distribution.
    - Health checks for Application Servers.
    - TLS termination (optional, can also be done at the Web Server level).
  - Security controls:
    - security control: DDoS protection - provided by cloud provider.
    - security control: TLS configuration - for secure communication.
    - security control: Access control lists (ACLs) - to restrict access to the load balancer.

- Name: Application Server 1 & Application Server 2
  - Type: Deployment Node
  - Description: Virtual machines or containers running the Web Server and Application Logic containers. These servers host the application code that utilizes the `friendly_id` gem.
  - Responsibilities:
    - Running the Web Server and Application Logic.
    - Processing user requests.
    - Interacting with the Database.
  - Security controls:
    - security control: Operating system hardening - to minimize attack surface.
    - security control: Security patching - for OS and application dependencies.
    - security control: Firewall - to restrict network access.
    - security control: Intrusion detection/prevention system (IDS/IPS) - for monitoring and preventing malicious activity.

- Name: Database Server
  - Type: Deployment Node
  - Description:  A dedicated server instance hosting the Database system.
  - Responsibilities:
    - Database management and operation.
    - Data storage and retrieval.
  - Security controls: (Same as in Context and Container Diagrams, plus infrastructure level controls)
    - security control: Database server hardening.
    - security control: Network segmentation - to isolate the database server.
    - security control: Regular security audits of the database infrastructure.

## BUILD

The build process for the `friendly_id` gem itself, as an open-source project, typically involves the following steps, focusing on security best practices for software supply chain security:

```mermaid
flowchart LR
    A["Developer"] --> B["Code Repository (GitHub)"]: Code Commit & Push
    B --> C["CI/CD Pipeline (GitHub Actions)"]: Trigger Build
    C --> D["Build Environment"]: Build & Test
    D --> E["Security Scanners (SAST, Dependency)"]: Security Checks
    E --> F["Artifact Repository (RubyGems)"]: Publish Gem Artifact

    style A person
    classDef person fill:#8dd1fc,stroke:#333,stroke-width:2px
    style B,C,D,E,F software_system
    classDef software_system fill:#ffffb3,stroke:#333,stroke-width:2px
```

### Build Diagram Elements

- Name: Developer
  - Type: Person
  - Description: Software developers contributing to the `friendly_id` gem.
  - Responsibilities:
    - Writing and committing code changes.
    - Performing local testing.
    - Participating in code reviews.
  - Security controls:
    - security control: Secure coding training - to promote secure development practices.
    - security control: Code review process - to identify potential security flaws before code is merged.
    - security control: Multi-factor authentication (MFA) - for access to code repository and build systems.

- Name: Code Repository (GitHub)
  - Type: Software System
  - Description:  GitHub repository hosting the source code of the `friendly_id` gem.
  - Responsibilities:
    - Version control.
    - Code storage and management.
    - Collaboration platform.
    - Triggering CI/CD pipelines.
  - Security controls:
    - security control: Access control - to restrict who can commit and modify code.
    - security control: Branch protection - to enforce code review and prevent direct commits to main branches.
    - security control: Audit logs - to track changes and activities within the repository.

- Name: CI/CD Pipeline (GitHub Actions)
  - Type: Software System
  - Description:  Automated CI/CD pipeline configured using GitHub Actions to build, test, and publish the gem.
  - Responsibilities:
    - Automated build process.
    - Running tests.
    - Performing security scans.
    - Publishing artifacts.
  - Security controls:
    - security control: Secure pipeline configuration - to prevent unauthorized modifications.
    - security control: Secrets management - to securely handle API keys and credentials.
    - security control: Isolated build environment - to prevent contamination and ensure build reproducibility.

- Name: Build Environment
  - Type: Software System
  - Description:  The environment where the gem is built and tested. This could be a containerized environment or a dedicated build server.
  - Responsibilities:
    - Compiling and packaging the gem.
    - Running unit and integration tests.
  - Security controls:
    - security control: Hardened build environment - to minimize attack surface.
    - security control: Regularly updated build tools and dependencies.

- Name: Security Scanners (SAST, Dependency)
  - Type: Software System
  - Description:  Automated security scanning tools integrated into the CI/CD pipeline. Includes SAST for static code analysis and dependency scanning for vulnerability detection in dependencies.
  - Responsibilities:
    - Identifying potential security vulnerabilities in the code and dependencies.
    - Generating security reports.
    - Failing the build if critical vulnerabilities are found (policy driven).
  - Security controls:
    - security control: Regularly updated vulnerability databases for scanners.
    - security control: Configuration of scanners to match security policies.

- Name: Artifact Repository (RubyGems)
  - Type: Software System
  - Description:  RubyGems.org, the public repository for Ruby gems, where the `friendly_id` gem is published.
  - Responsibilities:
    - Hosting and distributing the gem package.
    - Providing gem installation and dependency management.
  - Security controls:
    - security control: Gem signing - to ensure the integrity and authenticity of the gem package.
    - security control: RubyGems platform security - relying on the security measures implemented by RubyGems.org.
    - security control: Provenance information - ideally, the build process should generate and attach provenance information to the published gem, allowing consumers to verify the gem's origin and build process.

# RISK ASSESSMENT

## Critical Business Processes

The critical business processes being protected when using `friendly_id` are indirectly related to the core functionality of the applications that utilize it.  If `friendly_id` has vulnerabilities, it could impact:

- Website Availability and Performance: Vulnerabilities could lead to denial of service or performance degradation in applications using the gem.
- Data Integrity:  Slug collision vulnerabilities could lead to incorrect routing and potentially data corruption or exposure.
- SEO and User Experience:  If slugs are not generated or resolved correctly due to vulnerabilities, it can negatively impact SEO and user experience.

## Data Sensitivity

The `friendly_id` gem itself does not directly handle sensitive data. However, it operates on data within the applications that use it. The sensitivity of data indirectly related to `friendly_id` depends on the application context.

- Slugs themselves are generally not sensitive data.
- The data associated with slugs (e.g., product names, article titles) can vary in sensitivity depending on the application. For example, in a healthcare application, slugs might be related to patient information, which is highly sensitive. In a public blog, the data might be less sensitive.

The sensitivity level should be assessed in the context of the application using `friendly_id`.  From the gem's perspective, the primary concern is to prevent vulnerabilities that could be exploited within consuming applications, regardless of the data sensitivity in those applications.

# QUESTIONS & ASSUMPTIONS

## Questions

- What is the specific business context where `friendly_id` is being used? (e.g., e-commerce, blog, internal application). This context will help refine the risk assessment and security requirements.
- What are the specific performance requirements for slug generation and resolution in the target application? This can influence design choices and optimization efforts.
- Are there any specific compliance requirements (e.g., GDPR, HIPAA, PCI DSS) that the application using `friendly_id` must adhere to? This will impact security requirements and controls.
- What is the organization's risk appetite? A higher risk appetite might lead to accepting more accepted risks and prioritizing speed of development over extensive security controls.

## Assumptions

- BUSINESS POSTURE: It is assumed that the primary business goals for using `friendly_id` are to improve user experience and SEO. The business risk appetite is assumed to be moderate, requiring reasonable security measures without excessive overhead.
- SECURITY POSTURE: It is assumed that the application using `friendly_id` is a web application.  The existing security controls are assumed to be basic, and there is a need to enhance security posture with recommended controls. It is assumed that secure software development lifecycle (SSDLC) practices are desired but may not be fully implemented yet.
- DESIGN: It is assumed that `friendly_id` is used within a typical three-tier web application architecture (Web Server, Application Logic, Database). The deployment environment is assumed to be a cloud-based infrastructure for scalability and availability. The build process for `friendly_id` gem is assumed to be automated using CI/CD pipelines and includes basic security checks.