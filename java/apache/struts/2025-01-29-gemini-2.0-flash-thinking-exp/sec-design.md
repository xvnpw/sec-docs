# BUSINESS POSTURE

The Apache Struts project is an open-source web application framework for developing Java web applications.

- Business Priorities and Goals:
  - Provide a robust and flexible framework for building enterprise-level Java web applications.
  - Simplify the development process for Java web applications by providing reusable components and following the Model-View-Controller (MVC) pattern.
  - Maintain a stable and well-documented framework that is widely adopted and supported by the Java developer community.
  - Ensure the security and reliability of the framework to protect applications built upon it.

- Business Risks:
  - Security vulnerabilities in the framework could lead to widespread exploitation in applications using Struts, resulting in data breaches, service disruption, and reputational damage.
  - Lack of active community support and maintenance could lead to stagnation and increased security risks as vulnerabilities are not promptly addressed.
  - Compatibility issues with newer Java versions or other libraries could hinder adoption and create maintenance burdens for existing applications.
  - Performance bottlenecks in the framework could negatively impact the responsiveness and scalability of applications built with Struts.

# SECURITY POSTURE

- Existing Security Controls:
  - security control Open source code: The source code is publicly available on GitHub, allowing for community review and scrutiny. Implemented: GitHub Repository.
  - security control Community feedback:  The project benefits from community contributions and bug reports, which can help identify and address security issues. Implemented: Apache Struts community channels, issue tracking.
  - security control Version control: Git is used for version control, providing a history of changes and facilitating collaboration. Implemented: GitHub Repository.
  - accepted risk Reliance on community contributions for security fixes: The project's security posture relies on the availability and responsiveness of community members to identify and fix vulnerabilities.

- Recommended Security Controls:
  - security control Automated Static Application Security Testing (SAST): Integrate SAST tools into the build process to automatically detect potential security vulnerabilities in the code. Recommended implementation: CI/CD pipeline.
  - security control Dependency Scanning: Implement dependency scanning to identify known vulnerabilities in third-party libraries used by Struts. Recommended implementation: CI/CD pipeline, dependency management tools.
  - security control Regular Security Audits: Conduct periodic security audits by external security experts to identify and address potential weaknesses in the framework. Recommended implementation: Scheduled security assessments.
  - security control Vulnerability Disclosure Program: Establish a clear process for reporting and handling security vulnerabilities, encouraging responsible disclosure from the community. Recommended implementation: Project website, security policy.
  - security control Security Champions: Designate security champions within the development team to promote security awareness and best practices. Recommended implementation: Team structure, training programs.

- Security Requirements:
  - Authentication:
    - security requirement Struts itself may not handle authentication directly, but applications built with Struts often require authentication to protect access to resources. Applications should implement robust authentication mechanisms.
  - Authorization:
    - security requirement Applications built with Struts must implement authorization controls to ensure that users only have access to the resources they are permitted to access.
  - Input Validation:
    - security requirement Struts applications must rigorously validate all user inputs to prevent common web application vulnerabilities such as Cross-Site Scripting (XSS) and SQL Injection.
    - security control Struts framework provides built-in input validation mechanisms. Implemented: Struts framework.
  - Cryptography:
    - security requirement If Struts applications handle sensitive data, they must use strong cryptography to protect data in transit and at rest.
    - security control Java platform provides cryptographic libraries that can be used by Struts applications. Implemented: Java platform.

# DESIGN

## C4 CONTEXT

```mermaid
flowchart LR
    subgraph "Organization"
        style Organization fill:#f9f,stroke:#333,stroke-width:2px
        JavaDevelopers("Java Developers")
    end
    WebBrowsers("Web Browsers")
    ApplicationServers("Application Servers")
    Databases("Databases")
    JavaLibraries("Other Java Libraries/Frameworks")

    StrutsFramework("Apache Struts Framework")

    JavaDevelopers --> StrutsFramework : Uses
    WebBrowsers --> ApplicationServers : Accesses Web Applications
    ApplicationServers --> StrutsFramework : Runs Web Applications
    ApplicationServers --> Databases : Data Storage
    ApplicationServers --> JavaLibraries : Uses
    StrutsFramework --> JavaLibraries : Uses

    style StrutsFramework fill:#ccf,stroke:#333,stroke-width:2px
```

- Context Diagram Elements:
  - - Name: Java Developers
    - Type: Person
    - Description: Software developers who use the Apache Struts framework to build web applications.
    - Responsibilities: Develop, maintain, and deploy web applications using the Struts framework.
    - Security controls: Access control to development environments, secure coding practices, code review.
  - - Name: Web Browsers
    - Type: Person
    - Description: End-users who access web applications built using the Apache Struts framework.
    - Responsibilities: Interact with web applications to perform tasks and access information.
    - Security controls: Browser security features, HTTPS for secure communication.
  - - Name: Application Servers
    - Type: Software System
    - Description: Runtime environment for Java web applications built with Struts, such as Apache Tomcat, Jetty, or JBoss.
    - Responsibilities: Host and execute Struts-based web applications, manage application lifecycle, handle HTTP requests and responses.
    - Security controls: Application server security configurations, access controls, security updates, web application firewalls (WAF).
  - - Name: Databases
    - Type: Software System
    - Description: Data storage systems used by web applications built with Struts to persist and retrieve data, such as relational databases (e.g., MySQL, PostgreSQL) or NoSQL databases.
    - Responsibilities: Store and manage application data, provide data access to applications.
    - Security controls: Database access controls, encryption at rest and in transit, database security hardening, regular backups.
  - - Name: Other Java Libraries/Frameworks
    - Type: Software System
    - Description: External Java libraries and frameworks that the Struts framework or applications built with Struts may depend on, such as logging frameworks, utility libraries, or other web frameworks.
    - Responsibilities: Provide reusable functionalities and components to Struts and Struts-based applications.
    - Security controls: Dependency management, vulnerability scanning of dependencies, secure configuration of libraries.
  - - Name: Apache Struts Framework
    - Type: Software System
    - Description: The Apache Struts web application framework itself, providing the core functionalities and components for building MVC-based Java web applications.
    - Responsibilities: Provide a framework for developing web applications, handle request processing, manage application flow, provide UI components.
    - Security controls: Input validation mechanisms, security features within the framework, regular security updates, security testing.

## C4 CONTAINER

```mermaid
flowchart LR
    subgraph ApplicationServer["Application Server"]
        style ApplicationServer fill:#f9f,stroke:#333,stroke-width:2px
        WebApp["Web Application\n(Struts based)"]
        StrutsCore["Struts Core Framework"]
        TagLibraries["Struts Tag Libraries"]
        Plugins["Struts Plugins\n(Optional)"]
    end
    WebBrowser["Web Browser"]
    Database["Database"]
    JavaLibrariesExternal["External Java Libraries"]

    WebBrowser --> WebApp : HTTP Requests/Responses
    WebApp --> StrutsCore : Uses
    WebApp --> TagLibraries : Uses
    WebApp --> Plugins : Uses
    WebApp --> Database : Data Access (JDBC, ORM)
    StrutsCore --> JavaLibrariesExternal : Uses
    TagLibraries --> StrutsCore : Uses
    Plugins --> StrutsCore : Uses

    style WebApp fill:#ccf,stroke:#333,stroke-width:2px
    style StrutsCore fill:#ddd,stroke:#333,stroke-width:2px
    style TagLibraries fill:#ddd,stroke:#333,stroke-width:2px
    style Plugins fill:#ddd,stroke:#333,stroke-width:2px
```

- Container Diagram Elements:
  - - Name: Web Application (Struts based)
    - Type: Web Application
    - Description: A web application built using the Apache Struts framework, deployed within an application server.
    - Responsibilities: Implement specific business logic, handle user requests, interact with databases, render web pages.
    - Security controls: Application-level authentication and authorization, input validation, session management, secure coding practices, vulnerability scanning.
  - - Name: Struts Core Framework
    - Type: Library
    - Description: The core components of the Apache Struts framework, providing the fundamental MVC architecture, request processing, and configuration management.
    - Responsibilities: Handle request routing, action invocation, interceptor management, configuration loading.
    - Security controls: Framework-level input validation, security features within the core framework, regular security updates, security testing.
  - - Name: Struts Tag Libraries
    - Type: Library
    - Description: JSP tag libraries provided by Struts to simplify the development of user interfaces in JSP pages.
    - Responsibilities: Provide reusable UI components and simplify JSP development.
    - Security controls: Secure tag library implementation, prevention of XSS vulnerabilities in generated HTML.
  - - Name: Struts Plugins (Optional)
    - Type: Library
    - Description: Optional plugins that extend the functionality of the Struts framework, providing features like tiles, sitemesh, or other integrations.
    - Responsibilities: Extend framework capabilities, provide additional features.
    - Security controls: Plugin-specific security considerations, vulnerability scanning of plugins, secure plugin configuration.
  - - Name: Database
    - Type: Database
    - Description: Database system used by the web application for data persistence.
    - Responsibilities: Store and manage application data.
    - Security controls: Database access controls, encryption at rest and in transit, database security hardening.
  - - Name: External Java Libraries
    - Type: Library
    - Description: Third-party Java libraries used by Struts Core or plugins.
    - Responsibilities: Provide functionalities to Struts framework.
    - Security controls: Dependency scanning, vulnerability management of dependencies.

## DEPLOYMENT

Deployment Architecture: Standalone Application Server Deployment

```mermaid
flowchart LR
    subgraph "Production Environment"
        subgraph "Application Server Instance"
            style "Application Server Instance" fill:#f9f,stroke:#333,stroke-width:2px
            ApplicationServerNode["Application Server\n(e.g., Tomcat)"]
            WebAppDeployment["Web Application Archive\n(WAR file)"]
        end
        DatabaseServer["Database Server"]
        LoadBalancer["Load Balancer\n(Optional)"]
        Firewall["Firewall"]
    end
    Internet["Internet"]

    Internet --> Firewall
    Firewall --> LoadBalancer
    LoadBalancer --> ApplicationServerNode
    ApplicationServerNode --> WebAppDeployment : Runs
    WebAppDeployment --> DatabaseServer : Data Access

    style ApplicationServerNode fill:#ddd,stroke:#333,stroke-width:2px
    style WebAppDeployment fill:#ccf,stroke:#333,stroke-width:2px
    style DatabaseServer fill:#ddd,stroke:#333,stroke-width:2px
    style LoadBalancer fill:#ddd,stroke:#333,stroke-width:2px
    style Firewall fill:#ddd,stroke:#333,stroke-width:2px
```

- Deployment Diagram Elements:
  - - Name: Internet
    - Type: Environment
    - Description: Public network through which users access the web application.
    - Responsibilities: Provide network connectivity for users.
    - Security controls: N/A (External environment).
  - - Name: Firewall
    - Type: Infrastructure
    - Description: Network firewall to control inbound and outbound traffic, protecting the application server and database.
    - Responsibilities: Filter network traffic, block unauthorized access.
    - Security controls: Firewall rules, intrusion detection/prevention system (IDS/IPS).
  - - Name: Load Balancer (Optional)
    - Type: Infrastructure
    - Description: Distributes incoming traffic across multiple application server instances for scalability and high availability.
    - Responsibilities: Load balancing, traffic distribution, health checks.
    - Security controls: Load balancer security configurations, SSL termination, DDoS protection.
  - - Name: Application Server Node
    - Type: Infrastructure
    - Description: Physical or virtual server instance running the application server (e.g., Tomcat).
    - Responsibilities: Host the application server, execute web applications.
    - Security controls: Server hardening, operating system security, access controls, security monitoring.
  - - Name: Web Application Archive (WAR file)
    - Type: Container
    - Description: Packaged web application (WAR file) deployed on the application server.
    - Responsibilities: Run the Struts-based web application.
    - Security controls: Application security controls (as described in Container Diagram), secure deployment practices.
  - - Name: Database Server
    - Type: Infrastructure
    - Description: Server hosting the database system.
    - Responsibilities: Manage and store application data.
    - Security controls: Database server hardening, database security configurations, access controls, encryption at rest and in transit.

## BUILD

```mermaid
flowchart LR
    subgraph DeveloperWorkstation["Developer Workstation"]
        Developer["Developer"]
        SourceCode["Source Code\n(Git Repository)"]
    end
    subgraph CI_CD_Pipeline["CI/CD Pipeline\n(e.g., GitHub Actions)"]
        BuildServer["Build Server"]
        CodeRepository["Code Repository\n(GitHub)"]
        SASTScanner["SAST Scanner"]
        DependencyScanner["Dependency Scanner"]
        UnitTests["Unit Tests"]
        Package["Package\n(WAR/JAR)"]
        ArtifactRepository["Artifact Repository"]
    end

    Developer --> SourceCode : Writes Code
    SourceCode --> CodeRepository : Push
    CodeRepository --> BuildServer : Trigger Build
    BuildServer --> SASTScanner : Run Scan
    BuildServer --> DependencyScanner : Run Scan
    BuildServer --> UnitTests : Run Tests
    BuildServer --> Package : Package Application
    Package --> ArtifactRepository : Publish Artifact

    style SourceCode fill:#ddd,stroke:#333,stroke-width:2px
    style CodeRepository fill:#ddd,stroke:#333,stroke-width:2px
    style BuildServer fill:#ddd,stroke:#333,stroke-width:2px
    style SASTScanner fill:#ddd,stroke:#333,stroke-width:2px
    style DependencyScanner fill:#ddd,stroke:#333,stroke-width:2px
    style UnitTests fill:#ddd,stroke:#333,stroke-width:2px
    style Package fill:#ddd,stroke:#333,stroke-width:2px
    style ArtifactRepository fill:#ddd,stroke:#333,stroke-width:2px
```

- Build Process Elements:
  - - Name: Developer
    - Type: Person
    - Description: Software developer writing and modifying the Struts framework code.
    - Responsibilities: Develop code, write unit tests, fix bugs, commit code changes.
    - Security controls: Secure development workstation, access control to code repository, code review.
  - - Name: Source Code (Git Repository)
    - Type: Data Store
    - Description: Git repository hosting the source code of the Apache Struts framework.
    - Responsibilities: Store and version control source code.
    - Security controls: Access control to repository, branch protection, audit logging.
  - - Name: CI/CD Pipeline (e.g., GitHub Actions)
    - Type: Automation System
    - Description: Automated CI/CD pipeline for building, testing, and packaging the Struts framework.
    - Responsibilities: Automate build process, run security scans, execute tests, package artifacts.
    - Security controls: Secure CI/CD pipeline configuration, access control to pipeline, secrets management.
  - - Name: Build Server
    - Type: Compute
    - Description: Server executing the build process within the CI/CD pipeline.
    - Responsibilities: Compile code, run tests, execute security scans, package artifacts.
    - Security controls: Build server hardening, access control, security monitoring.
  - - Name: SAST Scanner
    - Type: Security Tool
    - Description: Static Application Security Testing tool integrated into the build pipeline to analyze source code for vulnerabilities.
    - Responsibilities: Detect potential security vulnerabilities in code.
    - Security controls: SAST tool configuration, vulnerability reporting.
  - - Name: Dependency Scanner
    - Type: Security Tool
    - Description: Tool to scan project dependencies for known vulnerabilities.
    - Responsibilities: Identify vulnerable dependencies.
    - Security controls: Dependency scanner configuration, vulnerability reporting, dependency management.
  - - Name: Unit Tests
    - Type: Software
    - Description: Automated unit tests to verify the functionality of the code.
    - Responsibilities: Ensure code quality and functionality.
    - Security controls: Test coverage for security-related functionalities, secure test data management.
  - - Name: Package (WAR/JAR)
    - Type: Artifact
    - Description: Packaged build artifacts (WAR or JAR files) of the Struts framework.
    - Responsibilities: Distributable artifacts of the framework.
    - Security controls: Integrity checks of packages, secure artifact signing (optional).
  - - Name: Artifact Repository
    - Type: Data Store
    - Description: Repository for storing and managing build artifacts.
    - Responsibilities: Store and distribute build artifacts.
    - Security controls: Access control to artifact repository, integrity checks of artifacts, audit logging.

# RISK ASSESSMENT

- Critical Business Processes:
  - Development and maintenance of the Apache Struts framework itself.
  - Development and operation of web applications built using the Struts framework.
  - Maintaining the reputation and trust associated with the Apache Struts project and the Apache Software Foundation.

- Data to Protect and Sensitivity:
  - Source code of the Struts framework: High sensitivity. Confidentiality and integrity are crucial to prevent unauthorized modifications or disclosure of vulnerabilities.
  - Build artifacts (JAR/WAR files): Medium sensitivity. Integrity is important to ensure users download and use genuine and untampered artifacts.
  - Vulnerability reports and security-related discussions: High sensitivity. Confidentiality is important to prevent premature disclosure of vulnerabilities before fixes are available.
  - User data processed by applications built with Struts: Sensitivity depends on the application. Can range from low to high sensitivity (e.g., personal data, financial data). Applications need to classify and protect data accordingly.

# QUESTIONS & ASSUMPTIONS

- Questions:
  - What is the current process for security vulnerability testing and remediation within the Apache Struts project?
  - Is there a dedicated security team or security champions within the Struts project?
  - What are the plans for improving the security posture of the Struts framework in the future?
  - Are there any specific security certifications or compliance requirements that the Struts project aims to meet?
  - What is the process for users to report security vulnerabilities in Struts?

- Assumptions:
  - The Apache Struts project aims to provide a secure and reliable framework for web application development.
  - Security is a recognized concern for the Struts project, given its history of vulnerabilities.
  - The project benefits from community contributions to identify and address security issues.
  - Applications built with Struts are expected to implement their own application-level security controls in addition to the framework's security features.
  - The project uses standard software development practices, including version control and build automation.