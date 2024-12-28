### High and Critical MariaDB Threats

Here's an updated list of high and critical threats that directly involve the MariaDB software itself (https://github.com/mariadb/mariadb):

**Threat:** Weak or Default Credentials
: **Description:** An attacker might attempt to brute-force weak passwords or exploit default credentials for MariaDB user accounts (especially the `root` user) to gain unauthorized access. This directly involves the authentication mechanisms within MariaDB.
: **Impact:** Full access to the database, leading to data breaches, data manipulation, deletion, or denial of service.
: **Risk Severity:** Critical

**Threat:** SQL Injection
: **Description:** An attacker might inject malicious SQL code through application input fields or other entry points that are not properly sanitized or parameterized. This exploits vulnerabilities in MariaDB's SQL parsing and execution engine.
: **Impact:** Data breaches, data manipulation, unauthorized data access, potential execution of operating system commands on the database server (if `INTO OUTFILE` or similar is exploitable).
: **Risk Severity:** Critical

**Threat:** Stored Procedure Vulnerabilities
: **Description:** An attacker might exploit vulnerabilities within stored procedures written in SQL or other supported languages. This directly involves the stored procedure execution engine within MariaDB.
: **Impact:** Similar to SQL injection, potentially with higher privileges if the stored procedure runs with elevated permissions. Could lead to data breaches, manipulation, or denial of service.
: **Risk Severity:** High

**Threat:** Insecure Data Storage Practices (Lack of Encryption)
: **Description:** An attacker who gains access to the database (even with limited privileges) can directly access sensitive data if MariaDB's built-in encryption features are not used, or if custom encryption implementations are flawed.
: **Impact:** Data breaches and exposure of confidential information.
: **Risk Severity:** Critical

**Threat:** Resource Exhaustion Attacks
: **Description:** An attacker might send a large number of malicious or inefficient queries or connection requests directly to the MariaDB server, exploiting potential weaknesses in connection handling or query processing to consume excessive resources.
: **Impact:** Database slowdowns, crashes, and unavailability for legitimate users.
: **Risk Severity:** High

**Threat:** Replication Vulnerabilities
: **Description:** An attacker might exploit vulnerabilities in the MariaDB replication process itself to gain unauthorized access or manipulate data on slave servers. This involves flaws in the replication protocol or its implementation within MariaDB.
: **Impact:** Compromising replicated data, potentially using slave servers as a stepping stone for further attacks, and data inconsistencies.
: **Risk Severity:** High

**Threat:** Outdated MariaDB Version
: **Description:** An attacker might exploit known security vulnerabilities present in an outdated version of MariaDB that have been patched in later releases. This directly involves vulnerabilities within the MariaDB codebase.
: **Impact:** Exposure to known exploits, potentially leading to full database compromise.
: **Risk Severity:** High