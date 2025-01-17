# Attack Tree Analysis for redis/redis

Objective: Achieve Remote Code Execution (RCE) on the application server or exfiltrate sensitive application data by exploiting vulnerabilities in the Redis instance.

## Attack Tree Visualization

```
* Compromise Application via Redis Exploitation
    * Exploit Data Manipulation Vulnerabilities
        * Inject Malicious Data
            * Inject Scripting Payloads (e.g., Lua via EVAL)
    * Exploit Redis Configuration Vulnerabilities
        * Leverage Unsecured Access
            * Connect to Redis without Authentication
        * Abuse Dangerous Configuration Options
            * Exploit enabled `CONFIG SET` command
                * Enable `MODULE LOAD` to load malicious modules
    * Exploit Redis Command Vulnerabilities
        * Leverage Dangerous Commands
            * Execute `EVAL` with malicious Lua scripts
    * Exploit Network Access Vulnerabilities
        * Exploit Open Redis Port
            * Directly connect to the Redis instance from an external network
```


## Attack Tree Path: [Inject Scripting Payloads (e.g., Lua via EVAL)](./attack_tree_paths/inject_scripting_payloads__e_g___lua_via_eval_.md)

**Attack Vector:**
* The attacker identifies a way to send the `EVAL` command to the Redis server with attacker-controlled input. This could be through a vulnerability in the application's logic that constructs Redis commands based on user input, or if the application directly exposes the `EVAL` command without proper sanitization.
* The attacker crafts a malicious Lua script that, when executed by Redis, performs actions like:
    * Executing arbitrary system commands on the Redis server (if the `redis.call()` function is used to interact with external programs or if the `package.loadlib` function is accessible).
    * Reading or writing arbitrary files on the Redis server's file system (if file system access is not restricted within the Lua environment).
    * Manipulating data within Redis to further compromise the application.
* If the Redis server and application server share the same host or have network access to each other, the attacker might be able to pivot from the Redis server to compromise the application server.

## Attack Tree Path: [Connect to Redis without Authentication](./attack_tree_paths/connect_to_redis_without_authentication.md)

**Attack Vector:**
* The attacker scans for open Redis ports (default is 6379) that are accessible without requiring a password.
* Using a Redis client (like `redis-cli`), the attacker connects to the unsecured Redis instance.
* Once connected, the attacker can execute any Redis command, including dangerous ones.

## Attack Tree Path: [Enable `MODULE LOAD` to load malicious modules](./attack_tree_paths/enable__module_load__to_load_malicious_modules.md)

**Attack Vector:**
* The attacker gains access to the Redis server with sufficient privileges to execute the `CONFIG SET` command (this often follows gaining unsecured access).
* The attacker uses the `CONFIG SET` command to enable the `MODULE LOAD` directive (if it's not already enabled).
* The attacker then uses the `MODULE LOAD` command, providing the path to a malicious Redis module (`.so` file).
* This malicious module, written in C, can contain arbitrary code that is executed within the Redis server process, granting the attacker full control over the Redis server.

## Attack Tree Path: [Execute `EVAL` with malicious Lua scripts (as a Critical Node)](./attack_tree_paths/execute__eval__with_malicious_lua_scripts__as_a_critical_node_.md)

**Attack Vector:** (This is the same as the first point, but highlighted as a critical node due to the direct code execution capability)
* The attacker identifies a way to send the `EVAL` command to the Redis server with attacker-controlled input.
* The attacker crafts a malicious Lua script to execute arbitrary code on the Redis server.

## Attack Tree Path: [Directly connect to the Redis instance from an external network](./attack_tree_paths/directly_connect_to_the_redis_instance_from_an_external_network.md)

**Attack Vector:**
* The attacker scans for publicly accessible Redis ports (default 6379).
* If the Redis instance is exposed without proper firewall rules, the attacker can directly connect to it from the internet.
* If authentication is not enabled (see "Connect to Redis without Authentication"), the attacker gains immediate access to execute arbitrary Redis commands. Even with authentication, if the password is weak, the attacker might attempt brute-force attacks.

