```javascript
/* Example demonstrating vulnerable code and mitigated code */

const qs = require('qs');

// --- Vulnerable Code Example ---
console.log("--- Vulnerable Code ---");
function processQueryVulnerable(queryString) {
  const parsed = qs.parse(queryString);
  return parsed;
}

const maliciousQueryVulnerable = '__proto__.isAdmin=true';
processQueryVulnerable(maliciousQueryVulnerable);

// Check if the prototype is polluted
console.log(({}).isAdmin); // Output: true (Prototype is polluted!)

// --- Mitigated Code Example ---
console.log("\n--- Mitigated Code ---");
function processQueryMitigated(queryString) {
  const parsed = qs.parse(queryString, { allowPrototypes: false });
  return parsed;
}

const maliciousQueryMitigated = '__proto__.isAdmin=true';
processQueryMitigated(maliciousQueryMitigated);

// Check if the prototype is polluted (should not be)
console.log(({}).isAdmin); // Output: undefined (Prototype is NOT polluted)

// --- Example of potential exploitation scenario ---
console.log("\n--- Potential Exploitation Scenario ---");

// Assume an application has a user object
const user = {
  name: 'Test User',
  isAdmin: false // Initially not an admin
};

function checkAdminStatus(user) {
  return user.isAdmin;
}

console.log("Initial Admin Status:", checkAdminStatus(user)); // Output: false

// Attacker crafts a malicious query string
const maliciousQueryAttack = '__proto__.isAdmin=true';
qs.parse(maliciousQueryAttack); // Vulnerable parsing

console.log("Admin Status After Pollution (Vulnerable):", checkAdminStatus(user)); // Output: true (Security Bypass!)

// Reset the prototype for the mitigated example
delete Object.prototype.isAdmin;

// Mitigated scenario
const userMitigated = {
  name: 'Test User',
  isAdmin: false
};

function checkAdminStatusMitigated(user) {
  return user.isAdmin;
}

console.log("Initial Admin Status (Mitigated):", checkAdminStatusMitigated(userMitigated)); // Output: false

const maliciousQueryAttackMitigated = '__proto__.isAdmin=true';
qs.parse(maliciousQueryAttackMitigated, { allowPrototypes: false });

console.log("Admin Status After Attempted Pollution (Mitigated):", checkAdminStatusMitigated(userMitigated)); // Output: false (Protection works!)
```