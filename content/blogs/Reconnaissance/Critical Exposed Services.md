---
title: "Critical Services, Exposed Ports, and Default Authentication"
slug: "critical-services-exposed-ports-default-authentication"
date: "2025-05-19"
author: "BugB Security Team"
authorTitle: "Security Researchers"
excerpt: "Discover how misconfigured services with default or no authentication can expose your infrastructure to attacks. This comprehensive guide reveals default ports, authentication states, and hardening tips for Redis, Kafka, Kubernetes, and other critical services."
category: "research"
---

# Critical Services, Exposed Ports, and Default Authentication

Your infrastructure is only as secure as its weakest link. Many modern services are deployed with **default settings** that prioritize functionality over security, leaving critical ports **exposed** and **unauthenticated**. This comprehensive analysis examines:

* **Default ports** where attackers begin their reconnaissance
* **Authentication status** of popular services out-of-the-box
* **Attack vectors** through unauthenticated services
* **Hardening techniques** to secure these services properly

This guide focuses on **critical infrastructure components** that are frequently overlooked in security assessments but represent significant attack vectors when misconfigured.

---

## Why Default Configurations Are Dangerous

1. **Ease of Deployment ≠ Security**
   
   Default configurations prioritize quick setup and developer convenience, often at the expense of security. Many services ship with:
   
   * Authentication disabled
   * Default credentials
   * Binding to all network interfaces (0.0.0.0)
   * Unnecessary port exposure

2. **Reconnaissance Value**
   
   Open, unauthenticated services provide attackers with:
   
   * Valuable insights into your infrastructure
   * Lateral movement opportunities
   * Data exposure without requiring exploitation
   * Service identification through port scanning

3. **Scale of Risk**
   
   As containerization and microservices architectures proliferate, organizations deploy more services than ever before, creating an expanded attack surface with overlooked security configurations.

---

## Service Analysis: Default Ports and Authentication Status

### Redis

| Port | Protocol | Default Auth | CVE Examples | Risk Level |
|------|----------|--------------|--------------|------------|
| 6379 | TCP | **NO AUTH** | CVE-2022-0543, CVE-2023-28425 | **HIGH** |

Redis, an in-memory data structure store, is notorious for its lack of authentication by default. When deployed with default settings, **anyone who can reach port 6379** can:

* Access and modify all data
* Execute arbitrary Lua scripts (potential RCE)
* Write to disk via config commands
* Access potentially sensitive information

**Attack Scenario:** Attackers commonly search for exposed Redis instances to write SSH keys to authorized_keys files or create scheduled tasks for persistence after initial discovery.

**Hardening Required:**
* Enable authentication with a strong password (`requirepass` directive)
* Bind to localhost only when possible
* Implement network segmentation
* Disable dangerous commands

---

### Apache Kafka

| Port | Protocol | Default Auth | CVE Examples | Risk Level |
|------|----------|--------------|--------------|------------|
| 9092 | TCP | **NO AUTH** | CVE-2018-1288, CVE-2019-12399 | **HIGH** |
| 9093 | TCP (SSL) | **OPTIONAL** | | |
| 2181 | TCP (ZooKeeper) | **NO AUTH** | CVE-2021-21409 | **HIGH** |

Kafka, a distributed event streaming platform, defaults to no authentication for client communications. The ecosystem involves multiple components, each with potential security issues:

* **Brokers** (9092) - No authentication by default
* **ZooKeeper** (2181) - No authentication by default
* **JMX** (Various) - Often exposed without authentication

**Attack Scenario:** Unauthenticated Kafka access allows attackers to read sensitive data streams, publish malicious messages, or disrupt operations by creating/deleting topics.

**Hardening Required:**
* Implement SASL authentication
* Configure TLS/SSL for encryption
* Implement ACLs for authorization
* Secure ZooKeeper with authentication

---

### Kubernetes API Server

| Port | Protocol | Default Auth | CVE Examples | Risk Level |
|------|----------|--------------|--------------|------------|
| 6443 | TCP (HTTPS) | **PARTIAL** | CVE-2018-1002105, CVE-2019-11253 | **CRITICAL** |
| 8080 | TCP (HTTP) | **NO AUTH** | | **CRITICAL** |

Kubernetes API server provides the primary control plane for clusters. Authentication is now typically enabled in most distributions, but:

* **Port 8080** - Insecure port with NO authentication (deprecated but still found in the wild)
* **Port 6443** - Secure port with authentication, but default configurations may use self-signed certificates

**Attack Scenario:** Access to an unauthenticated Kubernetes API server grants complete control over workloads, potentially leading to container escapes and host compromise.

**Hardening Required:**
* Disable insecure port (8080) completely
* Implement RBAC policies
* Use proper PKI for API server certificates
* Enable audit logging
* Use NetworkPolicies to restrict pod-to-pod communication

---

### Docker API

| Port | Protocol | Default Auth | CVE Examples | Risk Level |
|------|----------|--------------|--------------|------------|
| 2375 | TCP (HTTP) | **NO AUTH** | CVE-2019-5736, CVE-2020-15257 | **CRITICAL** |
| 2376 | TCP (HTTPS) | **CERT-BASED** | | **HIGH** |

The Docker API allows remote management of Docker daemon. Many developers enable the remote API for convenience, often without realizing the security implications:

* **Port 2375** - Unencrypted with no authentication
* **Port 2376** - Encrypted but requires proper certificate configuration

**Attack Scenario:** An exposed Docker API allows attackers to create containers that mount the host filesystem, leading to full host compromise.

**Hardening Required:**
* Never expose Docker API to public networks
* Use TLS with client certificate authentication
* Implement authorization plugins
* Use Unix socket instead of TCP when possible

---

### Elasticsearch

| Port | Protocol | Default Auth | CVE Examples | Risk Level |
|------|----------|--------------|--------------|------------|
| 9200 | TCP (HTTP) | **NO AUTH** (Pre 8.0) | CVE-2015-1427, CVE-2021-22137 | **HIGH** |
| 9300 | TCP | **NO AUTH** (Pre 8.0) | | **HIGH** |

Elasticsearch is a search and analytics engine commonly deployed in ELK stacks (Elasticsearch, Logstash, Kibana). Before version 8.0:

* **No authentication** was enabled by default
* Exposed REST API allowed full index control
* JavaScript code execution via search templates

Since version 8.0, security features are enabled by default, but many deployments still run older versions.

**Attack Scenario:** Attackers target exposed Elasticsearch instances to extract sensitive data from logs and indexes or to execute code via search template injection.

**Hardening Required:**
* Upgrade to Elasticsearch 8.x+ with default security
* Enable X-Pack security on older versions
* Implement proper authentication and authorization
* Network segmentation to limit access

---

### cAdvisor

| Port | Protocol | Default Auth | CVE Examples | Risk Level |
|------|----------|--------------|--------------|------------|
| 8080 | TCP (HTTP) | **NO AUTH** | CVE-2019-11250 | **MEDIUM** |

cAdvisor (Container Advisor) provides container users with resource usage and performance metrics. By default:

* **No authentication** is required
* Exposes detailed system information
* Reveals container names, images, and configurations

**Attack Scenario:** Attackers use exposed cAdvisor instances to gather intelligence on container deployments, identify potential targets, and plan more sophisticated attacks.

**Hardening Required:**
* Place behind reverse proxy with authentication
* Use network policies to restrict access
* Consider running as a DaemonSet in Kubernetes with proper RBAC

---

### Prometheus

| Port | Protocol | Default Auth | CVE Examples | Risk Level |
|------|----------|--------------|--------------|------------|
| 9090 | TCP (HTTP) | **NO AUTH** | CVE-2019-3826 | **MEDIUM** |

Prometheus is an open-source monitoring and alerting toolkit designed for reliability and scalability. Out of the box:

* **No authentication** mechanisms are enabled
* Administrative APIs are exposed
* Query interface can reveal sensitive system information

**Attack Scenario:** Exposed Prometheus servers reveal detailed metrics about infrastructure, which attackers use for reconnaissance and to identify vulnerabilities.

**Hardening Required:**
* Implement authentication via reverse proxy
* Configure TLS for encrypted communications
* Use network segmentation
* Implement strict firewall rules

---

### etcd

| Port | Protocol | Default Auth | CVE Examples | Risk Level |
|------|----------|--------------|--------------|------------|
| 2379 | TCP (Client) | **NO AUTH** | CVE-2020-15115 | **CRITICAL** |
| 2380 | TCP (Peer) | **NO AUTH** | | **CRITICAL** |

etcd is a distributed key-value store used as Kubernetes' primary datastore for all cluster data. When improperly configured:

* **No authentication** is required
* Contains complete Kubernetes cluster state
* Stores secrets (though encrypted in newer versions)

**Attack Scenario:** Access to an unauthenticated etcd instance can provide attackers with Kubernetes secrets, certificates, and complete cluster configuration.

**Hardening Required:**
* Enable authentication with strong credentials
* Configure TLS for client and peer communication
* Implement proper network security controls
* Regular credential rotation

---

### RabbitMQ

| Port | Protocol | Default Auth | CVE Examples | Risk Level |
|------|----------|--------------|--------------|------------|
| 5672 | TCP (AMQP) | **DEFAULT CREDS** | CVE-2021-32718 | **HIGH** |
| 15672 | TCP (HTTP) | **DEFAULT CREDS** | | **HIGH** |

RabbitMQ is a message broker that implements AMQP. Unlike some other services, it does require authentication but ships with:

* **Default credentials** (guest/guest)
* Management interface on port 15672
* Default credentials only work from localhost in newer versions

**Attack Scenario:** Attackers with access to RabbitMQ can intercept messages, potentially capturing sensitive information or disrupting message delivery.

**Hardening Required:**
* Remove default users
* Create users with least privilege
* Enable TLS for all connections
* Restrict management plugin access

---

### MongoDB

| Port | Protocol | Default Auth | CVE Examples | Risk Level |
|------|----------|--------------|--------------|------------|
| 27017 | TCP | **NO AUTH** | CVE-2019-2788 | **HIGH** |

MongoDB, a popular NoSQL database, has become infamous for ransomware attacks due to widespread misconfiguration:

* **No authentication** required by default (pre-v3)
* Newer versions require authentication but are often misconfigured
* Commonly exposed directly to the internet

**Attack Scenario:** The "MongoDB Apocalypse" ransomware attacks of 2017 targeted thousands of exposed MongoDB instances, deleting data and demanding ransom for its return.

**Hardening Required:**
* Enable authentication
* Create dedicated users with appropriate privileges
* Bind only to necessary interfaces
* Implement network access controls

---

### Memcached

| Port | Protocol | Default Auth | CVE Examples | Risk Level |
|------|----------|--------------|--------------|------------|
| 11211 | TCP/UDP | **NO AUTH** | CVE-2018-1000115 | **HIGH** |

Memcached, an in-memory key-value store, has been at the center of massive DDoS amplification attacks:

* **No authentication** mechanism available in standard distributions
* No encryption support natively
* Commonly deployed with public exposure

**Attack Scenario:** Beyond data exposure, attackers exploit internet-facing Memcached servers for DDoS amplification, with amplification factors exceeding 50,000x.

**Hardening Required:**
* Never expose to public networks
* Bind to localhost or internal interfaces only
* Implement network-level authentication
* Consider SASL-enabled distributions if authentication is required

---

### CouchDB

| Port | Protocol | Default Auth | CVE Examples | Risk Level |
|------|----------|--------------|--------------|------------|
| 5984 | TCP (HTTP) | **NO AUTH** | CVE-2017-12635 | **HIGH** |
| 6984 | TCP (HTTPS) | **NO AUTH** | | **HIGH** |

Apache CouchDB is a document-oriented NoSQL database with an HTTP API. By default:

* **Admin Party** mode with no authentication (pre-3.0)
* All visitors have administrative privileges
* Version 3.0+ prompts for admin during setup

**Attack Scenario:** Unauthenticated CouchDB access allows attackers to read all documents, modify databases, and potentially execute code through design documents.

**Hardening Required:**
* Create admin users immediately after installation
* Enable HTTPS with valid certificates
* Implement proper firewall rules
* Use proxy authentication when applicable

---

## Vulnerable Service Combinations: Compounding Risk

The risk posed by individual services increases dramatically when multiple vulnerable services are exposed in the same environment. Consider these high-risk combinations:

| Service Combination | Compounded Risk | Attack Path |
|---------------------|-----------------|-------------|
| Redis + Docker API | **CRITICAL** | Use Redis to write SSH keys → gain system access → access Docker API → mount host filesystem |
| Kubernetes API + etcd | **CRITICAL** | Gain cluster configs from etcd → access Kubernetes API → deploy privileged containers |
| Elasticsearch + Kibana | **HIGH** | Extract sensitive data from Elasticsearch → use Kibana for code execution |
| Prometheus + cAdvisor | **HIGH** | Map infrastructure via Prometheus → target specific containers identified via cAdvisor |

These combinations create complete attack chains that allow for efficient compromise with minimal exploitation required.

---

## Detection and Monitoring

Detecting exposed services should be part of regular security assessments. Implement:

1. **External Port Scanning**
   * Regular external scans from multiple geographic locations
   * Service fingerprinting to identify exposed components
   * Authentication testing to verify security controls

2. **Continuous Monitoring**
   * Deploy canaries for sensitive services
   * Monitor for unexpected connection attempts
   * Alert on authentication failures

3. **Network Traffic Analysis**
   * Baseline normal service communications
   * Detect unusual access patterns or data transfers
   * Monitor for typical attack patterns

---

## Security Best Practices Across All Services

While each service has specific security requirements, these universal principles apply:

1. **Default Deny**
   * Begin with all services inaccessible, then explicitly allow required access
   * Never expose administrative interfaces to public networks

2. **Defense in Depth**
   * Layer security controls: network, authentication, authorization
   * Do not rely on single perimeter security

3. **Principle of Least Privilege**
   * Create service-specific accounts with minimal permissions
   * Regularly audit and remove unnecessary privileges

4. **Network Segmentation**
   * Implement proper segmentation for internal services
   * Use internal DNS to avoid hardcoded IPs

5. **Regular Assessments**
   * Conduct internal and external security assessments
   * Verify security configurations after deployments or changes

---

## Conclusion

The explosion of specialized services in modern infrastructure has created a complex security landscape where default configurations often prioritize functionality over security. Understanding the **default authentication state** of critical services is essential for proper security hardening.

Key takeaways:

* Most critical infrastructure services **do not authenticate by default**
* Exposed services provide valuable **reconnaissance information** even when exploitation isn't possible
* **Combinations of vulnerable services** create complete attack paths
* **Proper authentication configuration** is the minimum baseline for security
* **Defense in depth** requires additional security layers beyond authentication

By understanding these default configurations and implementing proper security controls, organizations can significantly reduce their attack surface and prevent common exploitation scenarios.

Remember: in security, defaults are dangerous—explicit configuration is essential.

---

## Appendix: Comprehensive Service Port and Authentication Reference

The following table provides an extensive reference of 70+ critical services categorized by function, their common ports, authentication status, and the reasoning behind their default security configuration.

| Service | Common Port(s) | Unauthenticated by Default | Reason for Default Configuration |
|---------|---------------|----------------------------|----------------------------------|
| **Infrastructure & Containerization** |
| Redis | 6379 | Yes | Designed for internal trusted networks; prioritizes performance and simplicity |
| Docker API | 2375 | Yes | Designed for local development; remote API intended for trusted environments |
| Kubernetes API Server | 8080 (insecure) | Yes | Legacy insecure port; originally designed for testing and internal communication |
| Kubernetes etcd | 2379, 2380 | Yes | Designed as trusted backend component; assumes perimeter security |
| Kubernetes Kubelet | 10250 | Yes | Intended for internal cluster communication only |
| Kubernetes Dashboard | 30000-32767 | Yes (older versions) | Created for ease of use in development environments |
| Docker Registry | 5000 | Yes | Intended for development environments; production use expected to add auth |
| Consul | 8500 (HTTP), 8501 (HTTPS) | Yes | Designed for service-to-service communication in trusted networks |
| Nomad | 4646 | Yes | Designed for internal use with assumed network-level protections |
| Vagrant | 2222 | Yes | Development tool; SSH key authentication handled separately |
| **Databases** |
| MongoDB | 27017 | Yes (pre-v3) | Legacy design prioritized ease of use over security |
| CouchDB | 5984 | Yes (pre-v3) | "Admin Party" mode for ease of setup and development |
| Elasticsearch | 9200, 9300 | Yes (pre-v8) | Originally designed for trusted environments and internal use |
| Cassandra | 9042, 7000 | Yes | Built for trusted internal network deployment |
| InfluxDB | 8086 | Yes (pre-v2) | Optimized for quick setup and metrics collection |
| MySQL | 3306 | No | Uses username/password, but default users may exist |
| PostgreSQL | 5432 | No | Requires authentication but may have local trust configuration |
| Neo4j | 7474, 7687 | Yes (pre-v4) | Designed for developer-friendly startup experience |
| RethinkDB | 8080, 28015 | Yes | Prioritized developer experience and internal use |
| ArangoDB | 8529 | Yes | Web interface accessible without auth for easier setup |
| **Message Brokers & Queues** |
| Apache Kafka | 9092 | Yes | Designed for internal network use with assumed security |
| RabbitMQ | 5672, 15672 | No | Uses default credentials (guest/guest) instead of no auth |
| ActiveMQ | 61616, 8161 | Mixed | Broker requires auth, web console uses default credentials |
| NATS | 4222 | Yes | Optimized for performance in trusted environments |
| ZeroMQ | Variable | Yes | Security handled at application layer, not transport |
| Apache Pulsar | 6650, 8080 | Yes | Original design assumed deployment in secure environments |
| NSQ | 4150, 4151 | Yes | Designed for simplicity in internal deployments |
| EMQ X | 1883, 8083 | Yes | Designed for IoT scenarios with auth at application layer |
| **Caching & In-Memory Systems** |
| Memcached | 11211 | Yes | No authentication mechanism in core design; prioritizes speed |
| Hazelcast | 5701 | Yes | Cluster communication designed for internal networks |
| Ehcache | 9998 | Yes | Intended as embedded or internal component |
| **Monitoring & Metrics** |
| Prometheus | 9090 | Yes | Designed for internal metrics collection without overhead |
| Grafana | 3000 | No | Uses default credentials (admin/admin) |
| cAdvisor | 8080 | Yes | Designed as infrastructure component with assumed security |
| Nagios | 80 | No | Web interface uses default credentials |
| Zabbix | 10051 | Yes | Agent-server protocol without auth; web interface has auth |
| InfluxDB Telegraf | 8125 | Yes | Metrics receiver designed for internal use |
| Graphite | 2003, 8080 | Yes | Original design focused on metrics collection, not security |
| StatsD | 8125 | Yes | Optimized for speed and internal metrics collection |
| Icinga | 5665 | Yes | Agent protocol designed for internal networks |
| **API Gateways & Load Balancers** |
| Nginx | 80, 443 | Yes | Web server/proxy with no auth by default; auth configured per-site |
| HAProxy | 80, 443 | Yes | Proxy layer; authentication implemented at application level |
| Traefik | 80, 8080 | Yes | Dashboard exposed without auth for easier management |
| Kong | 8000, 8001 | Yes | Admin API designed for protected internal access |
| Envoy | 9901 | Yes | Admin interface assumes deployment in secure environment |
| **Storage & File Services** |
| MinIO | 9000 | No | Uses access/secret keys similar to S3 |
| NFS | 2049 | Yes | Relies on IP-based authentication and Unix permissions |
| Samba | 445 | No | Uses username/password or domain authentication |
| GlusterFS | 24007 | Yes | Distributed storage designed for trusted networks |
| Ceph | 6800-7300 | Yes | Internal cluster communication assumes network security |
| WebDAV | 80, 443 | Mixed | Protocol supports auth but often deployed without it |
| **DevOps & CI/CD Tools** |
| Jenkins | 8080 | No | Initial setup requires unlock key, then creates admin user |
| GitLab | 80, 443 | No | Requires user creation during setup |
| GitHub Actions Runner | 80, 443 | No | Uses tokens for authentication |
| TeamCity | 8111 | No | Requires setup of admin user |
| Artifactory | 8081 | No | Uses default credentials (admin/password) |
| Nexus Repository | 8081 | No | Uses default credentials (admin/admin123) |
| SonarQube | 9000 | No | Uses default credentials (admin/admin) |
| **Search Engines** |
| Solr | 8983 | Yes | Originally designed for embedded use with no auth |
| OpenSearch | 9200 | No | Fork of Elasticsearch with security enabled by default |
| Sphinx | 9312, 9306 | Yes | Designed as backend component with assumed security |
| **Service Discovery** |
| etcd | 2379, 2380 | Yes | Key-value store designed for trusted internal networks |
| Apache ZooKeeper | 2181 | Yes | Designed for internal cluster coordination |
| Eureka | 8761 | Yes | Internal service registry for microservices |
| Nacos | 8848 | No | Uses default credentials (nacos/nacos) |
| **Configuration Management** |
| Spring Cloud Config Server | 8888 | Yes | Configuration server often deployed without auth in dev |
| Apache Apollo | 61680 | Yes | Management web interface without default auth |
| **Identity Services** |
| Keycloak | 8080 | No | Identity server with initial admin user creation |
| OpenLDAP | 389, 636 | No | Directory service with mandatory authentication |
| FreeIPA | 80, 443 | No | Identity management with mandatory authentication |
| **Miscellaneous Services** |
| RPC Bind | 111 | Yes | Legacy design from trusted network era |
| CUPS | 631 | Yes | Print server with optional authentication |
| Strapi | 1337 | No | CMS requiring admin setup during installation |
| Jupyter Notebook | 8888 | Yes | Development tool using token-based auth but easily disabled |
| Ghost | 2368 | No | CMS with setup wizard for admin user |
| Kibana | 5601 | Yes (pre-v8) | Analytics UI for Elasticsearch following same security model |
| Apache Airflow | 8080 | No | Uses default credentials (airflow/airflow) |
| phpMyAdmin | 80 | No | Requires database credentials |
| Portainer | 9000 | No | Requires admin setup on first launch |
| RStudio Server | 8787 | No | Uses system authentication |
| Node-RED | 1880 | Yes | Development tool designed for easier access |
| Home Assistant | 8123 | No | Smart home platform requiring user setup |
| Superset | 8088 | No | Analytics platform with user authentication |
| WordPress | 80, 443 | No | CMS requiring admin setup |
| Drupal | 80, 443 | No | CMS requiring installation and admin setup |
| Joomla | 80, 443 | No | CMS requiring installation and admin setup |

### Why Services Often Lack Authentication By Default

Many critical services ship without authentication by default for several key reasons:

1. **Historical Context**: Many services were designed during an era when internal networks were considered trusted, and external firewalls were the primary security control.

2. **Performance Considerations**: Authentication adds overhead to every request. Services prioritizing high throughput or low latency often omit authentication.

3. **Developer Experience**: Faster setup and easier debugging drive adoption. Authentication adds complexity during development.

4. **Internal Component Assumption**: Many services were designed to be internal components protected by other layers of security, not directly exposed.

5. **Segregation of Concerns**: Some services delegate authentication to frontend proxies or API gateways rather than implementing it themselves.

6. **Configuration Over Convention**: Certain services expect operators to configure security based on their specific needs, rather than enforcing opinions.

7. **Backward Compatibility**: Services maintain insecure defaults to avoid breaking existing deployments.

This explains why even modern infrastructure components often require explicit security hardening, creating an "insecure by default" problem that continues to plague many deployments.

