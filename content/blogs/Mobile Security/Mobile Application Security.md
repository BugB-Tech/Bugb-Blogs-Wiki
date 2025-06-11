---
title: "Mobile Application Security: From Static Analysis to Runtime Exploitation"
slug: "mobile-application-security-static-analysis-runtime-exploitation"
date: "2025-06-12"
author: "BugB Security Team"
authorTitle: "Security Researchers"
excerpt: "Comprehensive guide to mobile application security testing across Android and iOS platforms, covering static analysis, dynamic testing, runtime manipulation, and advanced exploitation techniques."
category: "mobile-security"
---

# Mobile Application Security: From Static Analysis to Runtime Exploitation

Mobile applications have become the primary interface between users and digital services, handling everything from financial transactions to personal communications. This ubiquity, combined with the inherent complexity of mobile platforms, creates a rich attack surface that requires specialized security assessment techniques.

This comprehensive analysis explores advanced mobile application security testing methodologies, covering both Android and iOS platforms with practical tools and techniques for identifying and exploiting vulnerabilities that traditional testing approaches often miss.

## Mobile Security Landscape Overview

### The Mobile Threat Ecosystem

Modern mobile applications face threats across multiple vectors, from platform-level vulnerabilities to application-specific flaws:

| Threat Category | Android Prevalence | iOS Prevalence | Common Attack Vectors |
|-----------------|-------------------|----------------|----------------------|
| **Insecure Data Storage** | 89% | 76% | Unencrypted databases, logs, temp files |
| **Insecure Communication** | 84% | 68% | HTTP usage, certificate pinning bypass |
| **Insufficient Authentication** | 72% | 58% | Weak session management, biometric bypass |
| **Client-Side Injection** | 67% | 45% | SQLi, XSS in WebView, command injection |
| **Insecure Authorization** | 78% | 62% | Privilege escalation, function-level access control |
| **Poor Code Quality** | 85% | 71% | Buffer overflows, race conditions, logic flaws |
| **Reverse Engineering** | 92% | 34% | Code obfuscation bypass, runtime manipulation |
| **Extraneous Functionality** | 43% | 38% | Debug flags, test endpoints, admin interfaces |

### Platform-Specific Security Models

```
┌─────────────────────────────────────────────────────────────┐
│                    Android Security Architecture             │
├─────────────────────────────────────────────────────────────┤
│ Application Layer    │ APK, ART Runtime, Permissions       │
├─────────────────────────────────────────────────────────────┤
│ Framework Layer      │ Android Framework, System Services   │
├─────────────────────────────────────────────────────────────┤
│ Runtime Layer        │ ART/Dalvik, Native Libraries        │
├─────────────────────────────────────────────────────────────┤
│ Kernel Layer         │ Linux Kernel, SELinux               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    iOS Security Architecture                │
├─────────────────────────────────────────────────────────────┤
│ Application Layer    │ Apps, iOS Framework, Entitlements   │
├─────────────────────────────────────────────────────────────┤
│ System Layer         │ Cocoa Touch, Core Services          │
├─────────────────────────────────────────────────────────────┤
│ Runtime Layer        │ Objective-C Runtime, Swift Runtime  │
├─────────────────────────────────────────────────────────────┤
│ Kernel Layer         │ XNU Kernel, Secure Enclave         │
└─────────────────────────────────────────────────────────────┘
```

---

## Android Security Assessment Framework

### Static Analysis and Reverse Engineering

#### APK Analysis and Decompilation

```python
#!/usr/bin/env python3
"""
Android Application Security Assessment Framework
Comprehensive APK analysis and vulnerability detection
"""

import os
import re
import json
import subprocess
import xml.etree.ElementTree as ET
from zipfile import ZipFile
import hashlib

class AndroidSecurityAnalyzer:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.vulnerabilities = []
        self.app_info = {}
        self.extracted_path = None
        
    def analyze_apk(self):
        """Comprehensive APK security analysis"""
        
        analysis_results = {
            "app_info": self.extract_app_info(),
            "manifest_analysis": self.analyze_manifest(),
            "permission_analysis": self.analyze_permissions(),
            "code_analysis": self.analyze_code(),
            "resource_analysis": self.analyze_resources(),
            "crypto_analysis": self.analyze_cryptography(),
            "network_analysis": self.analyze_network_security(),
            "storage_analysis": self.analyze_data_storage()
        }
        
        return analysis_results
    
    def extract_app_info(self):
        """Extract basic application information"""
        try:
            # Use aapt to extract app info
            aapt_output = subprocess.run([
                'aapt', 'dump', 'badging', self.apk_path
            ], capture_output=True, text=True)
            
            if aapt_output.returncode != 0:
                return {"error": "Failed to extract app info"}
            
            app_info = {}
            
            # Parse aapt output
            for line in aapt_output.stdout.split('\n'):
                if line.startswith('package:'):
                    # Extract package name and version
                    package_match = re.search(r"name='([^']+)'", line)
                    version_match = re.search(r"versionName='([^']+)'", line)
                    
                    if package_match:
                        app_info['package_name'] = package_match.group(1)
                    if version_match:
                        app_info['version'] = version_match.group(1)
                
                elif line.startswith('application-label:'):
                    label_match = re.search(r"'([^']+)'", line)
                    if label_match:
                        app_info['app_name'] = label_match.group(1)
                
                elif line.startswith('targetSdkVersion:'):
                    sdk_match = re.search(r"'(\d+)'", line)
                    if sdk_match:
                        app_info['target_sdk'] = int(sdk_match.group(1))
            
            # Calculate APK hash
            with open(self.apk_path, 'rb') as f:
                app_info['sha256'] = hashlib.sha256(f.read()).hexdigest()
            
            self.app_info = app_info
            return app_info
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_manifest(self):
        """Analyze AndroidManifest.xml for security issues"""
        manifest_findings = []
        
        try:
            # Extract manifest using aapt
            manifest_output = subprocess.run([
                'aapt', 'dump', 'xmltree', self.apk_path, 'AndroidManifest.xml'
            ], capture_output=True, text=True)
            
            if manifest_output.returncode != 0:
                return [{"error": "Failed to extract manifest"}]
            
            manifest_content = manifest_output.stdout
            
            # Check for debug flag
            if 'android:debuggable=true' in manifest_content:
                manifest_findings.append({
                    "type": "DEBUG_ENABLED",
                    "severity": "HIGH",
                    "description": "Application is debuggable in production",
                    "impact": "Attackers can debug and modify app behavior"
                })
            
            # Check for backup allowed
            if 'android:allowBackup=true' in manifest_content or 'android:allowBackup' not in manifest_content:
                manifest_findings.append({
                    "type": "BACKUP_ALLOWED",
                    "severity": "MEDIUM",
                    "description": "Application allows backup of sensitive data",
                    "impact": "Sensitive data can be extracted via ADB backup"
                })
            
            # Check for exported components without permission
            exported_components = re.findall(r'(activity|service|receiver|provider).*android:exported=true', manifest_content)
            for component in exported_components:
                if 'android:permission' not in component:
                    manifest_findings.append({
                        "type": "EXPORTED_COMPONENT_WITHOUT_PERMISSION",
                        "severity": "HIGH",
                        "component_type": component,
                        "description": f"Exported {component} without permission protection",
                        "impact": "Unauthorized access to application components"
                    })
            
            # Check for insecure content providers
            if 'android:grantUriPermissions=true' in manifest_content:
                manifest_findings.append({
                    "type": "GRANT_URI_PERMISSIONS",
                    "severity": "MEDIUM",
                    "description": "Content provider grants URI permissions",
                    "impact": "Potential unauthorized access to content"
                })
            
            # Check for network security config
            if 'android:networkSecurityConfig' not in manifest_content:
                manifest_findings.append({
                    "type": "NO_NETWORK_SECURITY_CONFIG",
                    "severity": "MEDIUM",
                    "description": "No network security configuration specified",
                    "impact": "May allow insecure network communications"
                })
            
            # Check for custom URL schemes
            custom_schemes = re.findall(r'android:scheme="([^"]+)"', manifest_content)
            for scheme in custom_schemes:
                if scheme not in ['http', 'https', 'ftp']:
                    manifest_findings.append({
                        "type": "CUSTOM_URL_SCHEME",
                        "severity": "LOW",
                        "scheme": scheme,
                        "description": f"Custom URL scheme: {scheme}",
                        "impact": "Potential deep link hijacking"
                    })
            
            return manifest_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def analyze_permissions(self):
        """Analyze requested permissions for privacy and security issues"""
        permission_findings = []
        
        try:
            # Extract permissions using aapt
            perm_output = subprocess.run([
                'aapt', 'dump', 'permissions', self.apk_path
            ], capture_output=True, text=True)
            
            if perm_output.returncode != 0:
                return [{"error": "Failed to extract permissions"}]
            
            permissions = []
            for line in perm_output.stdout.split('\n'):
                if line.startswith('uses-permission:'):
                    perm_match = re.search(r"name='([^']+)'", line)
                    if perm_match:
                        permissions.append(perm_match.group(1))
            
            # Categorize permissions by risk level
            dangerous_permissions = [
                'android.permission.READ_SMS',
                'android.permission.SEND_SMS',
                'android.permission.READ_CONTACTS',
                'android.permission.READ_CALL_LOG',
                'android.permission.RECORD_AUDIO',
                'android.permission.CAMERA',
                'android.permission.ACCESS_FINE_LOCATION',
                'android.permission.READ_EXTERNAL_STORAGE',
                'android.permission.WRITE_EXTERNAL_STORAGE'
            ]
            
            suspicious_permissions = [
                'android.permission.INSTALL_PACKAGES',
                'android.permission.DELETE_PACKAGES',
                'android.permission.CHANGE_WIFI_STATE',
                'android.permission.MODIFY_PHONE_STATE',
                'android.permission.MOUNT_UNMOUNT_FILESYSTEMS',
                'android.permission.SYSTEM_ALERT_WINDOW'
            ]
            
            for permission in permissions:
                if permission in dangerous_permissions:
                    permission_findings.append({
                        "type": "DANGEROUS_PERMISSION",
                        "severity": "MEDIUM",
                        "permission": permission,
                        "description": f"App requests dangerous permission: {permission}",
                        "impact": "Access to sensitive user data"
                    })
                
                elif permission in suspicious_permissions:
                    permission_findings.append({
                        "type": "SUSPICIOUS_PERMISSION",
                        "severity": "HIGH",
                        "permission": permission,
                        "description": f"App requests suspicious permission: {permission}",
                        "impact": "Potential malicious behavior"
                    })
            
            # Check for permission combinations that indicate malware
            malware_combinations = [
                (['android.permission.SEND_SMS', 'android.permission.READ_CONTACTS'], "SMS malware"),
                (['android.permission.RECORD_AUDIO', 'android.permission.ACCESS_FINE_LOCATION'], "Surveillance app"),
                (['android.permission.CAMERA', 'android.permission.RECORD_AUDIO', 'android.permission.ACCESS_FINE_LOCATION'], "Spyware")
            ]
            
            for perm_combo, malware_type in malware_combinations:
                if all(perm in permissions for perm in perm_combo):
                    permission_findings.append({
                        "type": "MALWARE_PERMISSION_PATTERN",
                        "severity": "CRITICAL",
                        "permissions": perm_combo,
                        "malware_type": malware_type,
                        "description": f"Permission combination indicates possible {malware_type}",
                        "impact": "High risk of malicious behavior"
                    })
            
            return permission_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def analyze_code(self):
        """Static code analysis for security vulnerabilities"""
        code_findings = []
        
        try:
            # Extract APK contents
            extract_dir = f"/tmp/apk_extract_{os.getpid()}"
            os.makedirs(extract_dir, exist_ok=True)
            
            with ZipFile(self.apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            self.extracted_path = extract_dir
            
            # Decompile DEX to Java using jadx
            java_dir = f"{extract_dir}/java_src"
            jadx_result = subprocess.run([
                'jadx', '-d', java_dir, self.apk_path
            ], capture_output=True, text=True)
            
            if jadx_result.returncode == 0:
                # Analyze Java source code
                code_findings.extend(self._analyze_java_source(java_dir))
            
            # Analyze native libraries
            lib_dir = f"{extract_dir}/lib"
            if os.path.exists(lib_dir):
                code_findings.extend(self._analyze_native_libraries(lib_dir))
            
            return code_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def _analyze_java_source(self, java_dir):
        """Analyze decompiled Java source for vulnerabilities"""
        java_findings = []
        
        try:
            # Security patterns to search for
            security_patterns = [
                {
                    "pattern": r"Log\.(d|e|i|v|w)\s*\(",
                    "type": "LOGGING_SENSITIVE_DATA",
                    "severity": "MEDIUM",
                    "description": "Application logs may contain sensitive data"
                },
                {
                    "pattern": r"webView\.getSettings\(\)\.setJavaScriptEnabled\(true\)",
                    "type": "JAVASCRIPT_ENABLED_WEBVIEW",
                    "severity": "HIGH",
                    "description": "WebView has JavaScript enabled"
                },
                {
                    "pattern": r"addJavascriptInterface\(",
                    "type": "JAVASCRIPT_INTERFACE",
                    "severity": "CRITICAL",
                    "description": "WebView exposes Java objects to JavaScript"
                },
                {
                    "pattern": r"MODE_WORLD_READABLE|MODE_WORLD_WRITABLE",
                    "type": "WORLD_READABLE_WRITABLE",
                    "severity": "HIGH",
                    "description": "File created with world readable/writable permissions"
                },
                {
                    "pattern": r"Runtime\.getRuntime\(\)\.exec\(",
                    "type": "COMMAND_EXECUTION",
                    "severity": "HIGH",
                    "description": "Application executes system commands"
                },
                {
                    "pattern": r"HttpURLConnection|DefaultHttpClient",
                    "type": "HTTP_CONNECTION",
                    "severity": "MEDIUM",
                    "description": "Application may use insecure HTTP connections"
                },
                {
                    "pattern": r"TrustAllX509TrustManager|NullHostnameVerifier",
                    "type": "TRUST_ALL_CERTIFICATES",
                    "severity": "CRITICAL",
                    "description": "Application trusts all SSL certificates"
                },
                {
                    "pattern": r"SecureRandom\(\)\.setSeed\(",
                    "type": "WEAK_RANDOM_SEED",
                    "severity": "HIGH",
                    "description": "SecureRandom uses predictable seed"
                }
            ]
            
            # Search for patterns in Java files
            for root, dirs, files in os.walk(java_dir):
                for file in files:
                    if file.endswith('.java'):
                        file_path = os.path.join(root, file)
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                                for pattern_info in security_patterns:
                                    matches = re.findall(pattern_info["pattern"], content, re.IGNORECASE)
                                    
                                    if matches:
                                        java_findings.append({
                                            "type": pattern_info["type"],
                                            "severity": pattern_info["severity"],
                                            "description": pattern_info["description"],
                                            "file": file_path,
                                            "matches": len(matches),
                                            "sample_match": matches[0] if matches else None
                                        })
                        except Exception:
                            continue
            
            # Look for hardcoded secrets
            java_findings.extend(self._find_hardcoded_secrets(java_dir))
            
        except Exception as e:
            java_findings.append({"error": str(e)})
        
        return java_findings
    
    def _find_hardcoded_secrets(self, java_dir):
        """Find hardcoded secrets in source code"""
        secret_findings = []
        
        secret_patterns = [
            {
                "pattern": r"['\"](?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
                "type": "HARDCODED_PASSWORD",
                "severity": "CRITICAL"
            },
            {
                "pattern": r"['\"](?:api_key|apikey|api-key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9]{16,})['\"]",
                "type": "HARDCODED_API_KEY",
                "severity": "HIGH"
            },
            {
                "pattern": r"['\"](?:secret|secret_key)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9]{16,})['\"]",
                "type": "HARDCODED_SECRET",
                "severity": "HIGH"
            },
            {
                "pattern": r"['\"](?:token|auth_token)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9]{20,})['\"]",
                "type": "HARDCODED_TOKEN",
                "severity": "HIGH"
            }
        ]
        
        for root, dirs, files in os.walk(java_dir):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for pattern_info in secret_patterns:
                                matches = re.findall(pattern_info["pattern"], content, re.IGNORECASE)
                                
                                for match in matches:
                                    secret_findings.append({
                                        "type": pattern_info["type"],
                                        "severity": pattern_info["severity"],
                                        "description": f"Hardcoded secret found in {file}",
                                        "file": file_path,
                                        "secret_preview": match[:10] + "..." if len(match) > 10 else match
                                    })
                    except Exception:
                        continue
        
        return secret_findings
    
    def _analyze_native_libraries(self, lib_dir):
        """Analyze native libraries for security issues"""
        native_findings = []
        
        try:
            for root, dirs, files in os.walk(lib_dir):
                for file in files:
                    if file.endswith('.so'):
                        lib_path = os.path.join(root, file)
                        
                        # Check for debugging symbols
                        strings_output = subprocess.run([
                            'strings', lib_path
                        ], capture_output=True, text=True)
                        
                        if strings_output.returncode == 0:
                            strings_content = strings_output.stdout
                            
                            # Look for debug strings
                            if any(debug_str in strings_content for debug_str in ['printf', 'fprintf', 'debug', 'DEBUG']):
                                native_findings.append({
                                    "type": "DEBUG_SYMBOLS_PRESENT",
                                    "severity": "LOW",
                                    "file": lib_path,
                                    "description": "Native library contains debug symbols"
                                })
                            
                            # Look for dangerous functions
                            dangerous_functions = ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf']
                            for func in dangerous_functions:
                                if func in strings_content:
                                    native_findings.append({
                                        "type": "DANGEROUS_FUNCTION_USAGE",
                                        "severity": "HIGH",
                                        "file": lib_path,
                                        "function": func,
                                        "description": f"Native library uses dangerous function: {func}"
                                    })
                        
                        # Check for stack protector
                        readelf_output = subprocess.run([
                            'readelf', '-s', lib_path
                        ], capture_output=True, text=True)
                        
                        if readelf_output.returncode == 0 and '__stack_chk_fail' not in readelf_output.stdout:
                            native_findings.append({
                                "type": "NO_STACK_PROTECTION",
                                "severity": "MEDIUM",
                                "file": lib_path,
                                "description": "Native library compiled without stack protection"
                            })
        
        except Exception as e:
            native_findings.append({"error": str(e)})
        
        return native_findings
    
    def analyze_cryptography(self):
        """Analyze cryptographic implementation"""
        crypto_findings = []
        
        if not self.extracted_path:
            return crypto_findings
        
        try:
            # Search for cryptographic patterns in decompiled code
            java_dir = f"{self.extracted_path}/java_src"
            
            crypto_patterns = [
                {
                    "pattern": r"DES|3DES|RC4|MD5|SHA1",
                    "type": "WEAK_CRYPTOGRAPHY",
                    "severity": "HIGH",
                    "description": "Use of weak cryptographic algorithms"
                },
                {
                    "pattern": r"AES/ECB",
                    "type": "ECB_MODE_USAGE",
                    "severity": "HIGH",
                    "description": "AES used in insecure ECB mode"
                },
                {
                    "pattern": r"KeyGenerator\.getInstance\(['\"]AES['\"]",
                    "type": "AES_KEY_GENERATION",
                    "severity": "INFO",
                    "description": "AES key generation detected"
                },
                {
                    "pattern": r"new\s+SecretKeySpec\(",
                    "type": "HARDCODED_KEY",
                    "severity": "CRITICAL",
                    "description": "Potentially hardcoded cryptographic key"
                }
            ]
            
            if os.path.exists(java_dir):
                for root, dirs, files in os.walk(java_dir):
                    for file in files:
                        if file.endswith('.java'):
                            file_path = os.path.join(root, file)
                            
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    
                                    for pattern_info in crypto_patterns:
                                        if re.search(pattern_info["pattern"], content, re.IGNORECASE):
                                            crypto_findings.append({
                                                "type": pattern_info["type"],
                                                "severity": pattern_info["severity"],
                                                "description": pattern_info["description"],
                                                "file": file_path
                                            })
                            except Exception:
                                continue
        
        except Exception as e:
            crypto_findings.append({"error": str(e)})
        
        return crypto_findings

def generate_android_dynamic_analysis():
    """Generate Android dynamic analysis framework"""
    
    dynamic_analysis_code = '''
#!/usr/bin/env python3
"""
Android Dynamic Analysis Framework
Runtime security testing using Frida
"""

import frida
import sys
import json
import time

class AndroidDynamicAnalyzer:
    def __init__(self, package_name):
        self.package_name = package_name
        self.session = None
        self.hooks = []
    
    def attach_to_app(self):
        """Attach to running Android application"""
        try:
            device = frida.get_usb_device()
            self.session = device.attach(self.package_name)
            print(f"[+] Attached to {self.package_name}")
            return True
        except Exception as e:
            print(f"[-] Failed to attach: {e}")
            return False
    
    def hook_crypto_functions(self):
        """Hook cryptographic functions"""
        crypto_script = """
        Java.perform(function() {
            // Hook AES encryption
            var Cipher = Java.use("javax.crypto.Cipher");
            Cipher.doFinal.overload('[B').implementation = function(input) {
                console.log("[*] AES Encryption detected");
                console.log("    Algorithm: " + this.getAlgorithm());
                console.log("    Input: " + Java.use("java.util.Arrays").toString(input));
                
                var result = this.doFinal(input);
                console.log("    Output: " + Java.use("java.util.Arrays").toString(result));
                return result;
            };
            
            // Hook key generation
            var KeyGenerator = Java.use("javax.crypto.KeyGenerator");
            KeyGenerator.generateKey.implementation = function() {
                console.log("[*] Key generation: " + this.getAlgorithm());
                return this.generateKey();
            };
        });
        """
        
        script = self.session.create_script(crypto_script)
        script.on('message', self._on_message)
        script.load()
        self.hooks.append(script)
    
    def hook_network_functions(self):
        """Hook network communication functions"""
        network_script = """
        Java.perform(function() {
            // Hook HTTP requests
            var URL = Java.use("java.net.URL");
            URL.$init.overload('java.lang.String').implementation = function(url) {
                console.log("[*] HTTP Request: " + url);
                return this.$init(url);
            };
            
            // Hook SSL context
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            SSLContext.init.implementation = function(km, tm, sr) {
                console.log("[*] SSL Context initialized");
                if (tm != null) {
                    console.log("    Trust managers: " + tm.length);
                }
                return this.init(km, tm, sr);
            };
            
            // Hook certificate validation
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            X509TrustManager.checkServerTrusted.implementation = function(chain, authType) {
                console.log("[*] Certificate validation bypassed!");
                return;
            };
        });
        """
        
        script = self.session.create_script(network_script)
        script.on('message', self._on_message)
        script.load()
        self.hooks.append(script)
    
    def hook_file_operations(self):
        """Hook file system operations"""
        file_script = """
        Java.perform(function() {
            // Hook file creation
            var File = Java.use("java.io.File");
            File.$init.overload('java.lang.String').implementation = function(pathname) {
                console.log("[*] File access: " + pathname);
                return this.$init(pathname);
            };
            
            // Hook shared preferences
            var SharedPreferences = Java.use("android.content.SharedPreferences");
            var Editor = Java.use("android.content.SharedPreferences$Editor");
            
            Editor.putString.implementation = function(key, value) {
                console.log("[*] SharedPreferences write:");
                console.log("    Key: " + key);
                console.log("    Value: " + value);
                return this.putString(key, value);
            };
        });
        """
        
        script = self.session.create_script(file_script)
        script.on('message', self._on_message)
        script.load()
        self.hooks.append(script)
    
    def hook_sensitive_apis(self):
        """Hook sensitive API calls"""
        sensitive_script = """
        Java.perform(function() {
            // Hook location access
            var LocationManager = Java.use("android.location.LocationManager");
            LocationManager.getLastKnownLocation.implementation = function(provider) {
                console.log("[*] Location access: " + provider);
                return this.getLastKnownLocation(provider);
            };
            
            // Hook contact access
            var ContactsContract = Java.use("android.provider.ContactsContract");
            // Hook database queries that might access contacts
            
            // Hook SMS access
            var SmsManager = Java.use("android.telephony.SmsManager");
            SmsManager.sendTextMessage.implementation = function(dest, scAddr, text, sentIntent, deliveryIntent) {
                console.log("[*] SMS sent to: " + dest);
                console.log("    Text: " + text);
                return this.sendTextMessage(dest, scAddr, text, sentIntent, deliveryIntent);
            };
        });
        """
        
        script = self.session.create_script(sensitive_script)
        script.on('message', self._on_message)
        script.load()
        self.hooks.append(script)
    
    def bypass_root_detection(self):
        """Bypass common root detection mechanisms"""
        root_bypass_script = """
        Java.perform(function() {
            // Hook common root detection methods
            
            // Bypass su binary check
            var Runtime = Java.use("java.lang.Runtime");
            Runtime.exec.overload('java.lang.String').implementation = function(command) {
                if (command.indexOf("su") !== -1) {
                    console.log("[*] Root detection bypassed: " + command);
                    throw new Error("Command not found");
                }
                return this.exec(command);
            };
            
            // Bypass file existence check for root files
            var File = Java.use("java.io.File");
            File.exists.implementation = function() {
                var path = this.getAbsolutePath();
                if (path.indexOf("/system/bin/su") !== -1 || 
                    path.indexOf("/system/xbin/su") !== -1 ||
                    path.indexOf("/system/app/Superuser.apk") !== -1) {
                    console.log("[*] Root file check bypassed: " + path);
                    return false;
                }
                return this.exists();
            };
            
            // Bypass build.prop check
            var SystemProperties = Java.use("android.os.SystemProperties");
            SystemProperties.get.overload('java.lang.String').implementation = function(key) {
                if (key === "ro.build.tags") {
                    console.log("[*] Build tags check bypassed");
                    return "release-keys";
                }
                return this.get(key);
            };
        });
        """
        
        script = self.session.create_script(root_bypass_script)
        script.on('message', self._on_message)
        script.load()
        self.hooks.append(script)
    
    def _on_message(self, message, data):
        """Handle messages from Frida scripts"""
        if message['type'] == 'send':
            print(f"[Frida] {message['payload']}")
        elif message['type'] == 'error':
            print(f"[Error] {message['stack']}")
    
    def start_monitoring(self):
        """Start comprehensive monitoring"""
        if not self.attach_to_app():
            return False
        
        print("[*] Setting up hooks...")
        self.hook_crypto_functions()
        self.hook_network_functions()
        self.hook_file_operations()
        self.hook_sensitive_apis()
        self.bypass_root_detection()
        
        print("[*] Monitoring started. Press Ctrl+C to stop.")
        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            print("\\n[*] Stopping monitoring...")
            self.session.detach()

# Usage
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 android_dynamic.py <package_name>")
        sys.exit(1)
    
    analyzer = AndroidDynamicAnalyzer(sys.argv[1])
    analyzer.start_monitoring()
'''
    
    return dynamic_analysis_code
```

---

## iOS Security Assessment Framework

### iOS Application Analysis

```python
#!/usr/bin/env python3
"""
iOS Application Security Assessment Framework
IPA analysis and iOS-specific vulnerability detection
"""

import os
import plistlib
import subprocess
import zipfile
import re
import json

class iOSSecurityAnalyzer:
    def __init__(self, ipa_path):
        self.ipa_path = ipa_path
        self.vulnerabilities = []
        self.app_info = {}
        self.extracted_path = None
    
    def analyze_ipa(self):
        """Comprehensive IPA security analysis"""
        
        analysis_results = {
            "app_info": self.extract_app_info(),
            "plist_analysis": self.analyze_info_plist(),
            "entitlements_analysis": self.analyze_entitlements(),
            "binary_analysis": self.analyze_binary(),
            "code_analysis": self.analyze_code(),
            "transport_security": self.analyze_transport_security(),
            "keychain_analysis": self.analyze_keychain_usage(),
            "url_scheme_analysis": self.analyze_url_schemes()
        }
        
        return analysis_results
    
    def extract_app_info(self):
        """Extract basic iOS application information"""
        try:
            # Extract IPA contents
            extract_dir = f"/tmp/ipa_extract_{os.getpid()}"
            os.makedirs(extract_dir, exist_ok=True)
            
            with zipfile.ZipFile(self.ipa_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            self.extracted_path = extract_dir
            
            # Find .app directory
            payload_dir = os.path.join(extract_dir, 'Payload')
            app_dirs = [d for d in os.listdir(payload_dir) if d.endswith('.app')]
            
            if not app_dirs:
                return {"error": "No .app directory found"}
            
            app_dir = os.path.join(payload_dir, app_dirs[0])
            
            # Read Info.plist
            info_plist_path = os.path.join(app_dir, 'Info.plist')
            if os.path.exists(info_plist_path):
                with open(info_plist_path, 'rb') as f:
                    plist_data = plistlib.load(f)
                
                app_info = {
                    "bundle_id": plist_data.get('CFBundleIdentifier'),
                    "app_name": plist_data.get('CFBundleDisplayName', plist_data.get('CFBundleName')),
                    "version": plist_data.get('CFBundleShortVersionString'),
                    "build": plist_data.get('CFBundleVersion'),
                    "minimum_os": plist_data.get('MinimumOSVersion'),
                    "supported_platforms": plist_data.get('CFBundleSupportedPlatforms', []),
                    "app_dir": app_dir
                }
                
                self.app_info = app_info
                return app_info
            
            return {"error": "Info.plist not found"}
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_info_plist(self):
        """Analyze Info.plist for security issues"""
        plist_findings = []
        
        try:
            app_dir = self.app_info.get('app_dir')
            if not app_dir:
                return [{"error": "App directory not found"}]
            
            info_plist_path = os.path.join(app_dir, 'Info.plist')
            
            with open(info_plist_path, 'rb') as f:
                plist_data = plistlib.load(f)
            
            # Check for debug configuration
            if plist_data.get('UIFileSharingEnabled'):
                plist_findings.append({
                    "type": "FILE_SHARING_ENABLED",
                    "severity": "MEDIUM",
                    "description": "iTunes file sharing is enabled",
                    "impact": "App documents accessible via iTunes"
                })
            
            # Check for URL schemes
            url_types = plist_data.get('CFBundleURLTypes', [])
            for url_type in url_types:
                schemes = url_type.get('CFBundleURLSchemes', [])
                for scheme in schemes:
                    if len(scheme) < 8:  # Short schemes are more prone to hijacking
                        plist_findings.append({
                            "type": "SHORT_URL_SCHEME",
                            "severity": "MEDIUM",
                            "scheme": scheme,
                            "description": f"Short URL scheme '{scheme}' prone to hijacking",
                            "impact": "URL scheme hijacking attacks"
                        })
            
            # Check for background modes
            background_modes = plist_data.get('UIBackgroundModes', [])
            dangerous_background_modes = ['background-processing', 'background-fetch', 'silent-push']
            
            for mode in background_modes:
                if mode in dangerous_background_modes:
                    plist_findings.append({
                        "type": "BACKGROUND_MODE_USAGE",
                        "severity": "LOW",
                        "mode": mode,
                        "description": f"App uses background mode: {mode}",
                        "impact": "Extended background execution capabilities"
                    })
            
            # Check for camera/microphone usage without description
            sensitive_permissions = {
                'NSCameraUsageDescription': 'camera',
                'NSMicrophoneUsageDescription': 'microphone',
                'NSLocationWhenInUseUsageDescription': 'location',
                'NSContactsUsageDescription': 'contacts',
                'NSPhotoLibraryUsageDescription': 'photo library'
            }
            
            for perm_key, perm_name in sensitive_permissions.items():
                if perm_key in plist_data:
                    description = plist_data[perm_key]
                    if not description or len(description.strip()) < 10:
                        plist_findings.append({
                            "type": "INSUFFICIENT_PERMISSION_DESCRIPTION",
                            "severity": "LOW",
                            "permission": perm_name,
                            "description": f"Insufficient usage description for {perm_name}",
                            "impact": "App Store rejection or user confusion"
                        })
            
            return plist_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def analyze_entitlements(self):
        """Analyze app entitlements for security issues"""
        entitlements_findings = []
        
        try:
            app_dir = self.app_info.get('app_dir')
            if not app_dir:
                return [{"error": "App directory not found"}]
            
            # Extract entitlements from binary
            app_name = self.app_info.get('app_name', 'app')
            binary_path = os.path.join(app_dir, app_name)
            
            if not os.path.exists(binary_path):
                # Try to find the binary
                binaries = [f for f in os.listdir(app_dir) 
                           if os.path.isfile(os.path.join(app_dir, f)) and not f.startswith('.')]
                if binaries:
                    binary_path = os.path.join(app_dir, binaries[0])
                else:
                    return [{"error": "Binary not found"}]
            
            # Use codesign to extract entitlements
            codesign_result = subprocess.run([
                'codesign', '-d', '--entitlements', ':-', binary_path
            ], capture_output=True, text=True)
            
            if codesign_result.returncode == 0:
                entitlements_xml = codesign_result.stdout
                
                # Parse entitlements for dangerous capabilities
                dangerous_entitlements = [
                    'com.apple.developer.kernel.increased-memory-limit',
                    'com.apple.developer.networking.networkextension',
                    'com.apple.security.network.server',
                    'com.apple.security.network.client',
                    'com.apple.developer.homekit',
                    'com.apple.developer.healthkit'
                ]
                
                for entitlement in dangerous_entitlements:
                    if entitlement in entitlements_xml:
                        entitlements_findings.append({
                            "type": "DANGEROUS_ENTITLEMENT",
                            "severity": "MEDIUM",
                            "entitlement": entitlement,
                            "description": f"App has dangerous entitlement: {entitlement}",
                            "impact": "Extended system capabilities"
                        })
                
                # Check for keychain access groups
                if 'keychain-access-groups' in entitlements_xml:
                    entitlements_findings.append({
                        "type": "KEYCHAIN_ACCESS_GROUPS",
                        "severity": "INFO",
                        "description": "App has keychain access group entitlements",
                        "impact": "Shared keychain access with other apps"
                    })
            
            return entitlements_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def analyze_binary(self):
        """Analyze iOS binary for security protections"""
        binary_findings = []
        
        try:
            app_dir = self.app_info.get('app_dir')
            if not app_dir:
                return [{"error": "App directory not found"}]
            
            # Find main binary
            app_name = self.app_info.get('app_name', 'app')
            binary_path = os.path.join(app_dir, app_name)
            
            if not os.path.exists(binary_path):
                binaries = [f for f in os.listdir(app_dir) 
                           if os.path.isfile(os.path.join(app_dir, f)) and not f.startswith('.')]
                if binaries:
                    binary_path = os.path.join(app_dir, binaries[0])
                else:
                    return [{"error": "Binary not found"}]
            
            # Check for binary protections using otool
            otool_result = subprocess.run([
                'otool', '-hv', binary_path
            ], capture_output=True, text=True)
            
            if otool_result.returncode == 0:
                otool_output = otool_result.stdout
                
                # Check for PIE (Position Independent Executable)
                if 'PIE' not in otool_output:
                    binary_findings.append({
                        "type": "NO_PIE_PROTECTION",
                        "severity": "MEDIUM",
                        "description": "Binary not compiled with PIE protection",
                        "impact": "Vulnerable to ROP/JOP attacks"
                    })
                
                # Check for stack canaries
                strings_result = subprocess.run([
                    'strings', binary_path
                ], capture_output=True, text=True)
                
                if strings_result.returncode == 0:
                    strings_output = strings_result.stdout
                    
                    if '__stack_chk_fail' not in strings_output:
                        binary_findings.append({
                            "type": "NO_STACK_CANARIES",
                            "severity": "MEDIUM", 
                            "description": "Binary compiled without stack canaries",
                            "impact": "Vulnerable to buffer overflow attacks"
                        })
                    
                    # Check for debugging symbols
                    if any(debug_str in strings_output for debug_str in ['DWARF', 'debug_', '__DWARF']):
                        binary_findings.append({
                            "type": "DEBUG_SYMBOLS_PRESENT",
                            "severity": "LOW",
                            "description": "Binary contains debugging symbols",
                            "impact": "Easier reverse engineering"
                        })
            
            # Check for code signing
            codesign_verify = subprocess.run([
                'codesign', '-v', binary_path
            ], capture_output=True, text=True)
            
            if codesign_verify.returncode != 0:
                binary_findings.append({
                    "type": "INVALID_CODE_SIGNATURE",
                    "severity": "HIGH",
                    "description": "Binary has invalid code signature",
                    "impact": "App may not run on non-jailbroken devices"
                })
            
            return binary_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def analyze_transport_security(self):
        """Analyze App Transport Security configuration"""
        ats_findings = []
        
        try:
            app_dir = self.app_info.get('app_dir')
            if not app_dir:
                return [{"error": "App directory not found"}]
            
            info_plist_path = os.path.join(app_dir, 'Info.plist')
            
            with open(info_plist_path, 'rb') as f:
                plist_data = plistlib.load(f)
            
            ats_config = plist_data.get('NSAppTransportSecurity', {})
            
            # Check if ATS is globally disabled
            if ats_config.get('NSAllowsArbitraryLoads'):
                ats_findings.append({
                    "type": "ATS_GLOBALLY_DISABLED",
                    "severity": "HIGH",
                    "description": "App Transport Security is globally disabled",
                    "impact": "App can make insecure HTTP connections"
                })
            
            # Check for localhost exception
            if ats_config.get('NSAllowsLocalNetworking'):
                ats_findings.append({
                    "type": "ATS_LOCAL_NETWORKING",
                    "severity": "MEDIUM",
                    "description": "ATS allows local networking connections",
                    "impact": "HTTP connections to local network allowed"
                })
            
            # Check domain-specific exceptions
            domain_exceptions = ats_config.get('NSExceptionDomains', {})
            for domain, settings in domain_exceptions.items():
                if settings.get('NSExceptionAllowsInsecureHTTPLoads'):
                    ats_findings.append({
                        "type": "ATS_DOMAIN_EXCEPTION",
                        "severity": "MEDIUM",
                        "domain": domain,
                        "description": f"ATS exception for domain: {domain}",
                        "impact": "HTTP connections allowed to specific domain"
                    })
            
            return ats_findings
            
        except Exception as e:
            return [{"error": str(e)}]

def generate_ios_runtime_analysis():
    """Generate iOS runtime analysis using Frida"""
    
    ios_frida_script = '''
#!/usr/bin/env python3
"""
iOS Runtime Analysis using Frida
Hook iOS-specific security mechanisms
"""

import frida
import sys

class iOSRuntimeAnalyzer:
    def __init__(self, bundle_id):
        self.bundle_id = bundle_id
        self.session = None
    
    def attach_to_app(self):
        """Attach to iOS application"""
        try:
            device = frida.get_usb_device()
            self.session = device.attach(self.bundle_id)
            print(f"[+] Attached to {self.bundle_id}")
            return True
        except Exception as e:
            print(f"[-] Failed to attach: {e}")
            return False
    
    def bypass_jailbreak_detection(self):
        """Bypass common jailbreak detection methods"""
        jb_bypass_script = """
        // Hook file existence checks
        var NSFileManager = ObjC.classes.NSFileManager;
        var fileExistsAtPath = NSFileManager['- fileExistsAtPath:'];
        
        Interceptor.attach(fileExistsAtPath.implementation, {
            onEnter: function(args) {
                var path = ObjC.Object(args[2]).toString();
                this.path = path;
            },
            onLeave: function(retval) {
                var jailbreakPaths = [
                    "/Applications/Cydia.app",
                    "/usr/sbin/sshd",
                    "/usr/bin/ssh",
                    "/etc/ssh/sshd_config",
                    "/private/var/lib/apt/",
                    "/Applications/MxTube.app",
                    "/Applications/RockApp.app",
                    "/Applications/Icy.app",
                    "/Applications/WinterBoard.app",
                    "/Applications/SBSettings.app",
                    "/Applications/blackra1n.app",
                    "/usr/bin/sshd"
                ];
                
                if (jailbreakPaths.indexOf(this.path) >= 0) {
                    console.log("[*] Jailbreak detection bypassed for: " + this.path);
                    retval.replace(ptr(0)); // Return NO
                }
            }
        });
        
        // Hook stat calls
        var stat = Module.findExportByName(null, "stat");
        if (stat) {
            Interceptor.attach(stat, {
                onEnter: function(args) {
                    this.path = Memory.readUtf8String(args[0]);
                },
                onLeave: function(retval) {
                    if (this.path && this.path.indexOf("Cydia") >= 0) {
                        console.log("[*] stat() jailbreak detection bypassed: " + this.path);
                        retval.replace(ptr(-1));
                    }
                }
            });
        }
        
        // Hook UIApplication canOpenURL
        var UIApplication = ObjC.classes.UIApplication;
        var canOpenURL = UIApplication['- canOpenURL:'];
        
        Interceptor.attach(canOpenURL.implementation, {
            onEnter: function(args) {
                var url = ObjC.Object(args[2]).toString();
                this.url = url;
            },
            onLeave: function(retval) {
                var jailbreakUrls = ["cydia://", "sileo://"];
                if (jailbreakUrls.some(jbUrl => this.url.indexOf(jbUrl) >= 0)) {
                    console.log("[*] canOpenURL jailbreak detection bypassed: " + this.url);
                    retval.replace(ptr(0));
                }
            }
        });
        """
        
        script = self.session.create_script(jb_bypass_script)
        script.on('message', self._on_message)
        script.load()
    
    def hook_keychain_operations(self):
        """Hook Keychain operations"""
        keychain_script = """
        // Hook SecItemAdd
        var SecItemAdd = Module.findExportByName("Security", "SecItemAdd");
        if (SecItemAdd) {
            Interceptor.attach(SecItemAdd, {
                onEnter: function(args) {
                    console.log("[*] SecItemAdd called");
                    var query = ObjC.Object(args[0]);
                    console.log("    Query: " + query.toString());
                },
                onLeave: function(retval) {
                    console.log("    Result: " + retval);
                }
            });
        }
        
        // Hook SecItemCopyMatching
        var SecItemCopyMatching = Module.findExportByName("Security", "SecItemCopyMatching");
        if (SecItemCopyMatching) {
            Interceptor.attach(SecItemCopyMatching, {
                onEnter: function(args) {
                    console.log("[*] SecItemCopyMatching called");
                    var query = ObjC.Object(args[0]);
                    console.log("    Query: " + query.toString());
                }
            });
        }
        """
        
        script = self.session.create_script(keychain_script)
        script.on('message', self._on_message)
        script.load()
    
    def hook_crypto_operations(self):
        """Hook cryptographic operations"""
        crypto_script = """
        // Hook CommonCrypto functions
        var CCCrypt = Module.findExportByName("libcommonCrypto.dylib", "CCCrypt");
        if (CCCrypt) {
            Interceptor.attach(CCCrypt, {
                onEnter: function(args) {
                    var op = args[0].toInt32();
                    var alg = args[1].toInt32();
                    var options = args[2].toInt32();
                    
                    console.log("[*] CCCrypt called");
                    console.log("    Operation: " + (op == 0 ? "Encrypt" : "Decrypt"));
                    console.log("    Algorithm: " + alg);
                    console.log("    Options: " + options);
                }
            });
        }
        
        // Hook SecKeyCreateWithData
        var SecKeyCreateWithData = Module.findExportByName("Security", "SecKeyCreateWithData");
        if (SecKeyCreateWithData) {
            Interceptor.attach(SecKeyCreateWithData, {
                onEnter: function(args) {
                    console.log("[*] SecKeyCreateWithData called");
                    var keyData = ObjC.Object(args[0]);
                    console.log("    Key data length: " + keyData.length());
                }
            });
        }
        """
        
        script = self.session.create_script(crypto_script)
        script.on('message', self._on_message) 
        script.load()
    
    def hook_network_operations(self):
        """Hook network operations"""
        network_script = """
        // Hook NSURLConnection
        var NSURLConnection = ObjC.classes.NSURLConnection;
        var sendSynchronousRequest = NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'];
        
        Interceptor.attach(sendSynchronousRequest.implementation, {
            onEnter: function(args) {
                var request = ObjC.Object(args[2]);
                var url = request.URL().toString();
                console.log("[*] NSURLConnection request: " + url);
            }
        });
        
        // Hook NSURLSession
        var NSURLSession = ObjC.classes.NSURLSession;
        var dataTaskWithRequest = NSURLSession['- dataTaskWithRequest:completionHandler:'];
        
        Interceptor.attach(dataTaskWithRequest.implementation, {
            onEnter: function(args) {
                var request = ObjC.Object(args[2]);
                var url = request.URL().toString();
                console.log("[*] NSURLSession request: " + url);
            }
        });
        """
        
        script = self.session.create_script(network_script)
        script.on('message', self._on_message)
        script.load()
    
    def _on_message(self, message, data):
        """Handle Frida messages"""
        if message['type'] == 'send':
            print(f"[Frida] {message['payload']}")
        elif message['type'] == 'error':
            print(f"[Error] {message['stack']}")
    
    def start_analysis(self):
        """Start comprehensive iOS analysis"""
        if not self.attach_to_app():
            return False
        
        print("[*] Starting iOS runtime analysis...")
        self.bypass_jailbreak_detection()
        self.hook_keychain_operations()
        self.hook_crypto_operations()
        self.hook_network_operations()
        
        print("[*] Analysis started. Press Ctrl+C to stop.")
        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            print("\\n[*] Stopping analysis...")
            self.session.detach()

# Usage
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 ios_runtime.py <bundle_id>")
        sys.exit(1)
    
    analyzer = iOSRuntimeAnalyzer(sys.argv[1])
    analyzer.start_analysis()
'''
    
    return ios_frida_script
```

---

## Cross-Platform Mobile Security Testing

### Universal Mobile Security Assessment

```python
#!/usr/bin/env python3
"""
Cross-Platform Mobile Security Testing Framework
Universal testing across Android and iOS
"""

import os
import json
import requests
from abc import ABC, abstractmethod

class MobileSecurityTester(ABC):
    """Abstract base class for mobile security testing"""
    
    def __init__(self, app_path):
        self.app_path = app_path
        self.vulnerabilities = []
        self.platform = self.detect_platform()
    
    @abstractmethod
    def detect_platform(self):
        """Detect mobile platform (Android/iOS)"""
        pass
    
    @abstractmethod
    def analyze_app(self):
        """Platform-specific app analysis"""
        pass
    
    def test_network_security(self, base_url):
        """Test network security across platforms"""
        network_findings = []
        
        # Test for HTTP usage
        try:
            http_response = requests.get(f"http://{base_url}", timeout=10, verify=False)
            if http_response.status_code == 200:
                network_findings.append({
                    "type": "HTTP_USAGE",
                    "severity": "HIGH",
                    "url": f"http://{base_url}",
                    "description": "Application uses insecure HTTP protocol"
                })
        except:
            pass
        
        # Test for certificate pinning
        try:
            # This would require more sophisticated testing
            https_response = requests.get(f"https://{base_url}", timeout=10, verify=False)
            if https_response.status_code == 200:
                network_findings.append({
                    "type": "NO_CERTIFICATE_PINNING",
                    "severity": "MEDIUM",
                    "url": f"https://{base_url}",
                    "description": "Application may not implement certificate pinning"
                })
        except:
            pass
        
        return network_findings
    
    def test_api_security(self, api_base_url):
        """Test API security implementation"""
        api_findings = []
        
        # Common API security tests
        test_endpoints = [
            "/api/users", "/api/admin", "/api/config",
            "/api/debug", "/api/test", "/api/internal"
        ]
        
        for endpoint in test_endpoints:
            try:
                response = requests.get(f"{api_base_url}{endpoint}", timeout=5)
                
                if response.status_code == 200:
                    api_findings.append({
                        "type": "EXPOSED_API_ENDPOINT",
                        "severity": "MEDIUM",
                        "endpoint": endpoint,
                        "description": f"API endpoint accessible: {endpoint}"
                    })
                
                # Test for verbose error messages
                if response.status_code >= 400:
                    if any(error_term in response.text.lower() for error_term in 
                          ['stack trace', 'exception', 'error', 'debug']):
                        api_findings.append({
                            "type": "VERBOSE_ERROR_MESSAGES",
                            "severity": "LOW",
                            "endpoint": endpoint,
                            "description": "API returns verbose error messages"
                        })
            
            except:
                continue
        
        return api_findings

class AndroidTester(MobileSecurityTester):
    def detect_platform(self):
        return "Android" if self.app_path.endswith('.apk') else None
    
    def analyze_app(self):
        if self.platform != "Android":
            return {"error": "Not an Android APK"}
        
        analyzer = AndroidSecurityAnalyzer(self.app_path)
        return analyzer.analyze_apk()

class iOSTester(MobileSecurityTester):
    def detect_platform(self):
        return "iOS" if self.app_path.endswith('.ipa') else None
    
    def analyze_app(self):
        if self.platform != "iOS":
            return {"error": "Not an iOS IPA"}
        
        analyzer = iOSSecurityAnalyzer(self.app_path)
        return analyzer.analyze_ipa()

def create_mobile_tester(app_path):
    """Factory function to create appropriate mobile tester"""
    if app_path.endswith('.apk'):
        return AndroidTester(app_path)
    elif app_path.endswith('.ipa'):
        return iOSTester(app_path)
    else:
        raise ValueError("Unsupported mobile app format")

def generate_mobile_security_report(analysis_results, app_path):
    """Generate comprehensive mobile security report"""
    
    report = {
        "executive_summary": {
            "app_path": app_path,
            "platform": analysis_results.get("platform", "Unknown"),
            "total_vulnerabilities": len(analysis_results.get("vulnerabilities", [])),
            "critical_issues": 0,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0
        },
        "detailed_findings": analysis_results,
        "recommendations": []
    }
    
    # Count vulnerabilities by severity
    for vuln in analysis_results.get("vulnerabilities", []):
        severity = vuln.get("severity", "").upper()
        if severity == "CRITICAL":
            report["executive_summary"]["critical_issues"] += 1
        elif severity == "HIGH":
            report["executive_summary"]["high_issues"] += 1
        elif severity == "MEDIUM":
            report["executive_summary"]["medium_issues"] += 1
        elif severity == "LOW":
            report["executive_summary"]["low_issues"] += 1
    
    # Generate recommendations based on findings
    if report["executive_summary"]["critical_issues"] > 0:
        report["recommendations"].append({
            "priority": "IMMEDIATE",
            "category": "Critical Security",
            "recommendation": "Address all critical security vulnerabilities immediately before production release"
        })
    
    if report["executive_summary"]["high_issues"] > 0:
        report["recommendations"].append({
            "priority": "HIGH",
            "category": "Security Hardening",
            "recommendation": "Implement security hardening measures for high-severity findings"
        })
    
    # Platform-specific recommendations
    platform = analysis_results.get("platform")
    if platform == "Android":
        report["recommendations"].extend([
            {
                "priority": "HIGH",
                "category": "Android Security",
                "recommendation": "Enable ProGuard/R8 code obfuscation for production builds"
            },
            {
                "priority": "MEDIUM",
                "category": "Android Security", 
                "recommendation": "Implement certificate pinning for network communications"
            }
        ])
    elif platform == "iOS":
        report["recommendations"].extend([
            {
                "priority": "HIGH",
                "category": "iOS Security",
                "recommendation": "Ensure proper App Transport Security configuration"
            },
            {
                "priority": "MEDIUM",
                "category": "iOS Security",
                "recommendation": "Implement jailbreak detection and response mechanisms"
            }
        ])
    
    return report
```

This comprehensive mobile security assessment framework covers both Android and iOS platforms with practical tools and techniques for identifying security vulnerabilities. The framework includes static analysis, dynamic testing capabilities, and cross-platform security assessment methodologies.

Would you like me to continue with the remaining 3 blogs covering Network Security & Lateral Movement, Cryptography & Privacy Engineering, and Digital Forensics & Incident Response?
