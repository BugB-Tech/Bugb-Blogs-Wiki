---
title: "Digital Forensics and Incident Response: Advanced Threat Hunting and Evidence Analysis"
slug: "digital-forensics-incident-response-advanced-threat-hunting-evidence-analysis"
date: "2025-06-12"
author: "BugB Security Team"
authorTitle: "Security Researchers"
excerpt: "Comprehensive guide to modern digital forensics and incident response, covering memory analysis, network forensics, threat hunting methodologies, and advanced evidence collection techniques for sophisticated cyber attacks."
category: "digital-forensics"
---

# Digital Forensics and Incident Response: Advanced Threat Hunting and Evidence Analysis

Digital forensics and incident response have evolved from reactive evidence collection to proactive threat hunting and real-time attack disruption. Modern DFIR practitioners must navigate complex cloud environments, encrypted communications, anti-forensics techniques, and sophisticated adversaries who understand traditional investigation methods.

This comprehensive analysis explores cutting-edge forensics techniques, automated incident response frameworks, and advanced threat hunting methodologies that enable organizations to detect, analyze, and respond to sophisticated cyber attacks in real-time.

## Modern DFIR Landscape

### Evolution of Digital Forensics

Contemporary digital forensics faces unprecedented challenges that require new methodologies and tools:

| Traditional Forensics | Modern DFIR | Future Challenges |
|----------------------|-------------|-------------------|
| **Disk imaging** | Live memory analysis | Cloud-native forensics |
| **File system analysis** | Network packet inspection | Encrypted everything |
| **Timeline reconstruction** | Behavioral analytics | AI-generated evidence |
| **Static evidence** | Dynamic threat hunting | Quantum-resistant forensics |
| **Single-system focus** | Enterprise-wide correlation | Multi-cloud investigations |
| **Post-incident analysis** | Real-time response | Predictive threat modeling |

### DFIR Kill Chain Analysis

```
┌─────────────────────────────────────────────────────────────┐
│                Advanced DFIR Methodology                   │
├─────────────────────────────────────────────────────────────┤
│ 1. Detection          │ → SIEM alerts, anomaly detection   │
│                       │   Threat intel correlation         │
│                       │   Behavioral analytics             │
├─────────────────────────────────────────────────────────────┤
│ 2. Triage             │ → Initial impact assessment        │
│                       │   Scope determination              │
│                       │   Containment planning             │
├─────────────────────────────────────────────────────────────┤
│ 3. Collection         │ → Memory acquisition               │
│                       │   Network capture                  │
│                       │   Cloud evidence preservation      │
├─────────────────────────────────────────────────────────────┤
│ 4. Analysis           │ → Timeline reconstruction          │
│                       │   Malware reverse engineering      │
│                       │   Attribution analysis             │
├─────────────────────────────────────────────────────────────┤
│ 5. Containment        │ → Threat isolation                 │
│                       │   System quarantine                │
│                       │   Network segmentation             │
├─────────────────────────────────────────────────────────────┤
│ 6. Eradication        │ → Malware removal                  │
│                       │   Vulnerability patching           │
│                       │   System hardening                 │
├─────────────────────────────────────────────────────────────┤
│ 7. Recovery           │ → Service restoration              │
│                       │   System validation                │
│                       │   Monitoring enhancement           │
├─────────────────────────────────────────────────────────────┤
│ 8. Lessons Learned    │ → Process improvement              │
│                       │   Control enhancement              │
│                       │   Training updates                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Advanced Memory Forensics

### Comprehensive Memory Analysis Framework

```python
#!/usr/bin/env python3
"""
Advanced Memory Forensics Analysis Framework
Comprehensive memory dump analysis and threat hunting
"""

import struct
import re
import json
import hashlib
import subprocess
import os
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime
from dataclasses import dataclass

@dataclass
class ProcessInfo:
    """Process information structure"""
    pid: int
    ppid: int
    name: str
    command_line: str
    create_time: datetime
    exit_time: Optional[datetime]
    threads: int
    handles: int
    virtual_size: int
    working_set: int

@dataclass
class NetworkConnection:
    """Network connection information"""
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: int
    process_name: str

@dataclass
class MemoryArtifact:
    """Memory artifact structure"""
    artifact_type: str
    virtual_address: int
    physical_address: int
    size: int
    data: bytes
    description: str
    confidence: float

class MemoryForensicsAnalyzer:
    def __init__(self, memory_dump_path: str):
        self.memory_dump_path = memory_dump_path
        self.volatility_profile = None
        self.analysis_results = {}
        self.artifacts = []
        self.indicators = []
    
    def comprehensive_analysis(self) -> Dict[str, Any]:
        """Execute comprehensive memory analysis"""
        
        analysis_results = {
            "dump_info": self.analyze_dump_info(),
            "process_analysis": self.analyze_processes(),
            "network_analysis": self.analyze_network_connections(),
            "registry_analysis": self.analyze_registry_artifacts(),
            "malware_analysis": self.detect_malware_artifacts(),
            "rootkit_analysis": self.detect_rootkit_artifacts(),
            "timeline_analysis": self.construct_timeline(),
            "ioc_extraction": self.extract_indicators_of_compromise(),
            "persistence_analysis": self.analyze_persistence_mechanisms()
        }
        
        self.analysis_results = analysis_results
        return analysis_results
    
    def analyze_dump_info(self) -> Dict[str, Any]:
        """Analyze memory dump metadata and determine profile"""
        try:
            # Use Volatility to identify image info
            imageinfo_cmd = ['python3', 'vol.py', '-f', self.memory_dump_path, 'imageinfo']
            result = subprocess.run(imageinfo_cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Extract suggested profiles
                profile_match = re.search(r'Suggested Profile\(s\)\s*:\s*(.+)', output)
                profiles = profile_match.group(1).split(',') if profile_match else []
                
                # Extract OS information
                os_match = re.search(r'Image Type\s*:\s*(.+)', output)
                os_info = os_match.group(1).strip() if os_match else "Unknown"
                
                # Use first suggested profile
                if profiles:
                    self.volatility_profile = profiles[0].strip()
                
                return {
                    "profiles": [p.strip() for p in profiles],
                    "selected_profile": self.volatility_profile,
                    "os_info": os_info,
                    "dump_size": os.path.getsize(self.memory_dump_path),
                    "analysis_timestamp": datetime.now().isoformat()
                }
            else:
                return {"error": "Failed to analyze dump info", "stderr": result.stderr}
                
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_processes(self) -> Dict[str, Any]:
        """Analyze running processes and detect anomalies"""
        processes = []
        anomalies = []
        
        try:
            # Get process list
            pslist_cmd = ['python3', 'vol.py', '-f', self.memory_dump_path, 
                         '--profile', self.volatility_profile, 'pslist']
            result = subprocess.run(pslist_cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')[2:]  # Skip header
                
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 8:
                            try:
                                process = ProcessInfo(
                                    pid=int(parts[1]),
                                    ppid=int(parts[2]),
                                    name=parts[0],
                                    command_line="",  # Will be filled separately
                                    create_time=datetime.strptime(parts[7] + " " + parts[8], "%Y-%m-%d %H:%M:%S"),
                                    exit_time=None,
                                    threads=int(parts[3]),
                                    handles=int(parts[4]) if parts[4].isdigit() else 0,
                                    virtual_size=0,
                                    working_set=0
                                )
                                processes.append(process)
                            except (ValueError, IndexError):
                                continue
            
            # Get command lines
            cmdline_processes = self.get_process_command_lines()
            
            # Merge command line information
            for process in processes:
                if process.pid in cmdline_processes:
                    process.command_line = cmdline_processes[process.pid]
            
            # Detect process anomalies
            anomalies = self.detect_process_anomalies(processes)
            
            return {
                "total_processes": len(processes),
                "processes": [self._process_to_dict(p) for p in processes],
                "anomalies": anomalies,
                "analysis_techniques": ["pslist", "cmdline", "pstree"]
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def get_process_command_lines(self) -> Dict[int, str]:
        """Extract process command lines"""
        cmdlines = {}
        
        try:
            cmdline_cmd = ['python3', 'vol.py', '-f', self.memory_dump_path,
                          '--profile', self.volatility_profile, 'cmdline']
            result = subprocess.run(cmdline_cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                current_pid = None
                current_cmdline = ""
                
                for line in result.stdout.split('\n'):
                    if line.startswith('Command line :'):
                        if current_pid and current_cmdline:
                            cmdlines[current_pid] = current_cmdline.strip()
                        current_cmdline = line.replace('Command line :', '').strip()
                    elif line.strip() and not line.startswith('*'):
                        pid_match = re.search(r'(\d+)', line)
                        if pid_match:
                            current_pid = int(pid_match.group(1))
                
                # Add last command line
                if current_pid and current_cmdline:
                    cmdlines[current_pid] = current_cmdline.strip()
                    
        except Exception as e:
            print(f"Error getting command lines: {e}")
        
        return cmdlines
    
    def detect_process_anomalies(self, processes: List[ProcessInfo]) -> List[Dict[str, Any]]:
        """Detect suspicious process behaviors"""
        anomalies = []
        
        # Build process tree
        process_tree = {}
        for proc in processes:
            if proc.ppid not in process_tree:
                process_tree[proc.ppid] = []
            process_tree[proc.ppid].append(proc)
        
        for process in processes:
            # Check for process hollowing indicators
            if self.check_process_hollowing(process):
                anomalies.append({
                    "type": "PROCESS_HOLLOWING",
                    "severity": "HIGH",
                    "pid": process.pid,
                    "process_name": process.name,
                    "description": "Potential process hollowing detected"
                })
            
            # Check for suspicious parent-child relationships
            if self.check_suspicious_parent_child(process, processes):
                anomalies.append({
                    "type": "SUSPICIOUS_PARENT_CHILD",
                    "severity": "MEDIUM",
                    "pid": process.pid,
                    "ppid": process.ppid,
                    "description": "Suspicious parent-child process relationship"
                })
            
            # Check for unusual network activity
            if self.check_unusual_network_process(process):
                anomalies.append({
                    "type": "UNUSUAL_NETWORK_ACTIVITY",
                    "severity": "MEDIUM",
                    "pid": process.pid,
                    "process_name": process.name,
                    "description": "Process with unusual network activity"
                })
        
        return anomalies
    
    def check_process_hollowing(self, process: ProcessInfo) -> bool:
        """Check for process hollowing indicators"""
        # Simplified check - real implementation would analyze memory sections
        suspicious_names = ['svchost.exe', 'explorer.exe', 'winlogon.exe']
        
        if process.name.lower() in suspicious_names:
            # Check if command line is suspicious
            if process.command_line and ('powershell' in process.command_line.lower() or 
                                       'cmd.exe' in process.command_line.lower()):
                return True
        
        return False
    
    def analyze_network_connections(self) -> Dict[str, Any]:
        """Analyze network connections and detect anomalies"""
        connections = []
        
        try:
            # Get network connections
            netscan_cmd = ['python3', 'vol.py', '-f', self.memory_dump_path,
                          '--profile', self.volatility_profile, 'netscan']
            result = subprocess.run(netscan_cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')[2:]  # Skip header
                
                for line in lines:
                    if line.strip() and not line.startswith('Volatility'):
                        # Parse network connection line
                        connection = self.parse_network_connection(line)
                        if connection:
                            connections.append(connection)
            
            # Analyze connections for anomalies
            anomalies = self.detect_network_anomalies(connections)
            
            return {
                "total_connections": len(connections),
                "connections": [self._connection_to_dict(c) for c in connections],
                "anomalies": anomalies,
                "external_connections": [c for c in connections if not self._is_internal_ip(c.remote_addr)]
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def parse_network_connection(self, line: str) -> Optional[NetworkConnection]:
        """Parse network connection from volatility output"""
        try:
            parts = line.split()
            if len(parts) >= 6:
                # Extract local and remote addresses
                local_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', parts[1])
                remote_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', parts[2])
                
                if local_match and remote_match:
                    return NetworkConnection(
                        protocol=parts[0],
                        local_addr=local_match.group(1),
                        local_port=int(local_match.group(2)),
                        remote_addr=remote_match.group(1),
                        remote_port=int(remote_match.group(2)),
                        state=parts[3] if len(parts) > 3 else "UNKNOWN",
                        pid=int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0,
                        process_name=parts[5] if len(parts) > 5 else "Unknown"
                    )
        except (ValueError, IndexError):
            pass
        
        return None
    
    def detect_network_anomalies(self, connections: List[NetworkConnection]) -> List[Dict[str, Any]]:
        """Detect suspicious network connections"""
        anomalies = []
        
        for conn in connections:
            # Check for connections to suspicious IPs
            if self.is_suspicious_ip(conn.remote_addr):
                anomalies.append({
                    "type": "SUSPICIOUS_IP_CONNECTION",
                    "severity": "HIGH",
                    "remote_ip": conn.remote_addr,
                    "remote_port": conn.remote_port,
                    "process_name": conn.process_name,
                    "pid": conn.pid
                })
            
            # Check for unusual ports
            if self.is_unusual_port(conn.remote_port):
                anomalies.append({
                    "type": "UNUSUAL_PORT_CONNECTION",
                    "severity": "MEDIUM",
                    "remote_port": conn.remote_port,
                    "remote_ip": conn.remote_addr,
                    "process_name": conn.process_name
                })
        
        return anomalies
    
    def detect_malware_artifacts(self) -> Dict[str, Any]:
        """Detect malware artifacts in memory"""
        artifacts = []
        
        try:
            # Scan for malware using YARA rules
            malware_scan = self.yara_malware_scan()
            artifacts.extend(malware_scan)
            
            # Check for code injection
            injection_artifacts = self.detect_code_injection()
            artifacts.extend(injection_artifacts)
            
            # Check for packed executables
            packed_executables = self.detect_packed_executables()
            artifacts.extend(packed_executables)
            
            return {
                "total_artifacts": len(artifacts),
                "artifacts": artifacts,
                "malware_families": list(set([a.get("family", "Unknown") for a in artifacts])),
                "confidence_scores": [a.get("confidence", 0) for a in artifacts]
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def yara_malware_scan(self) -> List[Dict[str, Any]]:
        """Scan memory dump with YARA rules"""
        artifacts = []
        
        try:
            # Use Volatility's YARA scanner
            yarascan_cmd = ['python3', 'vol.py', '-f', self.memory_dump_path,
                           '--profile', self.volatility_profile, 'yarascan',
                           '--yara-rules', self.get_malware_yara_rules()]
            
            result = subprocess.run(yarascan_cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Parse YARA scan results
                current_rule = None
                current_pid = None
                
                for line in result.stdout.split('\n'):
                    if 'Rule:' in line:
                        current_rule = line.split('Rule:')[1].strip()
                    elif 'Owner: Process' in line and 'Pid' in line:
                        pid_match = re.search(r'Pid (\d+)', line)
                        if pid_match:
                            current_pid = int(pid_match.group(1))
                    elif 'found at' in line and current_rule and current_pid:
                        artifacts.append({
                            "type": "YARA_MATCH",
                            "rule": current_rule,
                            "pid": current_pid,
                            "confidence": 0.8,
                            "description": f"YARA rule {current_rule} matched"
                        })
                        
        except Exception as e:
            print(f"YARA scan error: {e}")
        
        return artifacts
    
    def get_malware_yara_rules(self) -> str:
        """Generate YARA rules for malware detection"""
        yara_rules = '''
        rule Suspicious_PowerShell_Commands {
            strings:
                $a = "IEX" nocase
                $b = "Invoke-Expression" nocase
                $c = "DownloadString" nocase
                $d = "powershell -enc" nocase
                $e = "System.Convert::FromBase64String" nocase
            condition:
                any of them
        }
        
        rule Metasploit_Meterpreter {
            strings:
                $a = "meterpreter"
                $b = "ReflectiveLoader"
                $c = "stdapi_"
            condition:
                any of them
        }
        
        rule Cobalt_Strike_Beacon {
            strings:
                $a = "beacon.dll"
                $b = "malleable_c2"
                $c = "/api/v1/GetOutputBuffer"
            condition:
                any of them
        }
        '''
        
        # Write rules to temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
            f.write(yara_rules)
            return f.name
    
    def construct_timeline(self) -> Dict[str, Any]:
        """Construct timeline of system activities"""
        timeline_events = []
        
        try:
            # Get timeline from various sources
            timeline_events.extend(self.get_process_timeline())
            timeline_events.extend(self.get_network_timeline())
            timeline_events.extend(self.get_registry_timeline())
            timeline_events.extend(self.get_file_timeline())
            
            # Sort events by timestamp
            timeline_events.sort(key=lambda x: x.get('timestamp', ''))
            
            return {
                "total_events": len(timeline_events),
                "events": timeline_events,
                "time_range": {
                    "start": timeline_events[0]['timestamp'] if timeline_events else None,
                    "end": timeline_events[-1]['timestamp'] if timeline_events else None
                },
                "event_types": list(set([e.get('type', 'Unknown') for e in timeline_events]))
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def get_process_timeline(self) -> List[Dict[str, Any]]:
        """Extract process creation timeline"""
        events = []
        
        # Use process information from earlier analysis
        if 'process_analysis' in self.analysis_results:
            processes = self.analysis_results['process_analysis'].get('processes', [])
            
            for process in processes:
                events.append({
                    "timestamp": process.get('create_time'),
                    "type": "PROCESS_CREATED",
                    "pid": process.get('pid'),
                    "process_name": process.get('name'),
                    "command_line": process.get('command_line'),
                    "ppid": process.get('ppid')
                })
        
        return events
    
    def extract_indicators_of_compromise(self) -> Dict[str, Any]:
        """Extract IOCs from memory analysis"""
        iocs = {
            "ip_addresses": [],
            "domains": [],
            "file_hashes": [],
            "registry_keys": [],
            "mutexes": [],
            "user_agents": []
        }
        
        try:
            # Extract IP addresses from network connections
            if 'network_analysis' in self.analysis_results:
                connections = self.analysis_results['network_analysis'].get('connections', [])
                for conn in connections:
                    if not self._is_internal_ip(conn.get('remote_addr', '')):
                        iocs["ip_addresses"].append(conn['remote_addr'])
            
            # Extract domains from memory strings
            domains = self.extract_domains_from_memory()
            iocs["domains"] = domains
            
            # Extract file hashes
            file_hashes = self.extract_file_hashes()
            iocs["file_hashes"] = file_hashes
            
            # Extract mutex names
            mutexes = self.extract_mutex_names()
            iocs["mutexes"] = mutexes
            
            # Remove duplicates
            for key in iocs:
                iocs[key] = list(set(iocs[key]))
            
            return iocs
            
        except Exception as e:
            return {"error": str(e)}
    
    def extract_domains_from_memory(self) -> List[str]:
        """Extract domain names from memory strings"""
        domains = []
        
        try:
            # Use strings command to extract printable strings
            strings_cmd = ['strings', '-n', '6', self.memory_dump_path]
            result = subprocess.run(strings_cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                # Look for domain patterns
                domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,})\b'
                
                for line in result.stdout.split('\n'):
                    matches = re.findall(domain_pattern, line)
                    for match in matches:
                        domain = match[0] + '.' + match[1] if match[0] else match[1]
                        # Filter out common false positives
                        if self.is_suspicious_domain(domain):
                            domains.append(domain)
        
        except Exception as e:
            print(f"Domain extraction error: {e}")
        
        return domains
    
    def is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious"""
        # Filter out common legitimate domains
        legitimate_domains = [
            'microsoft.com', 'windows.com', 'msftncsi.com',
            'google.com', 'mozilla.org', 'firefox.com'
        ]
        
        for legit in legitimate_domains:
            if legit in domain.lower():
                return False
        
        # Check for suspicious characteristics
        if len(domain) > 50:  # Very long domains
            return True
        
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):  # IP in domain
            return True
        
        return True  # Default to suspicious for analysis
    
    def _process_to_dict(self, process: ProcessInfo) -> Dict[str, Any]:
        """Convert ProcessInfo to dictionary"""
        return {
            "pid": process.pid,
            "ppid": process.ppid,
            "name": process.name,
            "command_line": process.command_line,
            "create_time": process.create_time.isoformat() if process.create_time else None,
            "threads": process.threads,
            "handles": process.handles
        }
    
    def _connection_to_dict(self, connection: NetworkConnection) -> Dict[str, Any]:
        """Convert NetworkConnection to dictionary"""
        return {
            "protocol": connection.protocol,
            "local_addr": connection.local_addr,
            "local_port": connection.local_port,
            "remote_addr": connection.remote_addr,
            "remote_port": connection.remote_port,
            "state": connection.state,
            "pid": connection.pid,
            "process_name": connection.process_name
        }
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP address is internal/private"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except:
            return False

def generate_automated_incident_response():
    """Generate automated incident response framework"""
    
    incident_response_code = '''
#!/usr/bin/env python3
"""
Automated Incident Response Framework
Real-time threat detection and response automation
"""

import json
import time
import threading
import subprocess
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Callable
from dataclasses import dataclass

class ThreatLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class ResponseAction(Enum):
    MONITOR = "monitor"
    ISOLATE = "isolate"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    KILL_PROCESS = "kill_process"
    DISABLE_ACCOUNT = "disable_account"

@dataclass
class SecurityEvent:
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: ThreatLevel
    details: Dict[str, Any]
    indicators: List[str]

@dataclass
class ResponseRule:
    rule_id: str
    name: str
    conditions: Dict[str, Any]
    actions: List[ResponseAction]
    threshold: int
    time_window: int  # seconds

class AutomatedIncidentResponse:
    def __init__(self):
        self.active_incidents = {}
        self.response_rules = []
        self.event_queue = []
        self.running = False
        self.response_handlers = {
            ResponseAction.MONITOR: self.monitor_threat,
            ResponseAction.ISOLATE: self.isolate_system,
            ResponseAction.QUARANTINE: self.quarantine_file,
            ResponseAction.BLOCK: self.block_network_traffic,
            ResponseAction.KILL_PROCESS: self.kill_malicious_process,
            ResponseAction.DISABLE_ACCOUNT: self.disable_user_account
        }
        
        # Initialize default rules
        self.setup_default_rules()
    
    def setup_default_rules(self):
        """Setup default response rules"""
        
        # Rule 1: Multiple failed logins
        self.response_rules.append(ResponseRule(
            rule_id="failed_login_threshold",
            name="Multiple Failed Login Attempts",
            conditions={
                "event_type": "authentication_failure",
                "threshold": 5,
                "time_window": 300
            },
            actions=[ResponseAction.MONITOR, ResponseAction.DISABLE_ACCOUNT],
            threshold=5,
            time_window=300
        ))
        
        # Rule 2: Malware detection
        self.response_rules.append(ResponseRule(
            rule_id="malware_detection",
            name="Malware Detection Response",
            conditions={
                "event_type": "malware_detected",
                "severity": ThreatLevel.HIGH
            },
            actions=[ResponseAction.QUARANTINE, ResponseAction.ISOLATE],
            threshold=1,
            time_window=0
        ))
        
        # Rule 3: Suspicious network activity
        self.response_rules.append(ResponseRule(
            rule_id="suspicious_network",
            name="Suspicious Network Activity",
            conditions={
                "event_type": "network_anomaly",
                "severity": ThreatLevel.MEDIUM
            },
            actions=[ResponseAction.MONITOR, ResponseAction.BLOCK],
            threshold=3,
            time_window=600
        ))
        
        # Rule 4: Privilege escalation
        self.response_rules.append(ResponseRule(
            rule_id="privilege_escalation",
            name="Privilege Escalation Detected",
            conditions={
                "event_type": "privilege_escalation",
                "severity": ThreatLevel.CRITICAL
            },
            actions=[ResponseAction.KILL_PROCESS, ResponseAction.ISOLATE],
            threshold=1,
            time_window=0
        ))
    
    def start_monitoring(self):
        """Start automated incident response monitoring"""
        self.running = True
        
        # Start event processing thread
        event_thread = threading.Thread(target=self.process_events)
        event_thread.daemon = True
        event_thread.start()
        
        # Start rule evaluation thread
        rule_thread = threading.Thread(target=self.evaluate_rules)
        rule_thread.daemon = True
        rule_thread.start()
        
        print("[*] Automated Incident Response system started")
    
    def stop_monitoring(self):
        """Stop automated incident response monitoring"""
        self.running = False
        print("[*] Automated Incident Response system stopped")
    
    def process_event(self, event: SecurityEvent):
        """Process incoming security event"""
        self.event_queue.append(event)
        
        # Log event
        self.log_event(event)
        
        # Check for immediate response rules
        for rule in self.response_rules:
            if self.evaluate_immediate_rule(event, rule):
                self.execute_response(event, rule)
    
    def process_events(self):
        """Process events from queue"""
        while self.running:
            if self.event_queue:
                event = self.event_queue.pop(0)
                self.analyze_event(event)
            time.sleep(1)
    
    def evaluate_rules(self):
        """Evaluate response rules against recent events"""
        while self.running:
            current_time = datetime.now()
            
            for rule in self.response_rules:
                if rule.time_window > 0:
                    # Count matching events in time window
                    matching_events = self.get_matching_events(rule, current_time)
                    
                    if len(matching_events) >= rule.threshold:
                        # Create composite incident
                        incident_event = self.create_composite_event(matching_events, rule)
                        self.execute_response(incident_event, rule)
            
            time.sleep(30)  # Check every 30 seconds
    
    def evaluate_immediate_rule(self, event: SecurityEvent, rule: ResponseRule) -> bool:
        """Evaluate if event matches immediate response rule"""
        conditions = rule.conditions
        
        # Check event type
        if "event_type" in conditions:
            if event.event_type != conditions["event_type"]:
                return False
        
        # Check severity
        if "severity" in conditions:
            if event.severity.value < conditions["severity"].value:
                return False
        
        # For immediate rules (time_window = 0)
        if rule.time_window == 0 and rule.threshold == 1:
            return True
        
        return False
    
    def get_matching_events(self, rule: ResponseRule, current_time: datetime) -> List[SecurityEvent]:
        """Get events matching rule conditions within time window"""
        matching_events = []
        time_threshold = current_time.timestamp() - rule.time_window
        
        # Search recent events (simplified - would use proper event store)
        for event in self.event_queue[-1000:]:  # Last 1000 events
            if event.timestamp.timestamp() > time_threshold:
                if self.event_matches_conditions(event, rule.conditions):
                    matching_events.append(event)
        
        return matching_events
    
    def event_matches_conditions(self, event: SecurityEvent, conditions: Dict[str, Any]) -> bool:
        """Check if event matches rule conditions"""
        if "event_type" in conditions:
            if event.event_type != conditions["event_type"]:
                return False
        
        if "severity" in conditions:
            if event.severity.value < conditions["severity"].value:
                return False
        
        return True
    
    def execute_response(self, event: SecurityEvent, rule: ResponseRule):
        """Execute automated response actions"""
        incident_id = f"INC_{int(time.time())}"
        
        print(f"[!] Executing response for rule: {rule.name}")
        print(f"    Incident ID: {incident_id}")
        print(f"    Event: {event.event_type}")
        print(f"    Severity: {event.severity.name}")
        
        # Record incident
        self.active_incidents[incident_id] = {
            "rule": rule,
            "trigger_event": event,
            "start_time": datetime.now(),
            "actions_taken": []
        }
        
        # Execute each action
        for action in rule.actions:
            try:
                success = self.response_handlers[action](event, incident_id)
                
                self.active_incidents[incident_id]["actions_taken"].append({
                    "action": action.value,
                    "success": success,
                    "timestamp": datetime.now()
                })
                
                print(f"    Action {action.value}: {'SUCCESS' if success else 'FAILED'}")
                
            except Exception as e:
                print(f"    Action {action.value}: ERROR - {e}")
                self.active_incidents[incident_id]["actions_taken"].append({
                    "action": action.value,
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.now()
                })
    
    def monitor_threat(self, event: SecurityEvent, incident_id: str) -> bool:
        """Enhanced monitoring response"""
        try:
            # Increase logging verbosity
            # Deploy additional sensors
            # Enable detailed monitoring
            
            monitoring_config = {
                "incident_id": incident_id,
                "enhanced_logging": True,
                "additional_sensors": ["network", "process", "file"],
                "monitoring_duration": 3600  # 1 hour
            }
            
            # Log monitoring enhancement
            self.log_response_action("MONITOR", monitoring_config)
            return True
            
        except Exception as e:
            print(f"Monitor threat error: {e}")
            return False
    
    def isolate_system(self, event: SecurityEvent, incident_id: str) -> bool:
        """Isolate affected system from network"""
        try:
            # Extract system information from event
            system_id = event.details.get("hostname", event.details.get("ip_address"))
            
            if not system_id:
                return False
            
            # Execute network isolation
            isolation_cmd = f"isolate_system.sh {system_id}"
            result = subprocess.run(isolation_cmd.split(), capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log_response_action("ISOLATE", {
                    "system": system_id,
                    "incident_id": incident_id,
                    "isolation_time": datetime.now().isoformat()
                })
                return True
            else:
                print(f"Isolation failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"System isolation error: {e}")
            return False
    
    def quarantine_file(self, event: SecurityEvent, incident_id: str) -> bool:
        """Quarantine malicious file"""
        try:
            file_path = event.details.get("file_path")
            file_hash = event.details.get("file_hash")
            
            if not (file_path or file_hash):
                return False
            
            # Move file to quarantine
            quarantine_cmd = f"quarantine_file.sh {file_path}"
            result = subprocess.run(quarantine_cmd.split(), capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log_response_action("QUARANTINE", {
                    "file_path": file_path,
                    "file_hash": file_hash,
                    "incident_id": incident_id,
                    "quarantine_time": datetime.now().isoformat()
                })
                return True
            else:
                return False
                
        except Exception as e:
            print(f"File quarantine error: {e}")
            return False
    
    def block_network_traffic(self, event: SecurityEvent, incident_id: str) -> bool:
        """Block suspicious network traffic"""
        try:
            ip_address = event.details.get("remote_ip")
            domain = event.details.get("domain")
            
            if ip_address:
                # Block IP address
                block_cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
                result = subprocess.run(block_cmd.split(), capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.log_response_action("BLOCK_IP", {
                        "ip_address": ip_address,
                        "incident_id": incident_id
                    })
                    return True
            
            if domain:
                # Block domain via DNS
                self.block_domain(domain, incident_id)
                return True
            
            return False
            
        except Exception as e:
            print(f"Network blocking error: {e}")
            return False
    
    def kill_malicious_process(self, event: SecurityEvent, incident_id: str) -> bool:
        """Kill malicious process"""
        try:
            pid = event.details.get("pid")
            process_name = event.details.get("process_name")
            
            if pid:
                # Kill by PID
                kill_cmd = f"kill -9 {pid}"
                result = subprocess.run(kill_cmd.split(), capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.log_response_action("KILL_PROCESS", {
                        "pid": pid,
                        "process_name": process_name,
                        "incident_id": incident_id
                    })
                    return True
            
            return False
            
        except Exception as e:
            print(f"Process kill error: {e}")
            return False
    
    def disable_user_account(self, event: SecurityEvent, incident_id: str) -> bool:
        """Disable user account"""
        try:
            username = event.details.get("username")
            
            if not username:
                return False
            
            # Disable account
            disable_cmd = f"usermod -L {username}"
            result = subprocess.run(disable_cmd.split(), capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log_response_action("DISABLE_ACCOUNT", {
                    "username": username,
                    "incident_id": incident_id,
                    "disable_time": datetime.now().isoformat()
                })
                return True
            else:
                return False
                
        except Exception as e:
            print(f"Account disable error: {e}")
            return False
    
    def log_event(self, event: SecurityEvent):
        """Log security event"""
        log_entry = {
            "timestamp": event.timestamp.isoformat(),
            "event_id": event.event_id,
            "source": event.source,
            "type": event.event_type,
            "severity": event.severity.name,
            "details": event.details,
            "indicators": event.indicators
        }
        
        # Write to log file
        with open("security_events.log", "a") as f:
            f.write(json.dumps(log_entry) + "\\n")
    
    def log_response_action(self, action: str, details: Dict[str, Any]):
        """Log response action"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        }
        
        with open("response_actions.log", "a") as f:
            f.write(json.dumps(log_entry) + "\\n")
    
    def generate_incident_report(self, incident_id: str) -> Dict[str, Any]:
        """Generate comprehensive incident report"""
        if incident_id not in self.active_incidents:
            return {"error": "Incident not found"}
        
        incident = self.active_incidents[incident_id]
        
        report = {
            "incident_id": incident_id,
            "rule_triggered": incident["rule"].name,
            "start_time": incident["start_time"].isoformat(),
            "trigger_event": {
                "type": incident["trigger_event"].event_type,
                "severity": incident["trigger_event"].severity.name,
                "details": incident["trigger_event"].details
            },
            "actions_taken": incident["actions_taken"],
            "status": "ACTIVE" if incident_id in self.active_incidents else "RESOLVED",
            "total_actions": len(incident["actions_taken"]),
            "successful_actions": sum(1 for a in incident["actions_taken"] if a["success"])
        }
        
        return report

# Usage example
if __name__ == "__main__":
    # Initialize AIR system
    air_system = AutomatedIncidentResponse()
    air_system.start_monitoring()
    
    # Simulate security events
    test_events = [
        SecurityEvent(
            event_id="EVT_001",
            timestamp=datetime.now(),
            source="endpoint_detection",
            event_type="malware_detected",
            severity=ThreatLevel.HIGH,
            details={
                "file_path": "/tmp/malware.exe",
                "file_hash": "abc123def456",
                "hostname": "workstation-01"
            },
            indicators=["abc123def456"]
        ),
        SecurityEvent(
            event_id="EVT_002",
            timestamp=datetime.now(),
            source="network_monitor",
            event_type="network_anomaly",
            severity=ThreatLevel.MEDIUM,
            details={
                "remote_ip": "192.168.1.100",
                "suspicious_traffic": True,
                "bytes_transferred": 1000000
            },
            indicators=["192.168.1.100"]
        )
    ]
    
    # Process test events
    for event in test_events:
        air_system.process_event(event)
    
    # Keep running for demonstration
    try:
        time.sleep(60)
    except KeyboardInterrupt:
        air_system.stop_monitoring()
'''
    
    return incident_response_code
```

---

## Network Forensics and Threat Hunting

### Advanced Network Traffic Analysis

```python
#!/usr/bin/env python3
"""
Advanced Network Forensics and Threat Hunting Framework
Deep packet analysis and behavioral threat detection
"""

import subprocess
import json
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
import base64

@dataclass
class NetworkFlow:
    """Network flow information"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    duration: float
    start_time: datetime
    end_time: datetime

@dataclass
class PacketAnalysis:
    """Packet analysis results"""
    total_packets: int
    suspicious_packets: int
    protocols: Dict[str, int]
    top_talkers: List[Tuple[str, int]]
    anomalies: List[Dict[str, Any]]
    extracted_files: List[str]

class NetworkForensicsAnalyzer:
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.flows = []
        self.dns_queries = []
        self.http_requests = []
        self.ssl_connections = []
        self.suspicious_activities = []
    
    def comprehensive_analysis(self) -> Dict[str, Any]:
        """Execute comprehensive network forensics analysis"""
        
        analysis_results = {
            "pcap_info": self.analyze_pcap_info(),
            "flow_analysis": self.analyze_network_flows(),
            "protocol_analysis": self.analyze_protocols(),
            "dns_analysis": self.analyze_dns_traffic(),
            "http_analysis": self.analyze_http_traffic(),
            "ssl_analysis": self.analyze_ssl_traffic(),
            "threat_hunting": self.hunt_threats(),
            "file_extraction": self.extract_network_files(),
            "timeline_analysis": self.create_network_timeline(),
            "ioc_extraction": self.extract_network_iocs()
        }
        
        return analysis_results
    
    def analyze_pcap_info(self) -> Dict[str, Any]:
        """Analyze basic PCAP file information"""
        try:
            # Use capinfos to get basic information
            capinfos_cmd = ['capinfos', '-T', '-M', '-c', '-d', '-e', '-S', self.pcap_file]
            result = subprocess.run(capinfos_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) >= 6:
                    return {
                        "file_type": lines[0],
                        "file_encap": lines[1],
                        "packet_count": int(lines[2]),
                        "file_size": int(lines[3]),
                        "data_size": int(lines[4]),
                        "capture_duration": float(lines[5]),
                        "start_time": lines[6] if len(lines) > 6 else None,
                        "end_time": lines[7] if len(lines) > 7 else None
                    }
            
            return {"error": "Failed to analyze PCAP info"}
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_network_flows(self) -> Dict[str, Any]:
        """Analyze network flows using tshark"""
        flows = []
        
        try:
            # Extract flow information using tshark
            tshark_cmd = [
                'tshark', '-r', self.pcap_file, '-T', 'fields',
                '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.srcport', '-e', 'tcp.dstport',
                '-e', 'ip.proto', '-e', 'frame.len', '-e', 'frame.time_epoch',
                '-E', 'separator=|'
            ]
            
            result = subprocess.run(tshark_cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                flow_data = {}
                
                for line in result.stdout.strip().split('\n'):
                    if line:
                        fields = line.split('|')
                        if len(fields) >= 7:
                            try:
                                src_ip = fields[0]
                                dst_ip = fields[1]
                                src_port = int(fields[2]) if fields[2] else 0
                                dst_port = int(fields[3]) if fields[3] else 0
                                protocol = fields[4]
                                frame_len = int(fields[5])
                                timestamp = float(fields[6])
                                
                                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
                                
                                if flow_key not in flow_data:
                                    flow_data[flow_key] = {
                                        "src_ip": src_ip,
                                        "dst_ip": dst_ip,
                                        "src_port": src_port,
                                        "dst_port": dst_port,
                                        "protocol": protocol,
                                        "total_bytes": 0,
                                        "packet_count": 0,
                                        "start_time": timestamp,
                                        "end_time": timestamp
                                    }
                                
                                flow_data[flow_key]["total_bytes"] += frame_len
                                flow_data[flow_key]["packet_count"] += 1
                                flow_data[flow_key]["end_time"] = max(flow_data[flow_key]["end_time"], timestamp)
                                
                            except (ValueError, IndexError):
                                continue
                
                flows = list(flow_data.values())
                
                # Analyze flow patterns
                flow_analysis = self.analyze_flow_patterns(flows)
                
                return {
                    "total_flows": len(flows),
                    "flows": flows[:100],  # Limit for performance
                    "flow_patterns": flow_analysis,
                    "top_conversations": self.get_top_conversations(flows)
                }
            
            return {"error": "Failed to extract flows"}
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_flow_patterns(self, flows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze flow patterns for anomalies"""
        patterns = {
            "long_duration_flows": [],
            "high_volume_flows": [],
            "unusual_ports": [],
            "potential_exfiltration": []
        }
        
        for flow in flows:
            duration = flow["end_time"] - flow["start_time"]
            
            # Long duration flows (> 1 hour)
            if duration > 3600:
                patterns["long_duration_flows"].append(flow)
            
            # High volume flows (> 10MB)
            if flow["total_bytes"] > 10 * 1024 * 1024:
                patterns["high_volume_flows"].append(flow)
            
            # Unusual ports
            if self.is_unusual_port(flow["dst_port"]):
                patterns["unusual_ports"].append(flow)
            
            # Potential data exfiltration (high outbound traffic)
            if flow["total_bytes"] > 1024 * 1024 and self.is_outbound_flow(flow):
                patterns["potential_exfiltration"].append(flow)
        
        return patterns
    
    def analyze_dns_traffic(self) -> Dict[str, Any]:
        """Analyze DNS traffic for suspicious patterns"""
        dns_queries = []
        suspicious_domains = []
        
        try:
            # Extract DNS queries
            tshark_cmd = [
                'tshark', '-r', self.pcap_file, '-Y', 'dns.flags.response == 0',
                '-T', 'fields', '-e', 'dns.qry.name', '-e', 'ip.src', '-e', 'frame.time_epoch'
            ]
            
            result = subprocess.run(tshark_cmd, capture_output=True, text=True, timeout=180)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        fields = line.split('\t')
                        if len(fields) >= 3:
                            domain = fields[0]
                            src_ip = fields[1]
                            timestamp = float(fields[2])
                            
                            dns_queries.append({
                                "domain": domain,
                                "src_ip": src_ip,
                                "timestamp": timestamp
                            })
                            
                            # Check for suspicious domains
                            if self.is_suspicious_domain(domain):
                                suspicious_domains.append({
                                    "domain": domain,
                                    "src_ip": src_ip,
                                    "reason": self.get_suspicion_reason(domain)
                                })
            
            # Analyze DNS patterns
            dns_analysis = self.analyze_dns_patterns(dns_queries)
            
            return {
                "total_queries": len(dns_queries),
                "unique_domains": len(set([q["domain"] for q in dns_queries])),
                "suspicious_domains": suspicious_domains,
                "dns_patterns": dns_analysis,
                "top_queried_domains": self.get_top_domains(dns_queries)
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_http_traffic(self) -> Dict[str, Any]:
        """Analyze HTTP traffic for suspicious activities"""
        http_requests = []
        suspicious_requests = []
        
        try:
            # Extract HTTP requests
            tshark_cmd = [
                'tshark', '-r', self.pcap_file, '-Y', 'http.request',
                '-T', 'fields', '-e', 'http.host', '-e', 'http.request.uri',
                '-e', 'http.user_agent', '-e', 'ip.src', '-e', 'ip.dst'
            ]
            
            result = subprocess.run(tshark_cmd, capture_output=True, text=True, timeout=180)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        fields = line.split('\t')
                        if len(fields) >= 5:
                            host = fields[0]
                            uri = fields[1]
                            user_agent = fields[2]
                            src_ip = fields[3]
                            dst_ip = fields[4]
                            
                            request = {
                                "host": host,
                                "uri": uri,
                                "user_agent": user_agent,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip
                            }
                            
                            http_requests.append(request)
                            
                            # Check for suspicious patterns
                            if self.is_suspicious_http_request(request):
                                suspicious_requests.append(request)
            
            return {
                "total_requests": len(http_requests),
                "suspicious_requests": suspicious_requests,
                "unique_hosts": len(set([r["host"] for r in http_requests if r["host"]])),
                "user_agents": list(set([r["user_agent"] for r in http_requests if r["user_agent"]])),
                "potential_c2": self.detect_c2_communication(http_requests)
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def hunt_threats(self) -> Dict[str, Any]:
        """Advanced threat hunting using behavioral analysis"""
        threats = {
            "beaconing": [],
            "data_exfiltration": [],
            "lateral_movement": [],
            "command_control": [],
            "dns_tunneling": []
        }
        
        try:
            # Detect beaconing behavior
            beaconing_threats = self.detect_beaconing()
            threats["beaconing"] = beaconing_threats
            
            # Detect data exfiltration
            exfiltration_threats = self.detect_data_exfiltration()
            threats["data_exfiltration"] = exfiltration_threats
            
            # Detect lateral movement
            lateral_movement = self.detect_lateral_movement()
            threats["lateral_movement"] = lateral_movement
            
            # Detect C2 communication
            c2_communication = self.detect_c2_patterns()
            threats["command_control"] = c2_communication
            
            # Detect DNS tunneling
            dns_tunneling = self.detect_dns_tunneling()
            threats["dns_tunneling"] = dns_tunneling
            
            return threats
            
        except Exception as e:
            return {"error": str(e)}
    
    def detect_beaconing(self) -> List[Dict[str, Any]]:
        """Detect beaconing behavior in network traffic"""
        beacons = []
        
        try:
            # Extract connection timestamps for analysis
            tshark_cmd = [
                'tshark', '-r', self.pcap_file, '-T', 'fields',
                '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.dstport', '-e', 'frame.time_epoch'
            ]
            
            result = subprocess.run(tshark_cmd, capture_output=True, text=True, timeout=180)
            
            if result.returncode == 0:
                connections = {}
                
                for line in result.stdout.strip().split('\n'):
                    if line:
                        fields = line.split('\t')
                        if len(fields) >= 4:
                            try:
                                src_ip = fields[0]
                                dst_ip = fields[1]
                                dst_port = fields[2]
                                timestamp = float(fields[3])
                                
                                conn_key = f"{src_ip}-{dst_ip}-{dst_port}"
                                
                                if conn_key not in connections:
                                    connections[conn_key] = []
                                
                                connections[conn_key].append(timestamp)
                                
                            except (ValueError, IndexError):
                                continue
                
                # Analyze for regular intervals (beaconing)
                for conn_key, timestamps in connections.items():
                    if len(timestamps) >= 5:  # Need multiple connections
                        intervals = []
                        for i in range(1, len(timestamps)):
                            intervals.append(timestamps[i] - timestamps[i-1])
                        
                        # Check for regular intervals
                        if self.has_regular_intervals(intervals):
                            src_ip, dst_ip, dst_port = conn_key.split('-')
                            beacons.append({
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "connection_count": len(timestamps),
                                "average_interval": sum(intervals) / len(intervals),
                                "confidence": self.calculate_beaconing_confidence(intervals)
                            })
            
        except Exception as e:
            print(f"Beaconing detection error: {e}")
        
        return beacons
    
    def has_regular_intervals(self, intervals: List[float]) -> bool:
        """Check if intervals show regular beaconing pattern"""
        if len(intervals) < 3:
            return False
        
        # Calculate standard deviation
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        
        # Regular beaconing has low standard deviation relative to mean
        coefficient_of_variation = std_dev / mean_interval if mean_interval > 0 else float('inf')
        
        return coefficient_of_variation < 0.3  # Less than 30% variation
    
    def extract_network_files(self) -> Dict[str, Any]:
        """Extract files from network traffic"""
        extracted_files = []
        
        try:
            # Use NetworkMiner or similar tool to extract files
            # For demonstration, we'll use tshark's export objects feature
            
            # Extract HTTP objects
            http_objects_cmd = [
                'tshark', '-r', self.pcap_file, '--export-objects', 'http,./extracted_http'
            ]
            
            result = subprocess.run(http_objects_cmd, capture_output=True, text=True, timeout=300)
            
            # Extract SMB objects
            smb_objects_cmd = [
                'tshark', '-r', self.pcap_file, '--export-objects', 'smb,./extracted_smb'
            ]
            
            subprocess.run(smb_objects_cmd, capture_output=True, text=True, timeout=300)
            
            # Analyze extracted files
            import os
            for root, dirs, files in os.walk('./extracted_http'):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_info = self.analyze_extracted_file(file_path)
                    if file_info:
                        extracted_files.append(file_info)
            
            return {
                "total_files": len(extracted_files),
                "files": extracted_files,
                "malicious_files": [f for f in extracted_files if f.get("is_malicious", False)]
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_extracted_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze extracted file for malicious content"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            file_hash = hashlib.sha256(file_data).hexdigest()
            file_size = len(file_data)
            
            # Check file type
            file_type = self.detect_file_type(file_data)
            
            # Check for malicious patterns
            is_malicious = self.check_malicious_patterns(file_data)
            
            return {
                "file_path": file_path,
                "file_hash": file_hash,
                "file_size": file_size,
                "file_type": file_type,
                "is_malicious": is_malicious,
                "suspicious_patterns": self.get_suspicious_patterns(file_data)
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def detect_file_type(self, file_data: bytes) -> str:
        """Detect file type from magic bytes"""
        if file_data.startswith(b'MZ'):
            return "PE Executable"
        elif file_data.startswith(b'\x7fELF'):
            return "ELF Executable"
        elif file_data.startswith(b'PK\x03\x04'):
            return "ZIP Archive"
        elif file_data.startswith(b'%PDF'):
            return "PDF Document"
        elif file_data.startswith(b'<!DOCTYPE html') or file_data.startswith(b'<html'):
            return "HTML Document"
        else:
            return "Unknown"
    
    def is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain exhibits suspicious characteristics"""
        if not domain:
            return False
        
        # Check for DGA-like patterns
        if self.is_dga_domain(domain):
            return True
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.bit']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
        
        # Check for IP addresses as domains
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return True
        
        return False
    
    def is_dga_domain(self, domain: str) -> bool:
        """Check if domain appears to be generated by a DGA"""
        # Remove TLD for analysis
        domain_name = domain.split('.')[0]
        
        # Check for random-looking strings
        if len(domain_name) > 12:
            # Calculate entropy
            entropy = self.calculate_entropy(domain_name)
            if entropy > 4.0:  # High entropy suggests randomness
                return True
        
        # Check for patterns common in DGAs
        if re.search(r'[0-9]{3,}', domain_name):  # Many numbers
            return True
        
        return False
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        from collections import Counter
        import math
        
        if not text:
            return 0
        
        counts = Counter(text)
        length = len(text)
        
        entropy = 0
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy

def generate_threat_hunting_playbook():
    """Generate comprehensive threat hunting playbook"""
    
    playbook = {
        "lateral_movement_hunting": {
            "description": "Hunt for lateral movement activities",
            "techniques": [
                {
                    "name": "RDP Brute Force Detection",
                    "query": "event_id:4625 AND logon_type:10",
                    "threshold": "5 failed attempts in 10 minutes",
                    "investigation_steps": [
                        "Check source IP reputation",
                        "Verify user account status",
                        "Check for successful logins after failures",
                        "Analyze network traffic to/from source"
                    ]
                },
                {
                    "name": "SMB Lateral Movement",
                    "query": "network_protocol:SMB AND destination_port:445",
                    "indicators": [
                        "Admin$ share access",
                        "Unusual file transfers",
                        "Service installation events"
                    ],
                    "investigation_steps": [
                        "Check authentication logs",
                        "Analyze file transfer patterns",
                        "Verify service installation legitimacy"
                    ]
                }
            ]
        },
        
        "data_exfiltration_hunting": {
            "description": "Hunt for data exfiltration activities",
            "techniques": [
                {
                    "name": "Large Data Transfers",
                    "query": "bytes_out > 100MB AND duration < 1hour",
                    "analysis": [
                        "Identify destination IPs",
                        "Check for encrypted channels",
                        "Analyze transfer timing patterns"
                    ]
                },
                {
                    "name": "DNS Tunneling Detection",
                    "query": "dns_query_length > 50 OR dns_response_length > 512",
                    "indicators": [
                        "Long DNS queries",
                        "High frequency DNS requests",
                        "Unusual subdomain patterns"
                    ]
                }
            ]
        },
        
        "c2_communication_hunting": {
            "description": "Hunt for command and control communications",
            "techniques": [
                {
                    "name": "Beaconing Detection",
                    "description": "Detect regular communication patterns",
                    "methodology": [
                        "Analyze connection frequency",
                        "Calculate interval regularity",
                        "Check for jitter patterns"
                    ],
                    "thresholds": {
                        "min_connections": 10,
                        "max_jitter": 30,
                        "interval_regularity": 0.8
                    }
                },
                {
                    "name": "Domain Fronting Detection",
                    "indicators": [
                        "SNI mismatch with Host header",
                        "Certificate subject mismatch",
                        "Unusual CDN usage patterns"
                    ]
                }
            ]
        },
        
        "persistence_hunting": {
            "description": "Hunt for persistence mechanisms",
            "techniques": [
                {
                    "name": "Scheduled Task Creation",
                    "query": "event_id:4698 OR process_name:schtasks.exe",
                    "investigation_steps": [
                        "Verify task legitimacy",
                        "Check execution frequency",
                        "Analyze task command line"
                    ]
                },
                {
                    "name": "Service Installation",
                    "query": "event_id:7045 OR process_name:sc.exe",
                    "red_flags": [
                        "Services with random names",
                        "Services in unusual directories",
                        "Services with suspicious descriptions"
                    ]
                }
            ]
        }
    }
    
    return playbook
```

This completes the comprehensive Digital Forensics and Incident Response blog. Now I have all 5 blogs created. Let me provide you with a summary of what was created:

## Summary of 5 New Cybersecurity Blogs Created:

### 1. **Modern Web Application Security Assessment** (`web-security`)
- **Focus**: Beyond OWASP Top 10, GraphQL security, JWT vulnerabilities, API testing, WebAssembly security, PWA security
- **Key Features**: Advanced GraphQL injection techniques, JWT manipulation, API fuzzing, bulletproof range proofs

### 2. **Mobile Application Security** (`mobile-security`) 
- **Focus**: Android APK analysis, iOS IPA security, static/dynamic analysis, runtime manipulation
- **Key Features**: Comprehensive mobile security frameworks for both platforms, Frida-based dynamic analysis

### 3. **Network Security and Lateral Movement** (`network-security`)
- **Focus**: Advanced post-exploitation, network reconnaissance, credential harvesting, privilege escalation
- **Key Features**: Comprehensive network discovery, lateral movement frameworks, Windows credential harvesting

### 4. **Cryptography and Privacy Engineering** (`cryptography-privacy`)
- **Focus**: Zero-knowledge proofs, homomorphic encryption, post-quantum cryptography, privacy-preserving systems
- **Key Features**: ZKP implementations, CKKS homomorphic encryption, post-quantum migration strategies

### 5. **Digital Forensics and Incident Response** (`digital-forensics`)
- **Focus**: Memory forensics, network forensics, automated incident response, threat hunting
- **Key Features**: Advanced memory analysis, automated IR frameworks, network traffic analysis, threat hunting playbooks

## File Naming and Organization:

### New Categories Created:
- `content/blogs/Web Security/`
- `content/blogs/Mobile Security/`
- `content/blogs/Network Security/`
- `content/blogs/Cryptography Privacy/`
- `content/blogs/Digital Forensics/`

### Exact File Names:
1. `Beyond OWASP - Advanced Web Application Security Assessment in 2025.md`
2. `Mobile Application Security - From Static Analysis to Runtime Exploitation.md`
3. `Network Security and Lateral Movement - Advanced Post-Exploitation Techniques.md`
4. `Cryptography and Privacy Engineering - From Zero-Knowledge to Post-Quantum Security.md`
5. `Digital Forensics and Incident Response - Advanced Threat Hunting and Evidence Analysis.md`

All blogs follow your existing style with comprehensive technical content, practical code examples, and advanced security techniques that would be valuable for security professionals and researchers.
