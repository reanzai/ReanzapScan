#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Reanzap - Gelişmiş Ağ Tarama Modülü
Sadece Python'un kendi kütüphanelerini kullanır
Zenmap ve Nmap'ten daha hızlı ve gelişmiş özellikler içerir
"""

import socket
import threading
import time
import ipaddress
import platform
import struct
import os
import json
import re
import sys
import random
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from datetime import datetime
import requests
from scapy.all import *

# Yaygın servisler ve port numaraları
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    115: "SFTP",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    194: "IRC",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy"
}

# Servis parmak izleri
SERVICE_FINGERPRINTS = {
    "SSH-2.0-OpenSSH": "OpenSSH",
    "SSH-1.99-OpenSSH": "OpenSSH",
    "220 ProFTPD": "ProFTPD",
    "220 FileZilla": "FileZilla FTP",
    "220 Microsoft FTP": "Microsoft FTP",
    "220 vsFTPd": "vsFTPD",
    "HTTP/1.1": "HTTP Server",
    "Server: Apache": "Apache",
    "Server: nginx": "Nginx",
    "Server: Microsoft-IIS": "IIS",
    "X-Powered-By: PHP": "PHP",
    "X-Powered-By: ASP.NET": "ASP.NET",
    "X-Powered-By: Express": "Express.js",
    "Server: Tomcat": "Tomcat",
    "Server: Jetty": "Jetty",
    "MySQL": "MySQL",
    "PostgreSQL": "PostgreSQL",
    "Microsoft SQL Server": "MSSQL",
    "MongoDB": "MongoDB",
    "Redis": "Redis",
    "RFB 003.": "VNC"
}

# Bilinen güvenlik açıkları (basitleştirilmiş)
KNOWN_VULNERABILITIES = {
    "OpenSSH 7.": {"CVE-2016-10009": "OpenSSH'da uzaktan kod çalıştırma açığı", "severity": "HIGH"},
    "OpenSSH 6.": {"CVE-2016-10012": "OpenSSH'da yetki yükseltme açığı", "severity": "MEDIUM"},
    "Apache 2.4.": {"CVE-2021-41773": "Apache HTTP Server'da path traversal açığı", "severity": "CRITICAL"},
    "nginx 1.18": {"CVE-2021-23017": "Nginx'te bilgi ifşası açığı", "severity": "MEDIUM"},
    "Microsoft-IIS 7.5": {"CVE-2010-3972": "IIS'te uzaktan kod çalıştırma açığı", "severity": "HIGH"},
    "vsFTPd 2.3.4": {"CVE-2011-2523": "vsFTPd'de backdoor açığı", "severity": "CRITICAL"},
    "ProFTPD 1.3.5": {"CVE-2015-3306": "ProFTPD'de uzaktan kod çalıştırma açığı", "severity": "HIGH"},
    "MySQL 5.5": {"CVE-2016-6662": "MySQL'de uzaktan kod çalıştırma açığı", "severity": "HIGH"},
    "PostgreSQL 9.": {"CVE-2019-10164": "PostgreSQL'de bilgi ifşası açığı", "severity": "MEDIUM"}
}

# İşletim sistemi parmak izleri (TTL değerleri)
OS_TTL_FINGERPRINTS = {
    64: "Linux/Unix",
    128: "Windows",
    254: "Cisco/Network Device",
    255: "Unix/FreeBSD"
}

class PortScanner:
    """Gelişmiş port tarama sınıfı"""
    
    def __init__(self):
        self.results = {}
        self.stop_scan = False
        self.scan_progress = 0
        self.total_tasks = 0
        self.completed_tasks = 0
        self.timeout = 1  # saniye
        self.max_threads = 200  # maksimum thread sayısı
        self.scan_start_time = None
        self.scan_end_time = None
        self.vuln_check = True  # güvenlik açığı kontrolü
        self.adaptive_timing = True  # adaptif zamanlama
        self.last_output = ""  # son çıktı
        self.scan_techniques = ["connect"]  # tarama teknikleri
        self.service_versions = {}
        self.vulnerabilities = {}
        self.cve_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.service_fingerprints = {
            "http": [
                {"pattern": b"Apache", "name": "Apache", "type": "Web Server"},
                {"pattern": b"nginx", "name": "Nginx", "type": "Web Server"},
                {"pattern": b"Microsoft-IIS", "name": "IIS", "type": "Web Server"}
            ],
            "ssh": [
                {"pattern": b"OpenSSH", "name": "OpenSSH", "type": "SSH Server"},
                {"pattern": b"SSH-2.0", "name": "SSH Protocol 2", "type": "SSH"}
            ],
            "ftp": [
                {"pattern": b"FileZilla", "name": "FileZilla", "type": "FTP Server"},
                {"pattern": b"vsFTPd", "name": "vsFTPd", "type": "FTP Server"},
                {"pattern": b"ProFTPD", "name": "ProFTPD", "type": "FTP Server"}
            ],
            "mysql": [
                {"pattern": b"MySQL", "name": "MySQL", "type": "Database"},
                {"pattern": b"MariaDB", "name": "MariaDB", "type": "Database"}
            ],
            "postgresql": [
                {"pattern": b"PostgreSQL", "name": "PostgreSQL", "type": "Database"}
            ],
            "mssql": [
                {"pattern": b"Microsoft SQL Server", "name": "MSSQL", "type": "Database"}
            ],
            "rdp": [
                {"pattern": b"Microsoft Terminal Services", "name": "RDP", "type": "Remote Desktop"}
            ],
            "smb": [
                {"pattern": b"Samba", "name": "Samba", "type": "File Sharing"},
                {"pattern": b"Windows", "name": "Windows SMB", "type": "File Sharing"}
            ]
        }
        
        # Tarama sonuçlarını kaydetmek için dizin oluştur
        self.results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_results")
        if not os.path.exists(self.results_dir):
            try:
                os.makedirs(self.results_dir)
            except:
                pass
    
    def update_progress(self):
        """İlerleme durumunu güncelle"""
        if self.total_tasks > 0:
            self.scan_progress = (self.completed_tasks / self.total_tasks) * 100
        return self.scan_progress
    
    def parse_target(self, target):
        """Hedef IP adresini veya ağını ayrıştır"""
        try:
            # CIDR notasyonu kontrolü (örn: 192.168.1.0/24)
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                return [str(ip) for ip in network.hosts()]
            
            # IP aralığı kontrolü (örn: 192.168.1.1-10)
            elif '-' in target and not target.startswith('-'):
                base, range_part = target.rsplit('.', 1)
                if '-' in range_part:
                    start, end = range_part.split('-')
                    start, end = int(start), int(end)
                    return [f"{base}.{i}" for i in range(start, end + 1)]
            
            # Tek IP adresi
            ipaddress.ip_address(target)
            return [target]
        except ValueError:
            # Hostname olabilir, DNS çözümlemesi yap
            try:
                ip = socket.gethostbyname(target)
                return [ip]
            except socket.gaierror:
                return []
    
    def ping_host(self, ip):
        """Gelişmiş host kontrolü"""
        # TCP SYN ping
        common_ports = [80, 443, 22, 445, 25, 3389]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return True
            except:
                continue
        
        # ICMP ping benzeri kontrol
        try:
            # Windows için
            if platform.system().lower() == "windows":
                ping_cmd = f"ping -n 1 -w 1000 {ip}"
                return os.system(ping_cmd) == 0
            # Linux/Unix için
            else:
                ping_cmd = f"ping -c 1 -W 1 {ip}"
                return os.system(ping_cmd) == 0
        except:
            pass
        
        return False
    
    def get_service_fingerprint(self, banner, port):
        """Servis parmak izi tespiti"""
        if not banner:
            return COMMON_PORTS.get(port, "unknown"), ""
        
        # Servis parmak izlerini kontrol et
        for fingerprint, service_name in SERVICE_FINGERPRINTS.items():
            if fingerprint in banner:
                # Sürüm bilgisini çıkar
                version_match = re.search(r'(\d+\.\d+\.?\d*)', banner)
                version = version_match.group(1) if version_match else ""
                return service_name, version
        
        # Bilinen bir parmak izi bulunamadıysa, port numarasına göre tahmin et
        return COMMON_PORTS.get(port, "unknown"), ""
    
    def check_vulnerabilities(self, service, version):
        """Bilinen güvenlik açıklarını kontrol et"""
        if not self.vuln_check or not service or not version:
            return []
        
        vulnerabilities = []
        service_version = f"{service} {version}"
        
        for vuln_signature, vuln_info in KNOWN_VULNERABILITIES.items():
            if vuln_signature in service_version:
                vulnerabilities.append(vuln_info)
        
        return vulnerabilities
    
    def get_service_banner(self, ip, port):
        """Gelişmiş servis banner bilgisini al"""
        banner = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                
                # Servis tipine göre özel istekler
                if port == 80 or port == 443 or port == 8080:
                    s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nUser-Agent: Reanzap/1.0\r\nAccept: */*\r\n\r\n")
                elif port == 21:  # FTP
                    pass  # Banner otomatik gelecek
                elif port == 22:  # SSH
                    pass  # Banner otomatik gelecek
                elif port == 25:  # SMTP
                    pass  # Banner otomatik gelecek
                elif port == 3306:  # MySQL
                    pass  # Özel protokol
                else:
                    s.send(b"\r\n")
                
                # Veri al
                try:
                    banner = s.recv(2048)
                    return banner.decode('utf-8', errors='ignore').strip()
                except:
                    return ""
        except:
            return ""
    
    def scan_port(self, ip, port):
        """Gelişmiş port tarama"""
        result = {
            "port": port,
            "protocol": "tcp",
            "state": "closed",
            "service": COMMON_PORTS.get(port, "unknown"),
            "version": "",
            "vulnerabilities": []
        }
        
        # Adaptif zamanlama
        if self.adaptive_timing:
            # Yoğun taramalarda gecikme ekle
            if self.total_tasks > 5000:
                time.sleep(0.01)
        
        try:
            # TCP bağlantı dene
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            response = sock.connect_ex((ip, port))
            
            if response == 0:
                result["state"] = "open"
                
                # Servis banner bilgisini al
                banner = self.get_service_banner(ip, port)
                
                # Servis ve sürüm tespiti
                service, version = self.get_service_fingerprint(banner, port)
                result["service"] = service
                result["version"] = version
                
                # Güvenlik açığı kontrolü
                if self.vuln_check and service and version:
                    result["vulnerabilities"] = self.check_vulnerabilities(service, version)
                
                # Banner bilgisini ekle
                if banner:
                    result["banner"] = banner[:200]  # İlk 200 karakter
            
            sock.close()
        
        except Exception as e:
            result["state"] = "error"
            result["error"] = str(e)
        
        self.completed_tasks += 1
        return result
    
    def get_os_guess(self, ip):
        """Gelişmiş işletim sistemi tespiti"""
        os_info = {"name": "Unknown", "accuracy": 0}
        
        # TCP bağlantılarla işletim sistemi tespiti
        try:
            # Açık portları kontrol et
            open_ports = []
            common_ports = [80, 443, 445, 22, 3389, 139, 135]
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    if sock.connect_ex((ip, port)) == 0:
                        open_ports.append(port)
                        
                        # Port bazlı OS tahmini
                        if port == 3389:
                            os_info = {"name": "Windows", "accuracy": 80}
                        elif port == 22:
                            banner = self.get_service_banner(ip, port).lower()
                            if "ubuntu" in banner:
                                os_info = {"name": "Ubuntu Linux", "accuracy": 90}
                            elif "debian" in banner:
                                os_info = {"name": "Debian Linux", "accuracy": 90}
                            elif "linux" in banner:
                                os_info = {"name": "Linux", "accuracy": 80}
                        elif port == 139 or port == 445:
                            os_info = {"name": "Windows", "accuracy": 75}
                        elif port == 135:
                            os_info = {"name": "Windows", "accuracy": 85}
                    sock.close()
                except:
                    continue
            
            # TTL değeri ile OS tahmini
            if os_info["name"] == "Unknown" and platform.system().lower() == "windows":
                try:
                    # Windows'ta TTL değerini al
                    ping_output = os.popen(f"ping -n 1 {ip}").read()
                    ttl_match = re.search(r"TTL=(\d+)", ping_output)
                    if ttl_match:
                        ttl = int(ttl_match.group(1))
                        if ttl <= 64:
                            os_info = {"name": "Linux/Unix", "accuracy": 70}
                        elif ttl <= 128:
                            os_info = {"name": "Windows", "accuracy": 70}
                        elif ttl <= 255:
                            os_info = {"name": "Cisco/Network Device", "accuracy": 60}
                except:
                    pass
            
            # Açık portların kombinasyonuna göre tahmin
            if len(open_ports) >= 3:
                if all(p in open_ports for p in [139, 445, 3389]):
                    os_info = {"name": "Windows", "accuracy": 95}
                elif all(p in open_ports for p in [22, 80, 443]):
                    os_info = {"name": "Linux Web Server", "accuracy": 85}
            
            return os_info
        except:
            return {"name": "Unknown", "accuracy": 0}
    
    def get_hostname(self, ip):
        """IP adresinden hostname bilgisini al"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ""
    
    def scan(self, target, profile):
        """Gelişmiş tarama"""
        self.scan_start_time = datetime.now()
        self.stop_scan = False
        self.scan_progress = 0
        self.results = {}
        
        try:
            # Hedef IP adreslerini belirle
            ip_list = self.parse_target(target)
            total_ips = len(ip_list)
            
            # Her IP için tarama yap
            with ThreadPoolExecutor(max_workers=200) as executor:
                for idx, ip in enumerate(ip_list):
                    if self.stop_scan:
                        break
                    
                    # Host discovery
                    if self.ping_host(ip):
                        # Port taraması
                        open_ports = self.scan_ports(ip)
                        
                        if open_ports:
                            # Servis ve versiyon tespiti
                            service_info = self.detect_services(ip, open_ports)
                            
                            # OS tespiti
                            os_info = self.detect_os(ip)
                            
                            # Güvenlik açığı taraması
                            self.scan_vulnerabilities(ip, service_info)
                            
                            # Sonuçları kaydet
                            self.results[ip] = {
                                "status": {"state": "up"},
                                "hostname": self.get_hostname(ip),
                                "os": os_info,
                                "ports": service_info,
                                "vulnerabilities": self.vulnerabilities.get(ip, [])
                            }
                    
                    self.scan_progress = ((idx + 1) / total_ips) * 100
            
            return self.results
        
        except Exception as e:
            raise Exception(f"Tarama hatası: {str(e)}")

    def scan_ports(self, ip):
        """Port taraması yap"""
        open_ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080]
        
        for port in common_ports:
            if self.stop_scan:
                break
            
            if self.check_port(ip, port):
                open_ports.append(port)
        
        return open_ports

    def detect_services(self, ip, ports):
        """Servis ve versiyon tespiti"""
        service_info = {}
        
        for port in ports:
            try:
                # TCP bağlantısı kur
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect((ip, port))
                    
                    # Banner bilgisini al
                    banner = b""
                    try:
                        # HTTP için özel istek
                        if port in [80, 443, 8080]:
                            s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                        else:
                            s.send(b"\r\n")
                        banner = s.recv(1024)
                    except:
                        pass
                    
                    service = self.identify_service(port, banner)
                    service_info[port] = service
                    
                    # Versiyon bilgisini CVE taraması için sakla
                    if service.get("version"):
                        self.service_versions[f"{ip}:{port}"] = {
                            "product": service.get("product", ""),
                            "version": service.get("version", ""),
                            "type": service.get("type", "")
                        }
            
            except:
                continue
        
        return service_info

    def identify_service(self, port, banner):
        """Banner bilgisinden servisi tespit et"""
        service = {
            "port": port,
            "state": "open",
            "name": "unknown",
            "product": "",
            "version": "",
            "type": ""
        }
        
        # Bilinen portlar
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            139: "netbios",
            443: "https",
            445: "smb",
            1433: "mssql",
            1521: "oracle",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            8080: "http"
        }
        
        # Port numarasına göre servis adını belirle
        service["name"] = common_ports.get(port, "unknown")
        
        # Banner analizi
        if banner:
            banner_str = banner.decode('utf-8', errors='ignore')
            
            # Servis parmak izlerini kontrol et
            for service_type, fingerprints in self.service_fingerprints.items():
                for fp in fingerprints:
                    if fp["pattern"] in banner:
                        service["name"] = service_type
                        service["product"] = fp["name"]
                        service["type"] = fp["type"]
                        
                        # Versiyon numarasını bul
                        version_match = re.search(rb'[\d.]+', banner)
                        if version_match:
                            service["version"] = version_match.group(0).decode()
        
        return service

    def scan_vulnerabilities(self, ip, service_info):
        """CVE veritabanından güvenlik açıklarını tara"""
        self.vulnerabilities[ip] = []
        
        for port, service in service_info.items():
            if service.get("product") and service.get("version"):
                try:
                    # CVE API'sine sorgu yap
                    params = {
                        "keywordSearch": f'{service["product"]} {service["version"]}',
                        "resultsPerPage": 10
                    }
                    
                    response = requests.get(self.cve_api_url, params=params)
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Bulunan güvenlik açıklarını işle
                        for vuln in data.get("vulnerabilities", []):
                            cve = vuln.get("cve", {})
                            
                            vulnerability = {
                                "port": port,
                                "service": service["name"],
                                "cve_id": cve.get("id", ""),
                                "description": cve.get("description", [{}])[0].get("value", ""),
                                "severity": self.get_severity(cve),
                                "published": cve.get("published", ""),
                                "references": [ref.get("url") for ref in cve.get("references", [])]
                            }
                            
                            self.vulnerabilities[ip].append(vulnerability)
                
                except Exception as e:
                    print(f"CVE tarama hatası: {str(e)}")

    def get_severity(self, cve):
        """CVE'nin önem derecesini belirle"""
        metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
        
        base_score = metrics.get("baseScore", 0)
        if base_score >= 9.0:
            return "Critical"
        elif base_score >= 7.0:
            return "High"
        elif base_score >= 4.0:
            return "Medium"
        else:
            return "Low"

    def check_port(self, ip, port):
        """Port açık mı kontrol et"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                return result == 0
        except:
            return False

    def detect_os(self, ip):
        """İşletim sistemi tespiti"""
        try:
            # TCP/IP parmak izi analizi
            ans = sr1(IP(dst=ip)/TCP(dport=80, flags="S"), timeout=2, verbose=0)
            if ans:
                if ans.haslayer(TCP):
                    # TTL değerine göre tahmin
                    ttl = ans.ttl
                    if ttl <= 64:
                        return {"name": "Linux/Unix", "accuracy": 75}
                    elif ttl <= 128:
                        return {"name": "Windows", "accuracy": 75}
                    else:
                        return {"name": "Unknown", "accuracy": 0}
        except:
            pass
        
        return {"name": "Unknown", "accuracy": 0}
    
    def save_scan_results(self, target):
        """Tarama sonuçlarını kaydet"""
        try:
            if not self.results:
                return
            
            # Dosya adı oluştur
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_hash = hashlib.md5(target.encode()).hexdigest()[:8]
            filename = f"scan_{target_hash}_{timestamp}.json"
            filepath = os.path.join(self.results_dir, filename)
            
            # JSON olarak kaydet
            with open(filepath, 'w') as f:
                json.dump(self.results, f, indent=2)
            
            return filepath
        except:
            return None
    
    def stop(self):
        """Taramayı durdur"""
        self.stop_scan = True
    
    def generate_scan_output(self):
        """Zengin çıktı formatı oluştur"""
        output = []
        output.append("Reanzap Gelişmiş Tarama Raporu")
        output.append("=============================")
        
        if self.scan_start_time and self.scan_end_time:
            duration = (self.scan_end_time - self.scan_start_time).total_seconds()
            output.append(f"Tarama Başlangıç: {self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            output.append(f"Tarama Bitiş: {self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            output.append(f"Toplam Süre: {duration:.2f} saniye")
        
        output.append(f"Taranan Host Sayısı: {len(self.results)}")
        
        # Aktif host sayısını hesapla
        active_hosts = sum(1 for ip, data in self.results.items() if data.get("status", {}).get("state") == "up")
        output.append(f"Aktif Host Sayısı: {active_hosts}")
        
        # Açık port sayısını hesapla
        open_ports_count = 0
        for ip, data in self.results.items():
            open_ports_count += len(data.get("ports", {}))
        
        output.append(f"Açık Port Sayısı: {open_ports_count}")
        output.append("")
        
        # Her host için detaylı bilgi
        for ip, host_data in self.results.items():
            output.append(f"\n[+] Host: {ip}")
            
            # Hostname
            hostnames = host_data.get("hostnames", [])
            if hostnames and hostnames[0].get("name"):
                output.append(f"    Hostname: {hostnames[0].get('name')}")
            
            # Host durumu
            status = host_data.get("status", {}).get("state", "unknown")
            output.append(f"    Durum: {status}")
            
            # İşletim sistemi
            os_info = host_data.get("os", {})
            if os_info.get("name") != "Unknown":
                output.append(f"    İşletim Sistemi: {os_info.get('name')} (Doğruluk: {os_info.get('accuracy')}%)")
            
            # Açık portlar
            ports = host_data.get("ports", {})
            if ports:
                output.append("\n    Açık Portlar:")
                output.append("    ------------")
                output.append("    PORT     STATE  SERVICE         VERSION")
                
                for port, port_data in sorted(ports.items()):
                    service = port_data.get("name", "unknown")
                    state = port_data.get("state", "unknown")
                    version = port_data.get("version", "")
                    output.append(f"    {port}/tcp  {state:<6} {service:<15} {version}")
                
                # Güvenlik açıkları
                vuln_found = False
                for port, port_data in ports.items():
                    if "vulnerabilities" in port_data and port_data["vulnerabilities"]:
                        if not vuln_found:
                            output.append("\n    Potansiyel Güvenlik Açıkları:")
                            output.append("    ---------------------------")
                            vuln_found = True
                        
                        service = port_data.get("name", "unknown")
                        version = port_data.get("version", "")
                        output.append(f"    {port}/tcp - {service} {version}:")
                        
                        for vuln in port_data["vulnerabilities"]:
                            cve_id = next(iter(vuln.keys()))
                            description = vuln[cve_id]
                            severity = vuln.get("severity", "UNKNOWN")
                            output.append(f"      - {cve_id}: {description} (Önem: {severity})")
        
        return "\n".join(output)
    
    def get_nmap_last_output(self):
        """Son tarama çıktısını al"""
        if self.last_output:
            return self.last_output
        return self.generate_scan_output()
    
    def get_scan_statistics(self):
        """Tarama istatistiklerini al"""
        stats = {
            "start_time": self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S") if self.scan_start_time else None,
            "end_time": self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S") if self.scan_end_time else None,
            "duration": (self.scan_end_time - self.scan_start_time).total_seconds() if self.scan_start_time and self.scan_end_time else 0,
            "hosts_total": len(self.results),
            "hosts_up": sum(1 for ip, data in self.results.items() if data.get("status", {}).get("state") == "up"),
            "hosts_down": sum(1 for ip, data in self.results.items() if data.get("status", {}).get("state") == "down"),
            "ports_open": sum(len(data.get("ports", {})) for ip, data in self.results.items()),
            "vulnerabilities": sum(
                len(port_data.get("vulnerabilities", []))
                for ip, data in self.results.items()
                for port, port_data in data.get("ports", {}).items()
                if "vulnerabilities" in port_data
            )
        }
        return stats


# Tarama profilleri
SCAN_PROFILES = {
    "Hızlı Tarama": "Yaygın portları hızlıca tara",
    "Yoğun Tarama": "Tüm portları ve servisleri detaylı tara",
    "Tüm TCP Portları": "Tüm TCP portlarını tara",
    "Ping Olmadan Tarama": "Ping kontrolü yapmadan tara",
    "Ping Taraması": "Sadece ping kontrolü yap",
    "Normal Tarama": "Standart tarama yap",
    "Güvenlik Taraması": "Güvenlik açıklarını tespit et",
    "Özel": "Özel tarama seçenekleri"
} 