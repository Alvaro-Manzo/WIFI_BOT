# 🛡️ WiFi Network Administrator Bot

**Herramienta profesional para la administración y seguridad de tu propia red WiFi**

## ⚠️ ADVERTENCIA LEGAL

**Esta herramienta está diseñada ÚNICAMENTE para ser utilizada en tu propia red WiFi.**
- ✅ USO LEGAL: En tu red doméstica o empresarial donde tengas permisos de administrador
- ❌ USO ILEGAL: En redes de terceros sin autorización explícita
- El usuario es completamente responsable del uso de esta herramienta

## 🚀 Características Principales

### 🔍 **Escaneo y Monitoreo**
- Detección automática de dispositivos conectados
- Identificación de fabricantes por MAC address
- Monitoreo continuo en tiempo real
- Alertas de nuevos dispositivos

### 🚫 **Gestión de Acceso**
- Desconexión de dispositivos no autorizados
- Sistema de whitelist para dispositivos protegidos
- Deautenticación WiFi profesional
- Confirmación de seguridad antes de acciones

### ⚙️ **Configuración Avanzada**
- Configuración mediante archivo JSON
- Múltiples interfaces de red soportadas
- Parámetros personalizables
- Sistema de logging completo

### 🎯 **Interfaz de Usuario**
- Menú interactivo intuitivo
- Colores y formateo profesional
- Modo línea de comandos para automatización
- Reportes detallados

## 📋 Requisitos del Sistema

### **Sistema Operativo**
- Linux (Ubuntu, Debian, CentOS, Fedora, Arch)
- macOS (con limitaciones)
- Tarjeta WiFi compatible con modo monitor

### **Permisos**
- Acceso root/sudo (requerido para modo monitor)
- Permisos de administración de red

### **Hardware**
- Tarjeta WiFi compatible con injection/monitor mode
- Recomendado: Adaptadores USB WiFi específicos (Alfa, Panda, etc.)

## 🔧 Instalación

### **1. Clonar e Instalar Dependencias**

```bash
# Clonar el repositorio (o descargar archivos)
cd /path/to/wifi-admin-bot

# Instalar dependencias del sistema (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install python3-pip wireless-tools net-tools nmap aircrack-ng

# Instalar dependencias de Python
pip3 install -r requirements.txt
```

### **2. Configuración Inicial**

```bash
# Copiar configuración de ejemplo
cp wifi_config.json.example wifi_config.json

# Editar configuración según tu red
nano wifi_config.json
```

### **3. Verificar Instalación**

```bash
# Verificar que todo funciona
sudo python3 wifi.py --scan
```

## ⚙️ Configuración

### **Archivo de Configuración (`wifi_config.json`)**

```json
{
    "network": {
        "interface": "wlan0",           // Interfaz WiFi a usar
        "gateway": "192.168.1.1",       // IP del router
        "network_range": "192.168.1.0/24" // Rango de red
    },
    "security": {
        "whitelist": [                   // MACs protegidas
            "aa:bb:cc:dd:ee:ff"
        ],
        "admin_mac": "",                 // MAC del administrador
        "require_confirmation": true     // Confirmar antes de desconectar
    },
    "settings": {
        "scan_interval": 10,             // Intervalo de escaneo (segundos)
        "deauth_count": 5,               // Número de paquetes deauth
        "auto_scan": true                // Escaneo automático al iniciar
    }
}
```

### **Configuración de Red**

1. **Identificar tu interfaz WiFi:**
   ```bash
   iwconfig
   # o
   ip link show
   ```

2. **Configurar en el archivo JSON:**
   ```json
   {
       "network": {
           "interface": "wlan0",        // Cambia por tu interfaz
           "gateway": "192.168.1.1",    // IP de tu router
           "network_range": "192.168.1.0/24"  // Tu rango de red
       }
   }
   ```

## 🚀 Uso

### **Modo Interactivo**

```bash
# Ejecutar bot principal
sudo python3 wifi.py

# Con configuración personalizada
sudo python3 wifi.py --config mi_config.json
```

### **Modo Línea de Comandos**

```bash
# Solo escanear red
sudo python3 wifi.py --scan

# Desconectar dispositivo específico
sudo python3 wifi.py --interface wlan0 --target aa:bb:cc:dd:ee:ff --disconnect

# Con interfaz específica
sudo python3 wifi.py --interface wlan1
```

### **Opciones de Línea de Comandos**

```bash
python3 wifi.py --help

Opciones:
  -h, --help                    Mostrar ayuda
  -c, --config CONFIG          Archivo de configuración
  -i, --interface INTERFACE    Interfaz de red
  --scan                       Solo escanear y salir
  -t, --target MAC            MAC del dispositivo objetivo
  --disconnect                 Desconectar dispositivo objetivo
```

## 🎮 Interfaz Interactiva

### **Menú Principal**
```
==================================================
           WIFI NETWORK ADMINISTRATOR
==================================================
1. Escanear red
2. Mostrar dispositivos
3. Desconectar dispositivo  
4. Monitoreo continuo
5. Configurar interfaz
6. Configuración
7. Ver logs
0. Salir
```

### **Funciones del Menú**

1. **Escanear red**: Busca dispositivos conectados en la red
2. **Mostrar dispositivos**: Lista todos los dispositivos detectados
3. **Desconectar dispositivo**: Selecciona y desconecta un dispositivo
4. **Monitoreo continuo**: Escaneo automático cada X segundos
5. **Configurar interfaz**: Configura modo monitor en interfaz WiFi
6. **Configuración**: Gestiona whitelist y configuraciones
7. **Ver logs**: Muestra logs recientes de actividad

## 🔒 Seguridad y Mejores Prácticas

### **Lista Blanca (Whitelist)**
```json
{
    "security": {
        "whitelist": [
            "aa:bb:cc:dd:ee:ff",  // Tu dispositivo personal
            "11:22:33:44:55:66",  // Dispositivo familiar
            "77:88:99:aa:bb:cc"   // Dispositivo de trabajo
        ]
    }
}
```

### **Dispositivos Protegidos**
- Siempre agrega tus dispositivos a la whitelist
- Configura la MAC del administrador para autoprotección
- Usa confirmación antes de desconectar dispositivos

### **Monitoreo Responsable**
- Usa intervalos de escaneo razonables (≥10 segundos)
- Revisa logs regularmente
- No abuses de la función de desconexión

## 📊 Logs y Monitoreo

### **Archivo de Log**
- Ubicación: `wifi_admin.log`
- Rotación automática
- Niveles: INFO, WARNING, ERROR

### **Ejemplo de Logs**
```
2025-09-25 10:30:15 - INFO - WiFi Network Bot iniciado
2025-09-25 10:30:20 - INFO - Nuevo dispositivo: aa:bb:cc:dd:ee:ff (192.168.1.100)
2025-09-25 10:30:45 - WARNING - Dispositivo desautenticado: ff:ee:dd:cc:bb:aa (192.168.1.200)
```

## 🛠️ Solución de Problemas

### **Problemas Comunes**

#### **Error: "Se requieren permisos de root"**
```bash
# Solución: Ejecutar con sudo
sudo python3 wifi.py
```

#### **Error: "No se pudo configurar modo monitor"**
```bash
# Verificar que la tarjeta soporte modo monitor
sudo iwconfig

# Probar manualmente
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ifconfig wlan0 up
```

#### **Error: "Módulo scapy no encontrado"**
```bash
# Instalar dependencias
pip3 install -r requirements.txt
```

#### **No detecta dispositivos**
- Verificar que estés en la red correcta
- Comprobar configuración de gateway y rango de red
- Probar con diferentes interfaces

### **Diagnóstico**

```bash
# Verificar interfaz
iwconfig

# Verificar conectividad
ping 192.168.1.1

# Verificar Python y módulos
python3 -c "import scapy; print('Scapy OK')"
```

## 🔧 Configuración Avanzada

### **Múltiples Rangos de Red**
```json
{
    "network": {
        "alternative_ranges": [
            "192.168.0.0/24",
            "10.0.0.0/24", 
            "172.16.0.0/24"
        ]
    }
}
```

### **Personalización de Interface**
```json
{
    "ui": {
        "color_theme": "default",
        "show_vendor_info": true,
        "auto_refresh": true,
        "detailed_logs": true
    }
}
```

### **Configuraciones de Seguridad**
```json
{
    "security": {
        "max_deauth_per_hour": 10,
        "require_confirmation": true,
        "forensic_mode": false
    }
}
```

## 📈 Casos de Uso

### **1. Administrador de Red Doméstica**
- Monitorear dispositivos conectados
- Identificar intrusos o dispositivos no autorizados
- Gestionar acceso a red WiFi familiar

### **2. Administrador de Red Empresarial**
- Control de acceso en red corporativa
- Monitoreo de dispositivos BYOD
- Respuesta a incidentes de seguridad

### **3. Auditoría de Seguridad**
- Verificar seguridad de red propia
- Pruebas de resistencia a desconexión
- Análisis de dispositivos conectados

## 🤝 Contribuir

### **Reportar Bugs**
- Crear issue con detalles del error
- Incluir logs y configuración
- Especificar sistema operativo y hardware

### **Mejoras**
- Fork del repositorio
- Crear branch para nuevas características
- Enviar pull request con descripción detallada

## 📜 Licencia

Este proyecto está bajo licencia MIT. Ver archivo `LICENSE` para más detalles.

## ⚠️ Disclaimer

**IMPORTANTE**: Esta herramienta es para fines educativos y de administración de red propia. El autor no se hace responsable por el mal uso de esta herramienta. Úsala únicamente en redes donde tengas permisos explícitos de administración.

### **Uso Responsable**
- ✅ Tu propia red doméstica
- ✅ Red empresarial con autorización
- ✅ Laboratorio de pruebas propio
- ❌ Redes públicas o de terceros
- ❌ Redes sin autorización

---

## 🆘 Soporte

Para soporte técnico:
1. Revisar esta documentación
2. Verificar logs en `wifi_admin.log`
3. Crear issue en el repositorio
4. Incluir información detallada del problema

**¡Mantén tu red segura y úsala responsablemente!** 🛡️
