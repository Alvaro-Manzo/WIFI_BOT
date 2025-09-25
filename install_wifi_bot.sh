#!/bin/bash

# WiFi Network Administrator Bot - Script de Instalación
# Autor: Sistema de Administración de Red
# Versión: 2.0

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "============================================================"
echo "    🛡️  WIFI NETWORK ADMINISTRATOR BOT - INSTALADOR"
echo "============================================================"
echo -e "${NC}"

# Función para imprimir mensajes
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar permisos de root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Este script debe ejecutarse como root"
        echo "Uso: sudo bash install.sh"
        exit 1
    fi
}

# Detectar sistema operativo
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            OS="debian"
            print_status "Sistema detectado: Debian/Ubuntu"
        elif [ -f /etc/redhat-release ]; then
            OS="redhat"
            print_status "Sistema detectado: RedHat/CentOS/Fedora"
        elif [ -f /etc/arch-release ]; then
            OS="arch"
            print_status "Sistema detectado: Arch Linux"
        else
            OS="unknown"
            print_warning "Sistema Linux no reconocido, intentando instalación genérica"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        print_status "Sistema detectado: macOS"
    else
        print_error "Sistema operativo no soportado: $OSTYPE"
        exit 1
    fi
}

# Instalar dependencias del sistema
install_system_deps() {
    print_status "Instalando dependencias del sistema..."
    
    case $OS in
        "debian")
            apt-get update
            apt-get install -y python3 python3-pip wireless-tools net-tools nmap aircrack-ng iw
            ;;
        "redhat")
            if command -v dnf &> /dev/null; then
                dnf install -y python3 python3-pip wireless-tools net-tools nmap aircrack-ng iw
            else
                yum install -y python3 python3-pip wireless-tools net-tools nmap aircrack-ng iw
            fi
            ;;
        "arch")
            pacman -Sy --noconfirm python python-pip wireless_tools net-tools nmap aircrack-ng iw
            ;;
        "macos")
            if ! command -v brew &> /dev/null; then
                print_error "Homebrew no está instalado. Instala Homebrew primero:"
                echo "https://brew.sh/"
                exit 1
            fi
            brew install python3 nmap aircrack-ng
            ;;
        *)
            print_warning "Instalación manual requerida para este sistema"
            ;;
    esac
    
    print_status "Dependencias del sistema instaladas"
}

# Instalar dependencias de Python
install_python_deps() {
    print_status "Instalando dependencias de Python..."
    
    # Verificar si requirements.txt existe
    if [ ! -f "requirements.txt" ]; then
        print_error "Archivo requirements.txt no encontrado"
        exit 1
    fi
    
    # Instalar usando pip3
    pip3 install -r requirements.txt
    
    print_status "Dependencias de Python instaladas"
}

# Verificar instalación
verify_installation() {
    print_status "Verificando instalación..."
    
    # Verificar Python y módulos
    python3 -c "import scapy; print('✅ Scapy instalado correctamente')" 2>/dev/null || {
        print_error "Error: Scapy no está instalado correctamente"
        exit 1
    }
    
    python3 -c "import netifaces; print('✅ Netifaces instalado correctamente')" 2>/dev/null || {
        print_error "Error: Netifaces no está instalado correctamente"
        exit 1
    }
    
    # Verificar herramientas del sistema
    command -v iwconfig >/dev/null 2>&1 || {
        print_warning "iwconfig no encontrado, algunas funciones pueden no funcionar"
    }
    
    command -v ifconfig >/dev/null 2>&1 || {
        print_warning "ifconfig no encontrado, usando ip como alternativa"
    }
    
    print_status "Verificación completada"
}

# Configurar archivos iniciales
setup_config() {
    print_status "Configurando archivos iniciales..."
    
    # Crear archivo de configuración si no existe
    if [ ! -f "wifi_config.json" ]; then
        print_status "Creando archivo de configuración por defecto..."
        # El archivo ya está creado por el script principal
    fi
    
    # Hacer ejecutable el script principal
    chmod +x wifi.py
    
    # Crear enlace simbólico en /usr/local/bin (opcional)
    read -p "¿Crear enlace simbólico en /usr/local/bin para acceso global? (s/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Ss]$ ]]; then
        ln -sf "$(pwd)/wifi.py" /usr/local/bin/wifi-admin
        print_status "Enlace creado: wifi-admin"
        echo "Ahora puedes ejecutar: sudo wifi-admin"
    fi
    
    print_status "Configuración completada"
}

# Mostrar información final
show_final_info() {
    echo
    echo -e "${GREEN}============================================================"
    echo "           🎉 INSTALACIÓN COMPLETADA EXITOSAMENTE 🎉"
    echo "============================================================${NC}"
    echo
    echo "📋 PRÓXIMOS PASOS:"
    echo
    echo "1. Editar configuración:"
    echo "   nano wifi_config.json"
    echo
    echo "2. Ejecutar el bot:"
    echo "   sudo python3 wifi.py"
    echo
    echo "3. O usando enlace (si se creó):"
    echo "   sudo wifi-admin"
    echo
    echo "4. Para ayuda:"
    echo "   python3 wifi.py --help"
    echo
    echo -e "${YELLOW}⚠️  RECUERDA: Usar solo en tu propia red WiFi${NC}"
    echo -e "${BLUE}📖 Documentación: README_WiFi_Bot.md${NC}"
    echo
}

# Función de limpieza en caso de error
cleanup() {
    print_error "Instalación interrumpida"
    exit 1
}

# Configurar trap para limpieza
trap cleanup INT TERM

# Función principal
main() {
    print_status "Iniciando instalación del WiFi Network Administrator Bot..."
    
    check_root
    detect_os
    install_system_deps
    install_python_deps
    verify_installation
    setup_config
    show_final_info
    
    print_status "¡Instalación completada exitosamente!"
}

# Ejecutar función principal
main "$@"
