Servidor VPN con Scapy para Dispositivos Android

Servidor VPN basado en [VPN Server implemented in pure Python](https://github.com/qwj/python-vpn) pero usando unicamente Scapy y simplificando el Forward pensado para usar en dispositivos Android

Acerca del Proyecto:

El objetivo fue crear un VPN de capa 3 con un tunel (sin cifrado) que permita conectarse a internet. Como la mayoria de internet funciona con los protocolos UDP y TCP en su capa de transporte entonces fueron los únicos protocolos implementados

Requisitos:
- Linux (o Windows usando Hyper-V)
- El cliente pensado para esto es ToyVPN. Puede obtenerlo [aqui](https://github.com/qwj/python-vpn)
    
Pre-requistios:

Tener bloqueados los paquetes RST salientes debido al funcionamiento inhato del módulo Scapy (el IP del Host puede obtenerlo con ifconfig)  
```iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <IP del Host> -j DROP```

Instalación de módulos necesarios (requiere pip):
```
sudo apt update
sudo apt install python3-pip
sudo python3 -m pip install -r requirements.txt
```
Correr:
```
sudo python3 vpn_server.py
```
Notas:
- Si quiere usarlo fuera de la red local necesitará abrir los puertos (puede ser necesario contactar con su ISP)
- Si quiere, puede cambiar el puerto (por defecto es 12345)
- Si se utiliza Hyper-V con Ubuntu, deberá habilitar el modo Bridge para acceder a una IP dentro de la red local

Por mejorar:
- Algunas apps android no funcionan, entre ellas se puede nombrar WhatsApp, Telegram, etc (Estoy investigando qué sucede). Entre algunas que puedo nombrar que funciona es en Instagram, YouTube, Chrome
- Agregar soporte para el protocolo ICMP
- Seria deseable que el Servidor sea el encargado de asignarle un IP al Cliente (por el momento, el cliente debe tener el IP 10.8.0.2 caso contrario no funcionará)
- La encriptación es deseable pero cuando el resto funcione correctamente ya que por la inseguridad de los datos no hay que peocuparse al menos si las aplicaciones que se usen sobre él son de protocolos seguros como HTTPS, SSH, etc. Deberías preocuparte si piensas usarlas sobre protocolos inseguros como RDP, Telnet, etc
- Optimizaciones o migración de Scapy: Éste modulo tiene algunas deficiencias como llamadas send bloqueantes lo que entorpecen el performance, según mis investigaciones, para mejorar esto habría que cambiar de lenguaje y continuar las implementaciones en C
- Se podría pensar en agregar autenticación de usuarios
- Expiración de IPs para no reenviar paquetes innecesarios al cliente
