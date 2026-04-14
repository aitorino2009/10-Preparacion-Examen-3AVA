from scapy.all import sniff, ARP

# Nuestra "Fuente de Verdad" (Base de datos de confianza)
# IP: MAC_CORRECTA
trusted_devices = {
    "192.168.1.1": "00:11:22:33:44:55",  # Router
    "192.168.1.10": "AA:BB:CC:DD:EE:FF"  # Servidor
}


def monitor_arp(packet):
    # Filtramos: Solo nos interesan paquetes ARP de respuesta (is-at)
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        ip_fuente = packet[ARP].psrc
        mac_fuente = packet[ARP].hwsrc

        print(f"[*] Analizando respuesta ARP de {ip_fuente}...")

        # Lógica de vigilancia activa
        if ip_fuente in trusted_devices:
            if trusted_devices[ip_fuente].lower() != mac_fuente.lower():
                print(f"🚨 ¡ALERTA DE SEGURIDAD! 🚨")
                print(
                    f"Intento de MITM detectado: {ip_fuente} dice ser {mac_fuente}")
                print(f"DEBERÍA SER: {trusted_devices[ip_fuente]}")
                # Aquí podrías ejecutar una acción defensiva, como bloquear la IP
            else:
                print(f"✅ Paquete legítimo de {ip_fuente}")


# El "While True" está implícito en la función sniff de Scapy
print("🛡️ Iniciando Monitor Activo ARP... Presiona Ctrl+C para detener.")
sniff(filter="arp", prn=monitor_arp, store=0)
