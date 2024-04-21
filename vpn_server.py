import socket
import threading
from scapy.all import IP, TCP, UDP, Ether
from scapy.all import *
import netifaces as ni
import sys

sys.stdout.flush()

server_port = 12345
interface = "eth0"
interfaces = ni.interfaces()
print(interfaces)

server_IP = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
gateway = ni.gateways()['default'][ni.AF_INET][0]

router_mac = ""

client_address = ""
pendings_packets_mutex = threading.Lock()
pendings_packets = set()

# Servidor del Tunel VPN
server_address = ("0.0.0.0", server_port)
tunnel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tunnel.bind(server_address)
print("Server INFO: ",server_IP,":",server_port)

def get_router_ip(interface):
    return get_if_default_gateway(interface)
    
def get_router_mac(target_ip):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=target_ip)
    arp_response = srp(arp_request, timeout=2, verbose=False)[0]
    router_mac = arp_response[0][1].hwsrc
    return router_mac

def is_pending_packet(src_ip,dst_ip,src_port,dst_port,TYPE):
	global pendings_packets
	global server_IP

	new_dst_ip = None

	pendings_packets_mutex.acquire()
	finded = ("10.8.0.2",str(src_ip),str(dst_port),str(src_port))
	if finded in pendings_packets:
		new_dst_ip = "10.8.0.2"
	pendings_packets_mutex.release()
	
	return new_dst_ip
	
def run_sniffer(interface):
	global server_IP
		
	print(f"Sniffeando la interface {interface} ... ",)
	
	try:
		def handle_packet(packet):
			try:            
				if packet.haslayer(IP):
					pass
					#print(f"[HANDLE] {packet[IP].src} -> {packet[IP].dst}")
				
				if packet.haslayer(IP) and packet.haslayer(UDP):
					src_ip = packet[IP].src
					dst_ip = packet[IP].dst
					src_port = packet[UDP].sport
					dst_port = packet[UDP].dport
					new_dst_ip = is_pending_packet(src_ip,dst_ip,src_port,dst_port,"UDP")
					if not(new_dst_ip is None):
						new_packet = IP(bytes(packet[IP]))
						del new_packet[IP].chksum
						del new_packet[UDP].chksum
						new_packet[IP].dst=new_dst_ip
						#print(f"{new_packet.src} -> {new_packet.dst}")
						tunnel.sendto(bytes(new_packet), client_address)
		        
				elif packet.haslayer(IP) and packet.haslayer(TCP):
					if packet[IP].flags & 0x04:
						print("Flag RST enable")
					src_ip = packet[IP].src
					dst_ip = packet[IP].dst
					src_port = packet[TCP].sport
					dst_port = packet[TCP].dport
					new_dst_ip = is_pending_packet(src_ip,dst_ip,src_port,dst_port,"TCP")
					if not(new_dst_ip is None):
						new_packet = IP(bytes(packet[IP]))
						del new_packet[IP].chksum
						del new_packet[TCP].chksum
						new_packet[IP].dst=new_dst_ip
						#print(f"{new_packet.src} -> {new_packet.dst}")
						tunnel.sendto(bytes(new_packet), client_address)
			except Exception as e:
				print("[HANDLE] ",e)
		
		sniffer = AsyncSniffer(iface=interface, prn=handle_packet)
		sniffer.start()

	except Exception as e:
		print("[RUN SNIFF] ",e)

def handle_packet(packet):
	try:            
		if packet.haslayer(IP):
			pass
			#print(f"[HANDLE] {packet[IP].src} -> {packet[IP].dst}")
				
		if packet.haslayer(IP) and packet.haslayer(UDP):
			src_ip = packet[IP].src
			dst_ip = packet[IP].dst
			src_port = packet[UDP].sport
			dst_port = packet[UDP].dport
			new_dst_ip = is_pending_packet(src_ip,dst_ip,src_port,dst_port,"UDP")
			if not(new_dst_ip is None):
				new_packet = IP(bytes(packet[IP]))
				del new_packet[IP].chksum
				del new_packet[UDP].chksum
				new_packet[IP].dst=new_dst_ip
				#print(f"{new_packet.src} -> {new_packet.dst}")
				tunnel.sendto(bytes(new_packet), client_address)
		        
		elif packet.haslayer(IP) and packet.haslayer(TCP):
			if packet[IP].flags & 0x04:
				print("Flag RST enable")
			src_ip = packet[IP].src
			dst_ip = packet[IP].dst
			src_port = packet[TCP].sport
			dst_port = packet[TCP].dport
			new_dst_ip = is_pending_packet(src_ip,dst_ip,src_port,dst_port,"TCP")
			if not(new_dst_ip is None):
				new_packet = IP(bytes(packet[IP]))
				del new_packet[IP].chksum
				del new_packet[TCP].chksum
				new_packet[IP].dst=new_dst_ip
				#print(f"{new_packet.src} -> {new_packet.dst}")
				tunnel.sendto(bytes(new_packet), client_address)
	except Exception as e:
		print("[HANDLE] ",e)

def datagram_received(data):
	global connections
	global server_IP
	global pendings_packets
	global router_mac
    
	try:
		packet = Ether(dst=router_mac)/IP(bytes(data))
		#print(packet[IP].src," -> ",packet[IP].dst)
		del packet[IP].chksum
		#packet.show2()
		if packet.haslayer(UDP):
			del packet[UDP].chksum
            
			pending_packet = (str(packet[IP].src),str(packet[IP].dst),str(packet[UDP].sport),str(packet[UDP].dport))
            
			      
		elif packet.haslayer(TCP):
			del packet[TCP].chksum
            
			pending_packet = (str(packet[IP].src),str(packet[IP].dst),str(packet[TCP].sport),str(packet[TCP].dport))
			
		else:
			#print("Paquete no TCP o UDP")
			return
        
		packet[IP].src = server_IP 
		pendings_packets_mutex.acquire()
		pendings_packets.add(pending_packet)
		pendings_packets_mutex.release()		
		response = srp1(packet, timeout=1,verbose=False)
		if response:
			#print("inicio")
			#response.show()
			#print("fin")
			handle_packet(response)
		
	except Exception as e:
		print("Error en send to server:",e)

def main():
	global tunnel
	global client_address
	global router_mac
	global interfaces

	print("Gateway: ",gateway)
	router_mac = get_router_mac(gateway)
	print("Router MAC: ",router_mac)
	for i in interfaces:
		run_sniffer(i)

	try:
		while True:
			data, client_address = tunnel.recvfrom(65535)
			#datagram_received(data)
			t = threading.Thread(target=datagram_received ,args=(data,) )
			t.start()
	finally:
		tunnel.close()

if __name__ == "__main__":
    main()

"""
IMPORTANTE, DEBIDO AL FUNCIONAMIENTO DE SCAPY, ES NECESARIO DESACTIVAR LOS PAQUETES RST

sudo apt update
sudo apt install python3-pip
sudo python3 -m pip install -r requirements.txt

cd /mnt/c/Users/XPATHER/Desktop/ServerVPN
sudo python3 vpn_server.py

Linux:
iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.0.102 -j DROP

(ip.addr == 216.92.159.32) and (tcp.port == 80)

"""
