import scapy.all as scapy
import argparse



def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", dest="target", help="Wpisz adres IP swojej sieci || xxx.xxx.xxx.xxx/24")
    options = parser.parse_args()

    
    if not options.target:
        
        parser.error("[-] Okresl adrss IP, pomoc --help")
    return options

options = get_args()

def scan(ip):
    arp_req_frame = scapy.ARP(pdst = ip)

    broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    
    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False)[0]
    result = []
    for i in range(0,len(answered_list)):
        client_dict = {"ip" : answered_list[i][1].psrc}
        result.append(client_dict)

    return result
  
def display_result(result):
	print("-----------------------------------\nDotepne adresy IP\n-----------------------------------")
	for i in result:
		 print(i["ip"])


options = get_args()
scanned_output = scan(options.target)
display_result(scanned_output)


print("Wybierz tryb:  || a - ping   b - ping z payloadem")
opc = input("")
if opc.lower() == "a":
    
	print("Podaj adres IP: ")
	ip_dst = input("")	
	from scapy.all import sr1, IP, ICMP

	TIMEOUT = 2
	packet = IP(dst=str(ip_dst), ttl=20)/ICMP()
	reply = sr1(packet, timeout=TIMEOUT)
	if not (reply is None):
		 print (reply.dst, "jest online")
	else:
		 print ("Limit czasu oczekiwania  %s" % packet[IP].dst, "\nBrak odpowiedzi")
elif opc.lower() == "b":
	print("Podaj adres IP: ")
	ip_dst = input("")	
	print("Podaj payload: ")
	payload = input("")	
	from scapy.all import sr1, IP, ICMP

	TIMEOUT = 2
	packet = IP(dst=str(ip_dst), ttl=20)/ICMP() / (payload)
	reply = sr1(packet, timeout=TIMEOUT)
	if not (reply is None):
		 print (reply.dst, "jest online")
	else:
		 print ("Limit czasu oczekiwania %s" % packet[IP].dst, "\nBrak odpowiedzi")
	
else:
	print("Wybierz dostepna opcje")		 


