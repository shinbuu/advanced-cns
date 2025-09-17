from scapy.all import rdpcap, ARP, DNS, DNSRR, IP
from collections import defaultdict
import datetime

def find_anomalies(pcap_file):
    """
    Анализирует .pcap файл для выявления аномалий в ARP и DNS трафике.

    Args:
        pcap_file (str): Путь к .pcap файлу.
    """
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"Ошибка: Файл '{pcap_file}' не найден.")
        return

    print(f"Анализ аномалий в файле: {pcap_file}")
    print("-" * 40)
    
    dns_requests = defaultdict(int)
    arp_requests = defaultdict(int)

    start_time = packets[0].time if packets else 0
   
    print("Проверка ARP-трафика...")
    
    suspicious_arp_requests = []
    
    for packet in packets:
        if packet.haslayer(ARP):
            if packet[ARP].op == 1:
                src_mac = packet.sprintf("%ARP.hwsrc%")
                src_ip = packet.sprintf("%ARP.psrc%")
                dst_ip = packet.sprintf("%ARP.pdst%")
                
                arp_requests[src_ip] += 1
                
                if arp_requests[src_ip] > 5 and (src_ip, dst_ip) not in suspicious_arp_requests:
                    suspicious_arp_requests.append((src_ip, dst_ip))
                    print(f"  [!] Обнаружено: Аномальное количество ARP-запросов от {src_ip} к {dst_ip}.")
                    
    if not suspicious_arp_requests:
        print("  Аномалий в ARP-трафике не найдено.")
    
    print("\nПроверка DNS-трафика...")
    
    suspicious_dns_requests = []
    
    for i, packet in enumerate(packets):
        if packet.haslayer(DNS):
            if packet[DNS].qr == 0:
                query_name = packet[DNS].qd.qname.decode('utf-8')
                has_response = False
                for j in range(i + 1, len(packets)):
                    if packets[j].haslayer(DNS) and packets[j].haslayer(IP) and packets[j][DNS].id == packet[DNS].id:
                        has_response = True
                        break
                
                if not has_response:
                    suspicious_dns_requests.append(query_name)
                    
    if suspicious_dns_requests:
        print("  [!] Обнаружено: Следующие DNS-запросы не получили ответа:")
        for query in set(suspicious_dns_requests):
            print(f"    - {query}")
    else:
        print("  Аномалий в DNS-трафике не найдено.")

file_path = 'pr1.pcapng'
find_anomalies(file_path)