from scapy.all import fuzz, IP, Ether, TCP, sr1
import sys

# ip = IP(src="192.168.0.165", dst="192.168.0.165")
# tcp_syn = TCP(dport=8900, flags='S', seq=100)
# pkt = ip/tcp_syn
# tcp_syn_ack = sr1(pkt)

# tcp_ack=TCP(sport=tcp_syn.sport, dport=8900, flags="A", seq=tcp_syn_ack.seq + 1, ack=tcp_syn_ack.seq)
# answ, un_answ = sr1(ip/tcp_ack)
# print(answ)
# print(un_answ)
# Create an IP packet with a TCP layer
packet = IP(dst="127.0.0.1")/TCP(dport=8900, flags="S")

# Send the packet and receive a response
response = sr1(packet)

# Show the response
response.show()
