#include "utils.h"

void getAttackerInfo(string interface, Mac& attacker_mac, Ip& attacker_ip ) {
    //get Mac Address
    ifstream fp ("/sys/class/net/" + interface + "/address");
    string mac_addr;
    fp >> mac_addr;
    fp.close();
    attacker_mac = mac_addr;

    // get IP Address
    int fs = socket(AF_INET, SOCK_DGRAM, 0);
    if(fs == -1){
        perror("Socket open error");
        exit(-1);
    }
    ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ -1);

    if(ioctl(fs, SIOCGIFADDR, &ifr) < 0){
        perror("ioctl error");
        exit(-1);
    }

    string ip_addr = inet_ntoa(((sockaddr_in *) &ifr.ifr_addr) -> sin_addr);
    attacker_ip = Ip(ip_addr);
}

void sendARPPacket(pcap_t* handle, Mac& eth_dmac, Mac& eth_smac, Mac& arp_smac, Ip& arp_sip, Mac& arp_tmac, Ip& arp_tip, bool isRequest){

	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = isRequest ? htons(ArpHdr::Request) : htons(ArpHdr::Reply);
	packet.arp_.smac_ = arp_smac;
	packet.arp_.sip_ = arp_sip;
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.tip_ = arp_tip;

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void getSenderInfo(pcap_t* handle, Mac& sender_mac, Ip& sender_ip, Mac& attacker_mac, Ip& attacker_ip){
    Mac eth_broadcast = Mac("ff:ff:ff:ff:ff:ff");
    Mac arp_unknown = Mac("00:00:00:00:00:00");
    // send normal arp packet attacker -> sender
    // don't know sender's mac so set it to broadcast option
    sendARPPacket(handle, eth_broadcast, attacker_mac, attacker_mac, attacker_ip, arp_unknown, sender_ip, true);

    while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
        EthArpPacket* captured_packet = (EthArpPacket*) packet;
        // if Arp packet and reply and sip is known sender's ip and tmac is attacker's mac
        // it is the packet we want
        if(captured_packet->eth_.type() == EthHdr::Arp && captured_packet->arp_.op() == ArpHdr::Reply && captured_packet->arp_.sip() == sender_ip && captured_packet->arp_.tmac() == attacker_mac){
            sender_mac = captured_packet->arp_.smac();
            break;
        }
    }
}