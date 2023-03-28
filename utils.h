#pragma once

#include <bits/stdc++.h>

// get from internet getAttackerInfo code
#include <iostream>
#include <cstring>
#include <fstream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <pcap.h>

// include local header file
#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"

using namespace std;

// Get Attacker's MAC address
// Get Sender MAC address (ARP request and reply)
// send ARP packet

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void getAttackerInfo(string interface, Mac& attackerMac, Ip& attackerIP);

void sendARPPacket(pcap_t* handle, Mac& eth_dmac, Mac& eth_smac, Mac& arp_smac, Ip& arp_sip, Mac& arp_tmac, Ip& arp_tip, bool isRequest);

void getSenderInfo(pcap_t* handle, Mac& sender_mac, Ip& sender_ip, Mac& attacker_mac, Ip& attacker_ip);