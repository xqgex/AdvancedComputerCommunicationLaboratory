#include "L2_ARP.h"

using namespace std;

/***********************************************************/
/****	Public Functions				****/
/***********************************************************/
L2_ARP::~L2_ARP() {
	for (auto &cacheEntry : this->pktQueue) {
		if (cacheEntry.second.data) { /* Delete the PacketData.data only if its not NULL */
			delete[] cacheEntry.second.data;
		}
	}
	this->ARPCache.clear();
	this->pktQueue.clear();
}

int L2_ARP::arprequest(string ip_addr) {
	uint64_t pktCount = 0;
	uint64_t timeSent = 0;
	double timePassed = 0;
	ArpPacket pkt;
	byte* buff = new byte[sizeof(ArpPacket)];
	CacheLine* newLine = &this->ARPCache[ip_addr];
	/* Setting up the packet */
	memset(&pkt, 0, sizeof(ArpPacket));
	pkt.hardwareAddrSpace = htons(1);
	pkt.protocolAddrSpace = htons(IP_VERSION_HEX);
	pkt.hardwareAddrLen = MAC_LENGTH;
	pkt.protocolAddrLen = IP_LENGTH;
	pkt.opCode = htons(1);
	memcpy(pkt.srcHardwareAddr, l2_str_to_byte((char*) nic->myMACAddr.c_str()), MAC_LENGTH);
	pkt.srcProtocolAddr = inet_addr(nic->myIP.c_str());
	pkt.dstProtocolAddr = inet_addr(ip_addr.c_str());
	if (debug) {
		pthread_mutex_lock(&NIC::print_mutex);
		l2_arp_print(pkt);
		pthread_mutex_unlock(&NIC::print_mutex);
	}
	/* Moving packet data into byte buffer */
	memcpy(buff, &pkt, sizeof(ArpPacket));
	memcpy(buff + 14, &pkt.srcProtocolAddr, 4);
	memcpy(buff + 18, &pkt.dstHardwareAddr, 6);
	memcpy(buff + 24, &pkt.dstProtocolAddr, 4);
	while (!newLine->isValid) {
		timePassed = difftime(time(NULL), timeSent);
		if ((0 < pktCount) && (pktCount % 5 == 0) && (timePassed < 20)) {
			Sleep((DWORD)(20 - timePassed) * 1000);
		} else if ((pktCount % 5 != 0) && timePassed < 1) {
			Sleep((DWORD)(1 - timePassed) * 1000);
		} else {
			nic->getUpperInterface()->sendToL2(buff, sizeof(ArpPacket), AF_UNSPEC, DEFAULT_MAC_ADDR, ARP, ip_addr);
			pktCount += 1;
			timeSent = time(NULL);
		}
	}
	delete[] buff;
	return sizeof(ArpPacket);
}

string L2_ARP::arpresolve(string ip_addr, byte* sendData, size_t sendDataLen) {
	/* If in chache return its MAC Address */
	CacheLine* newLine = (CacheLine*)arplookup(ip_addr, true);
	if (newLine) {
		return (string)newLine->MACAddress;
	}
	/* Adding the new data to queue */
	PacketData pkt;
	pkt.data = new byte[sendDataLen];
	memcpy(pkt.data, sendData, sendDataLen);
	pkt.dataLen = sendDataLen;
	pkt.ip = ip_addr;
	/* If queue have already data to this destination we remove it */
	if (0 < this->pktQueue.count(ip_addr)) {
		delete[] this->pktQueue[ip_addr].data;
	}
	this->pktQueue[ip_addr] = pkt;
	/* Finally making request */
	arprequest(ip_addr);
	return "";
}

void* L2_ARP::arplookup(string ip_addr, bool create) {
	if (0 < this->ARPCache.count(ip_addr)) {
		CacheLine* newLine = &this->ARPCache[ip_addr];
		if (!newLine->isValid) {
			return nullptr;
		} else if (ENTRY_LIFETIME < difftime(newLine->genesis, time(NULL))) {
			newLine->isValid = false;
			return nullptr;
		} else {
			return newLine;
		}
	} else if (create) {
		CacheLine newLine = {};
		newLine.isValid = false;
		this->ARPCache[ip_addr] = newLine;
	}
	return nullptr;
}

int L2_ARP::in_arpinput(byte* recvData, size_t recvDataLen) {
	byte tmpMacAddr[MAC_LENGTH];
	char* srcMacAddr;
	string dstAddr;
	struct in_addr da;
	CacheLine* newLine;
	ArpPacket pkt;
	PacketData* queuePkt;
	/* Validate packet length */
	if (recvDataLen < sizeof(ArpPacket)) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			std::cout << "[L2 ARP] [ERROR] Got Invalid ARP Packet - Length is Less Then Minimum" << std::endl;
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return 0;
	}
	/* Moving data into arp packet struct */
	memset(&pkt, 0, sizeof(ArpPacket));
	memcpy(&pkt.srcProtocolAddr, recvData + 14, 4);
	memcpy(&pkt.dstHardwareAddr, recvData + 18, 6);
	memcpy(&pkt.dstProtocolAddr, recvData + 24, 4);
	/* retriving the addresses and convert them to string */
	memcpy(tmpMacAddr, recvData + 8, MAC_LENGTH);
	srcMacAddr = l2_byte_to_str(tmpMacAddr);
	da.s_addr = pkt.srcProtocolAddr;
	dstAddr = (string)inet_ntoa(da);
	/* Insert the line into the cache */
	newLine = &this->ARPCache[dstAddr];
	newLine->isValid = true;
	newLine->MACAddress = new char[strlen(srcMacAddr)];
	strcpy(newLine->MACAddress, srcMacAddr);
	newLine->genesis = time(NULL);
	pkt.opCode = ntohs(pkt.opCode);
	if ((0 < this->pktQueue.count(dstAddr)) && (pkt.opCode != 2)) {
		queuePkt = &this->pktQueue[dstAddr];
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			std::cout << "[L2 ARP] [INFO] Packet Sent" << std::endl;
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		nic->getUpperInterface()->sendToL2(queuePkt->data, queuePkt->dataLen, AF_INET, newLine->MACAddress, 0, dstAddr);
		/* Remove the packet from the queue */
		delete[] queuePkt->data;
		this->pktQueue.erase(dstAddr);
		return recvDataLen;
	}
	return 0;
}

void* L2_ARP::SendArpReply(string itaddr, string isaddr, string hw_tgt, string hw_snd) {
	return nullptr;
}

/***********************************************************/
/****	Implemented for us				****/
/***********************************************************/
L2_ARP::L2_ARP(bool debug) : debug(debug) { }
void L2_ARP::setNIC(NIC* nic) { this->nic = nic; }

/***********************************************************/
/****	Private Functions				****/
/***********************************************************/
void l2_arp_print(ArpPacket pkt) {
	struct in_addr tmp;
	printf("ARP INFO:\n");
	printf("\tHW Type: 0x%x\n", ntohs(pkt.hardwareAddrSpace));
	printf("\tProtocol Type: 0x%x\n", ntohs(pkt.protocolAddrSpace));
	printf("\tHW Address Length: %d\n", pkt.hardwareAddrLen);
	printf("\tProtocol Address Length: %d\n", pkt.protocolAddrLen);
	printf("\tOPCODE: %d\n", ntohs(pkt.opCode));
	printf("\tSource MAC Address: %s\n", l2_byte_to_str(pkt.srcHardwareAddr));
	printf("\tDestination MAC Address: %s\n", l2_byte_to_str(pkt.dstHardwareAddr));
	tmp.s_addr = pkt.srcProtocolAddr;
	printf("\tSource HW Address: %s\n", inet_ntoa(tmp));
	tmp.s_addr = pkt.dstProtocolAddr;
	printf("\tDestination HW Address: %s\n", inet_ntoa(tmp));
	printf("END OF ARP INFO\n");
}
