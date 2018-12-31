#include "L2_ARP.h"

using namespace std;

/***********************************************************/
/****	Public Functions				****/
/***********************************************************/
L2_ARP::~L2_ARP() {
	for (auto &cacheEntry : queue) {
		if (cacheEntry.second.data) { /* Delete the entry only if its not NULL */
			delete[] cacheEntry.second.data;
		}
	}
	cache.clear();
	queue.clear();
}

int L2_ARP::arprequest(string ip_addr) { /* TODO Refactor */
	// declaration
	ArpPacket arpPacket;
	byte * buffer = new byte[ARP_PKT_LEN_BYTE];
	byte tmpMac[MAC_LENGTH];
	CacheEntry * cacheEntry = &cache[ip_addr];
	uint64_t timeSent = 0;
	double timePassed;
	uint64_t cnt = 0;
	bool cond;
	string tmp;
	memset(&arpPacket, 0, sizeof(ArpPacket)); // cleaning mem spcae
	arpPacket.hardwareAddrSpace = htons(1);
	arpPacket.protocolAddrSpace = htons(IP_VERSION); // TODO
	arpPacket.hardwareAddrLen = MAC_LENGTH;
	arpPacket.protocolAddrLen = IP_LENGTH;
	arpPacket.opCode = htons(1);
	tmp = (string)nic->myMACAddr;
	strMac2ByteMac(tmp,tmpMac);
	memcpy(arpPacket.srcHardwareAddr,tmpMac,6); // arpPacket.srcHardwareAddr = the MAC as byte array
	arpPacket.srcProtocolAddr = inet_addr(nic->myIP.c_str());
	arpPacket.dstProtocolAddr = inet_addr(ip_addr.c_str());
	memcpy(buffer, &arpPacket, ARP_PKT_LEN_BYTE); // TODO
	memcpy(buffer + 14, &arpPacket.srcProtocolAddr, 4);
	memcpy(buffer + 18, &arpPacket.dstHardwareAddr, 6);
	memcpy(buffer + 24, &arpPacket.dstProtocolAddr, 4);
	printArp(arpPacket);
	while (cacheEntry->isValid == false) { // while the entry is not available 
		timePassed = difftime(time(NULL), timeSent); // we calac the time 
		// limits the num of arp req at once
		// if its a multipe of 5, we need to sleep
		// needs to sleep for 20 sec
		cond = cnt % 5 == 0;
		if ((cnt > 0) && cond && (timePassed < 20)) {
			Sleep((DWORD)(20 - timePassed) * 1000); //we multiply by 1000 since Sleep is in mil second
			continue;
		} else if ((!cond) && timePassed < 1) { //we slep for 20 sec already
			Sleep((DWORD)(1 - timePassed) * 1000); //we multiply by 1000 since Sleep is in mil second
			continue;
		}
		nic->getUpperInterface()->sendToL2(buffer, ARP_PKT_LEN_BYTE, AF_UNSPEC, "ff:ff:ff:ff:ff:ff", 0x0806, ip_addr);
		cnt += 1;
		timeSent = time(NULL);
	}
	// release resources
	delete[] buffer;
	return ARP_PKT_LEN_BYTE;
}

string L2_ARP::arpresolve(string ip_addr, byte* sendData, size_t sendDataLen) { /* TODO Refactor */
	// first we check if the ip is in the cache
	CacheEntry* cacheEntry = (CacheEntry*)arplookup(ip_addr, true);
	if (cacheEntry) {
		return cacheEntry->macAddr;
	}
	// else we do the following - creating arp req
	// declarations
	PacketData packetData;
	packetData.data = new byte[sendDataLen]; // we allocate the data mem
	memcpy(packetData.data, sendData, sendDataLen); // we init the data after it has been aloocated
	packetData.len = sendDataLen;
	packetData.ip = ip_addr;
	// if we alredy have a packet to this dst we remove it from queue
	if (queue.count(ip_addr) != 0) { // reference in https://stackoverflow.com/questions/1939953/how-to-find-if-a-given-key-exists-in-a-c-stdmap?utm_medium=organic&utm_source=google_rich_qa&utm_campaign=google_rich_qa
		delete[] queue[ip_addr].data; // why count and not find
	}
	// insert packet to queue
	queue[ip_addr] = packetData;
	// making the request
	arprequest(ip_addr);
	return "";
}

void* L2_ARP::arplookup(string ip_addr, bool create) { /* TODO Refactor */
	double timePassed = 0;
	if (this->cache.count(ip_addr) != 0) {
		// declarations
		CacheEntry* cacheEntry;
		cacheEntry = &this->cache[ip_addr];
		if (cacheEntry->isValid == false) {
			return nullptr;
		}
		timePassed = difftime(cacheEntry->time, time(NULL));
		if (timePassed > ENTRY_LIFETIME) {
			cacheEntry->isValid = false;
			return nullptr;
		}
		return cacheEntry;
	}
	if (create) { // TODO
		CacheEntry cacheEntry;
		cacheEntry = {};
		cacheEntry.isValid = false; // TODO
		cache[ip_addr] = cacheEntry;
	}
	return nullptr;
}

int L2_ARP::in_arpinput(byte* recvData, size_t recvDataLen) { /* TODO Refactor */
	// declaration
	CacheEntry* cacheEntry;
	ArpPacket arpPacket;
	byte tmpSrcMacAddr[6];
	byte tmpDstMacAddr[6];
	memset(&arpPacket, 0, 28); // cleaning mem space
	memcpy(&arpPacket.srcProtocolAddr, recvData + 14, 4);
	memcpy(&arpPacket.dstHardwareAddr, recvData + 18, 6);
	memcpy(&arpPacket.dstProtocolAddr, recvData + 24, 4);
	// check is packet is valid
	if (recvDataLen < ARP_PKT_LEN_BYTE){
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			printf("[ERROR] - Arp packet is invalid!\n");
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return 0;
	}
	// retriving the addresses and converting them to string
	memcpy(tmpSrcMacAddr, recvData + 8, 6);
	string srcMacAddr = byteMac2StrMac(tmpSrcMacAddr);
	memcpy(tmpDstMacAddr, recvData + 18, 6);
	string dstMacAddr = byteMac2StrMac(tmpDstMacAddr);
	string dstAddr;
	string srcAddr;
	struct in_addr da;
	struct in_addr sa;
	da.s_addr = arpPacket.srcProtocolAddr;
	dstAddr = (string)inet_ntoa(da);
	sa.s_addr = arpPacket.dstProtocolAddr;
	srcAddr = (string)inet_ntoa(sa);
	cacheEntry = &cache[dstAddr]; // TODO
	cacheEntry->isValid = true;
	cacheEntry->macAddr = srcMacAddr;
	cacheEntry->time = time(NULL);
	// getting opcode
	arpPacket.opCode = ntohs(arpPacket.opCode);
	if (queue.count(dstAddr) != 0 && arpPacket.opCode != 2) {
		// SendArpReply(dstAddr, srcAddr, dstMacAddr, srcMacAddr);
		// sending packet here
		PacketData* packetData = &queue[dstAddr];
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			printf("[INFO] - Sending packet!\n");
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		nic->getUpperInterface()->sendToL2(packetData->data, packetData->len, AF_INET, cacheEntry->macAddr, 0, dstAddr);
		// cleaning
		delete[] packetData->data;
		queue.erase(dstAddr);
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
void strMac2ByteMac(string strMac, byte* byteMac) { /* TODO Refactor */
	char c;
	int num = 0, i = 0;
	stringstream mac_ss(strMac);
	for (i=0; i<MAC_LENGTH; ++i) {
		mac_ss >> hex >> num >> c;
		byteMac[i] = num;
	}
}

string byteMac2StrMac(byte* data) { /* TODO Refactor */
	size_t i = 0;
	stringstream strs;
	stringstream tmp;
	for (i=0; i<6; ++i) {
		strs << setfill('0') << setw(2) << hex << (int)data[i] << (i != (6 - 1) ? ":" : "");
	}
	return strs.str();
}

void printArp(ArpPacket arpPacket) { /* TODO Refactor */
	struct in_addr da;
	byte tmpSrcMacAddr[6];
	byte tmpDstMacAddr[6];
	memcpy(tmpSrcMacAddr, arpPacket.srcHardwareAddr, 6);
	memcpy(tmpSrcMacAddr, arpPacket.dstHardwareAddr, 6);
	string srcMacAddr = byteMac2StrMac(arpPacket.srcHardwareAddr);
	string dstMacAddr = byteMac2StrMac(arpPacket.dstHardwareAddr);
	cout << endl;
	cout << "--------------------------------------------------------------------------" << endl;
	cout << "******							ARP Detales							*******" << endl;
	printf("Hardware Type = 0x%x\n", ntohs(arpPacket.hardwareAddrSpace));
	printf("Protocol Type = 0x%x\n", ntohs(arpPacket.protocolAddrSpace));
	cout << "Hardware addr len = " << dec << (int)arpPacket.hardwareAddrLen << endl;
	cout << "Protocol addr len =" << dec << (int)arpPacket.protocolAddrLen << endl;
	printf("Opcode = %d\n", ntohs(arpPacket.opCode));
	cout << "Src hardware addr = " << srcMacAddr << endl;
	da.s_addr = arpPacket.srcProtocolAddr;
	printf("Src protocol addr = %s\n", inet_ntoa(da));
	cout << "Dst hardware addr = " << dstMacAddr << endl;
	da.s_addr = arpPacket.dstProtocolAddr;
	printf("Dst protocol addr = %s \n\n", inet_ntoa(da));
	cout << "--------------------------------------------------------------------------" << endl;
}
