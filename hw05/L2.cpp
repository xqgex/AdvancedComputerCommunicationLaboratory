#include "L2.h"

using namespace std;

/***********************************************************/
/****	Public Functions				****/
/***********************************************************/
int L2::recvFromL2(byte* recvData, size_t recvDataLen) { /* TODO Refactor */
	// declarations
	int i;
	int frameLen;
	byte tmpRecvMacAddr[6];
	byte * buffer;
	uint16_t isArp;
	string recvMacAddr;
	// checking parameters
	if (recvDataLen < 1) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			printf("[ERROR] - The frame data recived is invalid!\n");
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return 0;
	}
	// checking mac addr recieved to myMACAddr
	memcpy(tmpRecvMacAddr, recvData, 6);
	// convert to string
	recvMacAddr = byteMac2StrMac(tmpRecvMacAddr);
	if (recvMacAddr.compare(nic->myMACAddr) != 0) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			printf("[ERROR] - MAC Address is invalid!\n");
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return 0;
	}
	// getting the data and data lenght
	buffer = recvData + ETH_HEADER_LEN;
	frameLen = recvDataLen - ETH_HEADER_LEN;

	printL2(recvData, buffer, frameLen);
	// retrieve action type
	isArp = (recvData[12] << 8);
	isArp += recvData[13];
	if (isArp == ARP) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			printf("[INFO] - Frame is ARP, sending to L2_ARP\n");
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		nic->getARP()->in_arpinput(buffer, frameLen);
	} else if (isArp == IP_VERSION_4) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			printf("[INFO] - Frame is IP, sending to L3\n");
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		this->upperInterface->recvFromL3(buffer, frameLen);
	} else {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			printf("[ERROR] - Frame action is invalid\n");
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return 0;
	}
	return recvDataLen;
}

int L2::sendToL2(byte* sendData, size_t sendDataLen, uint16_t family, string spec_mac, uint16_t spec_type, string dst_addr) { /* TODO Refactor */
	// declerations
	bool cond;
	string getMac;
	string retFromByte;
	byte *buffer;
	byte tmp[MAC_LENGTH];
	int frameLen;
	uint16_t isArp;
	uint32_t myNetMask = inet_addr(nic->myNetmask.c_str());
	uint32_t dstAddr = inet_addr(dst_addr.c_str());
	uint32_t myIP = inet_addr(nic->myIP.c_str());
	// checking if needs to send in my sub network
	if ((myNetMask & myIP) != (myNetMask & dstAddr)) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			printf("[INFO] - dst addr different, moving to default gateaway\n");
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		dst_addr = nic->myDefaultGateway;
	}
	if (family == AF_INET) {
		cond = spec_mac.compare("");
		if (!cond) {
			getMac = nic->getARP()->arpresolve(dst_addr, sendData, sendDataLen);
			cond = getMac.compare("");
			if (!cond) {
				if (debug) {
					pthread_mutex_lock(&NIC::print_mutex);
					printf("[ERROR] - MAC is invalid\n");
					pthread_mutex_unlock(&NIC::print_mutex);
				}
				return 0;
			}
		} else {
			getMac = spec_mac;
		}
		frameLen = max(sendDataLen, MIN_FRAME_LEN); // we make sure frame is at least 46 length
		frameLen += ETH_HEADER_LEN; // updating frame length
		buffer = new byte[frameLen]; // init frame with its right length
		memset(buffer, 0, frameLen); // reseting mem space
		isArp = IP_VERSION_4;
		strMac2ByteMac(getMac,tmp); // updating action
		retFromByte = byteMac2StrMac(tmp);
		memcpy(buffer,tmp,6); // getting the destination addr
	} else { // we get ARP
		frameLen = sendDataLen + ETH_HEADER_LEN;
		buffer = new byte[frameLen]; // init frame with its right length
		memset(buffer, 0, frameLen); // reseting mem space
		isArp = spec_type;
		strMac2ByteMac(spec_mac,tmp); // updating action
		retFromByte = byteMac2StrMac(tmp);
		memcpy(buffer, tmp, 6);
	}
	// updating data
	retFromByte = nic->myMACAddr;
	strMac2ByteMac(retFromByte,tmp);
	retFromByte = byteMac2StrMac(tmp);
	memcpy(buffer + MAC_LENGTH,tmp,6);
	buffer[12] = isArp >> 8;
	buffer[13] = isArp & GET_LSB;
	// putting the data in buffer
	memcpy(buffer + ETH_HEADER_LEN, sendData, sendDataLen);
	if (debug) {
		pthread_mutex_lock(&NIC::print_mutex);
		printL2(buffer,sendData,sendDataLen);
		pthread_mutex_unlock(&NIC::print_mutex);
	}
	// sending data
	nic->lestart(buffer, frameLen);
	// clean resources
	delete[] buffer;
	return frameLen;
}

/***********************************************************/
/****	Implemented for us				****/
/***********************************************************/
L2::~L2() {}
L2::L2(bool debug) : debug(debug) { }
void L2::setUpperInterface(L3* upperInterface) { this->upperInterface = upperInterface; }
void L2::setNIC(NIC* nic) { this->nic = nic; }
NIC* L2::getNIC() { return nic; }
std::string L2::getLowestInterface() { return nic->getLowestInterface(); }

/***********************************************************/
/****	Private Functions				****/
/***********************************************************/
void l2_print_packet(byte* recvData, byte* buffer, int frameLen) { /* TODO Refactor */
	int i;
	string tmp;
	uint16_t isArp = recvData[12] << 8;
	isArp += recvData[13];
	printf("-----------------------------------------------------------\n");
	printf("------Frame info------\n");
	tmp = byteMac2StrMac(recvData);
	cout << "Dst MAC addr = "<< tmp << endl;
	tmp = byteMac2StrMac(recvData + MAC_LENGTH);
	cout << "Src MAC addr = " << tmp << endl;
	printf("isArp = 0x%x\n",isArp);
	printf("Frame data = ");
	for (i=0; i<frameLen; ++i) {
		printf("%c",buffer[i]);
	}
	printf("-----------------------------------------------------------\n");
	printf("\n");
}
