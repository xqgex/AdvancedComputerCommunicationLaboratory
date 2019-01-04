#include "L2.h"

using namespace std;

/***********************************************************/
/****	Public Functions				****/
/***********************************************************/
int L2::recvFromL2(byte* data, size_t dataLen) {
	uint16_t action;
	/* Checking validity of data */
	if (dataLen < 1) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			std::cout << "[L2] [ERROR] Frame Data is Too Small" << std::endl;
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return -1;
	}
	/* Compare recived mac address to nic mac address */
	if (! nic->myMACAddr.compare(l2_byte_to_str(data + MAC_LENGTH))) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			std::cout << "[L2] [ERROR] MAC Address is Wrong" << std::endl;
			std::cout << "[L2] [ERROR] recived MAC: " << l2_byte_to_str(data + MAC_LENGTH) << std::endl;
			std::cout << "[L2] [ERROR] wanted address: " << nic->myMACAddr << std::endl;
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return -1;
	}
	/* Check data type */
	action = data[12] << 8;
	action += data[13];
	if (action == ARP) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			std::cout << "[L2] [INFO] ARP Data Frame, Sending to L2" << std::endl;
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		nic->getARP()->in_arpinput(data + sizeof(Frame), dataLen - sizeof(Frame));
	} else {
		if (action == IP_VERSION_HEX) {
			if (debug) {
				pthread_mutex_lock(&NIC::print_mutex);
				std::cout << "[L2] [INFO] Got IP Frame, Sending to L3" << std::endl;
				pthread_mutex_unlock(&NIC::print_mutex);
			}
			this->upperInterface->recvFromL3(data + sizeof(Frame), dataLen - sizeof(Frame));
		} else {
			if (debug) {
				pthread_mutex_lock(&NIC::print_mutex);
				std::cout << "[L2] [ERROR] Unknown Action" << std::endl;
				pthread_mutex_unlock(&NIC::print_mutex);
			}
		}
		return -1;
	}
	return dataLen;
}

int L2::sendToL2(byte* sendingData, size_t sendingDataLen, uint16_t family, string specMAC, uint16_t specType, string dstAddr) {
	char MAC[17];
	int frameLength;
	uint16_t action;
	byte* frameData;
	/* Check if in subnet */
	uint32_t localMask = inet_addr(nic->myNetmask.c_str());
	uint32_t localIP = inet_addr(nic->myIP.c_str());
	uint32_t destenation = inet_addr(dstAddr.c_str());
	if ((localMask & localIP) != (localMask & destenation)) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			printf("[INFO] - Destination is Not in Subnet - Forwarding to Gateway\n");
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		dstAddr = nic->myDefaultGateway;
	}
	if (family == AF_INET) {
		if (!strcmp(specMAC.c_str(), "")) {
			sprintf(MAC,"%s",nic->getARP()->arpresolve(dstAddr, sendingData, sendingDataLen).c_str());
			if (!strcmp(MAC, "")) {
				if (debug) {
					pthread_mutex_lock(&NIC::print_mutex);
					printf("[ERROR] - Got Invalid MAC Address\n");
					pthread_mutex_unlock(&NIC::print_mutex);
				}
				return -1;
			}
		} else {
			sprintf(MAC,"%s",specMAC.c_str());
		}
		frameLength = max(sendingDataLen, MIN_FRAME_LEN);
		frameLength += sizeof(Frame);
		frameData = new byte[frameLength];
		memset(frameData, 0, frameLength);
		action = IP_VERSION_HEX;
		byte* byteMAC = l2_str_to_byte(MAC); 
		memcpy(frameData, byteMAC, MAC_LENGTH);
	} else { /* ARP frame */
		frameLength = sendingDataLen + sizeof(Frame);
		frameData = new byte[frameLength];
		memset(frameData, 0, frameLength);
		action = specType;
		byte* byteMAC = l2_str_to_byte((char*) specMAC.c_str()); 
		memcpy(frameData, byteMAC, MAC_LENGTH);
	}
	pthread_mutex_unlock(&NIC::print_mutex);
	byte* str2B = l2_str_to_byte((char*) nic->myMACAddr.c_str());
	memcpy(frameData + MAC_LENGTH, str2B, 6);
	frameData[12] = action >> 8;
	frameData[13] = action & 0xFF;
	/* Putting the data in buffer */
	memcpy(frameData + sizeof(Frame), sendingData, sendingDataLen);
	if (debug) {
		pthread_mutex_lock(&NIC::print_mutex);
		l2_print(frameData, sendingData, sendingDataLen);
		pthread_mutex_unlock(&NIC::print_mutex);
	}
	nic->lestart(frameData, frameLength);
	return frameLength;
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
char* l2_byte_to_str(byte* MAC) {
	char hexString[12+5]; /* 12 chars + 5 */
	int i = 0;
	for (i = 0; i < 6; ++i) {
		sprintf(hexString + i * 3, "%02x:" ,MAC[i]);
	}
	sprintf(hexString + i * 3 - 1, "\0");
	return hexString;
}

void l2_print(byte* data, byte* buff, int frameLength) {
	int i = 0;
	printf("FRAME INFO: \n");
	printf("\tDestination MAC Address: %s\n", l2_byte_to_str(data));
	printf("\tSource MAC Address: %s\n", l2_byte_to_str(data + MAC_LENGTH));
	printf("\tisARP: 0x%02x \n", data[12] << 8);
	printf("\tframe data: \n");
	printf("\t");
	for (i = 0; i < frameLength; ++i) {
		printf("%c", buff[i]);
	}
	printf("\nEND OFFRAME INFO\n");
	return;
}

byte* l2_str_to_byte(char* MACString) {
	byte res[MAC_LENGTH];
	int i = 0;
	if (strlen(MACString) < 17) {
		return res;
	}
	char* val = strtok(MACString, ":");
	for (i = 0; i < 6; ++i) {
		res[i] = (int)strtol(val, NULL, 16);
		val = strtok(NULL, ":");
	}
	return res;
}
