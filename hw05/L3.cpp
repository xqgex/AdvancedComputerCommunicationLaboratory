#include "L3.h"

using namespace std;

/***********************************************************/
/****	Public Functions				****/
/***********************************************************/
L3::L3(bool debug) { this->debug = debug; }

int L3::sendToL3(byte* sendData, size_t sendDataLen, std::string srcIP, std::string destIP) {
	Packet header = { 0 };
	int packetLen = sizeof(Packet) + sendDataLen;
	byte buffer[PACKET_MAX_LEN] = { 0 };
	/* Check packet length */
	if (packetLen <= PACKET_MAX_LEN) {
		l3_create_header(&header, sendDataLen, srcIP, destIP);
	} else {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			std::cout << "[L3] [ERROR] Packet length (" << packetLen << ") is bigger then the maximum length (" << PACKET_MAX_LEN << ")." << std::endl;
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return 0;
	}
	/* Transfer the packet to L2 */
	memcpy(buffer, &header, sizeof(Packet));
	memcpy(buffer + sizeof(Packet), sendData, sendDataLen);
	if (debug) {
		pthread_mutex_lock(&NIC::print_mutex);
		std::cout << "[L3] [INFO] Packet content:" << std::endl;
		l3_print_packet(header, buffer);
		pthread_mutex_unlock(&NIC::print_mutex);
	}
	if (this->lowerInterface->sendToL2(buffer, packetLen, AF_INET, "", 0, destIP) < 1) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			std::cout << "[L3] [ERROR] Invalid packet length." << std::endl;
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return 0;
	}
	return packetLen;
}

int L3::recvFromL3(byte *recvData, size_t recvDataLen) {
	byte* buffer;
	int sendDataLen = 0;
	uint16_t checkSum = 0;
	Packet header = { 0 };
	/* Check recvDataLen */
	if (recvDataLen < 1) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			std::cout << "[L3] [ERROR] Invalid packet length." << std::endl;
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return 0;
	} else if (PACKET_MAX_LEN < recvDataLen) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			std::cout << "[L3] [ERROR] Invalid packet length, Exceed maximum allowed length." << std::endl;
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return 0;
	}
	/* Receive data from L2 */
	memcpy(&header, recvData, sizeof(Packet));
	/* Switch big/small endian */
	header.flagsFragmentOffset = ntohs(header.flagsFragmentOffset);
	header.headerChecksum = ntohs(header.headerChecksum);
	/* Validate the IP header */
	if (l3_checkSum(&header) != 0) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			std::cout << "[L3] [ERROR] Invalid checksum." << std::endl;
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return 0;
	} else if (header.timeToLive < 1) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			std::cout << "[L3] [ERROR] Invalid TTL." << std::endl;
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return 0;
	} else if (header.protocol != PROTOCOL_ICMP) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			std::cout << "[L3] [ERROR] Invalid protocol." << std::endl;
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return 0;
	}
	if (debug) {
		pthread_mutex_lock(&NIC::print_mutex);
		std::cout << "[L3] [INFO] Recieved new packet from L4." << std::endl;
		pthread_mutex_unlock(&NIC::print_mutex);
	}
	/* Copy the data into recvData */
	buffer = recvData + sizeof(Packet); /* Set the pointer to the start of the packet data */
	sendDataLen = (int)recvDataLen - sizeof(Packet); /* The size of the packet data */
	if (this->upperInterface->recvFromL4(buffer, sendDataLen) < 1) {
		if (debug) {
			pthread_mutex_lock(&NIC::print_mutex);
			std::cout << "[L3] [ERROR] Invalid packet length." << std::endl;
			pthread_mutex_unlock(&NIC::print_mutex);
		}
		return 0;
	}
	return sendDataLen;
}

/***********************************************************/
/****	Implemented for us				****/
/***********************************************************/
void L3::setLowerInterface(L2* lowerInterface) { this->lowerInterface = lowerInterface; }
void L3::setUpperInterface(L4* upperInterface) { this->upperInterface = upperInterface; }
std::string L3::getLowestInterface() { return lowerInterface->getLowestInterface(); }

/***********************************************************/
/****	Private Functions				****/
/***********************************************************/
uint16_t l3_checkSum(Packet* header) {
	uint16_t* headerAsArray = (uint16_t*)header;
	uint32_t checkSum = 0, i = 0;
	for (i = 0; i<sizeof(Packet) / 2; ++i) { /* Sum all 16 bit words in the header */
		checkSum += headerAsArray[i];
	}
	while (checkSum > 0xFFFF) { /* Folds a 32-bit partial checksum into 16 bits */
		checkSum = (checkSum >> 16) + (checkSum & 0xFFFF);
	}
	return uint16_t(~checkSum);
}

void l3_create_header(Packet* header, size_t sendDataLen, std::string srcIP, std::string destIP) {
	header->versionAndIHL = (IP_VERSION << 4) + (sizeof(Packet) / 4); /* 01000101 */
	header->typeOfService = 0; /* 00000000 */
	header->totalLength = htons(sizeof(Packet) + sendDataLen);
	header->identification = htons(0); /* 0000000000000000 */
	header->flagsFragmentOffset = 0; /* 0000000000000000 */
	header->timeToLive = 255; /* 11111111 */
	header->protocol = PROTOCOL_ICMP; /* 00000001 */
	header->headerChecksum = 0; /* 0000000000000000 */ /* For computing the checksum, the checksum field should be zero */
	header->sourceAddress = inet_addr(srcIP.c_str());
	header->destinationAddress = inet_addr(destIP.c_str());
	header->headerChecksum = l3_checkSum(header);
}

void l3_print_packet(Packet header, byte* data) {
	int i = 0;
	std::bitset<4> cout_version(header.versionAndIHL >> 4);
	std::bitset<4> cout_ihl(header.versionAndIHL & 0xF);
	std::bitset<8> cout_typeOfService(header.typeOfService);
	std::bitset<16> cout_totalLength(header.totalLength);
	std::bitset<16> cout_identification(ntohs(header.identification));
	std::bitset<16> cout_flagsFragmentOffset(header.flagsFragmentOffset);
	std::bitset<8> cout_timeToLive(header.timeToLive);
	std::bitset<8> cout_protocol(header.protocol);
	std::bitset<16> cout_headerChecksum(header.headerChecksum);
	std::bitset<32> cout_sourceAddress(ntohs(header.sourceAddress));
	std::bitset<32> cout_destinationAddress(ntohs(header.destinationAddress));
	std::cout << "   |0| | | | | | | |1| | | | | | | |2| | | | | | | |3| | | | | | | |" << std::endl;
	std::cout << " --|-------|-------|-------|-------|-------|-------|-------|-------|" << std::endl;
	std::cout << "  0|Version|IHL    |Type of Service|Total Length                   |" << std::endl;
	std::cout << "   | " << cout_version << "  | " << cout_ihl << "  | " << cout_typeOfService << "      | " << cout_totalLength << "              |" << std::endl;
	std::cout << " --|-------|-------|---------------|-|-|-|-------------------------|" << std::endl;
	std::cout << "  4|Identification                 |x|D|M|Fragment Offset          |" << std::endl;
	std::cout << "   | " << cout_identification << "              |" << cout_flagsFragmentOffset[15] << "|" << cout_flagsFragmentOffset[14] << "|" << cout_flagsFragmentOffset[13] << "| ";
	for (i = 12; 0 <= i; --i) {
		std::cout << cout_flagsFragmentOffset[i];
	}
	std::cout << "           |" << std::endl;
	std::cout << " --|---------------|---------------|-|-|-|-------------------------|" << std::endl;
	std::cout << "  8|Time to live   |Protocol       |Header Checksum                |" << std::endl;
	std::cout << "   | " << cout_timeToLive << "      | " << cout_protocol << "      | " << cout_headerChecksum << "              |" << std::endl;
	std::cout << " --|---------------|---------------|-------------------------------|" << std::endl;
	std::cout << " 16|Source Address                                                 |" << std::endl;
	std::cout << "   | " << cout_sourceAddress << "                              |" << std::endl;
	std::cout << " --|---------------------------------------------------------------|" << std::endl;
	std::cout << " 20|Destination Address                                            |" << std::endl;
	std::cout << "   | " << cout_destinationAddress << "                              |" << std::endl;
	std::cout << " --|---------------------------------------------------------------|" << std::endl;
	std::cout << "   |                             Data                              |" << std::endl;
	for (i = sizeof(Packet); i < ntohs(header.totalLength) + sizeof(Packet); ++i) {
		cout << data[i];
	}
	std::cout << " --|-------|-------|-------|-------|-------|-------|-------|-------|" << std::endl;
	std::cout << "   | | | | | | | | | | |1|1|1|1|1|1|1|1|1|1|2|2|2|2|2|2|2|2|2|2|3|3|" << std::endl;
	std::cout << "   |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|" << std::endl;
}
