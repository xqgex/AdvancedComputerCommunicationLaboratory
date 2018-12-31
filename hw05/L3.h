#ifndef L3_H_
#define L3_H_
#include "L2.h"
#include "L4.h"
#include "NIC.h"
#include "Types.h"
#include <bitset>
#include <iostream>
#include <string>
#include <WinSock2.h>

#define IP_VERSION		4
#define PACKET_MAX_LEN		65535 /* 0xFFFF */
#define PROTOCOL_ICMP		1

/* The 16 bit one's complement of the one's complement sum of all 16 bit words in the header.
 * For computing the checksum, the checksum field should be zero.
 * This checksum may be replaced in the future. */
uint16_t l3_checkSum(Packet* header);
/* Create IP header from the length of the data, source IP address and destination IP address */
void l3_create_header(Packet* header, size_t sendDataLen, std::string srcIP, std::string destIP);
void l3_print_packet(Packet header, byte* data);

class L2;
class L4;

/*
 * Frame:
 *
 *   ┃0│ │ │ ┃ │ │ │ ┃1│ │ │ ┃ │ │       46-1500 bytes       ┃ │ │ │ ┃
 * ━━╉─┴─┴─┴─┸─┴─┴─┴─╂─┴─┴─┴─┸─┴─┴───────────────────────────╂─┴─┴─┴─┨
 *  0┃Dest MAC   │Source MAC ┃Typ│           Data            ┃CRC    ┃
 * ━━╉─┬─┬─┬─┰─┬─┬─┬─┰─┬─┬─┬─┰─┬─┬───────────────────────────╂─┬─┬─┬─┨
 *   ┃ │ │ │ ┃ │ │ │ ┃ │ │1│1┃1│1│                           ┃ │ │ │ ┃
 *   ┃0│1│2│3┃4│5│6│7┃8│9│0│1┃2│3│       46-1500 bytes       ┃ │ │ │ ┃
 *
 * Packet:
 *
 *   ┃0│ │ │ ┃ │ │ │ ┃1│ │ │ ┃ │ │ │ ┃2│ │ │ ┃ │ │ │ ┃3│ │ │ ┃ │ │ │ ┃
 * ━━╉─┴─┴─┴─╂─┴─┴─┴─╂─┴─┴─┴─┸─┴─┴─┴─╂─┴─┴─┴─┸─┴─┴─┴─┸─┴─┴─┴─┸─┴─┴─┴─┨
 *  0┃Version┃IHL    ┃Type of Service┃Total Length                   ┃
 * ━━╉───────┸───────┸───────────────╂─┬─┬─┬─────────────────────────┨
 *  4┃Identification                 ┃x│D│M│Fragment Offset          ┃
 * ━━╉───────────────┰───────────────╂─┴─┴─┴─────────────────────────┨
 *  8┃Time to live   ┃Protocol       ┃Header Checksum                ┃
 * ━━╉───────────────┸───────────────┸───────────────────────────────┨
 * 16┃Source Address                                                 ┃
 * ━━╉───────────────────────────────────────────────────────────────┨
 * 20┃Destination Address                                            ┃
 * ━━╉───────────────────────────────────────────────────────────────┨
 * ..┃                                                               ┃
 * ..┃                             Data                              ┃
 * ..┃                                                               ┃
 * ━━╉─┬─┬─┬─┰─┬─┬─┬─┰─┬─┬─┬─┰─┬─┬─┬─┰─┬─┬─┬─┰─┬─┬─┬─┰─┬─┬─┬─┰─┬─┬─┬─┨
 *   ┃ │ │ │ ┃ │ │ │ ┃ │ │1│1┃1│1│1│1┃1│1│1│1┃2│2│2│2┃2│2│2│2┃2│2│3│3┃
 *   ┃0│1│2│3┃4│5│6│7┃8│9│0│1┃2│3│4│5┃6│7│8│9┃0│1│2│3┃4│5│6│7┃8│9│0│1┃
 *
 * Drawing is based on https://nmap.org/book/tcpip-ref.html using https://en.wikipedia.org/wiki/Box-drawing_character
 */
typedef struct Frame_name { /* sizeof(Frame) == 14 */
	unsigned char destinationMAC[6];
	unsigned char sourceMAC[6];
	unsigned char etherType[2];
} Frame;
typedef struct Packet_name { /* sizeof(Packet) == 20 */
	uint8_t versionAndIHL;		/* Version (4 bits) and Internet header length in 32-bit words (4 bits) */
	uint8_t typeOfService;		/* Type of Service (TOS) = 0 */
	uint16_t totalLength;		/* Length of internet header and data in octets */
	uint16_t identification;	/* Identification */
	uint16_t flagsFragmentOffset;	/* Flags (3 bits) and Fragment Offset (13 bits) */
	uint8_t timeToLive;		/* Time to live in seconds */
	uint8_t protocol;		/* ICMP = 1 */
	uint16_t headerChecksum;	/* The 16 bit one’s complement of the one’s complement sum of all 16 bit words in the header */
	uint32_t sourceAddress;		/* The address of the gateway or host that composes the ICMP message */
	uint32_t destinationAddress;	/* The address of the gateway or host to which the message should be sent */
} Packet;

/**
* \class L3
* \brief Represents a Layer 3 interface (IP).
*/
class L3 {
public:
	/**
	* \brief Constructs an L3 interface.
	*
	* May use it to initiate variables and data structure that you wish to use.
	* Should remain empty by default (if no global class variables are beeing used).
	* 
	* \param debug \a (bool)
	* \parblock
	* Decide the mode of the interface, when true the interface will print messages for debuf purposes.
	* Default value is false.
	* \endparblock
	*/
	L3(bool debug);

	/**
	* \brief L3 output routine.
	*
	* This method wrap data with an IP header specifically for an ICMP request
	* packet and sends the data to sendToL2.
	*
	* \param sendData \a (byte*) The data to be sent.
	* \param sendDataLen \a (size_t) The length of the data to be sent.
	* \param srcIP \a (string) The source IP address (from NIC::myIP).
	* \param destIP \a (string) The destination IP address (from the main).
	* \retval int the number of bytes that were sent (from sendToL2).
	*/
	int sendToL3(byte* sendData, size_t sendDataLen, std::string srcIP, std::string destIP);

	/**
	* \brief L3 input routine.
	*
	* This method was called by the recvFromL2 (member function of the L2 class).
	* It unwraps the IP header of the received data, drops invalid packets,
	* passes the unwraped data to the correct upper interface and possibly prints
	* relevant information.
	*
	* \param recvData \a (byte*) The received data.
	* \param recvDataLen \a (size_t) The length of the received data.
	* \retval int the number of bytes that were received.
	*/
	int recvFromL3(byte* recvData, size_t recvDataLen);

	/**
	* \brief Setter for the pointer to the L2 to be used by this layer.
	*
	* \param lowerInterface \a (L2*) the L2 to be used by this layer.
	*/
	void setLowerInterface(L2* lowerInterface);

	/**
	* \brief Setter for the pointer to the L4 to be used by this layer.
	*
	* \param upperInterface \a (L4*) the L4 to be used by this layer.
	*/
	void setUpperInterface(L4* upperInterface);

	/**
	* \brief Getter for the name of the lowest interface.
	*
	* \retval string the name of the lowest interface.
	*/
	std::string getLowestInterface();

private:
	bool debug;
	L2* lowerInterface;
	L4* upperInterface;
};

#endif /* L3_H_ */
