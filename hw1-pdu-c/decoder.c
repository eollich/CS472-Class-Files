#include "decoder.h"
#include "nethelper.h"
#include "packet.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// This is where you will be putting your captured network frames for testing.
// Before you do your own, please test with the ones that I provided as samples:
#include "testframes.h"

// You can update this array as you add and remove test cases, you can
// also comment out all but one of them to isolate your testing. This
// allows us to loop over all of the test cases.  Note MAKE_PACKET creates
// a test_packet_t element for each sample, this allows us to get and use
// the packet length, which will be helpful later.
test_packet_t TEST_CASES[] = {MAKE_PACKET(raw_packet_icmp_frame198),
                              MAKE_PACKET(raw_packet_icmp_frame362),
                              MAKE_PACKET(raw_packet_arp_frame78)};

// !!!!!!!!!!!!!!!!!!!!! WHAT YOU NEED TO DO !!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//
// Search the code for TODO:, each one of these describes a place where
// you need to write code.  This scaffold should compile as is.  Make sure
// you delete the TODO: documentation in your implementation and provide
// some documentation on what you actually accomplished.

int main(int argc, char **argv) {
  // This code is here as a refresher on how to figure out how
  // many elements are in a statically defined C array. Note
  // that sizeof(TEST_CASES) is not 3, its the total number of
  // bytes.  On my machine it comes back with 48, because each
  // element is of type test_packet_t which on my machine is 16 bytes.
  // Thus, with the scaffold I am providing 48/16 = 3, which is
  // the correct size.
  int num_test_cases = sizeof(TEST_CASES) / sizeof(test_packet_t);

  printf("STARTING...");
  for (int i = 0; i < num_test_cases; i++) {
    printf("\n--------------------------------------------------\n");
    printf("TESTING A NEW PACKET\n");
    printf("--------------------------------------------------\n");
    test_packet_t test_case = TEST_CASES[i];

    decode_raw_packet(test_case.raw_packet, test_case.packet_len);
  }

  printf("\nDONE\n");
}

void decode_raw_packet(uint8_t *packet, uint64_t packet_len) {

  printf("Packet length = %ld bytes\n", packet_len);

  // Everything we are doing starts with the ethernet PDU at the
  // front.  The below code projects an ethernet_pdu structure
  // POINTER onto the front of the buffer so we can decode it.
  struct ether_pdu *p = (struct ether_pdu *)packet;
  uint16_t ft = ntohs(p->frame_type);

  printf("Detected raw frame type from ethernet header: 0x%x\n", ft);

  switch (ft) {
  case ARP_PTYPE:
    printf("Packet type = ARP\n");

    // Lets process the ARP packet, convert all of the network byte order
    // fields to host machine byte order
    arp_packet_t *arp = process_arp(packet);

    // Print the arp packet
    print_arp(arp);
    break;
  case IP4_PTYPE:
    printf("Frame type = IPv4, now lets check for ICMP...\n");

    // We know its IP, so lets type the raw packet as an IP packet
    ip_packet_t *ip = (ip_packet_t *)packet;

    // Now check the IP packet to see if its payload is an ICMP packet
    bool isICMP = check_ip_for_icmp(ip);
    if (!isICMP) {
      printf("ERROR: IP Packet is not ICMP\n");
      break;
    }

    // Now lets process the basic icmp packet, convert the network byte order
    // fields to host byte order
    icmp_packet_t *icmp = process_icmp(ip);

    // Now lets look deeper and see if the icmp packet is actually an
    // ICMP ECHO packet?
    bool is_echo = is_icmp_echo(icmp);
    if (!is_echo) {
      printf("ERROR: We have an ICMP packet, but it is not of type echo\n");
      break;
    }

    // Now lets process the icmp_packet as an icmp_echo_packet, again processing
    // the network byte order fields
    icmp_echo_packet_t *icmp_echo_packet = process_icmp_echo(icmp);

    // The ICMP packet now has its network byte order fields
    // adjusted, lets print it
    print_icmp_echo(icmp_echo_packet);

    break;
  default:
    printf("UNKNOWN Frame type?\n");
  }
}

/********************************************************************************/
/*                       ARP PROTOCOL HANDLERS */
/********************************************************************************/

/*
 *  This function takes a raw_packet that has already been verified to be an ARP
 *  packet.  It typecasts the raw_packet into an arp_packet_t *, and then
 *  converts all of the network byte order fields into host byte order.
 */
arp_packet_t *process_arp(raw_packet_t raw_packet) {

  // Convert raw_packet via type conversion to arp_packet_t and then convert the
  // network byte order fields to host byte order fields
  arp_packet_t *arp_packet = (arp_packet_t *)raw_packet;

  arp_packet->arp_hdr.htype = ntohs(arp_packet->arp_hdr.htype);
  arp_packet->arp_hdr.ptype = ntohs(arp_packet->arp_hdr.ptype);
  arp_packet->arp_hdr.op = ntohs(arp_packet->arp_hdr.op);

  return arp_packet;
}

/*
 *  This function takes an arp packet and just pretty-prints it to stdout using
 *  printf.  It decodes and indicates in the output if the request was an
 *  ARP_REQUEST or an ARP_RESPONSE
 */
void print_arp(arp_packet_t *arp) {
  char sha[18], tha[18], spa[16], tpa[16];
  mac_toStr(arp->arp_hdr.sha, sha, sizeof(sha));
  mac_toStr(arp->arp_hdr.tha, tha, sizeof(tha));
  ip_toStr(arp->arp_hdr.spa, spa, sizeof(spa));
  ip_toStr(arp->arp_hdr.tpa, tpa, sizeof(tpa));

  printf("ARP PACKET DETAILS\n");
  printf("     htype:     0x%04x\n", arp->arp_hdr.htype);
  printf("     ptype:     0x%04x\n", arp->arp_hdr.ptype);
  printf("     hlen:      %d\n", arp->arp_hdr.hlen);
  printf("     plen:      %d\n", arp->arp_hdr.plen);
  printf("     op:        %d (ARP %s)\n", arp->arp_hdr.op,
         arp->arp_hdr.op == ARP_REQ_OP ? "REQUEST" : "RESPONSE");
  printf("     spa:       %s\n", spa);
  printf("     sha:       %s\n", sha);
  printf("     tpa:       %s\n", tpa);
  printf("     tha:       %s\n", tha);
}

/********************************************************************************/
/*                       ICMP PROTOCOL HANDLERS */
/********************************************************************************/

/*
 *  This function takes an ip packet and then inspects its internal fields to
 *  see if the IP packet is managing an underlying ICMP packet.  If so, return
 *  true, if not return false.  You need to see if the "protocol" field in the
 *  IP PDU is set to ICMP_PTYPE to do this.
 */
bool check_ip_for_icmp(ip_packet_t *ip) {
  // checks if packet protocol is of type ICMP_PTYPE
  return ip->ip_hdr.protocol == ICMP_PTYPE;
}

/*
 *  This function takes an IP packet and converts it into an icmp packet. Note
 *  that it is assumed that we already checked if the IP packet is encapsulating
 *  an ICMP packet.  So we need to type convert it from (ip_packet_t *) to
 *  (icmp_packet *).  There are some that need to be converted from
 *  network to host byte order.
 */
icmp_packet_t *process_icmp(ip_packet_t *ip) {
  // Convert ip_packet via type conversion to icmp_packet_t and then convert
  // the network byte order fields to host byte order fields
  icmp_packet_t *icmp_packet = (icmp_packet_t *)ip;
  icmp_packet->icmp_hdr.checksum = ntohs(icmp_packet->icmp_hdr.checksum);
  return icmp_packet;
}

/*
 *  This function takes a known ICMP packet, and checks if its of type ECHO. We
 * do this by checking the "type" field in the icmp_hdr and evaluating if its
 * equal to ICMP_ECHO_REQUEST or ICMP_ECHO_RESPONSE.  If true, we return true.
 * If not, its still ICMP but not of type ICMP_ECHO.
 */
bool is_icmp_echo(icmp_packet_t *icmp) {
  // returns if ICMP packet is ICMP_ECHO_REQUEST or ICMP_ECHO_RESPONSE
  return icmp->icmp_hdr.type == ICMP_ECHO_REQUEST ||
         icmp->icmp_hdr.type == ICMP_ECHO_RESPONSE;
}

/*
 *  This function takes a known ICMP packet, that has already been checked to be
 *  of type ECHO and converts it to an (icmp_echo_packet_t).  Like in the other
 *  cases this is simply a type converstion, but there are also a few fields to
 *  convert from network to host byte order.
 */
icmp_echo_packet_t *process_icmp_echo(icmp_packet_t *icmp) {
  // Convert icmp_packet_t via type conversion to icmp_echo_packet_t and
  // then convert the network byte order fields to host byte order fields
  icmp_echo_packet_t *icmp_packet_echo = (icmp_echo_packet_t *)icmp;
  icmp_packet_echo->icmp_echo_hdr.id =
      ntohs(icmp_packet_echo->icmp_echo_hdr.id);
  icmp_packet_echo->icmp_echo_hdr.sequence =
      ntohs(icmp_packet_echo->icmp_echo_hdr.sequence);
  icmp_packet_echo->icmp_echo_hdr.timestamp =
      ntohl(icmp_packet_echo->icmp_echo_hdr.timestamp);
  icmp_packet_echo->icmp_echo_hdr.timestamp_ms =
      ntohl(icmp_packet_echo->icmp_echo_hdr.timestamp_ms);
  return icmp_packet_echo;
}

/*
 *  This function pretty prints the icmp_packet.
 */

void print_icmp_echo(icmp_echo_packet_t *icmp_packet) {
  uint16_t payload_size = ICMP_Payload_Size(icmp_packet);

  icmp_echo_pdu_t icmp_echo_packet = icmp_packet->icmp_echo_hdr;

  printf("TYPE %d \n", icmp_echo_packet.icmp_hdr.type);
  printf("ICMP PACKET DETAILS\n");
  printf("      type:      0x%02x\n", icmp_echo_packet.icmp_hdr.type);
  printf("      checksum:  0x%04x\n", icmp_echo_packet.icmp_hdr.checksum);
  printf("      id:        0x%04x\n", icmp_echo_packet.id);
  printf("      sequence:  0x%04x\n", icmp_echo_packet.sequence);
  printf("      timestamp: 0x%08x%08x\n", icmp_echo_packet.timestamp,
         icmp_echo_packet.timestamp_ms);
  printf("      payload:   %d bytes\n", payload_size);

  printf("      ECHO Timestamp: %s\n",
         get_ts_formatted(icmp_echo_packet.timestamp,
                          icmp_echo_packet.timestamp_ms));

  print_icmp_payload(icmp_packet->icmp_payload, payload_size);
}

/*
 *  This function pretty prints the icmp_echo_packet payload.  You can be
 */
void print_icmp_payload(uint8_t *payload, uint16_t payload_size) {
  printf("PAYLOAD\n");
  printf("\nOFFSET | CONTENTS\n");
  printf("-------------------------------------------------------\n");
  for (int i = 0; i < payload_size; i++) {
    if (i % 8 == 0) {
      printf("0x%04x | ", i);
    }
    printf("0x%02x  ", payload[i]);
    if (i % 8 == 8 - 1) {
      printf("\n");
    }
  }
}
