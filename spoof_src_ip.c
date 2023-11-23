#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PACKET_SIZE 4096
#define SRC_IP "1.2.3.4"
#define DST_IP "8.8.8.8"

// Function to calculate the checksum of the packet
unsigned short checksum(unsigned short *buf, int nwords) {
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

int main() {
  int sockfd;
  char packet[PACKET_SIZE];
  struct sockaddr_in dest_addr;

  // Create a raw socket
  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sockfd == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  // Set destination address
  memset(&dest_addr, 0, sizeof(struct sockaddr_in));
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = inet_addr(DST_IP);

  // Prepare the IP header
  struct iphdr *ip_header = (struct iphdr *)packet;
  ip_header->ihl = 5;
  ip_header->version = 4;
  ip_header->tos = 0;
  ip_header->tot_len = sizeof(struct iphdr);
  ip_header->id = htons(54321);
  ip_header->frag_off = 0;
  ip_header->ttl = 64;
  ip_header->protocol = IPPROTO_RAW; // We're sending a raw packet
  ip_header->check = 0;
  ip_header->saddr = inet_addr(SRC_IP);
  ip_header->daddr = dest_addr.sin_addr.s_addr;

  // Calculate the IP header checksum
  ip_header->check = checksum((unsigned short *)ip_header, ip_header->ihl << 1);

  // Send the packet
  if (sendto(sockfd, packet, sizeof(struct iphdr), 0,
             (struct sockaddr *)&dest_addr, sizeof(struct sockaddr)) == -1) {
    perror("sendto");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  close(sockfd);
  return 0;
}
