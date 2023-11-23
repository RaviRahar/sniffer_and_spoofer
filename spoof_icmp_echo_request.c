#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PACKET_SIZE 4096

// Function to calculate the checksum of the packet
unsigned short checksum(unsigned short *buf, int nwords) {
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

int main(int argc, char *argv[]) {
  char *SRC_IP, *DST_IP;
  if (argc < 1) {
    printf("Argument src_ip not set. Using default = 8.8.8.8\n");
    SRC_IP = "192.168.1.2";
  } else {
    SRC_IP = argv[1];
  }
  if (argc < 1) {
    printf("Argument dst_ip not set. Using default = 8.8.8.8\n");
    DST_IP = "8.8.8.8";
  } else {
    DST_IP = argv[1];
  }
  int sockfd;
  char packet[PACKET_SIZE];
  struct sockaddr_in dest_addr;

  // Create a raw socket
  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
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
  ip_header->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
  ip_header->id = htons(54321);
  ip_header->frag_off = 0;
  ip_header->ttl = 64;
  ip_header->protocol = IPPROTO_ICMP;
  ip_header->check = 0;
  ip_header->saddr = inet_addr(SRC_IP);
  ip_header->daddr = dest_addr.sin_addr.s_addr;

  // Prepare the ICMP header
  struct icmphdr *icmp_header =
      (struct icmphdr *)(packet + sizeof(struct iphdr));
  icmp_header->type = ICMP_ECHO;
  icmp_header->code = 0;
  icmp_header->checksum = 0;
  icmp_header->un.echo.id = 0; // You can set an arbitrary identifier here
  icmp_header->un.echo.sequence =
      0; // You can set an arbitrary sequence number here

  // Calculate the IP header checksum
  ip_header->check = checksum((unsigned short *)ip_header, ip_header->ihl << 1);

  // Calculate the ICMP header checksum
  icmp_header->checksum =
      checksum((unsigned short *)icmp_header, sizeof(struct icmphdr) >> 1);

  // Send the packet
  if (sendto(sockfd, packet, ip_header->tot_len, 0,
             (struct sockaddr *)&dest_addr, sizeof(struct sockaddr)) == -1) {
    perror("sendto");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  close(sockfd);
  return 0;
}
