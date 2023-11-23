#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int spoof_icmp(const u_char *old_packet, unsigned long packet_len) {

  u_char *packet = malloc(packet_len);
  memcpy(packet, old_packet, packet_len);
  struct ether_header *eth = (struct ether_header *)packet;
  struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
  struct icmphdr *icmp =
      (struct icmphdr *)(packet + sizeof(struct ether_header) + (ip->ihl << 2));

  int sockfd;
  struct sockaddr_in dest_addr;
  // Create a raw socket
  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd == -1) {
    perror(" Socket()");
    return 2;
  }
  // Set destination address
  memset(&dest_addr, 0, sizeof(struct sockaddr_in));
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = ip->saddr;

  ip->saddr = ip->daddr;
  ip->daddr = dest_addr.sin_addr.s_addr;

  // Prepare the ICMP header
  icmp->type = ICMP_ECHOREPLY;

  // Calculate the IP header checksum
  // ip->check = checksum((unsigned short *)ip, ip->ihl << 1);
  ip->check = 0;

  // Calculate the ICMP header checksum
  // icmp->checksum =
  //     checksum((unsigned short *)icmp, sizeof(struct icmphdr) >> 1);
  icmp->checksum = 0;

  printf("\n");
  printf(" Echo Reply:\n");
  printf("       From: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
  printf("         To: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));

  // Send the packet
  if (sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)&dest_addr,
             sizeof(struct sockaddr)) == -1) {
    perror(" SendTo()");
    close(sockfd);
    return 2;
  }

  close(sockfd);
  free(packet);
  return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  unsigned long packet_len = header->len;
  struct ether_header *eth = (struct ether_header *)packet;
  if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
    if (ip->protocol == IPPROTO_ICMP) {
      struct icmphdr *icmp =
          (struct icmphdr *)(packet + sizeof(struct ether_header) +
                             (ip->ihl << 2));

      if (icmp->type == ICMP_ECHO) {
        printf(" Protocol: ICMP\n");
        printf("     Type: Echo Request\n");
        printf("     From: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
        printf("       To: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
        spoof_icmp(packet, packet_len);
      }

      printf("\n");
    }
  }

  return;
};

int main(int argc, char *argv[]) {

  char *dev;
  pcap_if_t *devs;
  char *filter_exp = "icmp";
  int max_packets = -1;

  pcap_t *handle;
  bpf_u_int32 net;
  bpf_u_int32 mask;
  const u_char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  struct pcap_pkthdr header;

  char *__help = "\n"
                 "arg1 = interface_name ; default = default of your system\n"
                 "Set max_packets to -1 to run indefinitely\n";

  // Taking arguments
  if (argc > 1) {
    dev = argv[1];
  } else {
    printf("No interface_name provided. Using system default\n");
    int failure = pcap_findalldevs(&devs, errbuf);
    if (failure || devs == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
      return (2);
    }
    dev = devs->name;
  }

  // Find the properties for the device
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }
  // Open the session in promiscuous mode
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return (2);
  }
  // Compile and apply the filter
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    return (2);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
            pcap_geterr(handle));
    return (2);
  }
  // Grab a packet
  pcap_loop(handle, max_packets, got_packet, NULL);
  // packet = pcap_next(handle, &header);
  // Print its length
  // printf("Jacked a packet with length of [%d]\n", header.len);
  // And close the session
  pcap_close(handle);
  return (0);
}
