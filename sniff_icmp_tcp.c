#include <ctype.h>
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

// struct pcap_pkthdr {
// 	struct timeval ts; // time stamp
// 	bpf_u_int32 caplen; // length of portion present
// 	bpf_u_int32 len; // length this packet (off wire)
// };

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  int packet_len = header->len;
  struct ether_header *eth = (struct ether_header *)packet;
  if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ether_header));
    if (ip->protocol == IPPROTO_ICMP) {
      struct icmphdr *icmp =
          (struct icmphdr *)(packet + sizeof(struct ether_header) +
                             (ip->ihl << 2));
      printf(" Protocol: ICMP\n");
      printf("     From: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
      printf("       To: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
      printf("     Type: ");

      if (icmp->type == ICMP_ECHO || icmp->type == ICMP_ECHOREPLY) {
        if (icmp->type == ICMP_ECHO) {
          printf("ping request\n");
        } else if (icmp->type == ICMP_ECHOREPLY) {
          printf("ping reply\n");
        }
        if (packet_len > (sizeof(struct ether_header) + sizeof(struct iphdr) +
                          sizeof(struct icmphdr))) {
          printf("  Payload: ");
          puts((char *)packet +
               (sizeof(struct ether_header) + sizeof(struct iphdr) +
                sizeof(struct icmphdr)));
        }
      }
      printf("\n");
    } else if (ip->protocol == IPPROTO_TCP) {
      struct tcphdr *tcp =
          (struct tcphdr *)(packet + sizeof(struct ether_header) +
                            (ip->ihl << 2));
      size_t payload_len = ntohs(ip->tot_len) - ((ip->ihl + tcp->th_off) << 2);
      // Telnet passwords are sent as single characters
      // So only print packets with single characters
      // if (payload_len == 1) {
      printf(" Protocol: TCP\n");
      printf("            From: %s\n",
             inet_ntoa(*(struct in_addr *)&ip->saddr));
      printf("              To: %s\n",
             inet_ntoa(*(struct in_addr *)&ip->daddr));
      printf("     Source Port: %u\n", ntohs(tcp->source));
      printf("       Dest Port: %u\n", ntohs(tcp->dest));
      printf("     Payload Len: %lu\n", payload_len);
      printf("         Payload: \n");
      char *payload = (char *)tcp + (tcp->th_off << 2);
      char c;
      for (size_t i = 0; i < payload_len; i++) {
        c = payload[i];
        if (isprint(c)) {
          printf("%c", c);
        } else {
          printf(".");
        }
      }
      // ssize_t bytes_written = write(1, payload, payload_len);
      // sync();
      // if (bytes_written == -1) {
      // }
      printf("\n\n");
      // }
    }
  }

  return;
};

int main(int argc, char *argv[]) {

  char *dev;
  pcap_if_t *devs;
  char *filter_exp = "icmp";
  int max_packets = 10;

  pcap_t *handle;
  bpf_u_int32 net;
  bpf_u_int32 mask;
  const u_char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  struct pcap_pkthdr header;

  char *__help = "\n"
                 "arg2 = filter_exp     ; default = \"icmp\"\n"
                 "arg1 = max_packets    ; default = 10;\n"
                 "arg3 = interface_name ; default = default of your system\n"
                 "Set max_packets to -1 to run indefinitely\n";

  // Taking arguments
  if (argc > 1 &&
      (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
    printf("%s", __help);
    printf("\n\n");
    return (0);
  } else if (argc > 1) {
    filter_exp = argv[1];
  } else {
    printf("No filter_exp provided. Using default filter_exp = \"icmp\"\n");
  }
  if (argc > 3) {
    dev = argv[3];
  } else {
    printf("No interface_name provided. Using system default\n");
    int failure = pcap_findalldevs(&devs, errbuf);
    if (failure || devs == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
      return (2);
    }
    dev = devs->name;
  }
  if (argc > 2) {
    max_packets = atoi(argv[2]);
  } else {
    printf("No max_packets provided. Using default max_packets = 10\n");
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
