#ifndef _PUSH_H
#define _PUSH_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* Enumerations */
typedef enum check_item_e
{
        item_dst_MAC,
        item_src_MAC,
        item_frame_length,
        item_tagged,
        item_protocol,

} check_item_t;

typedef enum protocols_s
{
        proto_raw,
        proto_ipv4,
} protocols_t;

/* Structures */
typedef struct eth_hdr_s
{
        uint8_t dst_MAC[ETH_ALEN];
        uint8_t src_MAC[ETH_ALEN];
        uint16_t type_length;
} eth_hdr_t;

typedef struct vlan_tag_s
{
        uint8_t ether_type[2];
        uint16_t cos:3;
        uint16_t cfa:1;
        uint16_t vlan_id:12;
} vlan_tag_t;

typedef struct pkt_gen_configuration_s
{
        bool check_dst_MAC;
        bool check_src_MAC;
        bool check_frame_length;
        bool check_tagged;
        bool check_protocol;
        eth_hdr_t ethernet_header;
        vlan_tag_t vlan_tag;
        protocols_t protocol;
        struct iphdr ipv4_header;
        struct udphdr udp_header;

	int pkt_len;
	int data_len;
        uint8_t data[ETH_FRAME_LEN];
} pkt_gen_configuration_t;

/* Constants */
#define SUCCESS         0
#define FAILURE         1
#define SIGNATURE       "alphonsearackal."
#define MAX_FILE_FRAMES 100

#define O_NO_ARG        0
#define O_REQ_ARG       1
#define O_OPT_ARG       2

#endif /* _PUSH_H */
