/**
 * P.U.S.H. - Packetizer for Unix Shell Hosts
 *
 * Owner: alphonsearackal
 * gmail: alphonsearackal
 *
 */

/* Include files */
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <getopt.h>

#include "push.h"
#include "push_log.h"
#include "push_window.h"

/* Global Variables */
static char *g_interface_name = NULL;
static pcap_t *g_receiver = NULL;
static pcap_t *g_sender = NULL;
static bool g_capture_enabled = false;
static bool g_build_stream = false;
static uint8_t g_interface_MAC_address[ETH_ALEN];
static uint8_t g_broadcast_MAC_address[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static char *g_hexstream_file_name = NULL;
static char *g_pcap_file_name = NULL;
static char *g_filter = NULL;
static char *g_capture_file = NULL;
static uint32_t g_frames_per_second = 10;
static unsigned long g_capture_count = 10; 
static pkt_gen_configuration_t g_configuration;

/* Function Definitions */
static void usage()
{
	printf("USAGE:\n"
			"push -bh -i <interface-name> -n <number-of-packets-to-capture>\n"
			"     -f <capture-filter> -x <hex-stream-file-name> -r <frame-rate>\n"
			"     -p <pcap-file-name> -c <capture-file>\n"
#ifdef DEBUG
			"     -d <optional-debug-args>\n"
#endif
			"\n");
	printf("OPTIONS:\n"
			"     -i, --interface      : Interface on which send/recv to be done.\n"
			"                            Args required: interface name\n"
			"     -c, --capture        : Enable capture, output pcap file will be\n"
			"                            generated: \"capture.pcap\".\n"
			"                            Optional Args required: capture file name.\n"
			"     -n, --numCapture     : Number of packets to capture.\n"
			"                            Args required: packet count\n"
			"     -f, --filter         : Capture filter. Capture filters can be found\n"
			"                            here:\"https://www.tcpdump.org/manpages/pcap-filter.7.html\"\n"
			"                            Args required: filter name\n"
			"     -r, --framerate      : Frame rate in fps to send traffic.\n"
#ifdef DEBUG
			"                            Will not be accurate if debug enabled.\n"
#endif
			"                            Args required: frame rate in fps\n"
			"     -x, --hexstream      : Send packets from file. Packet should be\n"
			"                            written in hex stream in this text file.\n"
			"                            Args required: file name\n"
			"     -p, --pcapfile       : Send packets from pcap file.\n"
			"                            Args required: pcap file name\n"
			"     -b, --buildstream    : Generate packet stream and send.\n"
#ifdef DEBUG
			"     -d, --debug          : Enable debug options.\n"
#endif
			"     -h, --help           : Help. Displays usage.\n");
}

static void save_configuration(int signo)
{
	fill_save_configuration_data(&g_configuration);
	exit(SUCCESS);
}

static void sleep_till_next()
{
	struct timespec wait;
	long milliseconds =  1000 / g_frames_per_second;

	if (milliseconds > 999)
	{
		wait.tv_sec = (int)(milliseconds / 1000);/* Must be Non-Negative */
		wait.tv_nsec =
			(milliseconds - ((long)wait.tv_sec * 1000)) * 1000000; /* Must be in range of 0 to 999999999 */
	}
	else
	{
		wait.tv_sec = 0; /* Must be Non-Negative */
		wait.tv_nsec = milliseconds * 1000000;    /* Must be in range of 0 to 999999999 */
	}

	nanosleep(&wait , NULL);
}

static void send_packet(uint8_t *frame, int length)
{
	if (pcap_inject(g_sender, frame, length) == -1)
	{
		DEBUG_PRINT(DEBUG_ERROR, "pcap_inject() failed");
		pcap_perror(g_sender, 0);
		pcap_close(g_sender);
		exit(EXIT_FAILURE);
	}
	sleep_till_next();
}

static void send_generated_packet_stream()
{
	uint8_t *data = g_configuration.data;
	int length = 0;
	uint8_t LLC_header[3] =
	{ 0x00, 0x00, 0x03 };
	uint16_t ether_type = 0;

	memset(&g_configuration, 0, sizeof(pkt_gen_configuration_t));
	memcpy(g_configuration.ethernet_header.dst_MAC, g_broadcast_MAC_address, ETH_ALEN);
	memcpy(g_configuration.ethernet_header.src_MAC, g_interface_MAC_address, ETH_ALEN);
	g_configuration.vlan_tag.ether_type[0] = 0x81;
	g_configuration.vlan_tag.ether_type[1] = 0x00;
	g_configuration.vlan_tag.cos = 0;
	g_configuration.vlan_tag.cfa = 0;
	g_configuration.vlan_tag.vlan_id = 1;
	g_configuration.protocol = proto_raw;
	g_configuration.pkt_len = 64;

	DEBUG_PRINT(DEBUG_INFO, "Generating new packet stream");

	if (!show_welcome_window())
	{
		return;
	}

	fill_input_checks(&g_configuration);
	if (g_configuration.check_dst_MAC)
		fill_MAC_address(g_configuration.ethernet_header.dst_MAC, "Destination MAC Address");
	if (g_configuration.check_src_MAC)
		fill_MAC_address(g_configuration.ethernet_header.src_MAC, "Source MAC Address");
	if (g_configuration.check_frame_length)
		fill_frame_length(&g_configuration.pkt_len);
	if (g_configuration.check_tagged)
		fill_vlan_tag(&g_configuration.vlan_tag);
	if(g_configuration.check_protocol)
		fill_protocol(&g_configuration);

	memset(data, 0, ETH_FRAME_LEN);
	memcpy(data, g_configuration.ethernet_header.dst_MAC, ETH_ALEN);
	memcpy(data + ETH_ALEN, g_configuration.ethernet_header.src_MAC, ETH_ALEN);
	length = 2 * ETH_ALEN;

	if (g_configuration.check_tagged)
	{
		data[length] = g_configuration.vlan_tag.ether_type[0];
		data[length + 1] = g_configuration.vlan_tag.ether_type[1];
		length += 2;
		data[length] = g_configuration.vlan_tag.cos << 5;
		data[length] |= g_configuration.vlan_tag.cfa << 4;
		data[length] |= (g_configuration.vlan_tag.vlan_id >> 8) & 0x0f;
		data[length + 1] = g_configuration.vlan_tag.vlan_id & 0xff;
		length += 2;
	}

	if(g_configuration.protocol == proto_raw)
		ether_type = g_configuration.pkt_len;
	else if (g_configuration.protocol == proto_ipv4)
		ether_type = ETH_P_IP;
	else if (g_configuration.protocol == proto_ipv6)
		ether_type = ETH_P_IPV6;

	data[length] = ether_type >> 8;
	data[length + 1] = ether_type;
	length += 2;

	if(g_configuration.protocol == proto_raw)
	{
		memcpy(data + length, LLC_header, 3);
		length += 3;
	}
	else if (g_configuration.protocol == proto_ipv4)
	{
		memcpy(data + length, &g_configuration.ipv4_header, sizeof(struct iphdr));
		length += sizeof(struct iphdr);
		if (g_configuration.ipv4_header.protocol == IPPROTO_UDP)
		{
			memcpy(data + length, &g_configuration.udp_header, sizeof(struct udphdr));
			length += sizeof(struct udphdr);
		}
	}
	else if (g_configuration.protocol == proto_ipv6)
	{
		memcpy(data + length, &g_configuration.ipv6_header, sizeof(struct ip6_hdr));
		length += sizeof(struct ip6_hdr);
		if (g_configuration.ipv6_header.ip6_nxt == IPPROTO_UDP)
		{
			memcpy(data + length, &g_configuration.udp_header, sizeof(struct udphdr));
			length += sizeof(struct udphdr);
		}
	}

	strcpy((char *) &data[g_configuration.pkt_len - strlen(SIGNATURE)], SIGNATURE);
	printf("Sending packets at %d fps...\n", g_frames_per_second);
	DEBUG_PRINT_PACKET("Generated Stream", data, g_configuration.pkt_len);

	while(true)	
		send_packet(data, g_configuration.pkt_len);
}

static void send_pcap_packets(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet)
{
	uint8_t packet_data[ETH_FRAME_LEN] = { 0 };

	memcpy(packet_data, packet, packet_header->len);

	DEBUG_PRINT_PACKET("Packet from pcap file", packet_data, packet_header->len);

	send_packet(packet_data, packet_header->len);
}

static void send_pcaket_from_pcap_file()
{
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_reader = NULL;

	DEBUG_PRINT(DEBUG_INFO, "Reading from pcap file for packets");

	pcap_reader = pcap_open_offline(g_pcap_file_name, error_buffer);
	if (pcap_reader == NULL)
	{
		printf("Failed to read pcap file %s. Error: %s\n", g_pcap_file_name, error_buffer);
		DEBUG_PRINT(DEBUG_ERROR, 
				"Failed to read pcap file %s. Error: %s\n", g_pcap_file_name, error_buffer);
		return; 
	}

	/* loop for callback function */
	pcap_loop(pcap_reader, 0, send_pcap_packets, NULL);

	pcap_close(pcap_reader);
}

static void send_hex_stream_from_file()
{
	int i = 0;
	size_t buffer_length = 0;
	size_t length = 0;
	char *line = NULL;
	char *pos = NULL;
	int frame_count = 0;
	int packet_length[MAX_FILE_FRAMES] = { [0 ... MAX_FILE_FRAMES - 1] = 0 };
	uint8_t data[MAX_FILE_FRAMES][ETH_FRAME_LEN];

	DEBUG_PRINT(DEBUG_INFO, "Reading from file for hex streams");

	memset(data, 0, MAX_FILE_FRAMES * ETH_FRAME_LEN);
	FILE *file_pointer = fopen(g_hexstream_file_name, "r");
	if (file_pointer == NULL)
	{
		printf("Hex stream file not found\n");
		DEBUG_PRINT(DEBUG_ERROR, "Hex stream file not found");
		return;
	}

	while ((length = getline(&line, &buffer_length, file_pointer)) != EOF)
	{
		if (line != NULL)
		{
			pos = line;
			packet_length[frame_count] = 0;
			for (i = 0; i < ETH_FRAME_LEN; i++)
			{
				if (*pos == '\n' || *pos == '\0')
				{
					break;
				}
				else if (*pos == ' ')
				{
					pos += 1;
					continue;
				}

				sscanf(pos, "%2hhx", &data[frame_count][packet_length[frame_count]]);
				(packet_length[frame_count])++;
				pos += 2;
			}
			frame_count++;
			free(line);
			line = NULL;
		}
	}
	fclose(file_pointer);

	while (true)
	{
		for(i = 0; i < frame_count; i++)
		{
			DEBUG_PRINT_PACKET("Packet from hex stream file", data[i], packet_length[i]);			
			send_packet(data[i], packet_length[i]);
		}
	}
}

static void process_send_requests()
{
	char error_buffer[PCAP_ERRBUF_SIZE];

	if (g_frames_per_second == 0)
	{
		printf("Frame rate ZERO\n");
		return;
	}

	/* Open new pcap socket */
	if ((g_sender = pcap_open_live(g_interface_name, ETH_FRAME_LEN, 0, 0, error_buffer)) == NULL)
	{
		printf("%s\n", error_buffer);
		DEBUG_PRINT(DEBUG_ERROR,"pcap_open_live() failed with error: %s.", error_buffer);
		return;
	}

	if (g_hexstream_file_name != NULL)
	{
		printf("Sending packets from hexstream file at %d fps...\n", g_frames_per_second);
		send_hex_stream_from_file();
	}

	if (g_pcap_file_name != NULL)
	{
		printf("Sending packets from pcap file at %d fps...\n", g_frames_per_second);
		send_pcaket_from_pcap_file();
	}

	if (g_build_stream)
	{
		send_generated_packet_stream();
	}
	pcap_close(g_sender);	
}

static void capture_packets(u_char *user, const struct pcap_pkthdr *packet_header, const u_char *packet)
{
	pcap_dump(user, packet_header, packet);

	printf("Packet captured--> capture length: %d ... Total length: %d\n", packet_header->caplen, packet_header->len);
	DEBUG_PRINT_PACKET("Packet Captured", (uint8_t *) packet, packet_header->len);
}

static void process_receive_requests()
{
	char error_buffer[PCAP_ERRBUF_SIZE];
	bpf_u_int32 ip_address = 0;
	bpf_u_int32 netmask = 0;
	struct bpf_program filter_program; /* hold compiled program */
	pcap_dumper_t *pcapfile;

	if (!g_capture_enabled)
	{
		DEBUG_PRINT(DEBUG_INFO,"Capture not enabled. Returning.");
		return;
	}

	/* Get the network address and mask */
	pcap_lookupnet(g_interface_name, &ip_address, &netmask, error_buffer);

	if ((g_receiver = pcap_open_live(g_interface_name, ETH_FRAME_LEN, 1, 0, error_buffer)) == NULL)
	{
		printf("%s\n", error_buffer);
		DEBUG_PRINT(DEBUG_ERROR,"pcap_open_live() failed with error: %s.", error_buffer);
		return;
	}

	/* Now we'll compile the filter expression*/
	if(pcap_compile(g_receiver, &filter_program, g_filter, 0, ip_address) == -1) 
	{
		printf("Error : Bad filter\n");
		DEBUG_PRINT(DEBUG_ERROR,"pcap_compile() failed: Bad filter name.");
		return;
	}

	/* set the filter */
	if(pcap_setfilter(g_receiver, &filter_program) == -1)
	{
		printf("Error setting filter\n");
		DEBUG_PRINT(DEBUG_ERROR,"pcap_setfilter() failed to set filter.");
		return;
	}

	/* Open capture file */
	if ((pcapfile = pcap_dump_open(g_receiver, 
					(g_capture_file ? g_capture_file : "capture.pcap"))) == NULL)
	{
		printf("Error from pcap_dump_open(): %s\n", pcap_geterr(g_receiver)); 
		DEBUG_PRINT(DEBUG_ERROR,"pcap_dump_open() failed with error: %s.", pcap_geterr(g_receiver));
		return;
	}

	/* loop for callback function */
	DEBUG_PRINT(DEBUG_INFO,"Capturing packets on %s.", g_interface_name);
	pcap_loop(g_receiver, g_capture_count, capture_packets, (u_char *) pcapfile);

	pcap_dump_close(pcapfile);
	pcap_close(g_receiver);
}

static bool get_interface_MAC_address()
{
	int i;
	struct ifreq interface_request;
	int socket_descriptor = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	if (socket_descriptor < 0)
	{
		return false;
	}

	strcpy(interface_request.ifr_name, g_interface_name);
	if (0 == ioctl(socket_descriptor, SIOCGIFHWADDR, &interface_request))
	{
		for (i = 0; i < ETH_ALEN; ++i)
		{
			g_interface_MAC_address[i] = (uint8_t) interface_request.ifr_addr.sa_data[i];
		}
	}
	else
	{
		close(socket_descriptor);
		return false;
	}

	DEBUG_PRINT(DEBUG_INFO,"Interface MAC address- %02x:%02x:%02x:%02x:%02x:%02x", g_interface_MAC_address[0],
			g_interface_MAC_address[1], g_interface_MAC_address[2], g_interface_MAC_address[3],
			g_interface_MAC_address[4], g_interface_MAC_address[5]);
	close(socket_descriptor);

	return true;
}

static bool parse_inputs(int argc, char *argv[])
{
	int ch = 0;
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct option long_options[] =
	{
		{ "interface", O_REQ_ARG, NULL, 'i' },
		{ "capture", O_OPT_ARG, NULL, 'c' },
		{ "numCapture", O_REQ_ARG, NULL, 'n' },
		{ "filter", O_REQ_ARG, NULL, 'f' },
		{ "hexstream", O_REQ_ARG, NULL, 'x' },
		{ "pcapfile", O_REQ_ARG, NULL, 'p' },
		{ "framerate", O_REQ_ARG, NULL, 'r' },
		{ "buildstream", O_NO_ARG, NULL, 'b' },
		{ "debug", O_OPT_ARG, NULL, 'd' },
		{ "help", O_NO_ARG, NULL, 'h' },
		{ NULL, 0, NULL, 0 } };
	bool valid_request_found = false;

	/* Loop through user inputs */
	while ((ch = getopt_long(argc, argv, "i:d::hc::n:x:p:r:f:b", long_options, NULL)) != EOF)
	{
		switch (ch)
		{
			case 'i':
				if (optarg != NULL)
					g_interface_name = optarg;
				break;
			case 'c':
				g_capture_enabled = true;
				valid_request_found = true;
				if (optarg != NULL)
					g_capture_file = optarg;
				break;
			case 'n':
				if (optarg != NULL)
					g_capture_count = atoi(optarg);
				break;
			case 'x':
				if (optarg != NULL)
				{
					g_hexstream_file_name = optarg;
					valid_request_found = true;
				}
				break;
			case 'p':
				if (optarg != NULL)
				{
					g_pcap_file_name = optarg;
					valid_request_found = true;
				}
				break;
			case 'b':
				g_build_stream = true;
				valid_request_found = true;
				break;
			case 'f':
				if (optarg != NULL)
					g_filter = optarg;
				break;
			case 'r':
				if (optarg != NULL)
					g_frames_per_second = atoi(optarg);
				break;
#if DEBUG
			case 'd':
				g_debug_enabled = true;
				break;
#endif
			case 'h':
			default:
				usage();
				return ((ch == 'h') ? true : false);
		}
	}

	if (!valid_request_found)
	{
		printf("\nNo valid request found...!\n\n");
		usage();
		return false;
	}
	else 
	{
		if ((g_hexstream_file_name || g_pcap_file_name || g_build_stream) &&
				(g_capture_enabled))
		{
			printf("\nChoose any one of these options: "
					"\"capture\" \"hexstream\" \"pcapfile\" \"buildstream\"\n\n");
			usage();
			return false;
		}

		if ((g_hexstream_file_name && (g_pcap_file_name || g_build_stream)) ||
				(g_pcap_file_name && (g_hexstream_file_name || g_build_stream)) ||
				(g_build_stream && (g_hexstream_file_name || g_pcap_file_name)))
		{
			printf("\nChoose any one of these options: "
					"\"capture\" \"hexstream\" \"pcapfile\" \"buildstream\"\n\n");
			usage();
			return false;
		}
	}

	if (g_interface_name == NULL)
	{
		/* Find a device */
		DEBUG_PRINT(DEBUG_INFO,"No interface name suggested. Searching for suitable device.");
		g_interface_name = pcap_lookupdev(error_buffer);
		if (g_interface_name == NULL) 
		{
			printf("Error finding device: %s\n", error_buffer);
			DEBUG_PRINT(DEBUG_ERROR,"pcap_lookupdev() failed to find suitable devie: %s.", error_buffer);
			return false;
		}
		DEBUG_PRINT(DEBUG_INFO,"Found suitable interface: %s.", g_interface_name);
	}

	if (!get_interface_MAC_address())
	{
		printf("Failed to open device %s\n", g_interface_name);
		DEBUG_PRINT(DEBUG_ERROR,"Failed to open device %s", g_interface_name);
		return false;	
	}

	if (g_frames_per_second < 0)
	{
		printf("Invalid frame rate\n");
		return false;
	}

	/* Handle configuration save when kill request comes */
	if (g_build_stream)
		signal(SIGINT, save_configuration);

	printf("---------------------------------------------------------------------\n");
	printf("Working on interface: %s ...\n", g_interface_name);
	if (g_hexstream_file_name)
		printf("Pushing packets from hexstream file: %s\n", g_hexstream_file_name);
	if (g_pcap_file_name)
		printf("Pushing packets from pcap file: %s\n", g_pcap_file_name);
	printf("Capture: %s\n", g_capture_enabled ? "Enabled" : "Disabled");
	if (g_capture_enabled)
	{
		printf("Filter: %s\n", g_filter ? g_filter : "Nil");
		printf("Max packets to capture: %ld\n", g_capture_count);
	}
	if (g_build_stream)
		printf("Entering packet stream generate mode\n");
	if (g_hexstream_file_name || g_pcap_file_name || g_build_stream)
		printf("Frame rate set to: %d fps\n", g_frames_per_second);
	printf("---------------------------------------------------------------------\n");

	return true;
}

int main(int argc, char *argv[])
{
	/* Get user inputs from command line and makes it ready for processing*/	
	if(!parse_inputs(argc, argv))
	{
		return FAILURE;
	}

	/* process user requests got from command line */
	process_send_requests();
	process_receive_requests();

	return SUCCESS;
}
