
/* Includes */
#include "push.h"
#include "push_log.h"

/* Constants */
#define MAX_SYS_CMD_LEN 256
#define MAX_OUTPUT_LEN  256
#define DIALOG_BIN      "./dialog"
#define DIALOG_OUT      "dialog_out"

/* Function definitions */
static void get_dialog_output(char *output, size_t max_len)
{
        FILE *file_pointer = NULL;
        size_t buffer_length = 0;
        size_t length = 0;
        char *line = NULL;

        file_pointer = fopen(DIALOG_OUT, "r");
        if (file_pointer == NULL)
        {
                printf("Dialog output not found\n");
                return;
        }

        while ((length = getline(&line, &buffer_length, file_pointer)) != EOF)
        {
                if (line != NULL)
                {
                        strncpy(output, line, max_len);
                        free(line);
                        line = NULL;
                }
        }
        fclose(file_pointer);
}

static void fill_ipv4_protocols(pkt_gen_configuration_t *configuration)
{
        //TODO -
}

static void fill_ipv4_header(pkt_gen_configuration_t *configuration)
{
        char system_command[MAX_SYS_CMD_LEN] = { 0 };
        char dialog_output[MAX_OUTPUT_LEN] = { 0 };
        const int checks_DIALOG_HEIGHT = 10;
        const int checks_MAX_ITEMS = 4;
        char dialog_output_1[MAX_OUTPUT_LEN] = { 0 };

        DEBUG_PRINT(DEBUG_INFO, "Filling IPv4 Protocol header.");

        /* Fill default values */
        configuration->data_len = configuration->pkt_len - (sizeof(struct iphdr) + sizeof(struct udphdr)
                + ETH_HLEN + (configuration->check_tagged ? 4 : 0));
        configuration->ipv4_header.version = 4;
        configuration->ipv4_header.ihl = sizeof(struct iphdr) >> 2;
        configuration->ipv4_header.protocol = IPPROTO_UDP;
        configuration->ipv4_header.id = 0;
        configuration->ipv4_header.frag_off = 0;
        configuration->ipv4_header.ttl = 32;
        configuration->ipv4_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + configuration->data_len);

        configuration->udp_header.source = htons(44444);
        configuration->udp_header.dest = htons(55555);
        configuration->udp_header.len = htons(configuration->data_len + sizeof(struct udphdr));
        configuration->udp_header.check = 0;

        sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"IPv4 header\""
                " --checklist \"Choose fields you want to modify\" %d 40 %d",
                DIALOG_BIN, checks_DIALOG_HEIGHT, checks_MAX_ITEMS);
        strcat(system_command, " 0 tos off");
        strcat(system_command, " 1 Source-IP off");
        strcat(system_command, " 2 Dest-IP off");
        strcat(system_command, " 3 Protocol off");
        strcat(system_command, " 2>"DIALOG_OUT);
        system(system_command);
        get_dialog_output(dialog_output, MAX_OUTPUT_LEN);

        char *token = strtok(dialog_output, "\"");
        while (token)
        {
                switch(atoi(token))
                {
                        case 0:
                        {
                                sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"IPv4 header\""
                                        " --inputbox \"Enter TOS value:\" 8 40 2>%s", DIALOG_BIN, DIALOG_OUT);
                                system(system_command);
                                get_dialog_output(dialog_output_1, MAX_OUTPUT_LEN);
                                sscanf(dialog_output_1, "%2hhx", &configuration->ipv4_header.tos);
                        }
                        break;
                        case 1:
                        {
                                struct in_addr ip_addr;
                                sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"IPv4 header\""
                                        " --inputbox \"Enter Source IP:\" 8 40 2>%s", DIALOG_BIN, DIALOG_OUT);
                                system(system_command);
                                get_dialog_output(dialog_output_1, MAX_OUTPUT_LEN);
                                inet_aton(dialog_output_1, &ip_addr);
                                configuration->ipv4_header.saddr = ip_addr.s_addr;
                        }
                        break;
                        case 2:
                        {
                                struct in_addr ip_addr;
                                sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"IPv4 header\""
                                        " --inputbox \"Enter Dest IP:\" 8 40 2>%s", DIALOG_BIN, DIALOG_OUT);
                                system(system_command);
                                get_dialog_output(dialog_output_1, MAX_OUTPUT_LEN);
                                inet_aton(dialog_output_1, &ip_addr);
                                configuration->ipv4_header.daddr = ip_addr.s_addr;
                        }
                        break;
                        case 3:
                                fill_ipv4_protocols(configuration);
                        break;
                        default:
                        break;
                }
                token = strtok(NULL, "\"");
                token = strtok(NULL, "\"");
        }
        remove(DIALOG_OUT);
}

void fill_protocol(pkt_gen_configuration_t *configuration)
{
        char system_command[MAX_SYS_CMD_LEN] = { 0 };
        char dialog_output[MAX_OUTPUT_LEN] = { 0 };
        const int checks_DIALOG_HEIGHT = 10;
        const int checks_MAX_ITEMS = 2;

        DEBUG_PRINT(DEBUG_INFO, "Filling Protocols.");

        sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"Protocol\""
                " --menu \"Choose protocol:\" %d 40 %d",
                DIALOG_BIN, checks_DIALOG_HEIGHT, checks_MAX_ITEMS);
        strcat(system_command, " 0 Raw-Ethernet");
        strcat(system_command, " 1 IPv4");
        strcat(system_command, " 2>"DIALOG_OUT);
        system(system_command);
        get_dialog_output(dialog_output, MAX_OUTPUT_LEN);

        switch(atoi(dialog_output))
        {
                case 0:
                        configuration->protocol = proto_raw;
                break;
                case 1:
                {
                        configuration->protocol = proto_ipv4;
                        fill_ipv4_header(configuration);
                }
                break;
                default:
                break;
        }
        remove(DIALOG_OUT);
}

void fill_vlan_tag(vlan_tag_t *vlan_tag)
{
        char system_command[MAX_SYS_CMD_LEN] = { 0 };
        char dialog_output[MAX_OUTPUT_LEN] = { 0 };
        const int checks_DIALOG_HEIGHT = 10;
        const int checks_MAX_ITEMS = 4;
        char dialog_output_1[MAX_OUTPUT_LEN] = { 0 };

        DEBUG_PRINT(DEBUG_INFO, "Filling VLAN Tag.");

        sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"VLAN Tag\""
                " --checklist \"Mark fields you want to modify:\" %d 40 %d",
                DIALOG_BIN, checks_DIALOG_HEIGHT, checks_MAX_ITEMS);
        strcat(system_command, " 0 Ethertype off");
        strcat(system_command, " 1 Priority off");
        strcat(system_command, " 2 cfa off");
        strcat(system_command, " 3 VLAN-Id on");
        strcat(system_command, " 2>"DIALOG_OUT);
        system(system_command);
        get_dialog_output(dialog_output, MAX_OUTPUT_LEN);

        char *token = strtok(dialog_output, "\"");
        while (token)
        {
                switch(atoi(token))
                {
                        case 0:
                        {
                                sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"VLAN Tag\""
                                        " --inputbox \"Enter Ethertype in hex:\" 8 40 2>%s", DIALOG_BIN, DIALOG_OUT);
                                system(system_command);
                                get_dialog_output(dialog_output_1, MAX_OUTPUT_LEN);
                                sscanf(dialog_output_1, "%2hhx", &vlan_tag->ether_type[0]);
                                sscanf(dialog_output_1 + 2, "%2hhx", &vlan_tag->ether_type[1]);
                        }
                        break;
                        case 1:
                        {
                                sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"VLAN Tag\""
                                        " --inputbox \"Enter COS priority(0-7):\" 8 40 2>%s", DIALOG_BIN, DIALOG_OUT);
                                system(system_command);
                                get_dialog_output(dialog_output_1, MAX_OUTPUT_LEN);
                                vlan_tag->cos = atoi(dialog_output_1);
                        }
                        break;
                        case 2:
                        {
                                sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"VLAN Tag\""
                                        " --inputbox \"Enter cfa(0/1):\" 8 40 2>%s", DIALOG_BIN, DIALOG_OUT);
                                system(system_command);
                                get_dialog_output(dialog_output_1, MAX_OUTPUT_LEN);
                                vlan_tag->cfa = atoi(dialog_output_1);
                        }
                        break;
                        case 3:
                        {
                                sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"VLAN Tag\""
                                        " --inputbox \"Enter VLAN-ID:\" 8 40 2>%s", DIALOG_BIN, DIALOG_OUT);
                                system(system_command);
                                get_dialog_output(dialog_output_1, MAX_OUTPUT_LEN);
                                vlan_tag->vlan_id = atoi(dialog_output_1);
                        }
                        break;
                        default:
                        break;
                }
                token = strtok(NULL, "\"");
                token = strtok(NULL, "\"");
        }
        remove(DIALOG_OUT);
}

void fill_frame_length(int *length)
{
        char system_command[MAX_SYS_CMD_LEN] = { 0 };
        char dialog_output[MAX_OUTPUT_LEN] = { 0 };
        int input = 0;

        DEBUG_PRINT(DEBUG_INFO, "Filling frame length.");

        sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"Frame Length\""
                " --inputbox \"Enter Frame length:\" 8 40 2>%s", DIALOG_BIN, DIALOG_OUT);
        system(system_command);
        get_dialog_output(dialog_output, MAX_OUTPUT_LEN);

        input = atoi(dialog_output);
        input = (input < 60) ? 60 : input;
        input = (input > ETH_FRAME_LEN) ? ETH_FRAME_LEN : input;

        *length = input;
        remove(DIALOG_OUT);
}

void fill_MAC_address(uint8_t *MAC_address, char *title)
{
        int i = 0;
        char *pos = NULL;
        char system_command[MAX_SYS_CMD_LEN] = { 0 };
        char dialog_output[MAX_OUTPUT_LEN] = { 0 };
        int mac_len = 0;

        DEBUG_PRINT(DEBUG_INFO, "Filling %s.", title);

        sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"%s\""
                " --inputbox \"Enter MAC address:\" 8 40 2>%s", DIALOG_BIN, title, DIALOG_OUT);
        system(system_command);
        get_dialog_output(dialog_output, MAX_OUTPUT_LEN);

        pos = dialog_output;
        for (i = 0; i < strlen(dialog_output); i++)
        {
                if (*pos == '\0' || mac_len >= ETH_ALEN)
                {
                        break;
                }
                if(*pos == ' ' || *pos == ':')
                {
                        pos += 1;
                        continue;
                }

                sscanf(pos, "%2hhx", &MAC_address[mac_len++]);
                pos += 2;
        }
        remove(DIALOG_OUT);
}

void fill_input_checks(pkt_gen_configuration_t *configuration)
{
        char system_command[MAX_SYS_CMD_LEN] = { 0 };
        char dialog_output[MAX_OUTPUT_LEN] = { 0 };
        const int checks_DIALOG_HEIGHT = 10;
        const int checks_MAX_ITEMS = 5;

        DEBUG_PRINT(DEBUG_INFO, "Filling input checks.");

        sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"Check List\""
                " --checklist \"Mark fields you want to modify:\" %d 40 %d",
                DIALOG_BIN, checks_DIALOG_HEIGHT, checks_MAX_ITEMS);
        strcat(system_command, " 0 Dst-MAC off");
        strcat(system_command, " 1 Src-MAC off");
        strcat(system_command, " 2 Frame-length off");
        strcat(system_command, " 3 VLAN-Tag off");
        strcat(system_command, " 4 Protocol off");
        strcat(system_command, " 2>"DIALOG_OUT);
        system(system_command);
        get_dialog_output(dialog_output, MAX_OUTPUT_LEN);

        char *token = strtok(dialog_output, "\"");
        while (token)
        {
                switch(atoi(token))
                {
                        case item_dst_MAC:
                                configuration->check_dst_MAC = true;
                        break;
                        case item_src_MAC:
                                configuration->check_src_MAC = true;
                        break;
                        case item_frame_length:
                                configuration->check_frame_length = true;
                        break;
                        case item_tagged:
                                configuration->check_tagged = true;
                        break;
                        case item_protocol:
                                configuration->check_protocol = true;
                        break;
                        default:
                        break;
                }
                token = strtok(NULL, "\"");
                token = strtok(NULL, "\"");
        }
        remove(DIALOG_OUT);
}

void fill_save_configuration_data(pkt_gen_configuration_t *configuration)
{
        char system_command[MAX_SYS_CMD_LEN] = { 0 };
        char dialog_output[MAX_OUTPUT_LEN] = { 0 };

        sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"Save Configuration\""
                " --yesno \"Do you want to save configuration?\" 6 40 2>%s", DIALOG_BIN, DIALOG_OUT);

        if (system(system_command) == 0)
        {
                sprintf(system_command, "%s --backtitle \"P.U.S.H.\" --title \"Save Configuration\""
                                " --inputbox \"Enter file name to save\" 6 40 2>%s", DIALOG_BIN, DIALOG_OUT);
                system(system_command);
                get_dialog_output(dialog_output, MAX_OUTPUT_LEN);

                int i = 0;
                FILE *file_pointer = fopen (dialog_output, "w+");
                if (file_pointer == NULL)
                {
                        DEBUG_PRINT(DEBUG_ERROR, "Failed to save configuration file");
                        remove(DIALOG_OUT);
                        exit(SUCCESS);
                }

                for (i = 0; i < configuration->pkt_len; i++)
                {
                        fprintf(file_pointer, "%02x", configuration->data[i]);
                }
                fprintf(file_pointer, "\n");
                fclose(file_pointer);
        }

        remove(DIALOG_OUT);
}
