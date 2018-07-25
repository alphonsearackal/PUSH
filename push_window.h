#ifndef _PUSH_WINDOW_H
#define _PUSH_WINDOW_H

void fill_protocol(pkt_gen_configuration_t *configuration);
void fill_vlan_tag(vlan_tag_t *vlan_tag);
void fill_frame_length(int *length);
void fill_MAC_address(uint8_t *MAC_address, char *title);
void fill_input_checks(pkt_gen_configuration_t *configuration);
void fill_save_configuration_data(pkt_gen_configuration_t *configuration);

#endif /* _PUSH_WINDOW_H */
