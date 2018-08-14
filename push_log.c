
#if DEBUG
/* Includes */
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <linux/if_ether.h>

#include "push_log.h"

/* Global variables */ 
bool g_debug_enabled = false;
static const char *log_level_names[] =
{ "ERROR", "EVENT", "INFO" };

/* Function Definitions */
void log_message(log_levels_t level, const char *file_name, uint16_t line_number, char *message, ...)
{
	if (!g_debug_enabled)
		return;

	va_list list;
	char log_message_1[MAX_LOG_MESSAGE_SIZE] =
	{ 0 };
	char log_message_2[MAX_LOG_MESSAGE_SIZE] =
	{ 0 };

	va_start(list, message);
	snprintf(log_message_1, MAX_LOG_MESSAGE_SIZE, "[%s][%s][line: %d]: %s\r\n",
			(level >= DEBUG_ERROR && level <= DEBUG_INFO) ? log_level_names[level] : "",
			file_name, line_number, message);
	vsnprintf(log_message_2, MAX_LOG_MESSAGE_SIZE, log_message_1, list);
	va_end(list);

	printf("%s", log_message_2);
}

void log_packet(char *message, uint8_t *packet, int length)
{
	if (!g_debug_enabled)
		return;

	int i = 0;
	int j = 0;
	int k = 0;
	char temp_1[32] = { 0 };
	char temp_2[32] = { 0 };
	uint8_t temp_bytes[16] = { [0 ... 15] = 0 };
	char debug_string[ETH_FRAME_LEN * 5] = { [0 ... (ETH_FRAME_LEN * 5) - 1] = 0 };

	for (k = 0; k < length; k += 16)
	{
		memset(temp_bytes, 0, 16);
		memcpy(temp_bytes, &packet[k], (16 > (length - k)) ? (length - k) : 16 );

		for (i = 0; i < 16; i++)
		{
			if (i < (length - k))
			{
				sprintf(temp_1, "%02x ", temp_bytes[i]);
			}
			else
			{
				sprintf(temp_1, "%3s", "");
			}
			if(((i + 1) % 16) == 0)
			{
				strcat(temp_1, "    ");
				for (j = (i - 15); j <= i; j++)
				{
					sprintf(temp_2, "%c", (j < (length - k)) ?
							(isprint((int) temp_bytes[j]) ? temp_bytes[j] : '.') : ' ');
					strcat(temp_1, temp_2);
					if(((j + 1) % 8) == 0)
					{
						strcat(temp_1, " ");
					}
				}
				strcat(temp_1, "\n");
			}
			else if(((i + 1) % 8) == 0)
			{
				strcat(temp_1, " ");
			}
			strcat(debug_string, temp_1);
		}
	}
	DEBUG_PRINT(DEBUG_INFO, "%s, packet length: %d \n%s", message, length, debug_string);
}
#endif

