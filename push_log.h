#ifndef _PUSH_LOG_H
#define _PUSH_LOG_H

#ifdef DEBUG

#define MAX_LOG_MESSAGE_SIZE    8192
#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define DEBUG_PRINT(level, message, ...)        \
        log_message(level, __FILENAME__, __LINE__, message, ##__VA_ARGS__)
#define DEBUG_PRINT_PACKET(message, packet, length) log_packet(message, packet, length)

typedef enum log_levels_e
{
        DEBUG_ERROR,
        DEBUG_EVENT,
        DEBUG_INFO
} log_levels_t;


extern bool g_debug_enabled;

void log_message(log_levels_t level, const char *file_name, uint16_t line_number, char *message, ...);
void log_packet(char *message, uint8_t *packet, int length);

#else

#define DEBUG_PRINT(level, message, ...)
#define DEBUG_PRINT_PACKET(message, packet, length)

#endif

#endif /* _PUSH_LOG_H */
