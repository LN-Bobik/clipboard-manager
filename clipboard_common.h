#ifndef CLIPBOARD_COMMON_H
#define CLIPBOARD_COMMON_H

#include <stdint.h>
#include <time.h>

#define SOCKET_PATH "/tmp/clipboard_monitor.sock"
#define MAX_CLIP_SIZE 65536  // 64KB max clipboard data
#define MAX_USERS 100
#define MAX_HISTORY_PER_USER 50

// Commands
typedef enum {
    CMD_STORE_CLIPBOARD,
    CMD_GET_HISTORY,
    CMD_GET_ALL_HISTORIES,  // Admin only
    CMD_CLEAR_HISTORY,
    CMD_SHUTDOWN
} command_type_t;

// Encrypted clipboard entry
typedef struct {
    uint64_t id;
    uid_t uid;
    pid_t pid;
    time_t timestamp;
    size_t data_len;
    char encrypted_data[MAX_CLIP_SIZE];
    uint8_t iv[16];  // AES-256-CBC IV
    uint8_t tag[16]; // GCM auth tag
} clipboard_entry_t;

// Request from client
typedef struct {
    command_type_t command;
    uid_t requesting_uid;  // For admin queries
    uint32_t limit;
} request_t;

// Response to client
typedef struct {
    int32_t status;
    uint32_t count;
    // Followed by count clipboard_entry_t structures
} response_t;

#endif
