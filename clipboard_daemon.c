#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "clipboard_common.h"

#define ENCRYPTION_KEY_FILE "/etc/clipboard_monitor/key.bin"
#define ADMIN_UID 0

static unsigned char encryption_key[32];
static clipboard_entry_t history[MAX_HISTORY_PER_USER * MAX_USERS];
static uint64_t history_count = 0;
static int server_fd = -1;

void xor_obfuscate(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= 0xAA;
    }
}

int aes_gcm_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *ciphertext, unsigned char *iv,
                    unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!RAND_bytes(iv, 16)) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, encryption_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    xor_obfuscate(ciphertext, ciphertext_len);
    return ciphertext_len;
}

int aes_gcm_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                    unsigned char *plaintext, const unsigned char *iv,
                    const unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char deobfuscated[MAX_CLIP_SIZE];

    memcpy(deobfuscated, ciphertext, ciphertext_len);
    xor_obfuscate(deobfuscated, ciphertext_len);

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, encryption_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, deobfuscated, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        plaintext[plaintext_len] = '\0';
        return plaintext_len;
    } else {
        return -1;
    }
}

void load_or_generate_key() {
    FILE *key_file = fopen(ENCRYPTION_KEY_FILE, "rb");
    if (key_file) {
        if (fread(encryption_key, 1, 32, key_file) != 32) {
            fprintf(stderr, "Failed to read encryption key\n");
            exit(1);
        }
        fclose(key_file);
        printf("Loaded existing encryption key\n");
    } else {
        if (!RAND_bytes(encryption_key, 32)) {
            fprintf(stderr, "Failed to generate encryption key\n");
            exit(1);
        }

        int ret = mkdir("/etc/clipboard_monitor", 0755);
        if (ret != 0 && errno != EEXIST) {
            fprintf(stderr, "Failed to create directory: %s\n", strerror(errno));
            exit(1);
        }

        key_file = fopen(ENCRYPTION_KEY_FILE, "wb");
        if (!key_file) {
            fprintf(stderr, "Failed to save encryption key\n");
            exit(1);
        }

        fwrite(encryption_key, 1, 32, key_file);
        fclose(key_file);
        chmod(ENCRYPTION_KEY_FILE, 0400);
        printf("Generated new encryption key\n");
    }
}

void store_clipboard_entry(const clipboard_entry_t *entry) {
    if (history_count >= MAX_HISTORY_PER_USER * MAX_USERS) {
        memmove(&history[0], &history[1],
                sizeof(clipboard_entry_t) * (history_count - 1));
        history_count--;
    }

    memcpy(&history[history_count], entry, sizeof(clipboard_entry_t));
    history_count++;
}

int get_peer_uid(int client_fd, uid_t *uid, pid_t *pid) {
    struct ucred credentials;
    socklen_t len = sizeof(credentials);

    if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &len) == -1) {
        return -1;
    }

    *uid = credentials.uid;
    *pid = credentials.pid;
    return 0;
}

void handle_client(int client_fd) {
    request_t request;
    response_t response;
    uid_t peer_uid;
    pid_t peer_pid;

    if (get_peer_uid(client_fd, &peer_uid, &peer_pid) == -1) {
        fprintf(stderr, "Failed to get client credentials\n");
        close(client_fd);
        return;
    }

    printf("Connection from UID: %d, PID: %d\n", peer_uid, peer_pid);

    if (recv(client_fd, &request, sizeof(request), 0) != sizeof(request)) {
        close(client_fd);
        return;
    }

    memset(&response, 0, sizeof(response));

    switch (request.command) {
        case CMD_STORE_CLIPBOARD: {
            clipboard_entry_t entry;

            if (recv(client_fd, &entry, sizeof(entry), 0) != sizeof(entry)) {
                response.status = -1;
                send(client_fd, &response, sizeof(response), 0);
                break;
            }

            if (entry.uid != peer_uid) {
                response.status = -2;
                send(client_fd, &response, sizeof(response), 0);
                break;
            }

            entry.timestamp = time(NULL);

            unsigned char encrypted[MAX_CLIP_SIZE];
            unsigned char iv[16];
            unsigned char tag[16];

            int encrypted_len = aes_gcm_encrypt(
                (unsigned char *)entry.encrypted_data,
                entry.data_len,
                encrypted,
                iv,
                tag
            );

            if (encrypted_len > 0) {
                memset(entry.encrypted_data, 0, MAX_CLIP_SIZE);
                memcpy(entry.encrypted_data, encrypted, encrypted_len);
                memcpy(entry.iv, iv, 16);
                memcpy(entry.tag, tag, 16);
                entry.data_len = encrypted_len;
            }

            store_clipboard_entry(&entry);

            response.status = 0;
            send(client_fd, &response, sizeof(response), 0);
            break;
        }

        case CMD_GET_HISTORY: {
            uint32_t count = 0;
            clipboard_entry_t *user_history = malloc(sizeof(clipboard_entry_t) * MAX_HISTORY_PER_USER);

            if (!user_history) {
                response.status = -1;
                send(client_fd, &response, sizeof(response), 0);
                break;
            }

            for (uint64_t i = 0; i < history_count && count < MAX_HISTORY_PER_USER; i++) {
                if (history[i].uid == peer_uid) {
                    memcpy(&user_history[count], &history[i], sizeof(clipboard_entry_t));
                    count++;
                }
            }

            response.status = 0;
            response.count = count;
            send(client_fd, &response, sizeof(response), 0);

            if (count > 0) {
                send(client_fd, user_history, sizeof(clipboard_entry_t) * count, 0);
            }

            free(user_history);
            break;
        }

        case CMD_GET_ALL_HISTORIES: {
            if (peer_uid != ADMIN_UID) {
                response.status = -2;
                response.count = 0;
                send(client_fd, &response, sizeof(response), 0);
                break;
            }

            response.status = 0;
            response.count = history_count;
            send(client_fd, &response, sizeof(response), 0);

            if (history_count > 0) {
                send(client_fd, history, sizeof(clipboard_entry_t) * history_count, 0);
            }
            break;
        }

        case CMD_CLEAR_HISTORY: {
            response.status = 0;
            send(client_fd, &response, sizeof(response), 0);
            break;
        }

        case CMD_SHUTDOWN: {
            if (peer_uid == ADMIN_UID) {
                response.status = 0;
                send(client_fd, &response, sizeof(response), 0);
                unlink(SOCKET_PATH);
                exit(0);
            } else {
                response.status = -2;
                send(client_fd, &response, sizeof(response), 0);
            }
            break;
        }
    }

    close(client_fd);
}

void signal_handler(int sig) {
    (void)sig;
    if (server_fd >= 0) {
        close(server_fd);
        unlink(SOCKET_PATH);
    }
    printf("\nServer shutdown\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    struct sockaddr_un addr;
    int client_fd;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    OpenSSL_add_all_algorithms();
    load_or_generate_key();

    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        exit(1);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_PASSCRED, &opt, sizeof(opt));

    unlink(SOCKET_PATH);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(server_fd);
        exit(1);
    }

    chmod(SOCKET_PATH, 0666);

    if (listen(server_fd, 5) == -1) {
        perror("listen");
        close(server_fd);
        unlink(SOCKET_PATH);
        exit(1);
    }

    printf("Clipboard monitor daemon started\n");
    printf("Socket: %s\n", SOCKET_PATH);
    printf("Encryption key: %s\n", ENCRYPTION_KEY_FILE);

    if (argc > 1 && strcmp(argv[1], "-d") == 0) {
        if (daemon(0, 0) == -1) {
            perror("daemon");
            exit(1);
        }
    }

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd == -1) {
            perror("accept");
            continue;
        }

        handle_client(client_fd);
    }

    return 0;
}
