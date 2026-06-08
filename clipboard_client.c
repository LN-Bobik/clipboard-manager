#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <pwd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "clipboard_common.h"

#define ENCRYPTION_KEY_FILE "/etc/clipboard_monitor/key.bin"

static unsigned char admin_key[32];

void xor_obfuscate(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= 0xAA;
    }
}

int load_admin_key() {
    FILE *key_file = fopen(ENCRYPTION_KEY_FILE, "rb");
    if (!key_file) {
        fprintf(stderr, "Failed to open encryption key\n");
        return -1;
    }
    if (fread(admin_key, 1, 32, key_file) != 32) {
        fprintf(stderr, "Failed to read encryption key\n");
        fclose(key_file);
        return -1;
    }
    fclose(key_file);
    return 0;
}

int aes_gcm_decrypt_admin(const unsigned char *ciphertext, size_t ciphertext_len,
                           unsigned char *plaintext, const unsigned char *iv,
                           const unsigned char *tag) {
    unsigned char deobfuscated[MAX_CLIP_SIZE];
    memcpy(deobfuscated, ciphertext, ciphertext_len);
    xor_obfuscate(deobfuscated, ciphertext_len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, admin_key, iv);

    int len, plaintext_len;
    EVP_DecryptUpdate(ctx, plaintext, &len, deobfuscated, ciphertext_len);
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        plaintext[plaintext_len] = '\0';
        return plaintext_len;
    }
    return -1;
}

char* get_clipboard_content(size_t *len) {
    char *buffer = malloc(MAX_CLIP_SIZE);
    if (!buffer) return NULL;

    *len = read(STDIN_FILENO, buffer, MAX_CLIP_SIZE - 1);
    if (*len <= 0) {
        free(buffer);
        return NULL;
    }

    buffer[*len] = '\0';
    return buffer;
}

int connect_to_daemon() {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

int store_clipboard(int fd, const char *data, size_t len) {
    request_t request;
    clipboard_entry_t entry;
    response_t response;

    request.command = CMD_STORE_CLIPBOARD;
    request.requesting_uid = getuid();

    memset(&entry, 0, sizeof(entry));
    entry.uid = getuid();
    entry.pid = getpid();
    entry.data_len = len;
    memcpy(entry.encrypted_data, data, len);

    send(fd, &request, sizeof(request), 0);
    send(fd, &entry, sizeof(entry), 0);

    recv(fd, &response, sizeof(response), 0);
    return response.status;
}

int view_history(int fd) {
    request_t request;
    response_t response;

    request.command = CMD_GET_HISTORY;
    request.requesting_uid = getuid();

    send(fd, &request, sizeof(request), 0);
    recv(fd, &response, sizeof(response), 0);

    if (response.status == 0 && response.count > 0) {
        clipboard_entry_t *entries = malloc(sizeof(clipboard_entry_t) * response.count);
        recv(fd, entries, sizeof(clipboard_entry_t) * response.count, 0);

        printf("Your clipboard history (%u entries):\n", response.count);
        for (uint32_t i = 0; i < response.count; i++) {
            printf("  [%lu] PID: %d, Time: %s",
                   entries[i].id, entries[i].pid, ctime(&entries[i].timestamp));
            printf("  Data length: %zu bytes\n", entries[i].data_len);
        }

        free(entries);
    }

    return response.status;
}

int admin_view_all(int fd) {
    request_t request;
    response_t response;

    if (getuid() != 0) {
        fprintf(stderr, "This command requires root privileges\n");
        return -1;
    }

    if (load_admin_key() != 0) {
        return -1;
    }

    request.command = CMD_GET_ALL_HISTORIES;
    request.requesting_uid = getuid();

    send(fd, &request, sizeof(request), 0);
    recv(fd, &response, sizeof(response), 0);

    if (response.status == 0 && response.count > 0) {
        clipboard_entry_t *entries = malloc(sizeof(clipboard_entry_t) * response.count);
        recv(fd, entries, sizeof(clipboard_entry_t) * response.count, 0);

        printf("All clipboard histories (%u entries):\n", response.count);
        printf("================================\n");

        for (uint32_t i = 0; i < response.count; i++) {
            struct passwd *pw = getpwuid(entries[i].uid);
            printf("\nEntry #%lu\n", entries[i].id);
            printf("User: %s (UID: %d)\n", pw ? pw->pw_name : "unknown", entries[i].uid);
            printf("PID: %d\n", entries[i].pid);
            printf("Time: %s", ctime(&entries[i].timestamp));
            printf("Data length: %zu bytes\n", entries[i].data_len);

            if (entries[i].data_len > 0) {
                unsigned char *plaintext = malloc(entries[i].data_len + 1);
                if (plaintext) {
                    int decrypted_len = aes_gcm_decrypt_admin(
                        (unsigned char *)entries[i].encrypted_data,
                        entries[i].data_len,
                        plaintext,
                        entries[i].iv,
                        entries[i].tag
                    );
                    if (decrypted_len > 0) {
                        printf("Content: %s\n", plaintext);
                    } else {
                        printf("Content: [decryption failed]\n");
                    }
                    free(plaintext);
                }
            }
        }

        free(entries);
    }

    return response.status;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <command> [options]\n", argv[0]);
        printf("Commands:\n");
        printf("  store         - Store current clipboard\n");
        printf("  history       - View your clipboard history\n");
        printf("  admin-view    - View all histories with decryption (root only)\n");
        return 1;
    }

    int fd = connect_to_daemon();
    if (fd == -1) {
        fprintf(stderr, "Failed to connect to daemon\n");
        return 1;
    }

    if (strcmp(argv[1], "store") == 0) {
        size_t len;
        char *data = get_clipboard_content(&len);
        if (data) {
            if (store_clipboard(fd, data, len) == 0) {
                printf("Clipboard stored successfully\n");
            } else {
                printf("Failed to store clipboard\n");
            }
            free(data);
        }
    } else if (strcmp(argv[1], "history") == 0) {
        view_history(fd);
    } else if (strcmp(argv[1], "admin-view") == 0) {
        admin_view_all(fd);
    } else {
        printf("Unknown command\n");
    }

    close(fd);
    return 0;
}
