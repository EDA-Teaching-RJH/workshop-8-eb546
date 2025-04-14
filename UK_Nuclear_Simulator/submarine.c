#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8082
#define LOG_FILE "submarine.log"
#define CAESAR_SHIFT 3
#define SIMULATION_DURATION 60
#define BUFFER_SIZE 1024
#define LOG_MSG_SIZE 2048

void init_log_file(void) {
    FILE *fp = fopen(LOG_FILE, "w");
    if (fp) {
        time_t now = time(NULL);
        fprintf(fp, "===== Submarine Log =====\n");
        fprintf(fp, "Simulation Start: %s", ctime(&now));
        fprintf(fp, "=======================\n\n");
        fclose(fp);
    } else {
        fprintf(stderr, "Failed to create log file: %s (%s)\n", LOG_FILE, strerror(errno));
    }
}

void log_event(const char *event_type, const char *details) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) {
        fprintf(stderr, "Failed to open log file: %s (%s)\n", LOG_FILE, strerror(errno));
        return;
    }
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(fp, "[%s] %-10s %s\n", time_str, event_type, details);
    }
    fclose(fp);
}

void caesar_decrypt(const char *ciphertext, char *plaintext, size_t len) {
    memset(plaintext, 0, len);
    for (size_t i = 0; i < strlen(ciphertext) && i < len - 1; i++) {
        if (isalpha((unsigned char)ciphertext[i])) {
            char base = isupper((unsigned char)ciphertext[i]) ? 'A' : 'a';
            plaintext[i] = (char)((ciphertext[i] - base - CAESAR_SHIFT + 26) % 26 + base);
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
}

int parse_command(const char *message, char *command, char *target) {
    char *copy = strdup(message);
    if (!copy) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Memory allocation failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        return 0;
    }

    command[0] = '\0';
    target[0] = '\0';
    int valid = 1;
    char *token = strtok(copy, "|");
    while (token && valid) {
        char *key = strtok(token, ":");
        char *value = strtok(NULL, ":");
        if (!key || !value) {
            valid = 0;
            break;
        }
        if (strcmp(key, "command") == 0) {
            strncpy(command, value, 19);
            command[19] = '\0';
        } else if (strcmp(key, "target") == 0) {
            strncpy(target, value, 49);
            target[49] = '\0';
        }
        token = strtok(NULL, "|");
    }
    if (!valid || !command[0]) {
        free(copy);
        return 0;
    }
    free(copy);
    return 1;
}

int main(void) {
    srand((unsigned int)time(NULL));
    init_log_file();
    log_event("STARTUP", "Submarine System initializing");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Socket creation failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        return 1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Invalid server address: %s", SERVER_IP);
        log_event("ERROR", log_msg);
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Connection failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        close(sock);
        return 1;
    }

    log_event("CONNECTION", "Connected to Nuclear Control");

    char buffer[BUFFER_SIZE];
    char plaintext[BUFFER_SIZE];
    char command[20];
    char target[50];
    char log_msg[LOG_MSG_SIZE];
    time_t start_time = time(NULL);

    while (time(NULL) - start_time < SIMULATION_DURATION) {
        ssize_t bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            snprintf(log_msg, sizeof(log_msg), "Disconnected: %s",
                     bytes == 0 ? "Server closed connection" : strerror(errno));
            log_event("CONNECTION", log_msg);
            break;
        }
        buffer[bytes] = '\0';

        caesar_decrypt(buffer, plaintext, sizeof(plaintext));
        snprintf(log_msg, sizeof(log_msg), "Received: [Encrypted] %.1000s -> [Decrypted] %.1000s",
                 buffer, plaintext);
        log_event("MESSAGE", log_msg);

        if (parse_command(plaintext, command, target)) {
            if (strcmp(command, "launch") == 0) {
                snprintf(log_msg, sizeof(log_msg), "Launching missile at %s", target);
                log_event("COMMAND", log_msg);
            } else {
                snprintf(log_msg, sizeof(log_msg), "Unknown command: %s", command);
                log_event("ERROR", log_msg);
            }
        } else {
            snprintf(log_msg, sizeof(log_msg), "Invalid message format: %.1000s", plaintext);
            log_event("ERROR", log_msg);
        }
        usleep(500000); // 0.5s polling
    }

    close(sock);
    log_event("SHUTDOWN", "Submarine System terminated");
    return 0;
}

