#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8081
#define LOG_FILE "missile_silo.log"
#define CAESAR_SHIFT 3
#define SIMULATION_DURATION 120

void init_log_file() {
    FILE *fp = fopen(LOG_FILE, "w");
    if (fp) {
        fprintf(fp, "===== Missile Silo Log =====\n");
        fprintf(fp, "Simulation Start: %s", ctime(time(NULL)));
        fprintf(fp, "==========================\n\n");
        fclose(fp);
    }
}

void log_event(const char *event_type, const char *details) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) {
        perror("Failed to open log file");
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
        log_event("ERROR", "Memory allocation failed during parsing");
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
            log_event("ERROR", "Invalid command format");
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
    free(copy);
    if (!valid || !command[0]) {
        log_event("ERROR", "Incomplete command data");
        return 0;
    }
    return 1;
}

int main(void) {
    srand((unsigned int)time(NULL));
    init_log_file();
    log_event("STARTUP", "Missile Silo System initializing");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_event("ERROR", "Failed to create socket");
        return 1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        log_event("ERROR", "Invalid server address");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_event("ERROR", "Failed to connect to Nuclear Control");
        close(sock);
        return 1;
    }

    log_event("CONNECTION", "Connected to Nuclear Control");

    char buffer[1024];
    char plaintext[1024];
    char command[20];
    char target[50];
    char log_msg[2048];
    time_t start_time = time(NULL);

    while (time(NULL) - start_time < SIMULATION_DURATION) {
        ssize_t bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            log_event("CONNECTION", "Disconnected from Nuclear Control");
            break;
        }
        buffer[bytes] = '\0';

        caesar_decrypt(buffer, plaintext, sizeof(plaintext));
        snprintf(log_msg, sizeof(log_msg), "Received: [Encrypted] %s -> [Decrypted] %s", 
                 buffer, plaintext);
        log_event("MESSAGE", log_msg);

        if (parse_command(plaintext, command, target)) {
            if (strcmp(command, "launch") == 0) {
                snprintf(log_msg, sizeof(log_msg), "Command: Launch, Target=%s", target);
                log_event("COMMAND", log_msg);
            } else {
                snprintf(log_msg, sizeof(log_msg), "Unknown command: %s", command);
                log_event("ERROR", log_msg);
            }
        }
        usleep(500000); // 0.5s delay to prevent busy-waiting
    }

    close(sock);
    log_event("SHUTDOWN", "Missile Silo System terminated");
    return 0;
}

