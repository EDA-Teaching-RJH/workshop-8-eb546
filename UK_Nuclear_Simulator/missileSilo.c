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
#define SERVER_PORT 8081
#define LOG_FILE "missileSilo.log"
#define CAESAR_SHIFT 3
#define SIMULATION_DURATION 60
#define BUFFER_SIZE 1024
#define LOG_MSG_SIZE 2048

typedef struct {
    char source[20];
    char type[20];
    char data[256];
    double threat_level;
    char location[50];
} Intel;

void init_log_file(void) {
    FILE *fp = fopen(LOG_FILE, "w");
    if (fp) {
        time_t now = time(NULL);
        fprintf(fp, "===== Missile Silo Log =====\n");
        fprintf(fp, "Simulation Start: %s", ctime(&now));
        fprintf(fp, "==========================\n\n");
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

int parse_intel(const char *message, Intel *intel) {
    char *copy = strdup(message);
    if (!copy) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Memory allocation failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        return 0;
    }

    memset(intel, 0, sizeof(Intel));
    int valid = 1;
    char *token = strtok(copy, "|");
    while (token && valid) {
        char *key = strtok(token, ":");
        char *value = strtok(NULL, ":");
        if (!key || !value) {
            log_event("ERROR", "Invalid key-value pair in message");
            valid = 0;
            break;
        }
        if (strcmp(key, "source") == 0) {
            strncpy(intel->source, value, sizeof(intel->source) - 1);
        } else if (strcmp(key, "type") == 0) {
            strncpy(intel->type, value, sizeof(intel->type) - 1);
        } else if (strcmp(key, "data") == 0) {
            strncpy(intel->data, value, sizeof(intel->data) - 1);
        } else if (strcmp(key, "threat_level") == 0) {
            char *endptr;
            intel->threat_level = strtod(value, &endptr);
            if (*endptr != '\0' || intel->threat_level < 0) {
                log_event("ERROR", "Invalid threat_level format");
                valid = 0;
            }
        } else if (strcmp(key, "location") == 0) {
            strncpy(intel->location, value, sizeof(intel->location) - 1);
        }
        token = strtok(NULL, "|");
    }
    if (!valid || !intel->source[0] || !intel->type[0]) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Incomplete data: source=%s, type=%s",
                 intel->source, intel->type);
        log_event("ERROR", log_msg);
        valid = 0;
    }
    free(copy);
    return valid;
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
    if (!valid || !command[0]) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Incomplete command data: command=%s", command);
        log_event("ERROR", log_msg);
        valid = 0;
    }
    free(copy);
    return valid;
}

void process_threat(const Intel *intel) {
    char log_msg[LOG_MSG_SIZE];
    snprintf(log_msg, sizeof(log_msg),
             "Received Threat: Source=%s, Type=%s, Details=%s, ThreatLevel=%.2f, Location=%s",
             intel->source, intel->type, intel->data, intel->threat_level, intel->location);
    log_event("THREAT", log_msg);

    if (intel->threat_level > 0.7) {
        snprintf(log_msg, sizeof(log_msg), "Launching missile against threat at %s", intel->location);
        log_event("COMMAND", log_msg);
    } else {
        snprintf(log_msg, sizeof(log_msg), "Threat level %.2f below threshold (0.7); no launch", intel->threat_level);
        log_event("THREAT", log_msg);
    }
}

int main(void) {
    srand((unsigned int)time(NULL));
    init_log_file();
    log_event("STARTUP", "Missile Silo System initializing");

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
    Intel intel;
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
                snprintf(log_msg, sizeof(log_msg), "Command: Launch, Target=%s", target);
                log_event("COMMAND", log_msg);
            } else {
                snprintf(log_msg, sizeof(log_msg), "Unknown command: %s", command);
                log_event("ERROR", log_msg);
            }
        } else if (parse_intel(plaintext, &intel)) {
            process_threat(&intel);
        } else {
            snprintf(log_msg, sizeof(log_msg), "Invalid message format: %.1000s", plaintext);
            log_event("ERROR", log_msg);
        }
        usleep(500000); // 0.5s polling
    }

    close(sock);
    log_event("SHUTDOWN", "Missile Silo System terminated");
    return 0;
}