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
#define SUMMARY_FILE "missileSilo_summary.txt"

static FILE *log_fp = NULL;
static int missiles_launched = 0;

void init_log_file(void) {
    log_fp = fopen(LOG_FILE, "w");
    if (!log_fp) {
        fprintf(stderr, "Failed to create log file: %s\n", strerror(errno));
        exit(1);
    }
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(log_fp, "===== Missile Silo Log =====\n");
        fprintf(log_fp, "Simulation Start: %s\n", time_str);
        fprintf(log_fp, "==========================\n\n");
        fflush(log_fp);
    }
}

void log_event(const char *event_type, const char *details) {
    if (!log_fp) return;
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(log_fp, "[%s] %-10s %s\n", time_str, event_type, details);
        fflush(log_fp);
    }
}

void caesar_decrypt(const char *ciphertext, char *plaintext, size_t len) {
    memset(plaintext, 0, len);
    for (size_t i = 0; ciphertext[i] && i < len - 1; i++) {
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
    char *token = strtok(copy, "|");
    while (token) {
        char *colon = strchr(token, ':');
        if (!colon || colon == token || !colon[1]) {
            free(copy);
            return 0;
        }
        *colon = '\0';
        char *key = token;
        char *value = colon + 1;
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
    return (command[0] != '\0' && target[0] != '\0');
}

void generate_summary(void) {
    FILE *summary_fp = fopen(SUMMARY_FILE, "w");
    if (!summary_fp) {
        log_event("ERROR", "Failed to create summary file");
        return;
    }

    fprintf(summary_fp, "===== Missile Silo Simulation Summary =====\n");
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(summary_fp, "Simulation End: %s\n", time_str);
    }
    fprintf(summary_fp, "Total Missiles Launched: %d\n", missiles_launched);
    fprintf(summary_fp, "=====================================\n");
    fclose(summary_fp);

    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Summary generated in %s", SUMMARY_FILE);
    log_event("SUMMARY", log_msg);
}

int main(void) {
    init_log_file();
    log_event("STARTUP", "Missile Silo System initializing");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Socket creation failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        if (log_fp) fclose(log_fp);
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
        if (log_fp) fclose(log_fp);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Connection failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        close(sock);
        if (log_fp) fclose(log_fp);
        return 1;
    }

    log_event("CONNECTION", "Connected to Nuclear Control");

    char buffer[BUFFER_SIZE];
    char plaintext[BUFFER_SIZE];
    char command[20];
    char target[50];
    char log_msg[BUFFER_SIZE];
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
        snprintf(log_msg, sizeof(log_msg), "Received: [Encrypted] %s -> [Decrypted] %s",
                 buffer, plaintext);
        log_event("MESSAGE", log_msg);

        if (parse_command(plaintext, command, target)) {
            if (strcmp(command, "launch") == 0) {
                snprintf(log_msg, sizeof(log_msg), "Launching missile at %s", target);
                log_event("COMMAND", log_msg);
                missiles_launched++;
                // Simulate missile launch feedback
                char feedback[256];
                snprintf(feedback, sizeof(feedback), "Missile launched at %s successfully", target);
                log_event("FEEDBACK", feedback);
            } else {
                snprintf(log_msg, sizeof(log_msg), "Unknown command: %s", command);
                log_event("ERROR", log_msg);
            }
        } else {
            snprintf(log_msg, sizeof(log_msg), "Invalid message format: %s", plaintext);
            log_event("ERROR", log_msg);
        }
        usleep(500000);
    }

    shutdown(sock, SHUT_RDWR);
    close(sock);
    generate_summary();
    log_event("SHUTDOWN", "Missile Silo System terminated");
    if (log_fp) fclose(log_fp);
    return 0;
}

