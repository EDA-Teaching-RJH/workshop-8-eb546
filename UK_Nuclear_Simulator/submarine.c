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
#define SERVER_PORT 8082
#define LOG_FILE "submarine.log"
#define CAESAR_SHIFT 3
#define SIMULATION_DURATION 30

void log_event(const char *event_type, const char *details) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (fp == NULL) {
        perror("Log file open failed");
        return;
    }
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(fp, "[%s]  %-12s  %s\n", time_str, event_type, details);
    }
    fclose(fp);
}

void caesar_encrypt(const char *plaintext, char *ciphertext, size_t len) {
    memset(ciphertext, 0, len);
    for (size_t i = 0; i < strlen(plaintext) && i < len - 1; i++) {
        if (isalpha((unsigned char)plaintext[i])) {
            char base = isupper((unsigned char)plaintext[i]) ? 'A' : 'a';
            ciphertext[i] = (char)((plaintext[i] - base + CAESAR_SHIFT) % 26 + base);
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
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
        log_event("ERROR", "Memory allocation failed for parsing");
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
            log_event("ERROR", "Malformed command key-value pair");
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
        log_event("ERROR", "Invalid or incomplete command");
        return 0;
    }
    return 1;
}

void send_intel(int sock) {
    const char *threat_data[] = {"Enemy Submarine", "Torpedo Launch", "Naval Fleet"};
    const char *locations[] = {"Norwegian Sea", "Celtic Sea", "Irish Sea"};
    char message[512];
    int idx = rand() % 3;
    double threat_level = 0.1 + (rand() % 90) / 100.0;
    snprintf(message, sizeof(message),
             "source:Submarine|type:Sea|data:%s|threat_level:%.2f|location:%s",
             threat_data[idx], threat_level, locations[idx]);
    char ciphertext[1024];
    caesar_encrypt(message, ciphertext, sizeof(ciphertext));

    char log_msg[2048];
    snprintf(log_msg, sizeof(log_msg), "Encrypted Message:  %.1000s", ciphertext);
    log_event("MESSAGE", log_msg);
    snprintf(log_msg, sizeof(log_msg), "Original Message:  %.1000s", message);
    log_event("MESSAGE", log_msg);

    if (send(sock, ciphertext, strlen(ciphertext), 0) < 0) {
        log_event("ERROR", "Failed to send intelligence");
        return;
    }
    snprintf(log_msg, sizeof(log_msg), 
             "Intelligence Sent:  Type:  Sea,  Details:  %-15s,  Threat Level:  %.2f,  Location:  %s",
             threat_data[idx], threat_level, locations[idx]);
    log_event("INTEL", log_msg);
}

int main(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
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
        send_intel(sock);

        ssize_t bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            log_event("CONNECTION", "Disconnected from Nuclear Control");
            break;
        }
        buffer[bytes] = '\0';

        snprintf(log_msg, sizeof(log_msg), "Encrypted Message:  %.1000s", buffer);
        log_event("MESSAGE", log_msg);

        caesar_decrypt(buffer, plaintext, sizeof(plaintext));
        snprintf(log_msg, sizeof(log_msg), "Decrypted Message:  %.1000s", plaintext);
        log_event("MESSAGE", log_msg);

        if (parse_command(plaintext, command, target)) {
            if (strcmp(command, "launch") == 0) {
                snprintf(log_msg, sizeof(log_msg), "Launch Command:  Target = %s", target);
                log_event("COMMAND", log_msg);
            } else {
                snprintf(log_msg, sizeof(log_msg), "Unknown Command:  %s", command);
                log_event("ERROR", log_msg);
            }
        }
        sleep(5);
    }

    close(sock);
    log_event("SHUTDOWN", "Submarine terminated after 30 seconds simulation");
    return 0;
}

