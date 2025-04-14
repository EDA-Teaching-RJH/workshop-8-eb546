#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>

#define PORT_SILO 8081
#define PORT_SUB 8082
#define PORT_RADAR 8083
#define PORT_SAT 8084
#define MAX_CLIENTS 4
#define LOG_FILE "nuclearControl.log"
#define CAESAR_SHIFT 3
#define SIMULATION_DURATION 30

typedef struct {
    char source[20];
    char type[20];
    char data[256];
    double threat_level;
    char location[50];
} Intel;

typedef struct {
    int sock;
    char ip[INET_ADDRSTRLEN];
    int port;
} Client;

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
        fprintf(fp, "[%s] %-12s %s\n", time_str, event_type, details);
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

int parse_intel(const char *message, Intel *intel) {
    char *copy = strdup(message);
    if (!copy) {
        log_event("ERROR", "Memory allocation failed for parsing");
        return 0;
    }

    memset(intel, 0, sizeof(Intel));
    char *token = strtok(copy, "|");
    int has_source = 0, has_type = 0;
    while (token) {
        char *key = strtok(token, ":");
        char *value = strtok(NULL, ":");
        if (!key || !value) {
            log_event("ERROR", "Malformed key-value pair");
            free(copy);
            return 0;
        }
        if (strcmp(key, "source") == 0) {
            strncpy(intel->source, value, sizeof(intel->source) - 1);
            has_source = 1;
        } else if (strcmp(key, "type") == 0) {
            strncpy(intel->type, value, sizeof(intel->type) - 1);
            has_type = 1;
        } else if (strcmp(key, "data") == 0) {
            strncpy(intel->data, value, sizeof(intel->data) - 1);
        } else if (strcmp(key, "threat_level") == 0) {
            char *endptr;
            intel->threat_level = strtod(value, &endptr);
            if (*endptr != '\0') {
                log_event("ERROR", "Invalid threat_level format");
                free(copy);
                return 0;
            }
        } else if (strcmp(key, "location") == 0) {
            strncpy(intel->location, value, sizeof(intel->location) - 1);
        }
        token = strtok(NULL, "|");
    }
    free(copy);
    if (!has_source || !has_type) {
        log_event("ERROR", "Missing source or type in intelligence");
        return 0;
    }
    return 1;
}

void *handle_client(void *arg) {
    Client *client = (Client *)arg;
    int client_sock = client->sock;
    char buffer[1024];
    char plaintext[1024];
    Intel intel;
    char log_msg[2048];

    snprintf(log_msg, sizeof(log_msg), "Client connected from %s:%d", 
             client->ip, client->port);
    log_event("CONNECTION", log_msg);

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < SIMULATION_DURATION) {
        ssize_t bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            snprintf(log_msg, sizeof(log_msg), "Client %s:%d disconnected", 
                     client->ip, client->port);
            log_event("CONNECTION", log_msg);
            break;
        }
        buffer[bytes] = '\0';

        snprintf(log_msg, sizeof(log_msg), "Encrypted message: %.1000s", buffer);
        log_event("MESSAGE", log_msg);

        caesar_decrypt(buffer, plaintext, sizeof(plaintext));
        snprintf(log_msg, sizeof(log_msg), "Decrypted message: %.1000s", plaintext);
        log_event("MESSAGE", log_msg);

        if (parse_intel(plaintext, &intel)) {
            snprintf(log_msg, sizeof(log_msg), 
                     "Source: %s, Type: %s, Details: %s, Threat Level: %.2f, Location: %s",
                     intel.source, intel.type, intel.data, intel.threat_level, intel.location);
            log_event("THREAT", log_msg);
        }
    }

    snprintf(log_msg, sizeof(log_msg), "Client %s:%d terminated after 30s simulation", 
             client->ip, client->port);
    log_event("SHUTDOWN", log_msg);
    close(client_sock);
    free(client);
    return NULL;
}

void simulate_war_test(Client *clients, size_t client_count) {
    const char *threat_types[] = {"Air", "Sea"};
    const char *threat_data[] = {"Enemy Aircraft", "Ballistic Missile", "Enemy Submarine", "Naval Fleet"};
    const char *locations[] = {"North Atlantic", "Norwegian Sea", "English Channel", "Arctic Ocean"};
    Intel intel;

    snprintf(intel.source, sizeof(intel.source), "TEST");
    int idx = rand() % 4;
    snprintf(intel.type, sizeof(intel.type), "%s", threat_types[idx % 2]);
    snprintf(intel.data, sizeof(intel.data), "%s", threat_data[idx]);
    intel.threat_level = 0.1 + (rand() % 90) / 100.0;
    snprintf(intel.location, sizeof(intel.location), "%s", locations[rand() % 4]);

    char log_msg[1024];
    snprintf(log_msg, sizeof(log_msg), 
             "Source: %s, Type: %s, Details: %s, Threat Level: %.2f, Location: %s",
             intel.source, intel.type, intel.data, intel.threat_level, intel.location);
    log_event("WAR_TEST", log_msg);

    if (intel.threat_level > 0.7) {
        char command[256];
        snprintf(command, sizeof(command), "command:launch|target:%s", intel.location);
        char ciphertext[512];
        caesar_encrypt(command, ciphertext, sizeof(ciphertext));
        snprintf(log_msg, sizeof(log_msg), "Encrypted command: %.500s", ciphertext);
        log_event("COMMAND", log_msg);
        snprintf(log_msg, sizeof(log_msg), "Decrypted command: %s", command);
        log_event("COMMAND", log_msg);

        for (size_t i = 0; i < client_count; i++) {
            if (clients[i].port == PORT_SILO || clients[i].port == PORT_SUB) {
                if (send(clients[i].sock, ciphertext, strlen(ciphertext), 0) < 0) {
                    snprintf(log_msg, sizeof(log_msg), 
                             "Failed to send command to %s:%d", 
                             clients[i].ip, clients[i].port);
                    log_event("ERROR", log_msg);
                } else {
                    snprintf(log_msg, sizeof(log_msg), 
                             "Sent command to %s:%d", 
                             clients[i].ip, clients[i].port);
                    log_event("COMMAND", log_msg);
                }
            }
        }
    }
}

int start_server(int port) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        close(server_sock);
        return -1;
    }

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        return -1;
    }

    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        close(server_sock);
        return -1;
    }

    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Server started on port %d", port);
    log_event("STARTUP", log_msg);
    return server_sock;
}

int main(int argc, char *argv[]) {
    int test_mode = 0;
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        test_mode = 1;
        srand((unsigned int)time(NULL));
    }

    int ports[] = {PORT_SILO, PORT_SUB, PORT_RADAR, PORT_SAT};
    int server_socks[MAX_CLIENTS];
    pthread_t threads[MAX_CLIENTS];
    Client clients[MAX_CLIENTS];
    size_t client_count = 0;
    time_t start_time = time(NULL);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        server_socks[i] = start_server(ports[i]);
        if (server_socks[i] < 0) {
            for (int j = 0; j < i; j++) {
                close(server_socks[j]);
            }
            return 1;
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_socks[i], (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }

        Client *client = malloc(sizeof(Client));
        if (!client) {
            perror("Client allocation failed");
            close(client_sock);
            continue;
        }
        client->sock = client_sock;
        client->port = ports[i];
        inet_ntop(AF_INET, &client_addr.sin_addr, client->ip, sizeof(client->ip));

        clients[client_count] = *client;
        if (pthread_create(&threads[client_count], NULL, handle_client, client) != 0) {
            perror("Thread creation failed");
            close(client_sock);
            free(client);
            continue;
        }
        client_count++;
    }

    if (test_mode) {
        simulate_war_test(clients, client_count);
    }

    while (time(NULL) - start_time < SIMULATION_DURATION) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Simulation running: %ld seconds remaining",
                 SIMULATION_DURATION - (time(NULL) - start_time));
        log_event("SIMULATION", log_msg);
        sleep(5);
    }

    for (size_t i = 0; i < client_count; i++) {
        pthread_cancel(threads[i]);
    }
    for (size_t i = 0; i < client_count; i++) {
        pthread_join(threads[i], NULL);
        close(clients[i].sock);
    }
    for (int i = 0; i < MAX_CLIENTS; i++) {
        close(server_socks[i]);
    }

    log_event("SHUTDOWN", "Nuclear Control terminated after 30s simulation");
    return 0;
}

