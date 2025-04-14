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
#include <stdatomic.h>
#include <stdbool.h>

#define PORT_SILO 8081
#define PORT_SUB 8082
#define PORT_RADAR 8083
#define PORT_SAT 8084
#define MAX_CLIENTS 4
#define LOG_FILE "nuclearControl.log"
#define CAESAR_SHIFT 3
#define SIMULATION_DURATION 60
#define BUFFER_SIZE 1024

typedef struct {
    char source[20];
    char type[20];
    char data[256];
    int threat_level;
    char location[50];
} Intel;

typedef struct {
    int sock;
    char ip[INET_ADDRSTRLEN];
    int port;
    bool valid;
} Client;

static Client clients[MAX_CLIENTS];
static atomic_int client_count = 0;
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile atomic_bool running = ATOMIC_VAR_INIT(true);

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
        fprintf(fp, "[%s] %-12s %s\n", time_str, event_type, details);
    }
    fclose(fp);
}

void caesar_encrypt(const char *plaintext, char *ciphertext, size_t len) {
    memset(ciphertext, 0, len);
    for (size_t i = 0; plaintext[i] && i < len - 1; i++) {
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
    for (size_t i = 0; ciphertext[i] && i < len - 1; i++) {
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
    int fields_found = 0;
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

        if (strcmp(key, "source") == 0) {
            strncpy(intel->source, value, sizeof(intel->source) - 1);
            fields_found++;
        } else if (strcmp(key, "type") == 0) {
            strncpy(intel->type, value, sizeof(intel->type) - 1);
            fields_found++;
        } else if (strcmp(key, "data") == 0) {
            strncpy(intel->data, value, sizeof(intel->data) - 1);
            fields_found++;
        } else if (strcmp(key, "threat_level") == 0) {
            char *endptr;
            intel->threat_level = (int)strtol(value, &endptr, 10);
            if (*endptr != '\0' || intel->threat_level < 0) {
                free(copy);
                return 0;
            }
            fields_found++;
        } else if (strcmp(key, "location") == 0) {
            strncpy(intel->location, value, sizeof(intel->location) - 1);
            fields_found++;
        }
        token = strtok(NULL, "|");
    }
    free(copy);
    return fields_found == 5;
}

void send_command_to_clients(const char *location) {
    char command[256];
    char ciphertext[BUFFER_SIZE];
    char log_msg[BUFFER_SIZE];
    snprintf(command, sizeof(command), "command:launch|target:%s", location);
    caesar_encrypt(command, ciphertext, sizeof(ciphertext));

    snprintf(log_msg, sizeof(log_msg), "Encrypted command: %s", ciphertext);
    log_event("COMMAND", log_msg);
    snprintf(log_msg, sizeof(log_msg), "Decrypted command: %s", command);
    log_event("COMMAND", log_msg);

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].valid && (clients[i].port == PORT_SILO || clients[i].port == PORT_SUB)) {
            if (send(clients[i].sock, ciphertext, strlen(ciphertext), 0) < 0) {
                snprintf(log_msg, sizeof(log_msg), "Failed to send command to %s:%d", 
                         clients[i].ip, clients[i].port);
                log_event("ERROR", log_msg);
            } else {
                snprintf(log_msg, sizeof(log_msg), "Sent command to %s:%d", 
                         clients[i].ip, clients[i].port);
                log_event("COMMAND", log_msg);
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

void *handle_client(void *arg) {
    Client *client = (Client *)arg;
    int client_sock = client->sock;
    char buffer[BUFFER_SIZE];
    char plaintext[BUFFER_SIZE];
    Intel intel;
    char log_msg[BUFFER_SIZE];

    snprintf(log_msg, sizeof(log_msg), "Client connected from %s:%d", 
             client->ip, client->port);
    log_event("CONNECTION", log_msg);

    while (atomic_load(&running)) {
        ssize_t bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            snprintf(log_msg, sizeof(log_msg), "Client %s:%d disconnected", 
                     client->ip, client->port);
            log_event("CONNECTION", log_msg);
            break;
        }
        buffer[bytes] = '\0';

        snprintf(log_msg, sizeof(log_msg), "Encrypted message: %s", buffer);
        log_event("MESSAGE", log_msg);

        caesar_decrypt(buffer, plaintext, sizeof(plaintext));
        snprintf(log_msg, sizeof(log_msg), "Decrypted message: %s", plaintext);
        log_event("MESSAGE", log_msg);

        if (parse_intel(plaintext, &intel)) {
            snprintf(log_msg, sizeof(log_msg), 
                     "Source: %s, Type: %s, Details: %s, Threat Level: %d, Location: %s",
                     intel.source, intel.type, intel.data, intel.threat_level, intel.location);
            log_event("THREAT", log_msg);

            if (intel.threat_level > 70 && 
                (strcmp(intel.source, "Radar") == 0 || strcmp(intel.source, "Satellite") == 0)) {
                send_command_to_clients(intel.location);
            }
        } else {
            snprintf(log_msg, sizeof(log_msg), "Invalid message: %s", plaintext);
            log_event("ERROR", log_msg);
        }
    }

    close(client_sock);
    pthread_mutex_lock(&clients_mutex);
    client->valid = false;
    pthread_mutex_unlock(&clients_mutex);
    free(client);
    return NULL;
}

void simulate_war_test(void) {
    const char *threat_types[] = {"Air", "Sea"};
    const char *threat_data[] = {"Enemy Aircraft", "Ballistic Missile", "Enemy Submarine", "Naval Fleet"};
    const char *locations[] = {"North Atlantic", "Norwegian Sea", "English Channel", "Arctic Ocean"};
    Intel intel;

    snprintf(intel.source, sizeof(intel.source), "TEST");
    int idx = rand() % 4;
    snprintf(intel.type, sizeof(intel.type), "%s", threat_types[idx % 2]);
    snprintf(intel.data, sizeof(intel.data), "%s", threat_data[idx]);
    intel.threat_level = 91;
    snprintf(intel.location, sizeof(intel.location), "%s", locations[rand() % 4]);

    char log_msg[BUFFER_SIZE];
    snprintf(log_msg, sizeof(log_msg), 
             "Source: %s, Type: %s, Details: %s, Threat Level: %d, Location: %s",
             intel.source, intel.type, intel.data, intel.threat_level, intel.location);
    log_event("WAR_TEST", log_msg);

    if (intel.threat_level > 70) {
        send_command_to_clients(intel.location);
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

    FILE *fp = fopen(LOG_FILE, "w");
    if (!fp) {
        perror("Failed to create log file");
        return 1;
    }
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(fp, "===== Nuclear Control Log =====\n");
        fprintf(fp, "Simulation Start: %s\n", time_str);
        fprintf(fp, "=============================\n\n");
    }
    fclose(fp);

    int ports[] = {PORT_SILO, PORT_SUB, PORT_RADAR, PORT_SAT};
    int server_socks[MAX_CLIENTS] = {-1, -1, -1, -1};
    pthread_t threads[MAX_CLIENTS] = {0};
    int clients_added = 0;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        server_socks[i] = start_server(ports[i]);
        if (server_socks[i] < 0) {
            for (int j = 0; j < i; j++) {
                if (server_socks[j] != -1) {
                    close(server_socks[j]);
                }
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
        client->valid = true;
        inet_ntop(AF_INET, &client_addr.sin_addr, client->ip, sizeof(client->ip));

        pthread_mutex_lock(&clients_mutex);
        if (clients_added < MAX_CLIENTS) {
            clients[clients_added] = *client;
            atomic_fetch_add(&client_count, 1);
            clients_added++;
        } else {
            free(client);
            close(client_sock);
            pthread_mutex_unlock(&clients_mutex);
            continue;
        }
        pthread_mutex_unlock(&clients_mutex);

        if (pthread_create(&threads[i], NULL, handle_client, client) != 0) {
            perror("Thread creation failed");
            pthread_mutex_lock(&clients_mutex);
            clients[clients_added - 1].valid = false;
            atomic_fetch_sub(&client_count, 1);
            clients_added--;
            pthread_mutex_unlock(&clients_mutex);
            close(client_sock);
            free(client);
            continue;
        }
    }

    if (test_mode) {
        simulate_war_test();
    }

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < SIMULATION_DURATION) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Simulation running: %ld seconds remaining",
                 SIMULATION_DURATION - (time(NULL) - start_time));
        log_event("SIMULATION", log_msg);
        sleep(5);
    }

    atomic_store(&running, false);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server_socks[i] != -1) {
            shutdown(server_socks[i], SHUT_RDWR);
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (threads[i]) {
            pthread_join(threads[i], NULL);
        }
    }

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].valid) {
            close(clients[i].sock);
            clients[i].valid = false;
        }
    }
    atomic_store(&client_count, 0);
    pthread_mutex_unlock(&clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server_socks[i] != -1) {
            close(server_socks[i]);
        }
    }

    log_event("SHUTDOWN", "Nuclear Control terminated after 60s simulation");
    return 0;
}

