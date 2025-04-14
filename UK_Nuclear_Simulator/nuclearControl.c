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
#include <errno.h>

#define PORT_SILO 8081
#define PORT_SUB 8082
#define PORT_RADAR 8083
#define PORT_SAT 8084
#define MAX_CLIENTS 4
#define LOG_FILE "nuclearControl.log"
#define CAESAR_SHIFT 3
#define SIMULATION_DURATION 120
#define BUFFER_SIZE 1024
#define LOG_MSG_SIZE 2048

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
    volatile int running;
} Client;

void init_log_file(void) {
    FILE *fp = fopen(LOG_FILE, "w");
    if (fp) {
        time_t now = time(NULL);
        fprintf(fp, "===== Nuclear Control Log =====\n");
        fprintf(fp, "Simulation Start: %s", ctime(&now));
        fprintf(fp, "=============================\n\n");
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
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Memory allocation failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        return 0;
    }

    memset(intel, 0, sizeof(Intel));
    int valid = 1;
    char *saveptr = NULL;
    char *token = strtok_r(copy, "|", &saveptr);
    while (token && valid) {
        char *key = strtok_r(token, ":", &saveptr);
        char *value = strtok_r(NULL, ":", &saveptr);
        if (!key || !value) {
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), "Invalid key-value pair: %s", token);
            log_event("WARNING", log_msg);
            valid = 0;
            break;
        }

        // Trim whitespace from value
        while (isspace((unsigned char)*value)) value++;
        size_t len = strlen(value);
        while (len > 0 && isspace((unsigned char)value[len - 1])) value[--len] = '\0';

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
                char log_msg[256];
                snprintf(log_msg, sizeof(log_msg), "Invalid threat_level: %s", value);
                log_event("WARNING", log_msg);
                intel->threat_level = 0.0; // Default to 0
            }
        } else if (strcmp(key, "location") == 0) {
            strncpy(intel->location, value, sizeof(intel->location) - 1);
        } else {
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), "Unknown key: %s", key);
            log_event("WARNING", log_msg);
        }
        token = strtok_r(NULL, "|", &saveptr);
    }

    // Validate required fields
    if (!intel->source[0] || !intel->type[0]) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Missing required fields: source=%s, type=%s",
                 intel->source, intel->type);
        log_event("ERROR", log_msg);
        valid = 0;
    }

    free(copy);
    return valid;
}

void forward_threat(Client *clients, size_t client_count, const Intel *intel) {
    if (intel->threat_level <= 0.7) return;

    char command[512];
    char ciphertext[BUFFER_SIZE];
    char log_msg[LOG_MSG_SIZE];
    snprintf(command, sizeof(command),
             "source:%s|type:%s|data:%s|threat_level:%.2f|location:%s",
             intel->source, intel->type, intel->data, intel->threat_level, intel->location);
    caesar_encrypt(command, ciphertext, sizeof(ciphertext));

    snprintf(log_msg, sizeof(log_msg), "Forwarding threat: [Decrypted] %.500s -> [Encrypted] %.500s",
             command, ciphertext);
    log_event("THREAT", log_msg);

    for (size_t i = 0; i < client_count; i++) {
        if (clients[i].port == PORT_SILO || clients[i].port == PORT_SUB) {
            if (send(clients[i].sock, ciphertext, strlen(ciphertext), 0) < 0) {
                snprintf(log_msg, sizeof(log_msg), "Failed to forward threat to %s:%d: %s",
                         clients[i].ip, clients[i].port, strerror(errno));
                log_event("ERROR", log_msg);
            } else {
                snprintf(log_msg, sizeof(log_msg), "Threat forwarded to %s:%d",
                         clients[i].ip, clients[i].port);
                log_event("THREAT", log_msg);
            }
        }
    }
}

void *handle_client(void *arg) {
    Client *client = (Client *)arg;
    char buffer[BUFFER_SIZE];
    char plaintext[BUFFER_SIZE];
    Intel intel;
    char log_msg[LOG_MSG_SIZE];
    static Client *clients[MAX_CLIENTS];
    static size_t client_count = 0;
    static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&clients_mutex);
    if (client_count < MAX_CLIENTS) {
        clients[client_count++] = client;
    }
    pthread_mutex_unlock(&clients_mutex);

    snprintf(log_msg, sizeof(log_msg), "Connection established with %s:%d", client->ip, client->port);
    log_event("CONNECTION", log_msg);

    time_t start_time = time(NULL);
    client->running = 1;
    while (client->running && time(NULL) - start_time < SIMULATION_DURATION) {
        ssize_t bytes = recv(client->sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            snprintf(log_msg, sizeof(log_msg), "Disconnected from %s:%d: %s",
                     client->ip, client->port, bytes == 0 ? "Client closed connection" : strerror(errno));
            log_event("CONNECTION", log_msg);
            break;
        }
        buffer[bytes] = '\0';

        caesar_decrypt(buffer, plaintext, sizeof(plaintext));
        snprintf(log_msg, sizeof(log_msg), "Received from %s:%d: [Encrypted] %.1000s -> [Decrypted] %.1000s",
                 client->ip, client->port, buffer, plaintext);
        log_event("MESSAGE", log_msg);

        if (parse_intel(plaintext, &intel)) {
            snprintf(log_msg, sizeof(log_msg),
                     "Intelligence: Source=%s, Type=%s, Details=%s, ThreatLevel=%.2f, Location=%s",
                     intel.source, intel.type, intel.data, intel.threat_level, intel.location);
            log_event("THREAT", log_msg);

            pthread_mutex_lock(&clients_mutex);
            forward_threat(clients, client_count, &intel);
            pthread_mutex_unlock(&clients_mutex);
        } else {
            snprintf(log_msg, sizeof(log_msg), "Parsing failed for message: %.1000s", plaintext);
            log_event("ERROR", log_msg);
        }
    }

    snprintf(log_msg, sizeof(log_msg), "Client %s:%d terminated", client->ip, client->port);
    log_event("SHUTDOWN", log_msg);
    close(client->sock);

    pthread_mutex_lock(&clients_mutex);
    for (size_t i = 0; i < client_count; i++) {
        if (clients[i] == client) {
            clients[i] = clients[--client_count];
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    free(client);
    return NULL;
}

void simulate_war_test(Client *clients, size_t client_count) {
    const char *const threat_types[] = {"Air", "Sea"};
    const char *const threat_data[] = {"Enemy Aircraft", "Ballistic Missile", "Enemy Submarine", "Naval Fleet"};
    const char *const locations[] = {"North Atlantic", "Norwegian Sea", "English Channel", "Arctic Ocean"};
    Intel intel;
    char log_msg[LOG_MSG_SIZE];

    strncpy(intel.source, "TEST", sizeof(intel.source) - 1);
    int idx = rand() % 4;
    strncpy(intel.type, threat_types[idx % 2], sizeof(intel.type) - 1);
    strncpy(intel.data, threat_data[idx], sizeof(intel.data) - 1);
    intel.threat_level = 0.1 + (rand() % 90) / 100.0;
    strncpy(intel.location, locations[rand() % 4], sizeof(intel.location) - 1);

    snprintf(log_msg, sizeof(log_msg),
             "Test Scenario: Source=%s, Type=%s, Details=%s, ThreatLevel=%.2f, Location=%s",
             intel.source, intel.type, intel.data, intel.threat_level, intel.location);
    log_event("WAR_TEST", log_msg);

    forward_threat(clients, client_count, &intel);
}

int start_server(int port) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Socket creation failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        return -1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    const int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Failed to set socket options: %s", strerror(errno));
        log_event("ERROR", log_msg);
        close(server_sock);
        return -1;
    }

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Socket bind failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        close(server_sock);
        return -1;
    }

    if (listen(server_sock, 5) < 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Socket listen failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
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

    init_log_file();
    log_event("STARTUP", "Nuclear Control System initializing");

    const int ports[] = {PORT_SILO, PORT_SUB, PORT_RADAR, PORT_SAT};
    int server_socks[MAX_CLIENTS];
    pthread_t threads[MAX_CLIENTS];
    Client *clients[MAX_CLIENTS];
    size_t client_count = 0;
    time_t start_time = time(NULL);

    for (int i = 0; i < MAX_CLIENTS; i++) {
        server_socks[i] = start_server(ports[i]);
        if (server_socks[i] < 0) {
            for (int j = 0; j < i; j++) close(server_socks[j]);
            log_event("SHUTDOWN", "Initialization failed");
            return 1;
        }
    }

    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_socks[i], (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), "Failed to accept client: %s", strerror(errno));
            log_event("ERROR", log_msg);
            continue;
        }

        clients[client_count] = malloc(sizeof(Client));
        if (!clients[client_count]) {
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), "Memory allocation failed: %s", strerror(errno));
            log_event("ERROR", log_msg);
            close(client_sock);
            continue;
        }
        clients[client_count]->sock = client_sock;
        clients[client_count]->port = ports[i];
        clients[client_count]->running = 0;
        inet_ntop(AF_INET, &client_addr.sin_addr, clients[client_count]->ip, INET_ADDRSTRLEN);

        if (pthread_create(&threads[client_count], NULL, handle_client, clients[client_count]) != 0) {
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), "Failed to create client thread: %s", strerror(errno));
            log_event("ERROR", log_msg);
            close(client_sock);
            free(clients[client_count]);
            continue;
        }
        client_count++;
    }

    if (test_mode) {
        sleep(2); // Allow clients to connect
        simulate_war_test(clients, client_count);
    }

    while (time(NULL) - start_time < SIMULATION_DURATION) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Simulation active: %ld seconds remaining",
                 SIMULATION_DURATION - (time(NULL) - start_time));
        log_event("STATUS", log_msg);
        sleep(10);
    }

    for (size_t i = 0; i < client_count; i++) {
        clients[i]->running = 0;
    }
    for (size_t i = 0; i < client_count; i++) {
        pthread_join(threads[i], NULL);
    }
    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        close(server_socks[i]);
    }

    log_event("SHUTDOWN", "Nuclear Control System terminated");
    return 0;
}

