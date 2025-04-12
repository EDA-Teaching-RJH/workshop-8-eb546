#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <time.h>

// Constants
#define PORT 8080
#define MAX_CLIENTS 4
#define BUFFER_SIZE 1024
#define KEY "0123456789abcdef0123456789abcdef" // 32-byte AES-256 key
#define LOG_FILE "nuclearControl.log"

// Structure for client info
typedef struct {
    int sockfd;
    char *type;
} Client;

// Global variables
Client clients[MAX_CLIENTS] = {0};
int client_count = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
FILE *log_fp = NULL;

// Encrypt message using AES-256
void encrypt_message(const char *input, char *output, int *out_len) {
    AES_KEY enc_key;
    AES_set_encrypt_key((unsigned char *)KEY, 256, &enc_key);
    int len = strlen(input) + 1;
    int pad_len = (len / 16 + 1) * 16;
    unsigned char *padded = calloc(pad_len, 1);
    strcpy((char *)padded, input);
    for (int i = 0; i < pad_len; i += 16) {
        AES_encrypt(padded + i, (unsigned char *)output + i, &enc_key);
    }
    *out_len = pad_len;
    free(padded);
}

// Log message to file
void log_message(const char *msg) {
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // Remove newline
    fprintf(log_fp, "[%s] %s\n", time_str, msg);
    fflush(log_fp);
}

// Handle client communication
void *handle_client(void *arg) {
    int sockfd = *(int *)arg;
    char buffer[BUFFER_SIZE];
    free(arg);

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int n = read(sockfd, buffer, BUFFER_SIZE - 1);
        if (n <= 0) {
            log_message("Client disconnected");
            break;
        }

        buffer[n] = '\0';
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Received: %s", buffer);
        log_message(log_msg);

        // Process intelligence
        if (strstr(buffer, "THREAT")) {
            char decision[BUFFER_SIZE];
            snprintf(decision, BUFFER_SIZE, "Threat detected: %s", buffer);
            log_message(decision);

            // Random decision to launch (simplified for demo)
            if (rand() % 2) {
                char launch_cmd[] = "LAUNCH:TARGET_LONDON";
                char encrypted[BUFFER_SIZE];
                int enc_len;
                encrypt_message(launch_cmd, encrypted, &enc_len);

                pthread_mutex_lock(&mutex);
                for (int i = 0; i < client_count; i++) {
                    if (strstr(clients[i].type, "silo") || strstr(clients[i].type, "submarine")) {
                        write(clients[i].sockfd, encrypted, enc_len);
                        log_message("Sent encrypted launch command");
                    }
                }
                pthread_mutex_unlock(&mutex);
            }
        }
    }

    // Cleanup
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].sockfd == sockfd) {
            close(clients[i].sockfd);
            free(clients[i].type);
            clients[i] = clients[client_count - 1];
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
}

int main(int argc, char *argv[]) {
    int test_mode = 0;
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        test_mode = 1;
        printf("Running in test mode\n");
    }

    // Initialize logging
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        perror("Failed to open log file");
        exit(1);
    }
    chmod(LOG_FILE, 0600); // Secure permissions

    // Initialize random seed
    srand(time(NULL));

    // Setup server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(1);
    }

    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(1);
    }

    log_message("Server started");

    // Test mode: Simulate threat
    if (test_mode) {
        sleep(5); // Wait for clients to connect
        char threat[] = "THREAT:ENEMY_MISSILE:52.5200,13.4050";
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Test mode: Simulating %s", threat);
        log_message(log_msg);

        pthread_mutex_lock(&mutex);
        for (int i = 0; i < client_count; i++) {
            if (strstr(clients[i].type, "radar") || strstr(clients[i].type, "satelite")) {
                write(clients[i].sockfd, threat, strlen(threat));
            }
        }
        pthread_mutex_unlock(&mutex);
    }

    // Accept clients
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (*client_fd < 0) {
            perror("Accept failed");
            free(client_fd);
            continue;
        }

        // Receive client type
        char buffer[BUFFER_SIZE] = {0};
        read(*client_fd, buffer, BUFFER_SIZE - 1);
        log_message(buffer);

        pthread_mutex_lock(&mutex);
        if (client_count < MAX_CLIENTS) {
            clients[client_count].sockfd = *client_fd;
            clients[client_count].type = strdup(buffer);
            client_count++;
        } else {
            log_message("Max clients reached");
            close(*client_fd);
            free(client_fd);
            pthread_mutex_unlock(&mutex);
            continue;
        }
        pthread_mutex_unlock(&mutex);

        // Start client thread
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, client_fd) != 0) {
            perror("Thread creation failed");
            close(*client_fd);
            free(client_fd);
        }
        pthread_detach(thread);
    }

    // Cleanup
    fclose(log_fp);
    close(server_fd);
    return 0;
}

