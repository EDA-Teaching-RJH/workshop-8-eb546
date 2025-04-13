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
char last_threat[BUFFER_SIZE] = {0};

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

// Decrypt message using AES-256
void decrypt_message(const char *input, int in_len, char *output) {
    AES_KEY dec_key;
    AES_set_decrypt_key((unsigned char *)KEY, 256, &dec_key);
    for (int i = 0; i < in_len; i += 16) {
        AES_decrypt((unsigned char *)input + i, (unsigned char *)output + i, &dec_key);
    }
}

// Log message to file
void log_message(const char *msg) {
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0';
    fprintf(log_fp, "[%s] %s\n", time_str, msg);
    fflush(log_fp);
}

// Clear log file
void clear_logs() {
    fclose(log_fp);
    log_fp = fopen(LOG_FILE, "w");
    if (!log_fp) {
        printf("\nERROR: Failed to clear log file\n\n");
        log_fp = fopen(LOG_FILE, "a"); // Reopen in append mode to continue logging
        return;
    }
    printf("\nSUCCESS: Log file cleared\n\n");
    log_message("Log file cleared");
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

        // Store threat for menu
        if (strstr(buffer, "THREAT")) {
            strncpy(last_threat, buffer, BUFFER_SIZE - 1);
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

// Menu system for user interaction
void *menu_system(void *arg) {
    char input[10];
    while (1) {
        printf("\n=== Nuclear Control System ===\n");
        printf("1. View and Decrypt Log Messages\n");
        printf("2. Decide Launch Based on Last Threat\n");
        printf("3. Clear Log File\n");
        printf("4. Exit\n");
        printf("------------------------------\n");
        printf("Enter choice: ");
        if (!fgets(input, sizeof(input), stdin)) continue;

        int choice = atoi(input);
        printf("\n");
        switch (choice) {
            case 1: {
                // Read and decrypt log file
                FILE *temp_fp = fopen(LOG_FILE, "r");
                if (!temp_fp) {
                    printf("ERROR: Failed to open log file\n\n");
                    break;
                }
                printf("=== Log Messages ===\n");
                char line[BUFFER_SIZE];
                while (fgets(line, BUFFER_SIZE, temp_fp)) {
                    if (strstr(line, "Sent encrypted launch command")) {
                        printf("Decrypted: %s", line);
                    } else {
                        printf("%s", line);
                    }
                }
                printf("===================\n\n");
                fclose(temp_fp);
                break;
            }
            case 2: {
                if (strlen(last_threat) == 0) {
                    printf("INFO: No threat detected yet\n\n");
                    break;
                }
                printf("Last Threat Detected: %s\n", last_threat);
                printf("\nSelect Launch Asset:\n");
                printf("1. Missile Silo\n");
                printf("2. Submarine\n");
                printf("3. Cancel\n");
                printf("-------------------\n");
                printf("Enter choice: ");
                if (!fgets(input, sizeof(input), stdin)) continue;

                int asset = atoi(input);
                if (asset == 3) {
                    printf("INFO: Launch cancelled\n\n");
                    break;
                }

                char launch_cmd[BUFFER_SIZE];
                if (asset == 1 && strstr(last_threat, "AIR")) {
                    snprintf(launch_cmd, BUFFER_SIZE, "LAUNCH:TARGET_AIR");
                } else if (asset == 2 && (strstr(last_threat, "SEA") || strstr(last_threat, "SPACE"))) {
                    snprintf(launch_cmd, BUFFER_SIZE, "LAUNCH ---> TARGET_SEA_SPACE");
                } else {
                    printf("ERROR: Invalid asset for this threat\n\n");
                    break;
                }

                char encrypted[BUFFER_SIZE];
                int enc_len;
                encrypt_message(launch_cmd, encrypted, &enc_len);

                pthread_mutex_lock(&mutex);
                for (int i = 0; i < client_count; i++) {
                    if ((asset == 1 && strstr(clients[i].type, "silo")) ||
                        (asset == 2 && strstr(clients[i].type, "submarine"))) {
                        write(clients[i].sockfd, encrypted, enc_len);
                        char log_msg[BUFFER_SIZE];
                        snprintf(log_msg, BUFFER_SIZE, "Sent encrypted launch command to %s", clients[i].type);
                        log_message(log_msg);
                        printf("SUCCESS: Launch command sent to %s\n\n", clients[i].type);
                    }
                }
                pthread_mutex_unlock(&mutex);
                break;
            }
            case 3:
                clear_logs();
                break;
            case 4:
                printf("INFO: Exiting menu system\n\n");
                return NULL;
            default:
                printf("ERROR: Invalid choice\n\n");
        }
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int test_mode = 0;
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        test_mode = 1;
        printf("\nINFO: Running in test mode\n\n");
    }

    // Initialize logging
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        perror("\nERROR: Failed to open log file\n");
        exit(1);
    }
    chmod(LOG_FILE, 0600);

    // Initialize random seed
    srand(time(NULL));

    // Setup server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("\nERROR: Socket creation failed\n");
        exit(1);
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("\nERROR: Bind failed\n");
        close(server_fd);
        exit(1);
    }

    if (listen(server_fd, 10) < 0) {
        perror("\nERROR: Listen failed\n");
        close(server_fd);
        exit(1);
    }

    log_message("Server started");
    printf("\nINFO: Server started on port %d\n\n", PORT);

    // Start menu system
    pthread_t menu_thread;
    if (pthread_create(&menu_thread, NULL, menu_system, NULL) != 0) {
        perror("\nERROR: Menu thread creation failed\n");
        close(server_fd);
        exit(1);
    }
    pthread_detach(menu_thread);

    // Test mode: Simulate threat
    if (test_mode) {
        sleep(3);
        char threat[BUFFER_SIZE];
        int type = rand() % 2;
        if (type == 0) {
            snprintf(threat, BUFFER_SIZE, "THREAT ---> AIR ---> ENEMY_AIRCRAFT: Coordinate: 51.5074,-0.1278");
        } else {
            snprintf(threat, BUFFER_SIZE, "THREAT ---> SEA ---> ENEMY_SUB: Coordinate: 48.8566,2.3522");
        }
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Test mode: Simulating %s", threat);
        log_message(log_msg);
        printf("\nINFO: Test mode - Simulated threat: %s\n\n", threat);

        strncpy(last_threat, threat, BUFFER_SIZE - 1);
    }

    // Accept clients
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (*client_fd < 0) {
            perror("\nERROR: Accept failed\n");
            free(client_fd);
            continue;
        }

        // Receive client type
        char buffer[BUFFER_SIZE] = {0};
        read(*client_fd, buffer, BUFFER_SIZE - 1);
        log_message(buffer);
        printf("\nINFO: New client connected - Type: %s\n\n", buffer);

        pthread_mutex_lock(&mutex);
        if (client_count < MAX_CLIENTS) {
            clients[client_count].sockfd = *client_fd;
            clients[client_count].type = strdup(buffer);
            client_count++;
        } else {
            log_message("Max clients reached");
            printf("\nWARNING: Max clients reached, rejecting connection\n\n");
            close(*client_fd);
            free(client_fd);
            pthread_mutex_unlock(&mutex);
            continue;
        }
        pthread_mutex_unlock(&mutex);

        // Start client thread
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, client_fd) != 0) {
            perror("\nERROR: Thread creation failed\n");
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
