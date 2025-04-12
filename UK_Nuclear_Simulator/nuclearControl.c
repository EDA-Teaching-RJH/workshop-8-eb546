#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

// Constants
#define PORT 8080
#define MAX_CLIENTS 4
#define BUFFER_SIZE 1024
#define KEY "0123456789abcdef0123456789abcdef"
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
int shutdown_flag = 0;

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

// Delete all log files
void delete_logs() {
    const char *log_files[] = {"nuclearControl.log", "missileSilo.log", "submarine.log", "radar.log", "satelite.log"};
    int num_files = 5;

    for (int i = 0; i < num_files; i++) {
        if (unlink(log_files[i]) == 0) {
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "Deleted log file: %s", log_files[i]);
            if (strcmp(log_files[i], LOG_FILE) != 0) log_message(log_msg);
            printf("NuclearControl: %s\n", log_msg);
        } else {
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "Failed to delete log file %s: %s", log_files[i], strerror(errno));
            if (strcmp(log_files[i], LOG_FILE) != 0) log_message(log_msg);
            printf("NuclearControl: %s\n", log_msg);
        }
    }

    // Reopen nuclearControl.log
    fclose(log_fp);
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        perror("Failed to reopen log file");
        shutdown_flag = 1;
    } else {
        chmod(LOG_FILE, 0600);
        log_message("Reopened log file after deletion");
    }
}

// Handle client communication
void *handle_client(void *arg) {
    int sockfd = *(int *)arg;
    char buffer[BUFFER_SIZE];
    char *client_type = NULL;
    free(arg);

    // Set socket to non-blocking
    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    // Read client type
    memset(buffer, 0, BUFFER_SIZE);
    int n = read(sockfd, buffer, BUFFER_SIZE - 1);
    if (n > 0) {
        buffer[n] = '\0';
        client_type = strdup(buffer);
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "New client connected: %s", client_type);
        log_message(log_msg);
        printf("NuclearControl: %s\n", log_msg);
    } else {
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Failed to read client type: %s", n == 0 ? "closed" : strerror(errno));
        log_message(log_msg);
        printf("NuclearControl: %s\n", log_msg);
        close(sockfd);
        return NULL;
    }

    // Store client
    pthread_mutex_lock(&mutex);
    if (client_count < MAX_CLIENTS) {
        clients[client_count].sockfd = sockfd;
        clients[client_count].type = strdup(client_type);
        client_count++;
    } else {
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Max clients reached, rejecting %s", client_type);
        log_message(log_msg);
        printf("NuclearControl: %s\n", log_msg);
        close(sockfd);
        free(client_type);
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
    pthread_mutex_unlock(&mutex);

    // Main loop for client messages
    while (!shutdown_flag) {
        memset(buffer, 0, BUFFER_SIZE);
        n = read(sockfd, buffer, BUFFER_SIZE - 1);
        if (n > 0) {
            buffer[n] = '\0';
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "Received from %s: %s", client_type, buffer);
            log_message(log_msg);
            printf("NuclearControl: %s\n", log_msg);

            // Store threat for menu
            if (strstr(buffer, "THREAT")) {
                strncpy(last_threat, buffer, BUFFER_SIZE - 1);
            }
        } else if (n == 0) {
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "%s disconnected", client_type);
            log_message(log_msg);
            printf("NuclearControl: %s\n", log_msg);
            break;
        } else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, BUFFER_SIZE, "Error reading from %s: %s", client_type, strerror(errno));
                log_message(log_msg);
                printf("NuclearControl: %s\n", log_msg);
                break;
            }
            // Sleep to prevent CPU overuse (mimics timeout)
            usleep(100000); // 100ms
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
    free(client_type);
    return NULL;
}

// Menu system for user interaction
void *menu_system(void *arg) {
    char input[10];
    while (!shutdown_flag) {
        printf("\nNuclear Control Menu:\n");
        printf("1. View and decrypt log messages\n");
        printf("2. Decide launch based on last threat\n");
        printf("3. Exit\n");
        printf("4. Delete all logs\n");
        printf("Enter choice: ");
        if (!fgets(input, sizeof(input), stdin)) continue;

        int choice = atoi(input);
        switch (choice) {
            case 1: {
                FILE *temp_fp = fopen(LOG_FILE, "r");
                if (!temp_fp) {
                    printf("Failed to open log file\n");
                    break;
                }
                char line[BUFFER_SIZE];
                while (fgets(line, BUFFER_SIZE, temp_fp)) {
                    if (strstr(line, "Sent encrypted launch command")) {
                        printf("Decrypted log: %s", line);
                    } else {
                        printf("%s", line);
                    }
                }
                fclose(temp_fp);
                break;
            }
            case 2: {
                if (strlen(last_threat) == 0) {
                    printf("No threat detected yet\n");
                    break;
                }
                printf("Last threat: %s\n", last_threat);
                printf("Select launch asset:\n");
                printf("1. Missile Silo\n");
                printf("2. Submarine\n");
                printf("3. Cancel\n");
                printf("Enter choice: ");
                if (!fgets(input, sizeof(input), stdin)) continue;

                int asset = atoi(input);
                if (asset == 3) break;

                char launch_cmd[BUFFER_SIZE];
                if (asset == 1 && strstr(last_threat, "AIR")) {
                    snprintf(launch_cmd, BUFFER_SIZE, "LAUNCH:TARGET_AIR");
                } else if (asset == 2 && (strstr(last_threat, "SEA") || strstr(last_threat, "SPACE"))) {
                    snprintf(launch_cmd, BUFFER_SIZE, "LAUNCH:TARGET_SEA_SPACE");
                } else {
                    printf("Invalid asset for this threat!\n");
                    break;
                }

                char encrypted[BUFFER_SIZE];
                int enc_len;
                encrypt_message(launch_cmd, encrypted, &enc_len);

                pthread_mutex_lock(&mutex);
                for (int i = 0; i < client_count; i++) {
                    if ((asset == 1 && strstr(clients[i].type, "silo")) ||
                        (asset == 2 && strstr(clients[i].type, "submarine"))) {
                        if (write(clients[i].sockfd, encrypted, enc_len) < 0) {
                            char log_msg[BUFFER_SIZE];
                            snprintf(log_msg, BUFFER_SIZE, "Failed to send launch command to %s: %s", clients[i].type, strerror(errno));
                            log_message(log_msg);
                        } else {
                            char log_msg[BUFFER_SIZE];
                            snprintf(log_msg, BUFFER_SIZE, "Sent encrypted launch command to %s", clients[i].type);
                            log_message(log_msg);
                        }
                    }
                }
                pthread_mutex_unlock(&mutex);
                break;
            }
            case 3: {
                printf("Shutting down system\n");
                shutdown_flag = 1;

                // Send shutdown signal to all clients
                pthread_mutex_lock(&mutex);
                for (int i = 0; i < client_count; i++) {
                    if (write(clients[i].sockfd, "SHUTDOWN", strlen("SHUTDOWN")) < 0) {
                        char log_msg[BUFFER_SIZE];
                        snprintf(log_msg, BUFFER_SIZE, "Failed to send SHUTDOWN to %s: %s", clients[i].type, strerror(errno));
                        log_message(log_msg);
                    } else {
                        char log_msg[BUFFER_SIZE];
                        snprintf(log_msg, BUFFER_SIZE, "Sent SHUTDOWN to %s", clients[i].type);
                        log_message(log_msg);
                    }
                    close(clients[i].sockfd);
                    free(clients[i].type);
                }
                client_count = 0;
                pthread_mutex_unlock(&mutex);

                // Close log file
                fclose(log_fp);
                pthread_exit(NULL);
            }
            case 4: {
                delete_logs();
                printf("All logs deleted\n");
                break;
            }
            default:
                printf("Invalid choice\n");
        }
    }
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
        perror("Failed to open log file!");
        exit(1);
    }
    chmod(LOG_FILE, 0600);

    // Initialize random seed
    srand(time(NULL));

    // Setup server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed!");
        fclose(log_fp);
        exit(1);
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed!");
        close(server_fd);
        fclose(log_fp);
        exit(1);
    }

    if (listen(server_fd, 10) < 0) {
        perror("Listen failed!");
        close(server_fd);
        fclose(log_fp);
        exit(1);
    }

    log_message("Server started");
    printf("NuclearControl: Server started\n");

    // Start menu system
    pthread_t menu_thread;
    if (pthread_create(&menu_thread, NULL, menu_system, NULL) != 0) {
        perror("Menu thread creation failed!");
        close(server_fd);
        fclose(log_fp);
        exit(1);
    }

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
        printf("NuclearControl: %s\n", log_msg);

        strncpy(last_threat, threat, BUFFER_SIZE - 1);
    }

    // Accept clients
    while (!shutdown_flag) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int *client_fd = malloc(sizeof(int));
        *client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (*client_fd < 0) {
            if (!shutdown_flag) {
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, BUFFER_SIZE, "Accept failed: %s", strerror(errno));
                log_message(log_msg);
                printf("NuclearControl: %s\n", log_msg);
            }
            free(client_fd);
            continue;
        }

        // Start client thread
        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_client, client_fd) != 0) {
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "Thread creation failed: %s", strerror(errno));
            log_message(log_msg);
            printf("NuclearControl: %s\n", log_msg);
            close(*client_fd);
            free(client_fd);
        } else {
            pthread_detach(thread);
        }
    }

    // Cleanup
    close(server_fd);
    pthread_join(menu_thread, NULL);
    return 0;
}
