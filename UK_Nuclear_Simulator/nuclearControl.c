#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

// Constants
#define PORT 8080
#define MAX_CLIENTS 10
#define BUFFER_SIZE 1024
#define KEY "0123456789abcdef0123456789abcdef"
#define LOG_FILE "nuclearControl.log"
#define MAX_THREATS 50
#define BIND_RETRY_COUNT 5
#define BIND_RETRY_DELAY 2

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
char threat_list[MAX_THREATS][BUFFER_SIZE] = {0};
int threat_count = 0;
int shutdown_flag = 0;

// Encrypt message using AES-256
void encrypt_message(const char *input, char *output, int *out_len) {
    if (!input || !output || !out_len) return;
    AES_KEY enc_key;
    AES_set_encrypt_key((unsigned char *)KEY, 256, &enc_key);
    size_t len = strlen(input) + 1;
    if (len > BUFFER_SIZE) len = BUFFER_SIZE; // Prevent overflow
    int pad_len = (len + 15) / 16 * 16;
    unsigned char *padded = calloc(pad_len, 1);
    if (!padded) {
        *out_len = 0;
        return;
    }
    memcpy(padded, input, len);
    for (int i = 0; i < pad_len; i += 16) {
        AES_encrypt(padded + i, (unsigned char *)output + i, &enc_key);
    }
    *out_len = pad_len;
    free(padded);
}

// Decrypt message using AES-256
void decrypt_message(const char *input, int in_len, char *output) {
    if (!input || !output || in_len % 16 != 0 || in_len > BUFFER_SIZE) return;
    AES_KEY dec_key;
    AES_set_decrypt_key((unsigned char *)KEY, 256, &dec_key);
    for (int i = 0; i < in_len; i += 16) {
        AES_decrypt((unsigned char *)input + i, (unsigned char *)output + i, &dec_key);
    }
    output[in_len - 1] = '\0'; // Ensure null-termination
}

// Log message to file
void log_message(const char *msg) {
    pthread_mutex_lock(&mutex);
    if (!log_fp) {
        printf("NuclearControl: Log file closed, cannot log: %s\n", msg);
        pthread_mutex_unlock(&mutex);
        return;
    }
    time_t now = time(NULL);
    char time_buf[26];
    ctime_r(&now, time_buf);
    time_buf[strlen(time_buf) - 1] = '\0';
    fprintf(log_fp, "[%s] %s\n", time_buf, msg);
    fflush(log_fp);
    pthread_mutex_unlock(&mutex);
}

// Delete all log files
void delete_logs() {
    const char *log_files[] = {"nuclearControl.log", "missileSilo.log", "submarine.log", "radar.log", "satellite.log"};
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
    if (log_fp) fclose(log_fp);
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
    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0) {
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Failed to set socket non-blocking: %s", strerror(errno));
        log_message(log_msg);
        printf("NuclearControl: %s\n", log_msg);
        close(sockfd);
        return NULL;
    }

    // Read client type with timeout
    memset(buffer, 0, BUFFER_SIZE);
    int retries = 50; // 5s
    int n;
    while (retries > 0) {
        n = read(sockfd, buffer, BUFFER_SIZE - 1);
        if (n > 0) {
            buffer[n] = '\0';
            client_type = strdup(buffer);
            if (!client_type) {
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, BUFFER_SIZE, "Memory allocation failed for client type");
                log_message(log_msg);
                printf("NuclearControl: %s\n", log_msg);
                close(sockfd);
                return NULL;
            }
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "New client connected: %s", client_type);
            log_message(log_msg);
            printf("NuclearControl: %s\n", log_msg);
            break;
        } else if (n == 0) {
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "Client disconnected before sending type");
            log_message(log_msg);
            printf("NuclearControl: %s\n", log_msg);
            close(sockfd);
            return NULL;
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "Error reading client type: %s", strerror(errno));
            log_message(log_msg);
            printf("NuclearControl: %s\n", log_msg);
            close(sockfd);
            return NULL;
        }
        usleep(100000); // 100ms
        retries--;
    }
    if (!client_type) {
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Failed to read client type after retries");
        log_message(log_msg);
        printf("NuclearControl: %s\n", log_msg);
        close(sockfd);
        return NULL;
    }

    // Store client
    pthread_mutex_lock(&mutex);
    if (client_count >= MAX_CLIENTS) {
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Max clients reached, rejecting %s", client_type);
        log_message(log_msg);
        printf("NuclearControl: %s\n", log_msg);
        close(sockfd);
        free(client_type);
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
    clients[client_count].sockfd = sockfd;
    clients[client_count].type = client_type;
    client_count++;
    pthread_mutex_unlock(&mutex);

    // Main loop
    while (!shutdown_flag) {
        memset(buffer, 0, BUFFER_SIZE);
        n = read(sockfd, buffer, BUFFER_SIZE - 1);
        if (n > 0) {
            buffer[n] = '\0';
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "Received from %s: %s", client_type, buffer);
            log_message(log_msg);
            printf("NuclearControl: %s\n", log_msg);

            // Store threat
            if (strstr(buffer, "THREAT")) {
                pthread_mutex_lock(&mutex);
                if (threat_count < MAX_THREATS) {
                    strncpy(threat_list[threat_count], buffer, BUFFER_SIZE - 1);
                    threat_count++;
                } else {
                    memmove(threat_list[0], threat_list[1], (MAX_THREATS - 1) * BUFFER_SIZE);
                    strncpy(threat_list[MAX_THREATS - 1], buffer, BUFFER_SIZE - 1);
                }
                snprintf(log_msg, BUFFER_SIZE, "Added threat (count: %d): %s", threat_count, buffer);
                log_message(log_msg);
                pthread_mutex_unlock(&mutex);
            }
        } else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "%s disconnected: %s", client_type, n == 0 ? "closed" : strerror(errno));
            log_message(log_msg);
            printf("NuclearControl: %s\n", log_msg);
            break;
        }
        usleep(100000); // 100ms
    }

    // Cleanup
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i].sockfd == sockfd) {
            close(clients[i].sockfd);
            free(clients[i].type);
            memmove(&clients[i], &clients[i + 1], (client_count - i - 1) * sizeof(Client));
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
}

// Periodic client check
void *client_monitor(void *arg) {
    while (!shutdown_flag) {
        pthread_mutex_lock(&mutex);
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Connected clients: %d", client_count);
        log_message(log_msg);
        printf("NuclearControl: %s\n", log_msg);
        pthread_mutex_unlock(&mutex);
        sleep(60); // Check every minute
    }
    return NULL;
}

// Menu system
void *menu_system(void *arg) {
    char input[10];
    while (!shutdown_flag) {
        printf("\nNuclear Control Menu:\n");
        printf("1. View log messages\n");
        printf("2. Decide launch based on last threat\n");
        printf("3. Exit\n");
        printf("4. Delete all logs\n");
        printf("Enter choice: ");
        if (!fgets(input, sizeof(input), stdin)) {
            usleep(100000);
            continue;
        }

        int choice = atoi(input);
        switch (choice) {
            case 1: {
                pthread_mutex_lock(&mutex);
                FILE *temp_fp = fopen(LOG_FILE, "r");
                pthread_mutex_unlock(&mutex);
                if (!temp_fp) {
                    printf("Failed to open log file\n");
                    break;
                }
                char line[BUFFER_SIZE];
                while (fgets(line, BUFFER_SIZE, temp_fp)) {
                    printf("%s", line);
                }
                fclose(temp_fp);
                break;
            }
            case 2: {
                pthread_mutex_lock(&mutex);
                if (threat_count == 0) {
                    printf("No threat detected yet\n");
                    pthread_mutex_unlock(&mutex);
                    break;
                }
                int idx = rand() % threat_count;
                strncpy(last_threat, threat_list[idx], BUFFER_SIZE - 1);
                last_threat[BUFFER_SIZE - 1] = '\0';
                pthread_mutex_unlock(&mutex);

                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, BUFFER_SIZE, "Selected last threat: %s", last_threat);
                log_message(log_msg);
                printf("Last threat: %s\n", last_threat);
                printf("Select launch asset:\n");
                printf("1. Missile Silo\n");
                printf("2. Submarine\n");
                printf("3. Cancel\n");
                printf("Enter choice: ");
                if (!fgets(input, sizeof(input), stdin)) {
                    usleep(100000);
                    continue;
                }

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
                if (enc_len == 0) {
                    printf("Encryption failed\n");
                    break;
                }

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
                    clients[i].type = NULL;
                }
                client_count = 0;
                pthread_mutex_unlock(&mutex);

                if (log_fp) {
                    fclose(log_fp);
                    log_fp = NULL;
                }
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
        perror("Failed to open log file");
        exit(1);
    }
    chmod(LOG_FILE, 0600);

    // Initialize random seed
    srand(time(NULL));

    // Setup server socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        if (log_fp) fclose(log_fp);
        exit(1);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        close(server_fd);
        if (log_fp) fclose(log_fp);
        exit(1);
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Retry binding
    int bind_retries = BIND_RETRY_COUNT;
    while (bind_retries > 0) {
        if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
            break;
        }
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Bind failed, retrying (%d left): %s", bind_retries, strerror(errno));
        log_message(log_msg);
        printf("NuclearControl: %s\n", log_msg);
        sleep(BIND_RETRY_DELAY);
        bind_retries--;
    }
    if (bind_retries == 0) {
        perror("Bind failed after retries");
        close(server_fd);
        if (log_fp) fclose(log_fp);
        exit(1);
    }

    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        close(server_fd);
        if (log_fp) fclose(log_fp);
        exit(1);
    }

    log_message("Server started on port 8080");
    printf("NuclearControl: Server started on port 8080\n");

    // Start client monitor
    pthread_t monitor_thread;
    if (pthread_create(&monitor_thread, NULL, client_monitor, NULL) != 0) {
        perror("Monitor thread creation failed");
    } else {
        pthread_detach(monitor_thread);
    }

    // Start menu system
    pthread_t menu_thread;
    if (pthread_create(&menu_thread, NULL, menu_system, NULL) != 0) {
        perror("Menu thread creation failed");
        close(server_fd);
        if (log_fp) fclose(log_fp);
        exit(1);
    }

    // Test mode: Simulate threat
    if (test_mode) {
        sleep(3);
        char threat[BUFFER_SIZE];
        int type = rand() % 3;
        if (type == 0) {
            snprintf(threat, BUFFER_SIZE, "THREAT ---> AIR ---> ENEMY_AIRCRAFT: Coordinate: 51.5074,-0.1278");
        } else if (type == 1) {
            snprintf(threat, BUFFER_SIZE, "THREAT ---> SEA ---> ENEMY_SUB: Coordinate: 48.8566,2.3522");
        } else {
            snprintf(threat, BUFFER_SIZE, "THREAT ---> SPACE ---> ENEMY_SATELLITE: Coordinate: 55.7558,37.6173");
        }
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Test mode: Simulating %s", threat);
        log_message(log_msg);
        printf("NuclearControl: %s\n", log_msg);

        pthread_mutex_lock(&mutex);
        if (threat_count < MAX_THREATS) {
            strncpy(threat_list[threat_count], threat, BUFFER_SIZE - 1);
            threat_list[threat_count][BUFFER_SIZE - 1] = '\0';
            threat_count++;
        }
        pthread_mutex_unlock(&mutex);
    }

    // Accept clients
    while (!shutdown_flag) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int *client_fd = malloc(sizeof(int));
        if (!client_fd) {
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "Failed to allocate memory for client_fd");
            log_message(log_msg);
            printf("NuclearControl: %s\n", log_msg);
            usleep(100000);
            continue;
        }
        *client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (*client_fd < 0) {
            if (!shutdown_flag) {
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, BUFFER_SIZE, "Accept failed: %s", strerror(errno));
                log_message(log_msg);
                printf("NuclearControl: %s\n", log_msg);
            }
            free(client_fd);
            usleep(100000); // Prevent CPU spin
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
            if (pthread_detach(thread) != 0) {
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, BUFFER_SIZE, "Thread detach failed: %s", strerror(errno));
                log_message(log_msg);
                printf("NuclearControl: %s\n", log_msg);
            }
        }
    }

    // Cleanup
    close(server_fd);
    pthread_join(menu_thread, NULL);
    return 0;
}

