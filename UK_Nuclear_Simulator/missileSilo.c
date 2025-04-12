#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <time.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024
#define KEY "0123456789abcdef0123456789abcdef"
#define LOG_FILE "missileSilo.log"

// Decrypt message
void decrypt_message(const char *input, int in_len, char *output) {
    AES_KEY dec_key;
    AES_set_decrypt_key((unsigned char *)KEY, 256, &dec_key);
    for (int i = 0; i < in_len; i += 16) {
        AES_decrypt((unsigned char *)input + i, (unsigned char *)output + i, &dec_key);
    }
}

// Log message
void log_message(FILE *fp, const char *msg) {
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0';
    fprintf(fp, "[%s] %s\n", time_str, msg);
    fflush(fp);
}

int main() {
    // Initialize logging
    FILE *log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        perror("Failed to open log file");
        exit(1);
    }
    chmod(LOG_FILE, 0600);

    // Setup client socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        exit(1);
    }

    // Send client type
    char *type = "silo";
    write(sockfd, type, strlen(type));
    log_message(log_fp, "Connected to nuclearControl");

    // Listen for commands
    char buffer[BUFFER_SIZE];
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int n = read(sockfd, buffer, BUFFER_SIZE);
        if (n <= 0) {
            log_message(log_fp, "Disconnected from server");
            break;
        }

        buffer[n] = '\0';

        // Check for shutdown signal
        if (strcmp(buffer, "SHUTDOWN") == 0) {
            log_message(log_fp, "Received shutdown signal");
            break;
        }

        // Decrypt message
        char decrypted[BUFFER_SIZE] = {0};
        decrypt_message(buffer, n, decrypted);
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Received: %s", decrypted);
        log_message(log_fp, log_msg);

        // Process launch command
        if (strstr(decrypted, "LAUNCH:TARGET_AIR")) {
            log_message(log_fp, "Launch command verified for air target. Initiating countdown...");
            printf("Missile Silo: Launch command received for air target.\n");
            for (int i = 10; i >= 0; i--) {
                snprintf(log_msg, BUFFER_SIZE, "Launch in %d seconds", i);
                log_message(log_fp, log_msg);
                printf("Missile Silo: Launch in %d seconds\n", i);
                sleep(1);
            }
            log_message(log_fp, "Missile launched to air target");
            printf("Missile Silo: Missile launched to air target\n");
        }
    }

    // Cleanup
    fclose(log_fp);
    close(sockfd);
    printf("Missile Silo: Terminated\n");
    return 0;
}
