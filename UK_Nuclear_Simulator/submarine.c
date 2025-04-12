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
#define LOG_FILE "submarine.log"

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

    // Setup socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        fclose(log_fp);
        exit(1);
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sockfd);
        fclose(log_fp);
        exit(1);
    }

    // Send client type
    char *type = "submarine";
    if (write(sockfd, type, strlen(type)) < 0) {
        perror("Failed to send client type");
        close(sockfd);
        fclose(log_fp);
        exit(1);
    }
    log_message(log_fp, "Connected to nuclearControl");
    printf("Submarine: Connected to nuclearControl\n");

    // Main loop
    srand(time(NULL));
    char buffer[BUFFER_SIZE];
    while (1) {
        // Randomly send intelligence
        if (rand() % 10 < 2) {
            char intel[] = "THREAT ---> SEA ---> ENEMY_SUB ---> Coordinates: 48.8566,2.3522";
            if (write(sockfd, intel, strlen(intel)) < 0) {
                log_message(log_fp, "Failed to send intelligence");
                printf("Submarine: Failed to send intelligence\n");
            } else {
                log_message(log_fp, "Sent intelligence: THREAT ---> SEA ---> ENEMY_SUB");
                printf("Submarine: Sent intelligence: THREAT ---> SEA ---> ENEMY_SUB\n");
            }
        }

        // Listen for commands
        memset(buffer, 0, BUFFER_SIZE);
        int n = read(sockfd, buffer, BUFFER_SIZE);
        if (n <= 0) {
            log_message(log_fp, "Disconnected from server");
            printf("Submarine: Disconnected from server\n");
            break;
        }

        buffer[n] = '\0';

        // Check for shutdown signal
        if (strcmp(buffer, "SHUTDOWN") == 0) {
            log_message(log_fp, "Received shutdown signal");
            printf("Submarine: Received shutdown signal\n");
            break;
        }

        // Decrypt message
        char decrypted[BUFFER_SIZE] = {0};
        decrypt_message(buffer, n, decrypted);
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Received: %s", decrypted);
        log_message(log_fp, log_msg);
        printf("Submarine: %s\n", log_msg);

        // Process launch command
        if (strstr(decrypted, "LAUNCH:TARGET_SEA_SPACE")) {
            log_message(log_fp, "Launch command verified for sea/space target. Initiating countdown...");
            printf("Submarine: Launch command verified for sea/space target. Initiating countdown...\n");
            for (int i = 10; i >= 0; i--) {
                printf("\rSubmarine: Launch in %d seconds", i);
                fflush(stdout);
                snprintf(log_msg, BUFFER_SIZE, "Launch in %d seconds", i);
                log_message(log_fp, log_msg);
                sleep(1);
            }
            printf("\rSubmarine: Missile launched to sea/space target!        \n");
            log_message(log_fp, "Missile launched to sea/space target!");
        }

        sleep(5);
    }

    // Cleanup
    fclose(log_fp);
    close(sockfd);
    printf("Submarine: Terminated\n");
    return 0;
}

