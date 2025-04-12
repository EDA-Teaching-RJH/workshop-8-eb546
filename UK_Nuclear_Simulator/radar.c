#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024
#define LOG_FILE "radar.log"

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
    char *type = "radar";
    if (write(sockfd, type, strlen(type)) < 0) {
        perror("Failed to send client type");
        close(sockfd);
        fclose(log_fp);
        exit(1);
    }
    log_message(log_fp, "Connected to nuclearControl");
    printf("Radar: Connected to nuclearControl\n");

    // Simulate sending intelligence
    srand(time(NULL));
    char buffer[BUFFER_SIZE];
    while (1) {
        if (rand() % 10 < 3) {
            char intel[] = "THREAT ---> AIR ---> ENEMY_AIRCRAFT ---> Coordinate: 51.5074,-0.1278";
            if (write(sockfd, intel, strlen(intel)) < 0) {
                perror("Failed to send intelligence");
                log_message(log_fp, "Failed to send intelligence");
                break;
            }
            log_message(log_fp, "Sent intelligence: THREAT ---> AIR ---> ENEMY_AIRCRAFT");
            printf("Radar: Sent intelligence\n");
        }

        // Check for server messages
        memset(buffer, 0, BUFFER_SIZE);
        int n = read(sockfd, buffer, BUFFER_SIZE - 1);
        if (n <= 0) {
            log_message(log_fp, "Disconnected from server");
            break;
        }
        buffer[n] = '\0';
        if (strcmp(buffer, "SHUTDOWN") == 0) {
            log_message(log_fp, "Received shutdown signal");
            break;
        }

        sleep(10);
    }

    // Cleanup
    fclose(log_fp);
    close(sockfd);
    printf("Radar: Terminated\n");
    return 0;
}
