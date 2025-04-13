#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

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

    // Retry connect
    int connect_retries = 5;
    while (connect_retries > 0) {
        if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
            break;
        }
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Connection failed, retrying (%d left): %s", connect_retries, strerror(errno));
        log_message(log_fp, log_msg);
        printf("Radar: %s\n", log_msg);
        sleep(1);
        connect_retries--;
    }
    if (connect_retries == 0) {
        log_message(log_fp, "Connection failed after retries");
        printf("Radar: Connection failed after retries\n");
        close(sockfd);
        fclose(log_fp);
        exit(1);
    }

    // Send client type
    char *type = "radar";
    if (write(sockfd, type, strlen(type)) < 0) {
        char log_msg[BUFFER_SIZE];
        snprintf(log_msg, BUFFER_SIZE, "Failed to send client type: %s", strerror(errno));
        log_message(log_fp, log_msg);
        printf("Radar: %s\n", log_msg);
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
        log_message(log_fp, "Checking for threats");
        printf("Radar: Checking for threats\n");

        if (rand() % 10 < 4) { // 20% chance
            char intel[] = "THREAT ---> AIR ---> ENEMY_AIRCRAFT ---> Coordinate: 51.5074,-0.1278";
            int write_retries = 3;
            int sent = 0;
            while (write_retries > 0 && !sent) {
                if (write(sockfd, intel, strlen(intel)) > 0) {
                    log_message(log_fp, "Sent intelligence: THREAT ---> AIR ---> ENEMY_AIRCRAFT");
                    printf("Radar: Sent intelligence: THREAT ---> AIR ---> ENEMY_AIRCRAFT\n");
                    sent = 1;
                } else {
                    char log_msg[BUFFER_SIZE];
                    snprintf(log_msg, BUFFER_SIZE, "Failed to send intelligence: %s", strerror(errno));
                    log_message(log_fp, log_msg);
                    printf("Radar: %s\n", log_msg);
                    write_retries--;
                    usleep(100000); // 100ms
                }
            }
            if (!sent) {
                log_message(log_fp, "Aborted sending intelligence after retries");
                printf("Radar: Aborted sending intelligence after retries\n");
                break;
            }
        }

        // Check for server messages
        memset(buffer, 0, BUFFER_SIZE);
        int n = read(sockfd, buffer, BUFFER_SIZE - 1);
        if (n <= 0) {
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "Disconnected from server: %s", n == 0 ? "closed" : strerror(errno));
            log_message(log_fp, log_msg);
            printf("Radar: %s\n", log_msg);
            break;
        }
        buffer[n] = '\0';
        if (strcmp(buffer, "SHUTDOWN") == 0) {
            log_message(log_fp, "Received shutdown signal");
            printf("Radar: Received shutdown signal\n");
            break;
        }

        sleep(30); // Slowed down
    }

    // Cleanup
    fclose(log_fp);
    close(sockfd);
    printf("Radar: Terminated\n");
    return 0;
}
