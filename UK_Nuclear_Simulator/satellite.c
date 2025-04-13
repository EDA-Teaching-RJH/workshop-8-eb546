#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024
#define LOG_FILE "satellite.log"
#define CONNECT_RETRIES 5
#define CONNECT_RETRY_DELAY 2

// Log message
void log_message(FILE *fp, const char *msg) {
    time_t now = time(NULL);
    char time_buf[26];
    ctime_r(&now, time_buf);
    time_buf[strlen(time_buf) - 1] = '\0';
    fprintf(fp, "[%s] %s\n", time_buf, msg);
    fflush(fp);
}

int main() {
    FILE *log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        perror("Failed to open log file");
        exit(1);
    }
    chmod(LOG_FILE, 0600);

    srand(time(NULL));
    int sockfd = -1;
    while (1) {
        // Setup socket
        if (sockfd < 0) {
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
            if (sockfd < 0) {
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, BUFFER_SIZE, "Socket creation failed: %s", strerror(errno));
                log_message(log_fp, log_msg);
                printf("Satellite: %s\n", log_msg);
                fclose(log_fp);
                exit(1);
            }

            // Set non-blocking
            if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0) {
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, BUFFER_SIZE, "Failed to set socket non-blocking: %s", strerror(errno));
                log_message(log_fp, log_msg);
                printf("Satellite: %s\n", log_msg);
                close(sockfd);
                fclose(log_fp);
                exit(1);
            }

            struct sockaddr_in server_addr = {0};
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(PORT);
            inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

            // Connect with retries
            int retries = CONNECT_RETRIES;
            while (retries > 0) {
                if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
                    break;
                }
                if (errno != EINPROGRESS) {
                    char log_msg[BUFFER_SIZE];
                    snprintf(log_msg, BUFFER_SIZE, "Connection failed, retrying (%d left): %s", retries, strerror(errno));
                    log_message(log_fp, log_msg);
                    printf("Satellite: %s\n", log_msg);
                    sleep(CONNECT_RETRY_DELAY);
                    retries--;
                    continue;
                }
                fd_set fdset;
                FD_ZERO(&fdset);
                FD_SET(sockfd, &fdset);
                struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
                int sel_ret = select(sockfd + 1, NULL, &fdset, NULL, &tv);
                if (sel_ret > 0) {
                    int so_error;
                    socklen_t len = sizeof(so_error);
                    getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
                    if (so_error == 0) {
                        break;
                    }
                } else if (sel_ret < 0) {
                    char log_msg[BUFFER_SIZE];
                    snprintf(log_msg, BUFFER_SIZE, "Select failed: %s", strerror(errno));
                    log_message(log_fp, log_msg);
                    printf("Satellite: %s\n", log_msg);
                }
                retries--;
                sleep(CONNECT_RETRY_DELAY);
            }
            if (retries == 0) {
                log_message(log_fp, "Connection failed after retries");
                printf("Satellite: Connection failed after retries\n");
                close(sockfd);
                sockfd = -1;
                sleep(10);
                continue;
            }

            // Send client type
            char *type = "satellite";
            int write_retries = 3;
            while (write_retries > 0) {
                if (write(sockfd, type, strlen(type)) >= 0) {
                    break;
                }
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    char log_msg[BUFFER_SIZE];
                    snprintf(log_msg, BUFFER_SIZE, "Failed to send client type: %s", strerror(errno));
                    log_message(log_fp, log_msg);
                    printf("Satellite: %s\n", log_msg);
                    close(sockfd);
                    sockfd = -1;
                    break;
                }
                write_retries--;
                usleep(100000);
            }
            if (write_retries == 0 || sockfd < 0) {
                if (sockfd >= 0) close(sockfd);
                sockfd = -1;
                continue;
            }
            log_message(log_fp, "Connected to nuclearControl");
            printf("Satellite: Connected to nuclearControl\n");
        }

        // Send intelligence
        if ((rand() % 100) < 10) { // 10% chance
            char intel[] = "THREAT ---> SPACE ---> ENEMY_SATELLITE ---> Coordinate: 55.7558,37.6173";
            int write_retries = 3;
            while (write_retries > 0) {
                if (write(sockfd, intel, strlen(intel)) >= 0) {
                    log_message(log_fp, "Sent intelligence: THREAT ---> SPACE ---> ENEMY_SATELLITE");
                    printf("Satellite: Sent intelligence: THREAT ---> SPACE ---> ENEMY_SATELLITE\n");
                    break;
                }
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    char log_msg[BUFFER_SIZE];
                    snprintf(log_msg, BUFFER_SIZE, "Failed to send intelligence: %s", strerror(errno));
                    log_message(log_fp, log_msg);
                    printf("Satellite: %s\n", log_msg);
                    close(sockfd);
                    sockfd = -1;
                    break;
                }
                write_retries--;
                usleep(100000);
            }
            if (write_retries == 0 && sockfd >= 0) {
                log_message(log_fp, "Aborted sending intelligence after retries");
                printf("Satellite: Aborted sending intelligence after retries\n");
                close(sockfd);
                sockfd = -1;
                continue;
            }
        }

        // Check for server messages
        char buffer[BUFFER_SIZE];
        memset(buffer, 0, BUFFER_SIZE);
        int n = read(sockfd, buffer, BUFFER_SIZE - 1);
        if (n > 0) {
            buffer[n] = '\0';
            if (strcmp(buffer, "SHUTDOWN") == 0) {
                log_message(log_fp, "Received shutdown signal");
                printf("Satellite: Received shutdown signal\n");
                break;
            }
        } else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "Disconnected from server: %s", n == 0 ? "closed" : strerror(errno));
            log_message(log_fp, log_msg);
            printf("Satellite: %s\n", log_msg);
            close(sockfd);
            sockfd = -1;
            continue;
        }

        sleep(45); // Slow down
    }

    // Cleanup
    if (sockfd >= 0) close(sockfd);
    fclose(log_fp);
    printf("Satellite: Terminated\n");
    return 0;
}

