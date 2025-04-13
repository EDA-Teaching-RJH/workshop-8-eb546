#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <openssl/aes.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024
#define KEY "0123456789abcdef0123456789abcdef"
#define LOG_FILE "submarine.log"
#define CONNECT_RETRIES 5
#define CONNECT_RETRY_DELAY 2

void decrypt_message(const char *input, int in_len, char *output) {
    if (!input || !output || in_len % 16 != 0 || in_len > BUFFER_SIZE) return;
    AES_KEY dec_key;
    AES_set_decrypt_key((unsigned char *)KEY, 256, &dec_key);
    for (int i = 0; i < in_len; i += 16) {
        AES_decrypt((unsigned char *)input + i, (unsigned char *)output + i, &dec_key);
    }
    output[in_len - 1] = '\0';
}

void log_message(FILE *fp, const char *msg) {
    time_t now = time(NULL);
    char time_buf[26];
    ctime_r(&now, time_buf);
    time_buf[strlen(time_buf) - 1] = '\0';
    fprintf(fp, "[%s] %s\n", time_buf, msg);
    fflush(fp);
}

int main(void) {
    FILE *log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        perror("Failed to open log file");
        exit(1);
    }
    chmod(LOG_FILE, 0600);

    srand(time(NULL));
    int sockfd = -1;
    while (1) {
        if (sockfd < 0) {
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
            if (sockfd < 0) {
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, BUFFER_SIZE, "Socket creation failed: %s", strerror(errno));
                log_message(log_fp, log_msg);
                printf("Submarine: %s\n", log_msg);
                fclose(log_fp);
                exit(1);
            }

            if (fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0) {
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, BUFFER_SIZE, "Failed to set socket non-blocking: %s", strerror(errno));
                log_message(log_fp, log_msg);
                printf("Submarine: %s\n", log_msg);
                close(sockfd);
                fclose(log_fp);
                exit(1);
            }

            struct sockaddr_in server_addr = {0};
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(PORT);
            inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

            int retries = CONNECT_RETRIES;
            while (retries > 0) {
                if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
                    break;
                }
                if (errno != EINPROGRESS) {
                    char log_msg[BUFFER_SIZE];
                    snprintf(log_msg, BUFFER_SIZE, "Connection failed, retrying (%d left): %s", retries, strerror(errno));
                    log_message(log_fp, log_msg);
                    printf("Submarine: %s\n", log_msg);
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
                    printf("Submarine: %s\n", log_msg);
                }
                retries--;
                sleep(CONNECT_RETRY_DELAY);
            }
            if (retries == 0) {
                log_message(log_fp, "Connection failed after retries");
                printf("Submarine: Connection failed after retries\n");
                close(sockfd);
                sockfd = -1;
                sleep(10);
                continue;
            }

            char *type = "submarine";
            int write_retries = 3;
            while (write_retries > 0) {
                ssize_t w = write(sockfd, type, strlen(type));
                if (w >= 0) {
                    break;
                }
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    char log_msg[BUFFER_SIZE];
                    snprintf(log_msg, BUFFER_SIZE, "Failed to send client type: %s", strerror(errno));
                    log_message(log_fp, log_msg);
                    printf("Submarine: %s\n", log_msg);
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
            printf("Submarine: Connected to nuclearControl\n");
        }

        if ((unsigned)(rand() % 100) < 5) {
            char intel[] = "THREAT ---> SEA ---> ENEMY_SUB ---> Coordinates: 48.8566,2.3522";
            int write_retries = 3;
            while (write_retries > 0) {
                ssize_t w = write(sockfd, intel, strlen(intel));
                if (w >= 0) {
                    log_message(log_fp, "Sent intelligence: THREAT ---> SEA ---> ENEMY_SUB");
                    printf("Submarine: Sent intelligence: THREAT ---> SEA ---> ENEMY_SUB\n");
                    break;
                }
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    char log_msg[BUFFER_SIZE];
                    snprintf(log_msg, BUFFER_SIZE, "Failed to send intelligence: %s", strerror(errno));
                    log_message(log_fp, log_msg);
                    printf("Submarine: %s\n", log_msg);
                    close(sockfd);
                    sockfd = -1;
                    break;
                }
                write_retries--;
                usleep(100000);
            }
            if (write_retries == 0 && sockfd >= 0) {
                char log_msg[BUFFER_SIZE];
                snprintf(log_msg, BUFFER_SIZE, "Aborted sending intelligence after retries");
                log_message(log_fp, log_msg);
                printf("Submarine: %s\n", log_msg);
                close(sockfd);
                sockfd = -1;
                continue;
            }
        }

        char buffer[BUFFER_SIZE];
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t n = read(sockfd, buffer, BUFFER_SIZE - 1);
        if (n > 0) {
            buffer[n] = '\0';
            if (strcmp(buffer, "SHUTDOWN") == 0) {
                log_message(log_fp, "Received shutdown signal");
                printf("Submarine: Received shutdown signal\n");
                break;
            }

            char decrypted[BUFFER_SIZE] = {0};
            decrypt_message(buffer, n, decrypted);
            if (decrypted[0] == '\0') {
                log_message(log_fp, "Decryption failed or invalid message");
                printf("Submarine: Decryption failed or invalid message\n");
                continue;
            }
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "Received: %s", decrypted);
            log_message(log_fp, log_msg);
            printf("Submarine: %s\n", log_msg);

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
        } else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            char log_msg[BUFFER_SIZE];
            snprintf(log_msg, BUFFER_SIZE, "Disconnected from server: %s", n == 0 ? "closed" : strerror(errno));
            log_message(log_fp, log_msg);
            printf("Submarine: %s\n", log_msg);
            close(sockfd);
            sockfd = -1;
            continue;
        }

        sleep(10);
    }

    if (sockfd >= 0) close(sockfd);
    fclose(log_fp);
    printf("Submarine: Terminated\n");
    return 0;
}

