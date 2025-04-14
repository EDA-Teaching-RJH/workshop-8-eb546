#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8083
#define LOG_FILE "radar.log"
#define CAESAR_SHIFT 3
#define SIMULATION_DURATION 60
#define BUFFER_SIZE 1024
#define LOG_MSG_SIZE 2048

void init_log_file(void) {
    FILE *fp = fopen(LOG_FILE, "w");
    if (fp) {
        time_t now = time(NULL);
        fprintf(fp, "===== Radar Log =====\n");
        fprintf(fp, "Simulation Start: %s", ctime(&now));
        fprintf(fp, "====================\n\n");
        fclose(fp);
    }
}

void log_event(const char *event_type, const char *details) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) {
        fprintf(stderr, "Failed to open log file: %s\n", LOG_FILE);
        return;
    }
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(fp, "[%s] %-10s %s\n", time_str, event_type, details);
    }
    fclose(fp);
}

void caesar_encrypt(const char *plaintext, char *ciphertext, size_t len) {
    memset(ciphertext, 0, len);
    for (size_t i = 0; i < strlen(plaintext) && i < len - 1; i++) {
        if (isalpha((unsigned char)plaintext[i])) {
            char base = isupper((unsigned char)plaintext[i]) ? 'A' : 'a';
            ciphertext[i] = (char)((plaintext[i] - base + CAESAR_SHIFT) % 26 + base);
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
}

void send_intel(int sock) {
    const char *const threat_data[] = {"Enemy Aircraft", "Missile Strike", "Drone Swarm"};
    const char *const locations[] = {"North Atlantic", "English Channel", "Baltic Sea"};
    char message[512];
    char ciphertext[BUFFER_SIZE];
    char log_msg[LOG_MSG_SIZE];
    int idx = rand() % 3;
    double threat_level = 0.1 + (rand() % 90) / 100.0;

    snprintf(message, sizeof(message),
             "source:Radar|type:Air|data:%s|threat_level:%.2f|location:%s",
             threat_data[idx], threat_level, locations[idx]);
    caesar_encrypt(message, ciphertext, sizeof(ciphertext));

    snprintf(log_msg, sizeof(log_msg),
             "Sending Intelligence: Type=Air, Details=%s, ThreatLevel=%.2f, Location=%s, [Encrypted] %.1000s",
             threat_data[idx], threat_level, locations[idx], ciphertext);
    log_event("INTEL", log_msg);

    if (send(sock, ciphertext, strlen(ciphertext), 0) < 0) {
        log_event("ERROR", "Failed to send intelligence");
    }
}

int main(void) {
    srand((unsigned int)time(NULL));
    init_log_file();
    log_event("STARTUP", "Radar System initializing");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_event("ERROR", "Socket creation failed");
        return 1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        log_event("ERROR", "Invalid server address");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_event("ERROR", "Connection to Nuclear Control failed");
        close(sock);
        return 1;
    }

    log_event("CONNECTION", "Connected to Nuclear Control");

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < SIMULATION_DURATION) {
        send_intel(sock);
        sleep(10);
    }

    close(sock);
    log_event("SHUTDOWN", "Radar System terminated");
    return 0;
}

