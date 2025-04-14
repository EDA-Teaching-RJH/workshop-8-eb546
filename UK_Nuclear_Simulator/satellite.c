#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8084
#define LOG_FILE "satellite.log"
#define CAESAR_SHIFT 3
#define SIMULATION_DURATION 60
#define BUFFER_SIZE 1024
#define SUMMARY_FILE "satellite_summary.txt"

static FILE *log_fp = NULL;
static int intel_sent = 0;

void init_log_file(void) {
    log_fp = fopen(LOG_FILE, "w");
    if (!log_fp) {
        fprintf(stderr, "Failed to create log file: %s\n", strerror(errno));
        exit(1);
    }
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(log_fp, "===== Satellite Log =====\n");
        fprintf(log_fp, "Simulation Start: %s\n", time_str);
        fprintf(log_fp, "=======================\n\n");
        fflush(log_fp);
    }
}

void log_event(const char *event_type, const char *details) {
    if (!log_fp) return;
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(log_fp, "[%s] %-10s %s\n", time_str, event_type, details);
        fflush(log_fp);
    }
}

void caesar_encrypt(const char *plaintext, char *ciphertext, size_t len) {
    memset(ciphertext, 0, len);
    for (size_t i = 0; plaintext[i] && i < len - 1; i++) {
        if (isalpha((unsigned char)plaintext[i])) {
            char base = isupper((unsigned char)plaintext[i]) ? 'A' : 'a';
            ciphertext[i] = (char)((plaintext[i] - base + CAESAR_SHIFT) % 26 + base);
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
}

void send_intel(int sock) {
    const char *threat_types[] = {"Air", "Sea", "Space"};
    const char *threat_data[] = {"Ballistic Missile", "Naval Fleet", "Satellite Anomaly", "Orbital Debris"};
    const char *locations[] = {"Arctic Ocean", "Mediterranean", "Barents Sea", "North Sea"};
    char message[512];
    char ciphertext[BUFFER_SIZE];
    char log_msg[BUFFER_SIZE];
    int idx = rand() % 4;
    int type_idx = rand() % 3;
    int threat_level = (rand() % 100 < 30) ? 71 + (rand() % 30) : 10 + (rand() % 61);

    snprintf(message, sizeof(message),
             "source:Satellite|type:%s|data:%s|threat_level:%d|location:%s",
             threat_types[type_idx], threat_data[idx], threat_level, locations[idx]);
    caesar_encrypt(message, ciphertext, sizeof(ciphertext));

    snprintf(log_msg, sizeof(log_msg),
             "Sending Intelligence: Type=%s, Details=%s, ThreatLevel=%d, Location=%s, [Encrypted] %s",
             threat_types[type_idx], threat_data[idx], threat_level, locations[idx], ciphertext);
    log_event("INTEL", log_msg);

    if (send(sock, ciphertext, strlen(ciphertext), 0) < 0) {
        snprintf(log_msg, sizeof(log_msg), "Failed to send intelligence: %s", strerror(errno));
        log_event("ERROR", log_msg);
    } else {
        intel_sent++;
    }
}

void generate_summary(void) {
    FILE *summary_fp = fopen(SUMMARY_FILE, "w");
    if (!summary_fp) {
        log_event("ERROR", "Failed to create summary file");
        return;
    }

    fprintf(summary_fp, "===== Satellite Simulation Summary =====\n");
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(summary_fp, "Simulation End: %s\n", time_str);
    }
    fprintf(summary_fp, "Total Intelligence Reports Sent: %d\n", intel_sent);
    fprintf(summary_fp, "=====================================\n");
    fclose(summary_fp);

    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Summary generated in %s", SUMMARY_FILE);
    log_event("SUMMARY", log_msg);
}

int main(void) {
    srand((unsigned int)time(NULL));
    init_log_file();
    log_event("STARTUP", "Satellite System initializing");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Socket creation failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        if (log_fp) fclose(log_fp);
        return 1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Invalid server address: %s", SERVER_IP);
        log_event("ERROR", log_msg);
        close(sock);
        if (log_fp) fclose(log_fp);
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Connection failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        close(sock);
        if (log_fp) fclose(log_fp);
        return 1;
    }

    log_event("CONNECTION", "Connected to Nuclear Control");

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < SIMULATION_DURATION) {
        send_intel(sock);
        sleep(5 + (rand() % 6)); // Randomize interval
    }

    shutdown(sock, SHUT_RDWR);
    close(sock);
    generate_summary();
    log_event("SHUTDOWN", "Satellite System terminated");
    if (log_fp) fclose(log_fp);
    return 0;
}

