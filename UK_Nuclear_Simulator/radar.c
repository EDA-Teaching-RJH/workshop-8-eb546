/*These are the standard library headers included for the program such as 
inputs, outputs, strings, sockets, memory allocation, character handling, etc.*/
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

/*This is to defined the assigned port, simulation duration, and  
buffer size for the radar client to ping back to the server's IP address.*/
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8083
#define LOG_FILE "radar.log"
#define CAESAR_SHIFT 3
#define SIMULATION_DURATION 60
#define BUFFER_SIZE 1024
#define SUMMARY_FILE "radar_summary.txt"

//These are global variables that handles log file and tracks successful transmissions.
static FILE *log_fp = NULL;
static int intel_sent = 0;

/*This initialize a log file with a timestamped header and opens it in write file mode. 
It includes an error handling function in case there is a creation failure and a small 
title box that displays the time when the simulation starts.*/
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
        fprintf(log_fp, "===== Radar Log =====\n");
        fprintf(log_fp, "Simulation Start: %s\n", time_str);
        fprintf(log_fp, "====================\n\n");
        fflush(log_fp);
    }
}

/*This allows to have each event occurs with a timestamp and category.*/
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

//This uses the caesar cipher to encrypt messages.
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

/*This generates and sends intel reports to the nuclear control center about 
the enemy threats and their location. It also includes buffers of messages to get enough of 
characters to display. It randomly select any threats and locations from the data sets.
Lastly, it generates threat level with 30% chance of a threat above 70.*/
void send_intel(int sock) {
    const char *threat_data[] = {"Enemy Aircraft", "Missile Strike", "Drone Swarm", "Stealth Bomber"};
    const char *locations[] = {"North Atlantic", "English Channel", "Baltic Sea", "Irish Sea"};
    char message[512];
    char ciphertext[BUFFER_SIZE];
    char log_msg[BUFFER_SIZE];
    int idx = rand() % 4;
    int threat_level = (rand() % 100 < 30) ? 71 + (rand() % 30) : 10 + (rand() % 61);

    //The report details are encrypt by a caesar cipher and separated by a pipe delimiter in the nuclear control log file.
    snprintf(message, sizeof(message),
             "source:Radar|type:Air|data:%s|threat_level:%d|location:%s",
             threat_data[idx], threat_level, locations[idx]);
    caesar_encrypt(message, ciphertext, sizeof(ciphertext));

    /*This receives and sending intelligence report to the to the nuclear control.*/
    snprintf(log_msg, sizeof(log_msg),
             "Sending Intelligence: Type=Air, Details=%s, ThreatLevel=%d, Location=%s, [Encrypted] %s",
             threat_data[idx], threat_level, locations[idx], ciphertext);
    log_event("INTEL", log_msg);

    //This sends an encrypted data over network with error handling in case it fails to send intelligence.
    if (send(sock, ciphertext, strlen(ciphertext), 0) < 0) {
        snprintf(log_msg, sizeof(log_msg), "Failed to send intelligence: %s", strerror(errno));
        log_event("ERROR", log_msg);
    } else {
        intel_sent++;
    }
}

/*This generates a summary text file of the client operation of the radar
and opens it in write mode to edit. It includes details of the timestamped when the simulation ended and 
total intelligence reports have sent within the duration of the simulation.*/
void generate_summary(void) {
    FILE *summary_fp = fopen(SUMMARY_FILE, "w");
    if (!summary_fp) {
        log_event("ERROR", "Failed to create summary file");
        return;
    }

    //This creates like a box to store all of the details once the simulation ends.
    fprintf(summary_fp, "===== Radar Simulation Summary =====\n");
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(summary_fp, "Simulation End: %s\n", time_str);
    }
    fprintf(summary_fp, "Total Intelligence Reports Sent: %d\n", intel_sent);
    fprintf(summary_fp, "=====================================\n");
    fclose(summary_fp);

    //This transfers all of the summary details to the appropriate text file.
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Summary generated in %s", SUMMARY_FILE);
    log_event("SUMMARY", log_msg);
}

/*This is the main execution function that starts the radar client system.
This has the network set to create the TCP socket, server-to-client connection, 
and sending data to the nuclear control center.*/ 
int main(void) {
    srand((unsigned int)time(NULL));
    init_log_file();
    log_event("STARTUP", "Radar System initializing");

    //This creates the TCP socket of the client.
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Socket creation failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        if (log_fp) fclose(log_fp);
        return 1;
    }

    //This configures the server address for the connection with error handling if there is an invalid address.
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

    //This connects to the nuclear control center server with error handling if a connection failure occurs.
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Connection failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        close(sock);
        if (log_fp) fclose(log_fp);
        return 1;
    }

    //This prints out the message to confirm the connection to the nuclear control server.
    log_event("CONNECTION", "Connected to Nuclear Control");

    /*This is the main command loop that runs under the duration
    of the simulation; 60 seconds.*/
    time_t start_time = time(NULL);
    while (time(NULL) - start_time < SIMULATION_DURATION) {
        send_intel(sock);
        sleep(5 + (rand() % 6)); // Randomize interval
    }

    /*This shuts down the simulation sequence and 
    display a message saying the radar system has been terminated.*/
    shutdown(sock, SHUT_RDWR);
    close(sock);
    generate_summary();
    log_event("SHUTDOWN", "Radar System terminated");
    if (log_fp) fclose(log_fp);
    return 0;
}
