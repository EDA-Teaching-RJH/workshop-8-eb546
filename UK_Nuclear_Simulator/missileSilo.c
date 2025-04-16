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
buffer size for the missileSilo client to ping back to the server's IP address.*/
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8081
#define LOG_FILE "missileSilo.log"
#define CAESAR_SHIFT 3
#define SIMULATION_DURATION 60
#define BUFFER_SIZE 1024
#define SUMMARY_FILE "missileSilo_summary.txt"

//These are global variables that handles log file and tracks successful launches.
static FILE *log_fp = NULL;
static int missiles_launched = 0;

/*This initializes a log file with a timestamped header and opens it in write file mode. 
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
        fprintf(log_fp, "===== Missile Silo Log =====\n");
        fprintf(log_fp, "Simulation Start: %s\n", time_str);
        fprintf(log_fp, "==========================\n\n");
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

//This uses the caesar cipher to decrypt encrypted messages.
void caesar_decrypt(const char *ciphertext, char *plaintext, size_t len) {
    memset(plaintext, 0, len);
    for (size_t i = 0; ciphertext[i] && i < len - 1; i++) {
        if (isalpha((unsigned char)ciphertext[i])) {
            char base = isupper((unsigned char)ciphertext[i]) ? 'A' : 'a';
            plaintext[i] = (char)((ciphertext[i] - base - CAESAR_SHIFT + 26) % 26 + base);
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
}

//This set the launch commands formats that separates the command and target details.
int parse_command(const char *message, char *command, char *target) {
    char *copy = strdup(message);
    if (!copy) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Memory allocation failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        return 0;
    }

    //The details are separated by a pipe delimiter (|) and newline (\0) in the log file.
    command[0] = '\0';
    target[0] = '\0';
    char *token = strtok(copy, "|");
    while (token) {
        char *colon = strchr(token, ':');
        if (!colon || colon == token || !colon[1]) {
            free(copy);
            return 0;
        }
        *colon = '\0';
        char *key = token;
        char *value = colon + 1;
        if (strcmp(key, "command") == 0) {
            strncpy(command, value, 19);
            command[19] = '\0';
        } else if (strcmp(key, "target") == 0) {
            strncpy(target, value, 49);
            target[49] = '\0';
        }
        token = strtok(NULL, "|");
    }
    free(copy);
    return (command[0] != '\0' && target[0] != '\0');
}

/*This generates the summary of the client operation of the missile Silo.
It includes details of the timestamped when the simulation ended and total
missiles have launched within the duration of the simulation.*/
void generate_summary(void) {
    FILE *summary_fp = fopen(SUMMARY_FILE, "w");
    if (!summary_fp) {
        log_event("ERROR", "Failed to create summary file");
        return;
    }

    //This creates like a box to store all of the details once the simulation ends.
    fprintf(summary_fp, "===== Missile Silo Simulation Summary =====\n");
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(summary_fp, "Simulation End: %s\n", time_str);
    }
    fprintf(summary_fp, "Total Missiles Launched: %d\n", missiles_launched);
    fprintf(summary_fp, "=====================================\n");
    fclose(summary_fp);

    //This transfers all of the summary details to the appropriate text file.
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Summary generated in %s", SUMMARY_FILE);
    log_event("SUMMARY", log_msg);
}

/*This is the main execution function that starts the missile silo client system.
This has the network set to create the TCP socket, server-to-client connection, 
and receiving data from the nuclearControl center.*/ 
int main(void) {
    init_log_file();
    log_event("STARTUP", "Missile Silo System initializing");

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

    //This prints out the message to confirm the connection to the nuclear control server.
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Connection failed: %s", strerror(errno));
        log_event("ERROR", log_msg);
        close(sock);
        if (log_fp) fclose(log_fp);
        return 1;
    }

    //This prints out the message to confirm the server connection.
    log_event("CONNECTION", "Connected to Nuclear Control");

    /*This is the main command loop that runs under the duration
    of the simulation; 60 seconds.*/
    char buffer[BUFFER_SIZE];
    char plaintext[BUFFER_SIZE];
    char command[20];
    char target[50];
    char log_msg[BUFFER_SIZE];
    time_t start_time = time(NULL);

    /*This receives encryption command data with error handling to disconnect with the server
    to prevent leaks.*/
    while (time(NULL) - start_time < SIMULATION_DURATION) {
        ssize_t bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            snprintf(log_msg, sizeof(log_msg), "Disconnected: %s",
                     bytes == 0 ? "Server closed connection" : strerror(errno));
            log_event("CONNECTION", log_msg);
            break;
        }
        buffer[bytes] = '\0';

        //This is to decrypt the encryption command  by using the caesar cipher.
        caesar_decrypt(buffer, plaintext, sizeof(plaintext));
        snprintf(log_msg, sizeof(log_msg), "Received: [Encrypted] %s -> [Decrypted] %s",
                 buffer, plaintext);
        log_event("MESSAGE", log_msg);

        //This accepts valid commands to initiate the launching procedure to the target from the log file.
        if (parse_command(plaintext, command, target)) {
            if (strcmp(command, "launch") == 0) {
                snprintf(log_msg, sizeof(log_msg), "Launching missile at %s", target);
                log_event("COMMAND", log_msg);
                missiles_launched++;
                
                /*This allows to get feedback to confirm if the target is destroyed in the log file.
                It also includes an error handling function to display an error if there is an unknown command or format.*/
                char feedback[256];
                snprintf(feedback, sizeof(feedback), "Missile launched at %s successfully", target);
                log_event("FEEDBACK", feedback);
            } else {
                snprintf(log_msg, sizeof(log_msg), "Unknown command: %s", command);
                log_event("ERROR", log_msg);
            }
        } else {
            snprintf(log_msg, sizeof(log_msg), "Invalid message format: %s", plaintext);
            log_event("ERROR", log_msg);
        }
        usleep(500000); //Delay for 0.5 seconds between threats
    }

    /* This shuts down the simulation sequence and 
    display a message saying the missile silo system has been terminated.*/
    shutdown(sock, SHUT_RDWR);
    close(sock);
    generate_summary();
    log_event("SHUTDOWN", "Missile Silo System terminated");
    if (log_fp) fclose(log_fp);
    return 0;
}
