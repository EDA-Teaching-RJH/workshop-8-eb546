//These are the standard library headers included for the program such as inputs, outpus, strings, sockets, etc
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <errno.h>

/*These are to define ports for different clients. 
Included a log and summary text file for nuclearControl to 
display logs, encryption and decryption messages and 
operation details of the performance after the simulation */
#define PORT_SILO 8081
#define PORT_SUB 8082
#define PORT_RADAR 8083
#define PORT_SAT 8084
#define MAX_CLIENTS 4
#define LOG_FILE "nuclearControl.log"
#define CAESAR_SHIFT 3
#define SIMULATION_DURATION 60
#define BUFFER_SIZE 1024
#define SUMMARY_FILE "nuclearControl_summary.txt"

//These are structured to contain data of threat reports
typedef struct {
    char source[20];
    char type[20];
    char data[256];
    int threat_level;
    char location[50];
} Intel;

/*These are structured to track the client's connection 
to the server with its own socket, IP address, ports and threads 
to protect data from improving multiple tasks performances*/
typedef struct {
    int sock;
    char ip[INET_ADDRSTRLEN];
    int port;
    bool valid;
    pthread_t thread;
} Client;

/*These are global variables for server/client management system
and designed to be thread-safe so they can be safely modified by threads */
static Client clients[MAX_CLIENTS];
static atomic_int client_count = 0;
static pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_bool running = true;
static FILE *log_fp = NULL;
static int threats_detected = 0;
static int commands_issued = 0;

/*This block is to intialize the nuclearControl log file with a timestamp
It includes an error handling function and making the file in write mode to edit. 
The log file is program to set into the current time to convert it into a string. */
void init_log_file(void) {
    log_fp = fopen(LOG_FILE, "w");
    if (!log_fp) {
        perror("Failed to create log file");
        exit(1);
    }
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(log_fp, "===== Nuclear Control Log =====\n");
        fprintf(log_fp, "Simulation Start: %s\n", time_str);
        fprintf(log_fp, "=============================\n\n");
        fflush(log_fp);
    }
}

/*This is to log every messages with a timestamp and each category's detail*/
void log_event(const char *event_type, const char *details) {
    if (!log_fp) return;
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(log_fp, "[%s] %-12s %s\n", time_str, event_type, details);
        fflush(log_fp);
    }
}

//This is to use the caesar cipher to encrypt only letters in the plaintext messages 
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

//This is to use the caesar cipher to decrypt only letters in the encrypted messages 
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

/*This is for memory allocation pass an intelligence message into an Intel struct
This also includes error handling to return a 0 for invalid format. */
int parse_intel(const char *message, Intel *intel) {
    char *copy = strdup(message);
    if (!copy) {
        log_event("ERROR", "Memory allocation failed for parsing");
        return 0;
    }

    /*This is to clear the struct and split the input string into 
    tokens. It also includes error handling to return a 0 for invalid format. */ 
    memset(intel, 0, sizeof(Intel));
    int fields_found = 0;
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

        /*This is to label all the key data that were picked up by the radar or satellite.
        It also includes error handling to return a 0 for invalid format. */
        if (strcmp(key, "source") == 0) {
            strncpy(intel->source, value, sizeof(intel->source) - 1);
            fields_found++;
        } else if (strcmp(key, "type") == 0) {
            strncpy(intel->type, value, sizeof(intel->type) - 1);
            fields_found++;
        } else if (strcmp(key, "data") == 0) {
            strncpy(intel->data, value, sizeof(intel->data) - 1);
            fields_found++;
        } else if (strcmp(key, "threat_level") == 0) {
            char *endptr;
            intel->threat_level = (int)strtol(value, &endptr, 10);
            if (*endptr != '\0' || intel->threat_level < 0) {
                free(copy);
                return 0;
            }
            fields_found++;
        } else if (strcmp(key, "location") == 0) {
            strncpy(intel->location, value, sizeof(intel->location) - 1);
            fields_found++;
        }
        token = strtok(NULL, "|");
    }
    free(copy);
    return fields_found == 5; //Maximum of 5 field data 
}

/*This is to send encrypted launch commands to missileSilo and submarine to attack.
Then it displays the order from command and where the target is located. */
void send_command_to_clients(const char *location) {
    char command[256];
    char ciphertext[BUFFER_SIZE];
    char log_msg[BUFFER_SIZE];
    snprintf(command, sizeof(command), "command:launch|target:%s", location);
    caesar_encrypt(command, ciphertext, sizeof(ciphertext));

    //This is to deisplay the ecrypted and decrypted logs versions from the radar or satellite.
    snprintf(log_msg, sizeof(log_msg), "Encrypted command: %s", ciphertext);
    log_event("COMMAND", log_msg);
    snprintf(log_msg, sizeof(log_msg), "Decrypted command: %s", command);
    log_event("COMMAND", log_msg);

    /*This is to handle any errors during the simulation and be threaded safe 
    to synchronize access to the clients or shared data. */
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].valid && (clients[i].port == PORT_SILO || clients[i].port == PORT_SUB)) {
            if (send(clients[i].sock, ciphertext, strlen(ciphertext), 0) < 0) {
                snprintf(log_msg, sizeof(log_msg), "Failed to send command to %s:%d", 
                         clients[i].ip, clients[i].port);
                log_event("ERROR", log_msg);
            } else {
                snprintf(log_msg, sizeof(log_msg), "Sent command to %s:%d", 
                         clients[i].ip, clients[i].port);
                log_event("COMMAND", log_msg);
                commands_issued++;
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

/*This is to communicate with one of the clients and display
its messages with encrypted and decrypted logs and connection status. */
void *handle_client(void *arg) {
    Client *client = (Client *)arg;
    int client_sock = client->sock;
    char buffer[BUFFER_SIZE];
    char plaintext[BUFFER_SIZE];
    Intel intel;
    char log_msg[BUFFER_SIZE];

    //This is to log new intelligence messages from a different client.
    snprintf(log_msg, sizeof(log_msg), "Client connected from %s:%d", 
             client->ip, client->port);
    log_event("CONNECTION", log_msg);

    /*This to continue to simulate until the program's been terminated.
    Also to handle any errors or if disconnection occurs between the server and client. */
    while (atomic_load(&running)) {
        ssize_t bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            snprintf(log_msg, sizeof(log_msg), "Client %s:%d disconnected: %s", 
                     client->ip, client->port, bytes == 0 ? "closed connection" : strerror(errno));
            log_event("CONNECTION", log_msg);
            break;
        }
        buffer[bytes] = '\0';

        //Displays encrypted messages 
        snprintf(log_msg, sizeof(log_msg), "Encrypted message: %s", buffer);
        log_event("MESSAGE", log_msg);

         //Displays dedcrypted messages
        caesar_decrypt(buffer, plaintext, sizeof(plaintext));
        snprintf(log_msg, sizeof(log_msg), "Decrypted message: %s", plaintext);
        log_event("MESSAGE", log_msg);

        /*Parses and processes important details to form as an intelligence report*/
        if (parse_intel(plaintext, &intel)) {
            snprintf(log_msg, sizeof(log_msg), 
                     "Source: %s, Type: %s, Details: %s, Threat Level: %d, Location: %s",
                     intel.source, intel.type, intel.data, intel.threat_level, intel.location);
            log_event("THREAT", log_msg);
            threats_detected++;

             /*This triggers a launch command to the missileSilo and submarine if the radar or satellite detects a threat level above 70. 
            Also this includes an error handling function if na invalid message occurs */
            if (intel.threat_level > 70 && 
                (strcmp(intel.source, "Radar") == 0 || strcmp(intel.source, "Satellite") == 0)) {
                send_command_to_clients(intel.location);
            }
        } else {
            snprintf(log_msg, sizeof(log_msg), "Invalid message: %s", plaintext);
            log_event("ERROR", log_msg);
        }
    }

    //This is to cleanup the disconnection process. 
    close(client_sock);
    pthread_mutex_lock(&clients_mutex);
    client->valid = false;
    atomic_fetch_sub(&client_count, 1);
    pthread_mutex_unlock(&clients_mutex);
    return NULL;
}

//This is to start a test mode for simulating scenarios of different types of  air and sea threats. 
void simulate_war_test(void) {
    const char *threat_types[] = {"Air", "Sea"};
    const char *threat_data[] = {"Enemy Aircraft", "Ballistic Missile", "Enemy Submarine", "Naval Fleet"};
    const char *locations[] = {"North Atlantic", "Norwegian Sea", "English Channel", "Arctic Ocean"};
    Intel intel;
    char log_msg[BUFFER_SIZE];

    //This for loop receive threats randomy during a test mode. It receives 3 Intelligence reports.
    for (int i = 0; i < 3 && atomic_load(&running); i++) {
        snprintf(intel.source, sizeof(intel.source), "TEST");
        int idx = rand() % 4;
        snprintf(intel.type, sizeof(intel.type), "%s", threat_types[idx % 2]);
        snprintf(intel.data, sizeof(intel.data), "%s", threat_data[idx]);
        intel.threat_level = (rand() % 100 < 50) ? 71 + (rand() % 30) : 10 + (rand() % 61);
        snprintf(intel.location, sizeof(intel.location), "%s", locations[rand() % 4]);

        //This is to process and display threat logs with a delay of 10 seconds.
        snprintf(log_msg, sizeof(log_msg), 
                 "Source: %s, Type: %s, Details: %s, Threat Level: %d, Location: %s",
                 intel.source, intel.type, intel.data, intel.threat_level, intel.location);
        log_event("WAR_TEST", log_msg);
        threats_detected++;

        //This is to initiate a launch if the threat level is above 70
        if (intel.threat_level > 70) {
            send_command_to_clients(intel.location);
        }
        sleep(10); //Delay for 10 seconds between threats
    }
}

//This is to generate a summary report at the end of the simulation program
void generate_summary(void) {
    FILE *summary_fp = fopen(SUMMARY_FILE, "w");
    if (!summary_fp) {
        log_event("ERROR", "Failed to create summary file");
        return;
    }

    /*The report box starts here and contains the time when the simulation ended, 
    total threats it detected, total commands send to the silo and submarine, and
    number of clients it connected to the server.*/
    fprintf(summary_fp, "===== Nuclear Control Simulation Summary =====\n");
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    if (time_str) {
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(summary_fp, "Simulation End: %s\n", time_str);
    }
    fprintf(summary_fp, "Total Threats Detected: %d\n", threats_detected);
    fprintf(summary_fp, "Total Commands Issued: %d\n", commands_issued);
    fprintf(summary_fp, "Connected Clients:\n");
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].valid) {
            fprintf(summary_fp, "  - %s:%d\n", clients[i].ip, clients[i].port);
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    fprintf(summary_fp, "=====================================\n");
    fclose(summary_fp);

    //This shows where the summary report has been generated in an text file.
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Summary generated in %s", SUMMARY_FILE);
    log_event("SUMMARY", log_msg);
}

//This is to accept new client connections the user enters in a seperate terminal.
void *accept_clients(void *arg) {
    int server_sock = *(int *)arg;
    int port = *(int *)((char *)arg + sizeof(int));
    char log_msg[BUFFER_SIZE];

    /*This is a while loop that accepts incoming client connections on a listening socket.
    It also handles error and log failures. */
    while (atomic_load(&running)) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            if (errno != EINTR && atomic_load(&running)) {
                snprintf(log_msg, sizeof(log_msg), "Accept failed on port %d: %s", port, strerror(errno));
                log_event("ERROR", log_msg);
            }
            continue;
        }

        //This allocates the memory of incoming clients. It also includes handles error.
        Client *client = malloc(sizeof(Client));
        if (!client) {
            snprintf(log_msg, sizeof(log_msg), "Client allocation failed on port %d", port);
            log_event("ERROR", log_msg);
            close(client_sock);
            continue;
        }

        //This initialises to store thre client's data such as its socket, port, and IP.
        client->sock = client_sock;
        client->port = port;
        client->valid = true;
        inet_ntop(AF_INET, &client_addr.sin_addr, client->ip, sizeof(client->ip));

        //This is a safety procedure to handle thread and safely increments the counter without race conditions.
        pthread_mutex_lock(&clients_mutex);
        int added = 0;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i].valid) {
                clients[i] = *client;
                atomic_fetch_add(&client_count, 1);
                added = 1;
                break;
            }
        }
        pthread_mutex_unlock(&clients_mutex);

         /* This sets the maximum amount of clients the server can accept,
        and once it does, it rejects incoming clients*/
        if (!added) {
            snprintf(log_msg, sizeof(log_msg), "Max clients reached, rejecting %s:%d", client->ip, port);
            log_event("ERROR", log_msg);
            close(client_sock);
            free(client);
            continue;
        }

        /*This creates a new thread to handle a client connection in case one fails,
        it cleans up its old resources and logs the failure with error handling to close the socket,
        and freeing the memory prevent a leak. */
        if (pthread_create(&client->thread, NULL, handle_client, client) != 0) {
            snprintf(log_msg, sizeof(log_msg), "Thread creation failed for %s:%d", client->ip, port);
            log_event("ERROR", log_msg);
            pthread_mutex_lock(&clients_mutex);
            client->valid = false;
            atomic_fetch_sub(&client_count, 1);
            pthread_mutex_unlock(&clients_mutex);
            close(client_sock);
            free(client);
            continue;
        }
        pthread_detach(client->thread);
    }
    return NULL;
}

/* This int function initializes a TCP server on given port and
 configures its socket with en error handling function in all cases. */
int start_server(int port) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        close(server_sock);
        return -1;
    }

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_sock);
        return -1;
    }

    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        close(server_sock);
        return -1;
    }

    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Server started on port %d", port);
    log_event("STARTUP", log_msg);
    return server_sock;
}

/*This is the int main function that simulates the control center either in normal or test mode.
Its support by an implemented the multi-threaded server system and handles
multiple client connections across different ports. It includes a the duration timer to show how much
time is left before shutting down the server and disconnect all client connections. */
int main(int argc, char *argv[]) {
    int test_mode = 0;
    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        test_mode = 1;
        srand((unsigned int)time(NULL));
    }

    init_log_file(); //Opens a log file to keep track of the events.

    int ports[] = {PORT_SILO, PORT_SUB, PORT_RADAR, PORT_SAT};
    int server_socks[MAX_CLIENTS] = {-1, -1, -1, -1};
    pthread_t accept_threads[MAX_CLIENTS] = {0};

    /*These for looops starts the servers on multiple ports. If it fails, it
    closes all opened sockets prior.*/ 
    for (int i = 0; i < MAX_CLIENTS; i++) {
        server_socks[i] = start_server(ports[i]);
        if (server_socks[i] < 0) {
            for (int j = 0; j < i; j++) {
                if (server_socks[j] != -1) {
                    close(server_socks[j]);
                }
            }
            if (log_fp) fclose(log_fp);
            return 1;
        }
    }

    /*This for loop launches threads that stores sockets and port to accept clients. */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        int *args = malloc(sizeof(int) * 2);
        if (!args) {
            log_event("ERROR", "Failed to allocate memory for accept thread args");
            continue;
        }
        args[0] = server_socks[i];
        args[1] = ports[i];
        if (pthread_create(&accept_threads[i], NULL, accept_clients, args) != 0) {
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), "Failed to create accept thread for port %d", ports[i]);
            log_event("ERROR", log_msg);
            free(args);
            continue;
        }
    }

    //This runs the simulation in test mode.
    if (test_mode) {
        simulate_war_test();
    }

    time_t start_time = time(NULL);
    while (time(NULL) - start_time < SIMULATION_DURATION && atomic_load(&running)) {
            
        //Keeps track how much time left within a 60 seconds duration.
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Simulation running: %ld seconds remaining",
                 SIMULATION_DURATION - (time(NULL) - start_time));
        log_event("SIMULATION", log_msg);
        sleep(5);
    }

    atomic_store(&running, false);

    //This closes all server sockets.
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (server_socks[i] != -1) {
            shutdown(server_socks[i], SHUT_RDWR);
            close(server_socks[i]);
        }
    }

    //This wait for all threads to finish 
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (accept_threads[i]) {
            pthread_join(accept_threads[i], NULL);
        }
    }

    //This disconnect all clients at the end.
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].valid) {
            shutdown(clients[i].sock, SHUT_RDWR);
            close(clients[i].sock);
            clients[i].valid = false;
        }
    }
    atomic_store(&client_count, 0);
    pthread_mutex_unlock(&clients_mutex);

    generate_summary();

    //Prints out the shutdown message in the log file.
    log_event("SHUTDOWN", "Nuclear Control terminated");
    if (log_fp) fclose(log_fp);
    return 0;
}

