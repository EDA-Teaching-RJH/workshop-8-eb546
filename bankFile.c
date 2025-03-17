/* -------------------- bank_server.c -------------------- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdint.h>

#define PORT 8080
#define MAX_CLIENTS 5

typedef struct {
    int id;
    double balance;
    pthread_mutex_t lock;
} Account;

typedef struct {
    Account accounts[2];
    pthread_mutex_t log_mutex;
} Bank;

Bank bank = {
    .accounts = {
        {0, 1000.0, PTHREAD_MUTEX_INITIALIZER},
        {1, 2000.0, PTHREAD_MUTEX_INITIALIZER}
    },
    .log_mutex = PTHREAD_MUTEX_INITIALIZER
};

void log_transaction(const char* message) {
    pthread_mutex_lock(&bank.log_mutex);
    printf("[BANK LOG] %s\n", message);
    pthread_mutex_unlock(&bank.log_mutex);
}

int process_command(int client_sock, const char* cmd) {
    int account, target;
    double amount;
    char response[256];

    if(sscanf(cmd, "BALANCE %d", &account) == 1) {
        pthread_mutex_lock(&bank.accounts[account].lock);
        snprintf(response, sizeof(response), "Balance: %.2f", bank.accounts[account].balance);
        pthread_mutex_unlock(&bank.accounts[account].lock);
    }
    else if(sscanf(cmd, "DEPOSIT %d %lf", &account, &amount) == 2) {
        pthread_mutex_lock(&bank.accounts[account].lock);
        bank.accounts[account].balance += amount;
        snprintf(response, sizeof(response), "Deposit success. New balance: %.2f", 
                bank.accounts[account].balance);
        pthread_mutex_unlock(&bank.accounts[account].lock);
    }
    else if(sscanf(cmd, "WITHDRAW %d %lf", &account, &amount) == 2) {
        pthread_mutex_lock(&bank.accounts[account].lock);
        if(bank.accounts[account].balance >= amount) {
            bank.accounts[account].balance -= amount;
            snprintf(response, sizeof(response), "Withdrawal success. New balance: %.2f",
                    bank.accounts[account].balance);
        } else {
            strcpy(response, "Error: Insufficient funds");
        }
        pthread_mutex_unlock(&bank.accounts[account].lock);
    }
    else if(sscanf(cmd, "TRANSFER %d %d %lf", &account, &target, &amount) == 3) {
        Account *from = &bank.accounts[account];
        Account *to = &bank.accounts[target];
        
        // Lock ordering to prevent deadlocks
        if(account < target) {
            pthread_mutex_lock(&from->lock);
            pthread_mutex_lock(&to->lock);
        } else {
            pthread_mutex_lock(&to->lock);
            pthread_mutex_lock(&from->lock);
        }

        if(from->balance >= amount) {
            from->balance -= amount;
            to->balance += amount;
            snprintf(response, sizeof(response), 
                    "Transfer success. New balances: %d=%.2f, %d=%.2f",
                    account, from->balance, target, to->balance);
        } else {
            strcpy(response, "Transfer failed: Insufficient funds");
        }

        if(account < target) {
            pthread_mutex_unlock(&to->lock);
            pthread_mutex_unlock(&from->lock);
        } else {
            pthread_mutex_unlock(&from->lock);
            pthread_mutex_unlock(&to->lock);
        }
    }
    else {
        strcpy(response, "Invalid command");
    }

    send(client_sock, response, strlen(response), 0);
    return 0;
}

void* handle_client(void* arg) {
    int client_sock = *(int*)arg;
    char buffer[1024];
    
    while(1) {
        ssize_t bytes_read = recv(client_sock, buffer, sizeof(buffer)-1, 0);
        if(bytes_read <= 0) break;
        
        buffer[bytes_read] = '\0';
        log_transaction(buffer);
        process_command(client_sock, buffer);
    }
    
    close(client_sock);
    free(arg);
    return NULL;
}



int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if(bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    if(listen(server_fd, MAX_CLIENTS) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    
    printf("Bank server listening on port %d\n", PORT);
    
    while(1) {
        int *client_sock = malloc(sizeof(int));
        *client_sock = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        
        if(*client_sock < 0) {
            perror("accept failed");
            free(client_sock);
            continue;
        }
        
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_client, client_sock);
    }
    
    return 0;
}
