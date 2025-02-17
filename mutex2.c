#include <stdio.h>
#include <pthread.h>
#include <time.h>

#define NUM_THREADS 20
#define ITERATIONS 1000000

// Shared resources
pthread_mutex_t counter_mutex;
int shared_counter = 0;
int enable = 0;

void* increment_counter(void* arg) {
    for (int i = 0; i < ITERATIONS; i++) {
       pthread_mutex_lock(&counter_mutex);
        shared_counter++;  // Protected operation
       pthread_mutex_unlock(&counter_mutex);
    }
    return NULL;
}

int main() {

    clock_t t; 
    t = clock();
    pthread_t threads[NUM_THREADS];
    int i = 0;
    while (i < 10)
    {
    // Initialize mutex
    if (pthread_mutex_init(&counter_mutex, NULL) != 0) {
        perror("Mutex initialization failed");
        return 1;
    }
    
    }
}