#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BLOCK_SIZE 8  // 64-bit blocks for demonstration

// Simple block cipher functions
void madryga_encrypt(uint8_t *block, uint64_t key) {
    // Demonstration cipher (not secure for real-world use)
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] ^= (key >> (8 * i)) & 0xFF;  // XOR with key bytes
        block[i] = (block[i] << 4) | (block[i] >> 4);  // Nibble swap
    }
}

void madryga_decrypt(uint8_t *block, uint64_t key) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        block[i] = (block[i] << 4) | (block[i] >> 4);  // Reverse nibble swap
        block[i] ^= (key >> (8 * i)) & 0xFF;  // XOR with key bytes
    }
}

void encrypt_file(const char *input_path, const char *output_path, uint64_t key) {
    FILE *input = fopen(input_path, "rb");
    FILE *output = fopen(output_path, "wb");
    
    if (!input || !output) {
        perror("File error");
        exit(EXIT_FAILURE);
    }

    uint8_t buffer[BLOCK_SIZE];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE, input)) > 0) {
        if (bytes_read < BLOCK_SIZE) {
            memset(buffer + bytes_read, 0x90, BLOCK_SIZE - bytes_read);
        }
        madryga_encrypt(buffer, key);
        fwrite(buffer, 1, BLOCK_SIZE, output);
    }

    fclose(input);
    fclose(output);
}

void decrypt_file(const char *input_path, const char *output_path, uint64_t key) {
    FILE *input = fopen(input_path, "rb");
    FILE *output = fopen(output_path, "wb");
    
    if (!input || !output) {
        perror("File error");
        exit(EXIT_FAILURE);
    }

    uint8_t buffer[BLOCK_SIZE];
    size_t bytes_read;
    long file_size, bytes_processed = 0;

    fseek(input, 0, SEEK_END);
    file_size = ftell(input);
    fseek(input, 0, SEEK_SET);

    while ((bytes_read = fread(buffer, 1, BLOCK_SIZE, input)) > 0) {
        madryga_decrypt(buffer, key);
        bytes_processed += bytes_read;

        if (bytes_processed == file_size) {
            int padding = BLOCK_SIZE - 1;
            while (padding >= 0 && buffer[padding] == 0x90) {
                padding--;
            }
            fwrite(buffer, 1, padding + 1, output);
        } else {
            fwrite(buffer, 1, BLOCK_SIZE, output);
        }
    }

    fclose(input);
    fclose(output);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s <encrypt|decrypt> <input> <output> <key>\n", argv[0]);
        return 1;
    }

    uint64_t key = strtoull(argv[4], NULL, 10);
    
    if (strcmp(argv[1], "encrypt") == 0) {
        encrypt_file(argv[2], argv[3], key);
    } else if (strcmp(argv[1], "decrypt") == 0) {
        decrypt_file(argv[2], argv[3], key);
    } else {
        printf("Invalid operation\n");
        return 1;
    }

    printf("Operation completed successfully\n");
    return 0;
}
