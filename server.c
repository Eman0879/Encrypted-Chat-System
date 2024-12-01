#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

const int P = 23;
const int G = 9;
const int a = 3;

#define AES_KEY_SIZE 16
#define BUFFER_SIZE 256
#define SALT_SIZE 8
#define HASH_SIZE 64



// Function to generate a public key using Diffie-Hellman
int diffie_Hellman_public_key() {
    int k = ((int)pow(G, a)) % P;
    printf("k = %d\n", k);
    return k;
}

// Function to generate a symmetric key using Diffie-Hellman
int diffie_Hellman_symmetric_key(int k) {
    int ka = ((int)pow(k, a)) % P;
    return ka;
}

// Function to Base64 decode data
int base64_decode(const unsigned char *input, int length, unsigned char *output) {
    return EVP_DecodeBlock(output, input, length);
}

// Function to convert integer symmetric key to 16-byte AES key
void generate_aes_key_from_integer(int int_key, unsigned char *aes_key) {
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        aes_key[i] = (unsigned char)(int_key & 0xFF);
    }
}


int decrypt_aes_128_cbc(const unsigned char *key, const unsigned char *iv, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len = 0;

    if (!ctx) {
        printf("Error: failed to create EVP_CIPHER_CTX.\n");
        return -1;
    }

    // Initialize decryption
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        printf("Error initializing decryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Log the IV, key, and ciphertext length for debugging
    // printf("Decrypting with AES Key: ");
    // for (int i = 0; i < AES_KEY_SIZE; i++) printf("%02x", key[i]);
    // printf("\nIV: ");
    // for (int i = 0; i < AES_BLOCK_SIZE; i++) printf("%02x", iv[i]);
    // printf("\nCiphertext length: %d\n", ciphertext_len);

    // Decrypt the data
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        printf("Error during decryption update.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    // Finalize decryption (check for padding errors)
    if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len) <= 0) {
        printf("Error during decryption finalization (likely padding error).\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Null-terminate for printing as a string
    plaintext[plaintext_len] = '\0';
    return plaintext_len;
}





void generate_salt(unsigned char *salt, size_t size) {
    RAND_bytes(salt, size);
}

// Function to hash a password using SHA-256 and a salt
void hash_password(const char *password, const unsigned char *salt, size_t salt_len, unsigned char *hash) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, salt, salt_len);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, hash, NULL);
    EVP_MD_CTX_free(mdctx);
}

void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex_str) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0';  // Null-terminate the string
}

int username_exists(FILE *file, const char *username) {
    char line[BUFFER_SIZE];
    char file_username[BUFFER_SIZE];

    // Rewind file to start
    rewind(file);
    while (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf(line, "email:%*[^,], username:%[^,],", file_username) == 1) {
            if (strcmp(file_username, username) == 0) {
                return 1; // Username found
            }
        }
    }
    return 0; // Username not found
}

void save_credentials(const char *email, const char *username, const char *password) {
    FILE *file = fopen("creds.txt", "a+");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    // Generate a salt
    unsigned char salt[SALT_SIZE];
    generate_salt(salt, SALT_SIZE);

    // Hash the password with the salt
    unsigned char hash[HASH_SIZE];
    hash_password(password, salt, SALT_SIZE, hash);

    // Convert salt and hash to hex strings
    char salt_hex[SALT_SIZE * 2 + 1];
    char hash_hex[HASH_SIZE * 2 + 1];
    bytes_to_hex(salt, SALT_SIZE, salt_hex);
    bytes_to_hex(hash, 32, hash_hex);  // SHA-256 hash is 32 bytes

    // Write data to the file
    fprintf(file, "email:%s, username:%s, password:%s, salt:%s\n", email, username, hash_hex, salt_hex);
    printf("Credentials saved to creds.txt.\n");

    fclose(file);
}

// Assume this function is called after decryption
void handle_decrypted_credentials(const char *email, const char *username, const char *password, int client_socket, unsigned char aes_key[AES_KEY_SIZE], unsigned char iv[AES_BLOCK_SIZE]) {
    FILE *file = fopen("creds.txt", "a+");
    if (file == NULL) {
        perror("Error opening file"); 
        return;
    }



    // Check if username exists
    if (username_exists(file, username)) {
        char message[] = "Enter username again";
        send(client_socket, message, strlen(message), 0);
        fclose(file);
         
         unsigned char encrypted_username[BUFFER_SIZE];
   
    
       memset(encrypted_username, 0, BUFFER_SIZE);
       int bytes_received = recv(client_socket, encrypted_username, sizeof(encrypted_username) - 1, 0);
       if (bytes_received <= 0) {
         
         printf("Error: Failed to receive encrypted username.\n");
         return;
       }

     // encrypted_username[bytes_received] = '\0';
    
    // printf("Received Base64 encrypted username: %s\n", encrypted_username);

     unsigned char decoded_username[BUFFER_SIZE];
     int decoded_len = base64_decode(encrypted_username, strlen((char *)encrypted_username), decoded_username);
     //int decoded_len = base64_decode(encrypted_username, strlen((char *)encrypted_username), decoded_username);

    
     if (decoded_len <= 0)
     {
        printf("Error: Base64 decoding failed with length: %d\n", decoded_len);
        return;
     }

     //printf("Decoded username length: %d\n", decoded_len);
    
    //  printf("AES Key: ");
    //  for (size_t i = 0; i < AES_KEY_SIZE; i++)
    //  {
    //     printf("%02x", aes_key[i]);
    //  }
    //  printf("\n");

    //  printf("IV: ");
    //  for (size_t i = 0; i < AES_BLOCK_SIZE; i++)
    //  {
    //      printf("%02x", iv[i]);
    //  }

     unsigned char decrypted_text[BUFFER_SIZE];
     memset(decrypted_text, 0, BUFFER_SIZE);
     unsigned char iv_copy[AES_BLOCK_SIZE];
     memcpy(iv_copy, iv, AES_BLOCK_SIZE); // Copy IV for encryption
     int decrypted_len = decrypt_aes_128_cbc(aes_key, iv_copy, decoded_username, decoded_len, decrypted_text);
     //decrypted_text[decrypted_len] = '\0';
     printf("Decrypted length: %d\n", decrypted_len);
     return;
    }

    // If the username is unique, save the credentials
    save_credentials(email, username, password);
}

int main() {
    unsigned char buf[BUFFER_SIZE];
    char message[BUFFER_SIZE] = "Server: ";

    printf("\n\t>>>>>>>>>> Chat Server <<<<<<<<<<\n\n");

    // create the server socket
    int server_socket;
    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    // define the server address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8080);
    server_address.sin_addr.s_addr = INADDR_ANY;

    // bind the socket to the specified IP and port
    bind(server_socket, (struct sockaddr*) &server_address, sizeof(server_address));
    listen(server_socket, 5);
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char iv_copy[AES_BLOCK_SIZE];
    
    // Prepare to receive encrypted message
    unsigned char base64_ciphertext[BUFFER_SIZE];
    unsigned char decoded_ciphertext[BUFFER_SIZE];
    char email[BUFFER_SIZE], username[BUFFER_SIZE], password[BUFFER_SIZE];
    int decoded_len;

    int counter = 0;
 
    while (1) 
    {
        // accept incoming connections
        int client_socket;
        client_socket = accept(server_socket, NULL, NULL);
   
        // create a new process to handle the client
        pid_t new_pid;
        new_pid = fork();
        if (new_pid == -1) {
            // error occurred while forking
            printf("Error! Unable to fork process.\n");
        } else if (new_pid == 0) {
            // child process handles the client
            while (1) 
            {
                int pub_key_recv; 
                if (counter == 0) {  // receiving public key

                    printf("*******Receiving public key******\n");
                    recv(client_socket, &pub_key_recv, sizeof(pub_key_recv), 0);
                    printf("Public key received is= %d\n", pub_key_recv);

                    int symmetric_key = diffie_Hellman_symmetric_key(pub_key_recv);
                    printf("Symmetric key generated is= %d\n", symmetric_key);

                    int pub_key_own = diffie_Hellman_public_key();
                    printf("*******Sending public key******\n");
                    send(client_socket, &pub_key_own, sizeof(pub_key_own), 0);


                    generate_aes_key_from_integer(symmetric_key, aes_key);
                    
                    memset(iv, 0, AES_BLOCK_SIZE);

                    // Receive the IV (assumed to be 16 bytes)
                    recv(client_socket, iv, AES_BLOCK_SIZE, 0); 
                        
                } 

                else if (counter == 1)
               {
             

                 // Clear the base64 ciphertext buffer before receiving data
                memset(base64_ciphertext, 0, sizeof(base64_ciphertext));

                // Receive the Base64-encoded ciphertext
                recv(client_socket, base64_ciphertext, sizeof(base64_ciphertext), 0);

                // Print the received Base64 ciphertext (as a string)
                //printf("Received Base64 ciphertext: %s\n", base64_ciphertext);  

               // Decode the Base64 ciphertext
                decoded_len = base64_decode(base64_ciphertext, strlen((char *)base64_ciphertext), decoded_ciphertext);
          

               // Decrypt the decoded ciphertext
               unsigned char decrypted_text[BUFFER_SIZE];
               memcpy(iv_copy, iv, AES_BLOCK_SIZE); // Copy IV for decryption
               int decrypted_len = decrypt_aes_128_cbc(aes_key, iv_copy, decoded_ciphertext, decoded_len, decrypted_text);

               printf("Decrypted message: %s\n", decrypted_text);
    
               // Extract and print the individual fields

               sscanf((char *)decrypted_text, "email:%[^,],username:%[^,],password:%s", email, username, password);

               printf("Email: %s\n", email);
               printf("Username: %s\n", username);
               printf("Password: %s\n", password);   

    
                
            }
            else
            {

              handle_decrypted_credentials(email,username,password,client_socket,aes_key,iv);
            
              exit(0);
              // Standard chat handling
              memset(buf, 0, sizeof(buf));
              recv(client_socket, buf, sizeof(buf), 0);

                    if (strcmp((char *)buf, "exit") == 0) {
                        printf("Client disconnected.\n");
                        break;
                    }

                    printf("Client: %s\n", buf);
                    printf("You (Server): ");
                    char response[BUFFER_SIZE];
                    fgets(response, sizeof(response), stdin);

                    strcpy(message + 8, response);
                    send(client_socket, message, sizeof(message), 0);
                 
            }

            counter++;
        }
          
            close(client_socket);
            exit(0);
        }
         else
        {
            close(client_socket);
        }
    }

    close(server_socket);
    return 0;
}
