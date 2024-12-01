#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <math.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

int sock;

const int P = 23;
const int G = 9;
const int a = 4;
const int AES_KEY_SIZE = 16;  // 128-bit key for AES-128

int diffie_Hellman_public_key() {
    int k = ((int)pow(G, a)) % P;
    printf("k = %d\n", k);
    return k;
}

int diffie_Hellman_symmetric_key(int k) {
    int ka = ((int)pow(k, a)) % P;
    return ka;
}

int base64_encode(const unsigned char *input, int length, unsigned char *output) {
    return EVP_EncodeBlock(output, input, length);
}

// Function to convert integer symmetric key to 16-byte AES key
void generate_aes_key_from_integer(int int_key, unsigned char *aes_key) {
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        aes_key[i] = (unsigned char)(int_key & 0xFF);
    }
}



int encrypt_aes_128_cbc(const unsigned char *key, const unsigned char *iv, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len = 0;

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        printf("Error initializing encryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        printf("Error during encryption update.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    // Add padding and finalize encryption
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len)) {
        printf("Error during encryption finalization.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

void create_socket() {
    // create the socket
    sock = socket(AF_INET, SOCK_STREAM, 0);

    // setup an address
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(8080);

    connect(sock, (struct sockaddr *) &server_address, sizeof(server_address));
}

int main() {
    char buf[256];

    printf("\n\t>>>>>>>>>> Chat Client <<<<<<<<<<\n\n");
   
    int pub_key;
    
    // Create socket and connect to the server
    create_socket();

    int counter = 0;
    int symmetric_key;
    unsigned char aes_key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    int pub_key_recv; 
     //const char iv[] = "8587b319704cde9d2739c5243ee84d5f";
    //const char iv[AES_BLOCK_SIZE] = "8587b319704cde9d";

    while (1) {
            
        if(counter == 0)  // Exchange public keys and generate symmetric key
        {
            printf("*******Sending public key******\n");
            pub_key = diffie_Hellman_public_key();
            send(sock, &pub_key, sizeof(pub_key), 0);
            
            printf("*******Receiving public key******\n");
            recv(sock, &pub_key_recv, sizeof(pub_key_recv), 0);

            printf("Public key received is = %d\n", pub_key_recv);

            symmetric_key = diffie_Hellman_symmetric_key(pub_key_recv);
            printf("Symmetric key generated is = %d\n", symmetric_key);

            // Generate AES key from the symmetric key integer
            generate_aes_key_from_integer(symmetric_key, aes_key);

        

            // Generate a random IV
            if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
               fprintf(stderr, "Error generating random IV\n");
               return 1;
            }

              send(sock, iv, AES_BLOCK_SIZE, 0);  // Send IV first         

        
        }
        
        else if (counter == 1) // Take user input, encrypt it, and send
        {
            // Take inputs for email, username, and password
            char username[64], email[64], password[64];
            printf("Enter Email: ");
            fgets(email, sizeof(email), stdin);
            email[strcspn(email, "\n")] = 0;

            printf("Enter Username: ");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = 0; // Remove newline

            printf("Enter Password: ");
            fgets(password, sizeof(password), stdin);
            password[strcspn(password, "\n")] = 0;

            // Prepare plaintext for encryption
            char plaintext[256];
            snprintf(plaintext, sizeof(plaintext), "email:%s,username:%s,password:%s", email, username, password);

            // Encrypt the data
             unsigned char ciphertext[256];
            //int ciphertext_len = encrypt_aes_128_cbc(aes_key, iv, (unsigned char *)plaintext, strlen(plaintext), ciphertext);
         
             unsigned char iv_copy[AES_BLOCK_SIZE];
             memcpy(iv_copy, iv, AES_BLOCK_SIZE); // Copy IV for encryption

             // Use iv_copy in encryption instead of iv
             int ciphertext_len = encrypt_aes_128_cbc(aes_key, iv_copy, (unsigned char *)plaintext, strlen(plaintext), ciphertext);

            // Calculate required size for Base64 encoded output
            int base64_len = 4 * ((ciphertext_len + 2) / 3);
            unsigned char base64_ciphertext[base64_len];

            // Encode the ciphertext to Base64
            int encoded_len = base64_encode(ciphertext, ciphertext_len, base64_ciphertext);

           // Send IV and Base64 encoded ciphertext to the server
          
           //printf("The iv send has the value: %s\n", iv);
           
           
            send(sock, base64_ciphertext, encoded_len, 0);  // Send Base64 ciphertext
           
         
           // printf("Encrypted data = %s\n", base64_ciphertext);
            printf("Encrypted data sent to server.\n");


         }
        
        else  
        {
            char server_message[256];
            int bytes_received = recv(sock, server_message, sizeof(server_message) - 1, 0);
    
            if (bytes_received > 0)
           {
            server_message[bytes_received] = '\0'; // Null-terminate the received message
        
            if (strcmp(server_message, "Enter username again") == 0)
            {
               // Prompt the user to enter a new username
               char new_username[256];
               printf("The username is already taken. Please enter a new username: ");
               fgets(new_username, sizeof(new_username), stdin);
               new_username[strcspn(new_username, "\n")] = '\0'; // Remove newline

               // Encrypt the new username (assuming encryption function exists)
               unsigned char encrypted_username[256];
               unsigned char base64_username[256];
               //int encrypted_len = encrypt_aes_128_cbc(aes_key, iv, (unsigned char *)new_username, strlen(new_username), encrypted_username);
                unsigned char iv_copy[AES_BLOCK_SIZE];
                memcpy(iv_copy, iv, AES_BLOCK_SIZE); // Copy IV for encryption
                int encrypted_len = encrypt_aes_128_cbc(aes_key, iv_copy, (unsigned char *)new_username, strlen(new_username), encrypted_username);

               int base64_len = 4 * ((encrypted_len + 2) / 3);
               unsigned char base64_ciphertext[base64_len]; 
                
               int encoded_len = base64_encode(encrypted_username, encrypted_len, base64_username);
               
              // printf("base64_username = %s\n", base64_username);
               base64_username[encoded_len] = '\0';
               // Send the encrypted username to the server
               send(sock, base64_username, encoded_len, 0);

               printf("New encrypted username sent to server.\n");
               
      

               exit(0);
            }
           }

        }

         counter++;
    }

    // Close the socket after communication
    close(sock);

    return 0;
  }

