#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/types.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#define EXEC_FILE argv[0]
#define PORT argv[1]
#define SERVER_IP argv[2]
#define BUFFER 2048
#define NAME_LEN 32

volatile sig_atomic_t flag = 0;
int sockfd = 0;
char name[NAME_LEN];

//Functions

/*
 *      Alerts the user of a openssl error
 * 
 *      parameters : none
 * 
 *      return : none
 */
void handleErrors();


/*
 *      Prints the message writing spot and fulshes all remaining text 
 * 
 *      parameters : none
 * 
 *      return : none
 */
void StrOverwriteStdout();


/*
 *      Replaces the newline charecter with \0 character of a message
 * 
 *      parameters : message and its length
 * 
 *      return : none
 */
void StrTrimLf(char *arr, int length);


/*
 *      Catches users input of Cntrl+C and changes the flags value
 * 
 *      parameters : signal number
 * 
 *      return : none
 */
void CatchCtrlCAndExit(int sig);


/*
 *      Encrypts and sends users messages
 * 
 *      parameters : none
 * 
 *      return : none
 */
void SendMsgHandler();


/*
 *      Decrypts and prints the received messages
 * 
 *      parameters : none
 * 
 *      return : none
 */
void RecvMsgHandler();


/*
 *      The function used for decryption
 * 
 *      parameters : buffer for decrypted text, decrypted texts length, key, 
 *                   initialization vector(to verify the key), the text
 * 
 *      return : length of the decrypted message
 */
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
            
            
            
/*
 *      The function used for encryption
 * 
 *      parameters : the text, decrypted texts length, key, 
 *                   initialization vector(to verify the key), 
 *                   buffer for encrypted text
 * 
 *      return : length of the encrypted message
 */
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

int main(int argc, char **argv)
{
    if(argc != 3)
    {
        printf("Usage: %s <port> <ip>\n", EXEC_FILE);
        return EXIT_FAILURE;
    }
    
    char *ip = SERVER_IP;
    int port = atoi(PORT);
    
    signal(SIGINT, CatchCtrlCAndExit);
    
    do
    {
        printf("Enter your name: ");
        fgets(name, NAME_LEN, stdin);
        StrTrimLf(name, strlen(name));
        
        if(strlen(name) > NAME_LEN - 1 || strlen(name) < 2)
            printf("Name length has to be 2 to %d char long\n", NAME_LEN - 1);
    }
    while(strlen(name) > NAME_LEN - 1 || strlen(name) < 2);
    
    struct sockaddr_in server_addr;
    //Socket settings
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip);
    server_addr.sin_port = htons(port);
    
    //Connect to the server
    int err = connect(sockfd, (struct sockaddr *)&server_addr, 
        sizeof(server_addr));
    if(err == -1)
    {
        printf("ERROR: connect\n");
        return EXIT_FAILURE;
    }
    
    //Send name
    send(sockfd, name, NAME_LEN, 0);
    printf("-----WELCOME TO CRACKIFY-----\n");
    
    pthread_t sendMsgThread;
    if(pthread_create(&sendMsgThread, NULL, 
        (void *)SendMsgHandler, NULL) != 0)
    {
        printf("ERROR: pthread\n");
        return EXIT_FAILURE;
    }
    
    pthread_t recvMsgThread;
    if(pthread_create(&recvMsgThread, NULL, 
        (void *)RecvMsgHandler, NULL) != 0)
    {
        printf("ERROR: pthread\n");
        return EXIT_FAILURE;
    }
    
    while(1)
    {
        if(flag)
        {
            printf("\nBye\n");
            break;
        }
    }
    close(sockfd);
    
    
    return EXIT_SUCCESS;
}

void StrOverwriteStdout()
{
    printf("%s", "> ");
    fflush(stdout);
}

void StrTrimLf(char *arr, int length)
{
    for(int i = 0; i < length; i++)
    {
        if(arr[i] == '\n')
        {
            arr[i] = '\0';
            break;
        }
    }
}

void CatchCtrlCAndExit(int sig)
{
    flag = 1;
}

void RecvMsgHandler()
{
    
    unsigned char decryptedtext[BUFFER];
    int ciphertext_len;
    int decryptedtext_len;
    char message[BUFFER] = {};
    while(1)
    {
        int receive = recv(sockfd, message, BUFFER, 0);
        
        if(receive > 0)
        {
            // A 256 bit key unsigned 
            unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; 
            // 128 bit IV unsigned 
            unsigned char  *iv = (unsigned char *)"0123456789012345";

            ciphertext_len = strlen(message);
            //Decrypt the ciphertext
            decryptedtext_len = decrypt((unsigned char*)message, ciphertext_len, key, iv, decryptedtext);
            // Add a NULL terminator. We are expecting printable text 
            decryptedtext[decryptedtext_len] = '\0';

            printf("%s \n", decryptedtext);
            StrOverwriteStdout();
        }
        else if(receive == 0)
            break;
        memset(message, 0, sizeof(message));
    }
}

void handleErrors()
{
    printf("Openssl error\n");
}

void SendMsgHandler()
{
    int ciphertext_len; 
    // A 256 bit key unsigned 
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901"; 
    // 128 bit IV unsigned 
    unsigned char  *iv = (unsigned char *)"0123456789012345";
    
    char buffer[2 * NAME_LEN + BUFFER] = {};
    char message[BUFFER] = {};
    
    while(1)
    {
        StrOverwriteStdout();
        fgets(message, BUFFER, stdin);
        StrTrimLf(message, BUFFER);
        
        if(strncmp(message, "exit",4) == 0)
            break;
        else
        {
            sprintf(buffer, "%s: %s\n", name, message);

            unsigned char ciphertext[BUFFER]; // Buffer for the decrypted text 
            
            //Encrypt the plaintext
            ciphertext_len = encrypt ((unsigned char*)buffer, strlen ((char *)buffer), key, iv, ciphertext);

            send(sockfd, ciphertext, ciphertext_len, 0);
        }
        bzero(message, BUFFER);
        bzero(buffer, 2 * NAME_LEN + BUFFER);
    }
    CatchCtrlCAndExit(2);
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
