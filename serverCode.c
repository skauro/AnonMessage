#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
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
#define MAX_CLIENTS 10
#define BUFFER 2048
#define NAME_LEN 32


static _Atomic unsigned int cliCount = 0;
static int uID = 10;
 
typedef struct
{
    struct sockaddr_in address;
    int sockfd;
    int uID;
    char name[NAME_LEN];
}client;

client *clients[MAX_CLIENTS];

pthread_mutex_t clientsMutex = PTHREAD_MUTEX_INITIALIZER;


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


/*
 *      Prints the ip of user
 * 
 *      parameters : the struct holding all information
 * 
 *      return : none
 */
void PrintIP(struct sockaddr_in addr);


/*
 *      Adds a client to queue
 * 
 *      parameters : client info
 * 
 *      return : none
 */
void QueueAdd(client *cl);


/*
 *      removes client from queue
 * 
 *      parameters : client info
 * 
 *      return : none
 */
void QueueRemove(int uID);

/*
 *      Sends the messages sent from all clients
 * 
 *      parameters : the message, id of the user who sent the message
 * 
 *      return : none
 */
void SendMessage(char *s, int uID);


/*
 *      Connects to client and deals with the messages sent and received
 * 
 *      parameters : thread for the client
 * 
 *      return : none
 */
void *HandleClient(void *arg);


/*
 *      Sets the context for the user
 * 
 *      parameters : the context of the user
 * 
 *      return : none
 */
void configure_context(SSL_CTX *ctx);


/*
 *      Creates the contect for the user
 * 
 *      parameters : none
 * 
 *      return : none
 */
SSL_CTX *create_context();

int main(int argc, char **argv)
{
    if(argc != 3)
    {
        printf("Usage: %s <port> <ip>\n", EXEC_FILE);
        return EXIT_FAILURE;
    }
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    char *ip = SERVER_IP;
    int port = atoi(PORT);
    SSL_CTX *ctx;
    SSL *ssl;
    
    int option = 1;
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;
    struct sockaddr_in cli_addr;
    pthread_t tid;
    
    //Socket settings
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(port);
    
    //Signals
    signal(SIGPIPE, SIG_IGN);
    
    ctx = create_context();

    configure_context(ctx);

    if(setsockopt(listenfd, SOL_SOCKET, (SO_REUSEPORT | SO_REUSEADDR),
        (char *)&option, sizeof(option)) < 0)
    {
        perror("ERROR: setsockopt\n");
        return EXIT_FAILURE;
    }
    
    //Bind
    if(bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("ERROR: bind\n");
        return EXIT_FAILURE;
    }
    
    //Listen
    if(listen(listenfd, 10) < 0)
    {
        perror("ERROR: listen\n");
        return EXIT_FAILURE;
    }
    
    printf("Server succesfully started\n");
    
    while(1)
    {
        socklen_t cliLen = sizeof(cli_addr);
        connfd = accept(listenfd, (struct sockaddr *)&cli_addr, &cliLen); 
        SSL *ssl;
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, connfd);
        
        //Check if maximum clients is reached
        if((cliCount + 1) == MAX_CLIENTS)
        {
            printf("Maximum clients connected. Connection rejected\n");
            PrintIP(cli_addr);
            close(connfd);
            continue;
        }
        
        //Client settings
        client *cli = (client *)malloc(sizeof(client));
        cli->address = cli_addr;
        cli->sockfd = connfd;
        cli->uID = uID++;
        
        //Add client to queue
        QueueAdd(cli);
        pthread_create(&tid, NULL, &HandleClient, (void *)cli);
        
        //Reduce CPU usage
        sleep(10);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    return EXIT_SUCCESS;
}

void PrintIP(struct sockaddr_in addr)
{
    printf("%d.%d.%d.%d",
            addr.sin_addr.s_addr & 0xff,
            (addr.sin_addr.s_addr & 0xff00) >> 8,
            (addr.sin_addr.s_addr & 0xff0000) >> 16,
            (addr.sin_addr.s_addr & 0xff000000) >> 24);
}

void handleErrors()
{
    printf("Openssl error\n");
}

void SendMessage(char *s, int uID)
{
    pthread_mutex_lock(&clientsMutex);
    for(int i = 0; i < MAX_CLIENTS; ++i)
    {
        if(clients[i])
        {
            if(clients[i]->uID != uID)
            {
                if(write(clients[i]->sockfd, s, strlen(s)) < 0)
                {
                    perror("ERROR: write to descriptor failed\n");
                    break;
                }
            }
        }
    }
    pthread_mutex_unlock(&clientsMutex);
}

void StrOverwriteStdout()
{
    printf("\r%s", "> ");
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

void QueueAdd(client *cl)
{
    pthread_mutex_lock(&clientsMutex);
    for(int i = 0; i < MAX_CLIENTS; ++i)
    {
        if(!clients[i])
        {
            clients[i] = cl;
            break;
        }
    }
    
    pthread_mutex_unlock(&clientsMutex);
}

void QueueRemove(int uID)
{
    pthread_mutex_lock(&clientsMutex);
    for(int i = 0; i < MAX_CLIENTS; ++i)
    {
        if(clients[i])
        {
            if(clients[i]->uID == uID)
            {
                free(clients[i]);
                clients[i] = NULL;
                break;
            }
        }
    }
    
    pthread_mutex_unlock(&clientsMutex);
}


void *HandleClient(void *arg)
{
    char buffOut[BUFFER];
    char name[NAME_LEN];
    int leaveFlag = 0;
    cliCount++;

     // A 256 bit key 
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";

     // 128 bit IV 
    unsigned char *iv = (unsigned char *)"0123456789012345";
    
    unsigned char ciphertext[BUFFER];

    // Buffer for the decrypted text 
    unsigned char decryptedtext[BUFFER];

    int decryptedtextLen;

    client *cli = (client *)arg;
    
    //Name
    if(recv(cli->sockfd, name, NAME_LEN, 0) <= 0 || strlen(name) < 2 ||
        strlen(name) >= NAME_LEN - 1)
    {
        printf("Name was incorrect\n");
        leaveFlag = 1;
    }
    else
    {
        strcpy(cli->name, name);
        sprintf(buffOut, "%s has joined\n", cli->name);
        printf("%s", buffOut);

     //Encrypt the plaintext 
    encrypt ((unsigned char *)buffOut, strlen ((char *)buffOut), key, iv,
                              ciphertext);
        SendMessage((char*)ciphertext, cli->uID);
    }
    bzero (ciphertext, BUFFER);
    bzero(buffOut, BUFFER);
    
    while(1)
    {
        if(leaveFlag)
            break;
        
        int receive = recv(cli->sockfd, buffOut, BUFFER, 0); 
        
        //Decrypt the ciphertext 
        decryptedtextLen = decrypt((unsigned char*)buffOut, strlen(buffOut), key, iv, decryptedtext);

       // Add a NULL terminator. We are expecting printable text 
        decryptedtext[decryptedtextLen] = '\0';

        strcpy(buffOut, (char*)decryptedtext);
        if(receive > 0)
        {
            if(strlen(buffOut) > 0)
            {
                //mdea kas enam seda vaja......
                StrTrimLf(buffOut, strlen(buffOut));

                printf("%s -> %s\n", buffOut, cli->name);

                encrypt ((unsigned char*)buffOut, strlen ((char *)buffOut), key, iv, ciphertext);
                SendMessage((char*)ciphertext, cli->uID);
            }
        }
        else if(receive == 0 || strcmp(buffOut, "exit") == 0)
        {
            sprintf(buffOut, "%s has left\n", cli->name);
            printf("%s", buffOut);
             encrypt ((unsigned char*)buffOut, strlen ((char *)buffOut), key, iv, ciphertext);
            SendMessage((char*)ciphertext, cli->uID);
            leaveFlag = 1;
        }
        else
        {
            printf("ERROR: -1\n");
            leaveFlag = 1;
        }
        bzero(buffOut, BUFFER);
        bzero(decryptedtext, BUFFER);
        bzero(ciphertext, BUFFER);
    }
    
    //Delete client from queue
    pthread_mutex_lock(&clientsMutex);
    close(cli->sockfd);
    QueueRemove(cli->uID);
    free(cli);
    cliCount--;
    pthread_detach(pthread_self());
    
    return NULL;
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (ctx == NULL) 
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)  
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "certificate.pem", SSL_FILETYPE_PEM) <= 0) 
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) 
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }


    if(!SSL_CTX_check_private_key(ctx))
    {
        printf("Private key does not match\n");
        exit(EXIT_FAILURE);
    }
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
