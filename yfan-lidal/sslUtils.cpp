//============================================================================
// Name        : TP.cpp
// Author      : Huseyin Kayahan
// Version     : 1.0
// Copyright   : All rights reserved. Do not distribute.
// Description : TP Program
//============================================================================


#include <iostream>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <cstdio>
#include "sslUtils.h"
#include "commonUtils.h"

BIO *bio_err = 0;
BIO *bio;
char *CN;
int result;

/*AES 256 key length is 256 bit while iv is 128 bit,
 *  since the unsigned char's length is in bytes
 *  so the length of key and IV are follows
 */

int keyLen = 32;
int ivLen = 16;
unsigned char *key = new unsigned char[keyLen];
unsigned char *iv = new unsigned char[ivLen];



int berr_exit(const char *string) {
    BIO_printf(bio_err, "%s\n", string);
    ERR_print_errors(bio_err);
    exit(0);
}

int passwd_cb(char *buf, int size, int rwflag, void *password) {
    const char *pwd = "IK2206";
    strcpy(buf, pwd);
    return (strlen(buf));
}

void check_cert(SSL *ssl,char *host)
{
    X509 *peer;
    char peer_CN[256];

     /*Check the cert chain. The chain length is automatically checked by OpenSSL
      * when we set the verify depth in the ctx */
    if(SSL_get_verify_result(ssl)!=X509_V_OK)
        berr_exit("Certificate doesn't verify");


    /*Check the common name*/
        peer=SSL_get_peer_certificate(ssl);
        X509_NAME_get_text_by_NID
        (X509_get_subject_name(peer),
         NID_commonName, peer_CN, 256);
    if(strcasecmp(peer_CN,host)){
         printf("Common name doesn't match host name\n");
        berr_exit
            ("Common name doesn't match host name");

  }
}
//=======================Implement the four functions below============================================

SSL *createSslObj(int role, int contChannel, char *certfile, char *keyfile, char *rootCApath ) {
    /* In this function, you handle
     * 1) The SSL handshake between the server and the client.
     * 2) Authentication
     *         a) Both the server and the client rejects if the presented certificate is not signed by the trusted CA.
     *         b) Client rejects if the the server's certificate does not contain a pre-defined string of your choice in the common name (CN) in the subject.
     */

    /*Initialize the SSL library and loads all SSL algorithms and error message*/


    SSL_CTX *ctx;


	if(!bio_err){

    SSL_library_init();  //Loads up the algorithms that will be used by OpenSSL
    SSL_load_error_strings();   //initial openssl error message
    bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);//An error write context

	}

    OpenSSL_add_all_algorithms();  //Load all the ssl function



    //Set up connection method for both session
    if(role == 0)
        ctx = SSL_CTX_new(SSLv23_server_method());
    else
        ctx = SSL_CTX_new(SSLv23_client_method());


    //Loads the identity certificate
    if (SSL_CTX_use_certificate_file(ctx,certfile,SSL_FILETYPE_PEM) <= 0)
    {
        printf("Certificate error!\n");
        berr_exit("The certificate of user occurred error!\n");
    }

    //Loads the private key of the identity certificate
    //set the PEM pass phrase
    SSL_CTX_set_default_passwd_cb(ctx, passwd_cb);
    if(SSL_CTX_use_PrivateKey_file(ctx,keyfile,SSL_FILETYPE_PEM) <= 0)
    {
        printf("Private key error!\n");
        berr_exit("The private key has error!\n");
    }

    //Checks if the public key matches with private key
    if (SSL_CTX_check_private_key(ctx) < 1)
    {
        printf("The private key and public key does not match!");
        berr_exit("The private key and public key does not match!");
    }

    if(!(SSL_CTX_load_verify_locations(ctx, "/home/cdev/SSLCerts/CA/rootCA.pem", NULL)))
    //Loads the trust certificate
    {
          printf("Can't read rootCA !");
          berr_exit("Can't read rootCA");
      }
    //Configure the parameters shall verify peer’s certificate
    if (role == 0){
        SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
        CN = (char *) "TP Client yfan@kth.se lidal@kth.se";}
    else{
        SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
        CN = (char *) "TP Server yfan@kth.se lidal@kth.se";}

    /* set up a secure channel */
    SSL *ssl;
    ssl = SSL_new(ctx);    //set up ssl environment
    bio = BIO_new_socket(contChannel,BIO_NOCLOSE);
    //Wrap the TCP channel (file descriptor) named contChannel with a buffered input/output.
    SSL_set_bio(ssl, bio, bio);

    /* Set the verification depth to 1 */
    SSL_CTX_set_verify_depth(ctx,1);

    //Create ssl connection between server and client
    //Perform the SSL handshake. Use accept if server, connect if client.
    //server
    if (role == 0)
    {
        result = SSL_accept(ssl);
        if (result <= 0)
        {
            printf("accept error! %i %i\n", SSL_get_error(ssl, result), result);
            berr_exit("accept error!\n");
        }
        if(true)
                     check_cert(ssl,CN);  //Check the common name if it is not identified throw the error


    }
    //client
    else
    {
        result = SSL_connect(ssl);
        if (result  <= 0)
        {
            printf("connection error! %i %i", SSL_get_error(ssl, result), result);
            berr_exit("connection error!\n");
        }

    if(true)
              check_cert(ssl,CN);  //Check the common name if it is not identified throw the error
      }

    printf("Finish set up! \n");

    return ssl;

}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


void dataChannelKeyExchange(int role, SSL *ssl) {
    /* In this function, you handle
     * 1) The generation of the key and the IV that is needed to symmetrically encrypt/decrypt the IP datagrams over UDP (data channel).
     * 2) The exchange of the symmetric key and the IV over the control channel secured by the SSL object.
     */

    /* Server generates Key and iv and send to the client */

    if(role == 0){
        for (int i = 0; i < 32; i++){
            key[i] = (unsigned char)rand();   //Randomly generate Channel key
        }


        for (int i = 0; i < 16; i++){
            iv[i] = (unsigned char)rand();  //Randomly generate IV
        }

        SSL_write(ssl, key, keyLen);
        SSL_write(ssl, iv, ivLen);
    }

    else{
        // After client receive the key and IV from server
        result = SSL_read(ssl, key, keyLen);
        if (result != keyLen)
        {
            printf("Key's length is wrong!");
            berr_exit("The key's length is wrong!");
        }

        result = SSL_read(ssl, iv, ivLen);
        if (result != ivLen)
        {
            printf("iv's length is wrong!");
            berr_exit("iv's length is wrong!");
        }
    }
}

int encrypt(unsigned char *plainText, int plainTextLen,
            unsigned char *cipherText) {
    /* In this function, you store the symmetrically encrypted form of the IP datagram at *plainText, into the memory at *cipherText.
     * The memcpy below directly copies *plainText into *cipherText, therefore the tunnel works unencrypted. It is there for you to
     * test if the tunnel works initially, so remove that line once you start implementing this function.
     */

    EVP_CIPHER_CTX *ctx;

    int len;

    int cipherTextLen;

    /* Create and initialize the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialize the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, cipherText, &len, plainText, plainTextLen))
        handleErrors();
    cipherTextLen = len;

    /* Finalize the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, cipherText + len, &len)) handleErrors();
    cipherTextLen += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return cipherTextLen;

}

int decrypt(unsigned char *cipherText, int cipherTextLen,
            unsigned char *plainText) {
    /* In this function, you symmetrically decrypt the data at *cipherText and store the output IP datagram at *plainText.
     * The memcpy below directly copies *cipherText into *plainText, therefore the tunnel works unencrypted. It is there for you to
     * test if the tunnel works initially, so remove that line once you start implementing this function.
     */


    if(cipherTextLen % 16 != 0){
        return 0;
    }
    EVP_CIPHER_CTX *ctx;

    int len;

    int plainTextLen;

    /* Create and initialize the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialize the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plainText, &len, cipherText, cipherTextLen))
        handleErrors();
    plainTextLen = len;

    /* Finalize the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plainText + len, &len)) handleErrors();
    plainTextLen += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plainTextLen;

}


