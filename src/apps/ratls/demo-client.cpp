/****************************************************************************
 *                                                                          *
 *      demo-client.cpp - A proxy relaying data between UART and TLS        *
 *                                                                          *
 * This program is part of the iNGENIOUS UC3 demo. It runs on a Linux / M3  *
 * platform and reads data from the carriage sensor via UART. The client    *
 * then forwards this data to a (dashboard) server component. The client    *
 * and the server communicate via an encrypted and attested TCP connection  *
 * (RATLS on top of OpenSSL).                                               *
 *                                                                          *
 * Author: Carsten Weinhold (SSL / RATLS setup),                            * 
 *         Robert Walther   (SSL / RATLS setup),                            *
 *         Till Miemietz    (the rest ;)                                    *
 *                                                                          *
 ****************************************************************************/



/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#define _CRT_SECURE_NO_WARNINGS

#define TLS1_3_CERT_MSG_EXT

#include <stdio.h>                  /* Standard I/O functions               */
#include <stdlib.h>                 /* Memory management & friends...       */
#include <string.h>                 /* String manipulation, memset etc.     */
#include <errno.h>
#include <unistd.h>                 /* UNIX standard utilities              */
#include <termios.h>                /* Terminal control functions           */

#include <sys/types.h>              /* Standard system types                */
#include <sys/stat.h>               /* Get information about files          */
#include <fcntl.h>                  /* File control, needed for open syscall*/

#include <stdlib.h>                                                             
#include <stdio.h>                                                              
#include <iostream>                                                             
#include <map>                                                                  
#include <chrono>                                                               
                                                                                
#include <openssl/asn1.h>                                                       
#include <openssl/x509.h>                                                       
#include <openssl/pem.h>                                                        
#include <openssl/bn.h>                                                         
#include <openssl/ocsp.h>                                                       
#include <openssl/cms.h>                                                        
#include <openssl/ssl.h>                                                        
#include <openssl/err.h>                                                        
                                                                                
#include "errorhelper.h"                                                        
#include "ratls.h"                                                              
#include "ratls-tpm2.h"                                                         
#include "benchmark.h"                                                          
#include "demo.h"                                                               

using namespace Err;
using namespace TpmCpp;
                                                                                
/****************************************************************************
 *                                                                          *
 *                     global definitions and macros                        *
 *                                                                          *
 ****************************************************************************/


/* Path to serial USB device that the sensor data shall be read from.       */
#define USBSER_DEVPATH "/dev/ttyUSB1"

/* Size of sensor data header in Bytes (Header is "FEDCBA00")               */
#define HEADER_SIZE 8

/* Size of one streaming record in Bytes                                    */
#define RECORD_SIZE 282

/* Size of a record's payload in Bytes                                      */
#define PAYLOAD_SIZE (RECORD_SIZE - HEADER_SIZE)

/****************************************************************************
 *                                                                          *
 *                           global variables                               *
 *                                                                          *
 ****************************************************************************/


int uart_fd = -1;                       /* FD to UART interface             */

#if defined(__m3__)                                                             
#include <uart/uart.h>                  // Definitions for using UART on M3
#include <Tpm2.h>                                                               
const char * const tls_cert_chain_path = "/tls/fullchain.pem";                  
const char * const tls_priv_key_path = "/tls/privkey.pem";                      
#else                                                                           
#include <tss/Tpm2.h>                                                           
const char * const tls_cert_chain_path = "data/fullchain.pem";                  
const char * const tls_priv_key_path = "data/privkey.pem";                      
#endif  

RATLS::TpmRoT *tpmRoT = nullptr;

SSL_SESSION *currentSession = nullptr;

RATLS::RAClientContext raContext;

TpmCpp::ByteVec sealAuthValue = { 4, 43, 1, 34 };

// for testing purposes, client and server use the same PCR slots:
//  - PCR7: trusted computing base / OS
//  - PCR23: the app (either client or server)
std::vector<uint32_t> pcrSlotsToAttest = { 7, 23 };

/* Currently, the values expected from the PCRs are hardcoded and the same   *
 * for both the client and the server. TPM setup is done in a separate shell *
 * script which is part of this repository.                                  */
std::vector<TPM2B_DIGEST> expectedPcrValues = {
    TPM2B_DIGEST({0x2b, 0x13, 0xad, 0xc4, 0xb1, 0xd4, 0x10, 0x79, 0x06, 0x9e, 0x99, 0x1c, 0x99,
                  0xbf, 0xbd, 0x47, 0x40, 0xa8, 0x18, 0x6f, 0x54, 0xee, 0x0f, 0xee, 0x97, 0xce,
                  0x6d, 0x33, 0x57, 0xeb, 0xcd, 0xaf}),
    TPM2B_DIGEST({0x01, 0x98, 0x58, 0x25, 0x82, 0x88, 0x9d, 0xb8, 0x64, 0xcf, 0x7f, 0x39, 0x3a,
                  0xfc, 0xb5, 0x5b, 0x30, 0x37, 0x80, 0xb5, 0x61, 0x06, 0x99, 0x2c, 0x23, 0x51,
                  0x0a, 0xd2, 0x07, 0x31, 0xfa, 0x1c})
};

std::vector<uint32_t> sealingPcrSlots = { 7, 23 };

const int32_t defaultData = 42;

/* Representation of the record header as a string                          */
const char * const header = "FEDCBA00";

/* Fields for reporting unencrypted data records to remote UDP server       */
int         udpsock = -1;                   /* UDP socket                   */
const char *udpip   = "192.168.42.48";      /* IP address of server         */
uint16_t    udpport = 6000;                 /* Port Number of server        */

struct sockaddr_in udpsrv;                  /* Address struct for UDP server*/


/****************************************************************************
 *                                                                          *
 *                          static helper functions                         *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Removes all occurences of special characters ('\n' / '\r') from a given 
 * chunk of memory. In the scope of this function, "removed" means that the 
 * memory will be contracted by memmoving memory contents after the offending 
 * character one byte to the front. The resulting "space" at the end of the
 * memory chunk is zeroed.
 *
 * Params: ptr - Pointer to the starting memory address.
 *         len - The length of the memory chunk to work on.
 *
 * Returns: The number of characters purged from the input memory section.
 */
static unsigned int purge_newlines(unsigned char *ptr, size_t len) {
    unsigned int i;
    unsigned int purged = 0;                    // No. of chars removed

    // Step 1: Iterate through the array, removing all occurences of '\n'
    for (i = 0; i < len; i++) {
        if (ptr[i] == '\n' || ptr[i] == '\r') {
            // Only do a memmove, if we are not at the end of the array, 
            // otherwise we could get into OOB problems here
            if ((len - i) > 1) {
                memmove(ptr + i, ptr + i + 1, len - i - 1);
            }

            // Update the removed-chars counter
            purged++;
        }
    }

    // Step 2: Zero the remainder of the array
    for (i = 1; i <= purged; i++) {
        ptr[len - i] = '\0';
    }

    return(purged);
}

#ifndef __m3__
/****************************************************************************
 *
 * "Connects" to the sensor device by opening the respective serial device  
 * and setting suitable communication parameters. Currently, the serial line 
 * the the sensor will be configured as follows:
 *  - 115200 Baud
 *  - No parity
 *  - 8 Data bits
 *  - 1 Stop bit
 *  - No flow control
 *
 * Returns: 0 on success, 1 otherwise.
 */
static int setup_serial(void) {
    struct termios tty_cfg;             // TTY configuration

    // Open the serial device. Operations shall be sync. Keep in mind that 
    // the new TTY device MUST NOT become our controlling terminal (O_NOCTTY)
    uart_fd = open(USBSER_DEVPATH, O_RDWR | O_SYNC | O_NOCTTY);
    if (uart_fd < 0) {
        fprintf(stderr, "Failed to open serial device %s (%d).\n", 
                USBSER_DEVPATH, errno);
        return(1);
    }

    // Get the current configuration attributes of the serial line
    memset(&tty_cfg, 0, sizeof(struct termios));
    if (tcgetattr(uart_fd, &tty_cfg) != 0) {
        fprintf(stderr, "Failed to query TTY attributes.\n");
        return(1);
    }

    // Set serial speed to 155200 Baud
    if ((cfsetospeed(&tty_cfg, B115200) != 0) ||
        (cfsetispeed(&tty_cfg, B115200) != 0)) {
        fprintf(stderr, "Failed to configure termios struct.\n");
        return(1);
    }

    // Set other terminal configurations according to our needs
    tty_cfg.c_cflag     = (tty_cfg.c_cflag & ~CSIZE) | CS8;   // 8 Bit chars
    tty_cfg.c_cflag    &= ~PARENB;                            // no parity bit
    tty_cfg.c_cflag    &= ~CSTOPB;                            // 1 stop bit

    tty_cfg.c_iflag    &= ~(IXON | IXOFF | IXANY);            // no input flowc

    tty_cfg.c_cc[VMIN]  = 0;                                  // min. 0 chars
    tty_cfg.c_cc[VTIME] = 100;                                // 10s timeout

    // Configure serial line, changes shall become effective immediately
    if (tcsetattr(uart_fd, TCSANOW, &tty_cfg) != 0) {
        fprintf(stderr, "Failed to configure serial line.\n");
        return(1);
    }

    return(0);
}
#endif /* __m3__ */

/****************************************************************************
 *
 * Initialize the serial interface. This is only a wrapper function that
 * selects the appropriate handler, depending on the platform this program is
 * running on.
 */
static int init_serial(void) {
    #if defined(__m3__)
        uart_init();
        return(0);
    #else
        return(setup_serial());
    #endif
}

/****************************************************************************
 *
 * Read from the serial interface. This is only a wrapper function that 
 * selects the appropriate handler, depending on the platform this program is
 * running on.
 */
static ssize_t serial_read(int fd, void* buf, size_t count) {
    #if defined(__m3__)
        return(uart_fifo_read((uint8_t *) buf, count));
    #else
        return(read(fd, buf, count));
    #endif
}

static SOCKET openConnection(char const *hostname, int port) {
    SOCKET sock = -1;
    struct addrinfo addrInfoHints;
    struct addrinfo *addrInfo = NULL;

    memset(&addrInfoHints, 0, sizeof(addrInfoHints));
    addrInfoHints.ai_family   = AF_UNSPEC;
    addrInfoHints.ai_socktype = SOCK_STREAM;
    addrInfoHints.ai_protocol = IPPROTO_TCP;

    chk(getaddrinfo(hostname, std::to_string(port).c_str(),
                    &addrInfoHints, &addrInfo) == 0, "getaddrinfo");

    for (struct addrinfo *ai = addrInfo; ai != NULL; ai = ai->ai_next) {
        sock    = chksys(socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol),
                         "open socket");
        int res = connect(sock, ai->ai_addr, ai->ai_addrlen);
        
        if (res == 0)
            break;
        
        close(sock);
        sock = -1;
    }

    freeaddrinfo(addrInfo);

    return chk(sock, "connect to socket");
}

static SSL *doConnection(char const *serverAddress, SSL_CTX *ctx,
    bool attested, SSL_SESSION *session = nullptr) {
    
    fprintf(stderr, "\n\n=================================\n");

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "WARNING: ssl == NULL\n");
    }

    BI::demoClient.setConnectionStatus(BI::DemoStatus::Connecting,
                                       BI::DemoReport::NoSend);
    BI::demoClient.setTlsStatus(BI::DemoStatus::Connecting, "", 
                                BI::DemoReport::NoSend);
    
    if (attested)
        BI::demoClient.setAttestationStatus(BI::DemoStatus::Connecting, "", "", "");
    else
        BI::demoClient.setAttestationStatus(BI::DemoStatus::Unknown, "", "", "");

    SOCKET connectSocket;
    try {
        connectSocket = openConnection(serverAddress, 4433);
    }
    catch (const std::runtime_error &e) {
        BI::demoClient.setConnectionStatus(BI::DemoStatus::Error);
        throw std::runtime_error(std::string("cannot connect to server: ") + e.what());
    }

    SSL_set_fd(ssl, connectSocket);

    if (session != nullptr && SSL_SESSION_is_resumable(session)) {
        int res = SSL_set_session(ssl, session);
        if (res != 1) {
            printf("%s\n", ERR_error_string(SSL_get_error(ssl, res), NULL));
            ERR_print_errors_fp(stderr);
            
            throw std::runtime_error("Cannot resume SSL session.");
        }
    }

    int status = SSL_connect(ssl);
    if (status != 1) {
        printf("%s\n", ERR_error_string(SSL_get_error(ssl, status), NULL));
        ERR_print_errors_fp(stderr);
        
        throw std::runtime_error("SSL_connect failed.");
    }

    if (!attested)
        BI::demoClient.setTlsStatus(BI::DemoStatus::Ok, "Barkhausen Institute");
    
    BI::demoClient.setConnectionStatus(BI::DemoStatus::Ok);
    BI::demoClient.setConnectionStatus(BI::DemoStatus::Active);

    return(ssl);
}

/*****************************************************************************  
 *                                                                              
 * Shuts down an SSL connection. The SSL context is freed. Also, the            
 * underlying socket is closed. The demoClient will be reset as well.           
 *                                                                              
 * Params: ssl - The SSL context to shut down.                                  
 */                                                                             
static void shutdownSSLCtx(SSL *ssl) {
    int res = 0;                    // Result of SSL_shutdown operation.

    // Extract the underlying FD from the SSL context (we assume that both
    // read and write direction use the same fd here)
    int ssl_fd = SSL_get_fd(ssl);

    if (ssl_fd < 0) {
        // Error, bail out here
        return;
    }

    // Do the shutdown. We might need to read data again to wait for the
    // other end to acknowledge the graceful connection termination
    res = SSL_shutdown(ssl);
    printf("1st SSL_shutdown: %d\n", res);
    if (res == 0) {
        char tmp[1024];

        printf("SSL_read: %d\n", SSL_read(ssl, tmp, sizeof(tmp)));
        res = SSL_shutdown(ssl);
        printf("2nd SSL_shutwown: %d\n", res);
    }

    SSL_free(ssl);
    closesocket(ssl_fd);

    BI::demoClient.reset();
}

static SSL_CTX *createSSLContext() {
    const SSL_METHOD *method = TLS_client_method();

    SSL_CTX *ctx      = SSL_CTX_new(method);
    X509_STORE *store = SSL_CTX_get_cert_store(ctx);

#ifdef _WIN32
    // Load all root certificates from systems trust store
    HCERTSTORE winStore;
    PCCERT_CONTEXT certContext = NULL;
    X509 *x509;

    winStore = CertOpenSystemStore(NULL, L"ROOT");

    if (winStore) {
        while (certContext = CertEnumCertificatesInStore(winStore, certContext)) {
            x509 = NULL;
            x509 = d2i_X509(NULL, (const unsigned char**)&certContext->pbCertEncoded, certContext->cbCertEncoded);
            if (x509) {
                int i = X509_STORE_add_cert(store, x509);

                if (i == 1) {
                    char subject[1024];
                    X509_NAME_oneline(X509_get_subject_name(x509), subject, sizeof(subject));
                    //std::cout << "Root certificate added " << subject << std::endl;
                }
                X509_free(x509);
            }
        }

        CertFreeCertificateContext(certContext);
        CertCloseStore(winStore, 0);
    }
#endif
#ifdef __linux__
    FILE *server_cert_file;
    X509 *server_cert;
    server_cert_file = chksys(fopen(tls_cert_chain_path, "r"), "open cert chain file");
    server_cert = PEM_read_X509(server_cert_file, nullptr, nullptr, nullptr);
    fclose(server_cert_file);

    chk(X509_STORE_add_cert(store, server_cert) == 1, "add server cert");
    //X509_print_fp(stdout, server_cert);
    char subject[1024];
    X509_NAME_oneline(X509_get_subject_name(server_cert), subject, sizeof(subject));

    //std::cout << "Root certificate added " << subject << std::endl;
    //printf("\n\n=================================\n");

    X509_free(server_cert);
#endif

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT |
                                        SSL_SESS_CACHE_NO_INTERNAL_STORE);

    long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_2 | 
                 SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, flags);

    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, tls_cert_chain_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, tls_priv_key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_use_certificate_chain_file(ctx, tls_cert_chain_path);

    return ctx;
}

/****************************************************************************
 *                                                                          *
 *                          function implementation                         *
 *                                                                          *
 ****************************************************************************/


/***            Callback functions for SSL / RATLS library                ***/

int verifyCB(int preverifyOk, X509_STORE_CTX *ctx) {
    return 1;
}

int callbackNewSession(SSL *ssl, SSL_SESSION *sess) {
    if (currentSession != nullptr) {
        SSL_SESSION_free(currentSession);
    }

    // Duplicate the session so that it is not invalidated after ssl is 
    // closed ungracefully
    currentSession = SSL_SESSION_dup(sess);

    return 1;
}

uint8_t *createRequestCB(size_t *outLen) {
    *outLen      = 16;
    uint8_t *out = new uint8_t[*outLen];
    ByteVec b    = Crypto::GetRand(*outLen);
    
    for (size_t i = 0; i < *outLen; i++) {
        out[i] = b[i];
    }

    return out;
}

RATLS::RAQuote* remoteAttestCB(uint8_t *nonce, size_t nonceLen) {
    if (BI::demoClient.clientIsDemo()) {
#ifdef RATLS_DEBUG_OUTPUT
        printf("[INFO: %d] Client, remoteAttestCB: fake attestation [DEMO_CLIENT]\n",
               __LINE__);
#endif
        RATLS::RAQuote* quoteRA = new RATLS::RAQuote();
        quoteRA->quoteData      = new uint8_t[42];
        quoteRA->quoteDataLen   = 42;
        
        return quoteRA;
    }

    return tpmRoT->remoteAttest(pcrSlotsToAttest, nonce, nonceLen);
}

static std::string extractHexStringFromSerialization(std::string haystack, 
            std::string needle, size_t hexBytesOffset, size_t numBytes) {

    // extract hex bytes of format "3BB02D05 4F48637F ..." from serialized string
    size_t needlePos = haystack.find(needle) + needle.length();
    size_t hexBytesLength = numBytes * 2 + (numBytes / 4) - 1;
    std::string hexBytes  = haystack.substr(needlePos + hexBytesOffset,
                                            hexBytesLength);

    // remove spaces
    for (size_t spacePos = 8; spacePos < hexBytes.length(); spacePos += 8)
        hexBytes.erase(spacePos, 1);

    // add ":" after each hex byte
    for (size_t colonPos = 2; colonPos < hexBytes.length(); colonPos += 1 + 2)
        hexBytes.insert(colonPos, 1, ':');

    return hexBytes;
}

bool checkQuoteCB(RATLS::RAQuote &raQuote, uint8_t *nonceExpected, 
                  size_t nonceExpectedLen) {
    
    bool ok = tpmRoT->checkQuote(raQuote, pcrSlotsToAttest, expectedPcrValues, 
                                 nonceExpected, nonceExpectedLen);

    using namespace TpmCpp;
    std::string publicJson = std::string((char*)raQuote.quoteData);
    std::string quoteJson  = std::string(((char*)raQuote.quoteData + publicJson.size() + 1));
    QuoteResponse quote;
    quote.Deserialize(SerializationType::JSON, quoteJson);

    TPMT_PUBLIC pubKey;
    pubKey.Deserialize(SerializationType::JSON, publicJson);

    // printf("%s%s", pubKey.ToString().c_str(), quote.ToString().c_str());

    std::string pubKeyStr = extractHexStringFromSerialization(pubKey.ToString(), "BYTE[] buffer = [", 13, 32);
    std::string pcrDigest = extractHexStringFromSerialization(quote.ToString(), "BYTE[] pcrDigest = [", 0, 32);

    if (ok) {
        BI::demoClient.setAttestationStatus(BI::DemoStatus::Ok, pubKeyStr, pcrDigest, "RATLS Demo");
    } else {
        BI::demoClient.setAttestationStatus(BI::DemoStatus::Error, pubKeyStr, pcrDigest, "RATLS Demo");
        BI::demoClient.reset();
    }

    return ok;
}

uint8_t *sealSessionSecretCB(uint32_t sessionSecret, size_t *sealingDataLength) {
    if (BI::demoClient.clientIsDemo()) {
#ifdef RATLS_DEBUG_OUTPUT
        printf("[INFO: %d] Client, sealSessionSecretCB: fake seal [DEMO_CLIENT]\n", __LINE__);
#endif
        uint8_t *sealedData = new uint8_t[sizeof(sessionSecret)];
        memcpy(sealedData, &sessionSecret, sizeof(sessionSecret));
        *sealingDataLength = sizeof(sessionSecret);
        
        return sealedData;
    }

    return tpmRoT->seal(sealAuthValue, sealingPcrSlots, &sessionSecret, sizeof(uint32_t), sealingDataLength);
}

uint8_t *unsealSessionSecretCB(uint8_t *sealingData, size_t sealingDataLength, size_t *unsealedDataLength) {
    if (BI::demoClient.clientIsDemo()) {
#ifdef RATLS_DEBUG_OUTPUT
        printf("[INFO: %d] Client, unsealSessionSecretCB: fake unseal [DEMO_CLIENT]\n", __LINE__);
#endif
        uint8_t *UnealedData = new uint8_t[sealingDataLength];
        memcpy(UnealedData, sealingData, sealingDataLength);
        *unsealedDataLength = sealingDataLength;
        return UnealedData;
    }
    return tpmRoT->unseal(sealAuthValue, sealingPcrSlots, sealingData, sealingDataLength, unsealedDataLength);
}

/****************************************************************************
 ****************************************************************************
 ************************           M A I N           ***********************
 ****************************************************************************
 ****************************************************************************/
int main(int argc, char const* argv[]) {
    ssize_t bytes_read = 0;                      // No. of Bytes read per 
                                                 // read call    
    unsigned char read_buffer[RECORD_SIZE + 1];  // Buffer for input data 
                                                 // from sensor

    // Setup the serial sensor device
    if (init_serial() != 0) {
        fprintf(stderr, "Failed to setup serial line to sensor.\n");
        return(1);
    }

    fprintf(stderr, "Configured serial interface.\n");

    setlinebuf(stdout);

    BI::demoClient.parseCommandLine(argc, argv);
    BI::demoClient.init();
    BI::demoClient.setVerbose(false);

    // Check if the user has entered a custom IP for reporting via UDP
    if (BI::demoClient.hasUDPIP()) {
        udpip = BI::demoClient.getUDPIP().c_str();
    }

    // fprintf(stderr, "UDP IP is: %s\n", udpip);

    RATLS::TpmDevInfo tpmDevInfo = RATLS::TpmRoT::parseCommandLine(argc, argv);
    chk(tpmDevInfo.initMode != RATLS::TpmInitMode::Invalid, "no or invalid tpm init mode on command line");
        
    tpmRoT = chk(new RATLS::TpmRoT(tpmDevInfo, "ratls-test"), "init TPM");

    chk(argc > 1, "No server address specified");
    char const *serverAddress = argv[1];

    srand(time(0));

    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    SSL_load_error_strings();
    OPENSSL_add_all_algorithms_noconf();

    SSL_CTX *ctx_ratls = createSSLContext();
    SSL_CTX *ctx_tls = createSSLContext();

    RATLS::setupRATLS();

    /* Open UDP socket for sending data records                             */
    udpsock = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpsock == -1) {
        fprintf(stderr, "Failed to create UDP socket (%d).\n", errno);
        exit(1);
    }

    /* Set up sockaddr structure for use with communication channel         */
    udpsrv.sin_family      = AF_INET;
    udpsrv.sin_port        = htons(udpport);
    udpsrv.sin_addr.s_addr = inet_addr(udpip);

    if (BI::demoClient.clientIsDemo()) {
        raContext.customVerifyCallback = verifyCB;
        raContext.createRequestCB = createRequestCB;
        raContext.remoteAttestCB = remoteAttestCB;
        raContext.checkQuoteCB = checkQuoteCB;
        raContext.sealSessionSecretCB = sealSessionSecretCB;
        raContext.unsealSessionSecretCB = unsealSessionSecretCB;
        raContext.maxSessionTicketsNum = 2;
        raContext.customNewSession = callbackNewSession;
        RATLS::enableClientRemoteAttestation(&raContext, ctx_ratls);

        while (true) {
            SSL *ssl = NULL;            // SSL context from opened connections

            fprintf(stderr, "Waiting for command.\n");
            std::string cmd = BI::demoClient.waitForCommand();
            fprintf(stderr, "Done.\n");

            size_t valuePos = cmd.find("sensor-data:") + strlen("sensor-data:");
            int32_t value = -1;
            try {
                size_t numCharsProcessed = 0;
                value = std::stoi(cmd.substr(valuePos), &numCharsProcessed, 10);
                printf("Received value %d with command\n", value);
            }
            catch (...) { }

            if (cmd.find("command:connect\nmode:tls-attest\n") != std::string::npos) {
                printf("Command requested TLS+Attest connection\n");
                BI::demoClient.setMode(BI::DemoMode::TlsAttest);
                
                ssl = doConnection(serverAddress, ctx_ratls, true);

                SSL_write(ssl, &value, sizeof(value));

                char reply[1024];
                int res = SSL_read(ssl, reply, sizeof(reply));
                printf("SSL_read: %d; reply='%s'\n", res, reply);
            
                shutdownSSLCtx(ssl);    
            } else if (cmd.find("command:connect\nmode:tls\n") != std::string::npos) {
                printf("Command requested TLS-only connection\n");
                BI::demoClient.setMode(BI::DemoMode::Tls);
                doConnection(serverAddress, ctx_tls, false);
                
                SSL_write(ssl, &value, sizeof(value));

                char reply[1024];
                int res = SSL_read(ssl, reply, sizeof(reply));
                printf("SSL_read: %d; reply='%s'\n", res, reply);
            
                shutdownSSLCtx(ssl);    

            } 
            else if (cmd.empty()) {
                // Do nothing, just proceed
            } else {
                printf("Unknown command:\n%s", cmd.c_str());
                BI::demoClient.reset();
            }

            /* Read one record and send it to the UDP server                */
            
            // Reset read counter and input buffer
            bytes_read = 0;

            memset(read_buffer, '\0', RECORD_SIZE + 1);

            /*
             * We may start reading from the serial line in the middle of
             * a record that is just being sent. We thus need to synchronize
             * on the record header before we read any payload.
             */

            /* First read a complete header */
            while (bytes_read < HEADER_SIZE) {
                ssize_t b_read;             // Bytes read during this iteration
                size_t  len;                // Length of read operation

                len = HEADER_SIZE - bytes_read;

                b_read = serial_read(uart_fd, read_buffer + bytes_read, len);
                if (b_read == -1) {
                    fprintf(stderr, "Failed to read data from sensor device "
                            "(%d).\n", errno);
                    return(1);
                }
           
                // In case of EOF, jump directly to the shutdown routine
                if (b_read == 0) {
                    fprintf(stderr, "Reached EOF (header).\n");
                    exit(1);
                }

                // Purge newlines from the read buffer, any amount of newlines
                // removed have to be filled with valid data (hence decrease
                // the read progress)
                bytes_read += b_read;
                bytes_read -= purge_newlines(read_buffer, HEADER_SIZE);
            }

            /* Now forward the header window by one byte until the expected *
             * header is matched.                                           */
            while (memcmp(read_buffer, header, HEADER_SIZE) != 0) {
                ssize_t       b_read;           // Bytes read in this iteration
                unsigned char next_char = '\n'; // Next char read

                // Print first HEADER_SIZE bytes of the read buffer for
                // debugging purposes
                fprintf(stderr, "Header did not match (current value: \n");
                fprintf(stderr, "%.*s).\n\n", HEADER_SIZE, read_buffer);

                // Shift all header content in the buffer one byte to the left
                memmove(read_buffer, read_buffer + 1, HEADER_SIZE - 1);
               
                // Read one more byte to the end of the buffer. However, since
                // there might be garbage characters at any time, we have to
                // do so in a loop...
                while (next_char == '\n') {
                    b_read = serial_read(uart_fd, &next_char, 1);
                    if (b_read == -1) {
                        fprintf(stderr, "Failed to read data from sensor "
                                "device (%d).\n", errno);
                        return(1);
                    }
               
                    // In case of EOF, jump directly to the shutdown routine
                    if (b_read == 0) {
                        fprintf(stderr, "Reached EOF (header).\n");
                        return(1);
                    }
                }

                // If we read a sensible character, fill the next header
                // version for comparison
                read_buffer[HEADER_SIZE - 1] = next_char;
            }

            /* Inner read loop: Read from device until record is filled.
             *
             * Things get a little tricky here: The sensor device sends data
             * in some randomly sized chunks, each one finished with a \n
             * character. We need to collect enough data until we can send a
             * complete record. To this extent, we have to filter out any
             * intermediate \n characters as they are no real payload.
             */
            bytes_read = 0;                 // Don't forget to reset the counter
            while (bytes_read < PAYLOAD_SIZE) {
                ssize_t b_read;             // Bytes read during this iteration
                size_t  len;                // Length of read operation

                len = PAYLOAD_SIZE - bytes_read;

                b_read = serial_read(uart_fd, 
                                     read_buffer + HEADER_SIZE + bytes_read, 
                                     len);
                if (b_read == -1) {
                    fprintf(stderr, "Failed to read data from sensor device "
                            "(%d).\n", errno);
                    return(1);
                }
           
                // In case of EOF, jump directly to the shutdown routine
                if (b_read == 0) {
                    fprintf(stderr, "Reached EOF (msg body (msg body)).\n");
                    exit(1);
                }

                // Purge newlines from the read buffer, any amount of newlines
                // removed have to be filled with valid data (hence decrease
                // the read progress)
                bytes_read += b_read;
                bytes_read -= purge_newlines(read_buffer, RECORD_SIZE);
            }

            // Set a proper string termination character
            read_buffer[RECORD_SIZE] = '\0';

            fprintf(stderr, "Record: %s\n", read_buffer);
        
            if (sendto(udpsock, read_buffer, RECORD_SIZE, 0, 
                      (struct sockaddr *) &udpsrv, 
                      sizeof(struct sockaddr_in)) < 0) {
                fprintf(stderr, "Failed to send sensor record to server.\n");
            }
        }
    } else {
        raContext.customVerifyCallback = verifyCB;
        raContext.createRequestCB = createRequestCB;
        raContext.remoteAttestCB = remoteAttestCB;
        raContext.checkQuoteCB = checkQuoteCB;
        raContext.sealSessionSecretCB = sealSessionSecretCB;
        raContext.unsealSessionSecretCB = unsealSessionSecretCB;
        raContext.maxSessionTicketsNum = 2;
        raContext.customNewSession = callbackNewSession;
        RATLS::enableClientRemoteAttestation(&raContext, ctx_ratls);

        SSL *ssl = doConnection(serverAddress, ctx_ratls, true);

        fprintf(stderr, "==========\n");

        /*
         * Listen on the UART port to receive a record of sampled data. Once
         * a record is completely read, we forward it to the RATLS-verified
         * server.
         */
        for (;;) {
            // Reset read counter and input buffer
            bytes_read = 0;

            memset(read_buffer, '\0', RECORD_SIZE + 1);

            /*
             * We may start reading from the serial line in the middle of
             * a record that is just being sent. We thus need to synchronize
             * on the record header before we read any payload.
             */

            /* First read a complete header */
            while (bytes_read < HEADER_SIZE) {
                ssize_t b_read;             // Bytes read during this iteration
                size_t  len;                // Length of read operation

                len = HEADER_SIZE - bytes_read;

                b_read = read(uart_fd, read_buffer + bytes_read, len);
                if (b_read == -1) {
                    fprintf(stderr, "Failed to read data from sensor device "
                            "(%d).\n", errno);
                    return(1);
                }
           
                // In case of EOF, jump directly to the shutdown routine
                if (b_read == 0) {
                    fprintf(stderr, "Reached EOF.\n");
                    goto file_end;
                }

                // Purge newlines from the read buffer, any amount of newlines
                // removed have to be filled with valid data (hence decrease
                // the read progress)
                bytes_read += b_read;
                bytes_read -= purge_newlines(read_buffer, HEADER_SIZE);
            }
            fprintf(stderr, "Read first header\n");

            /* Now forward the header window by one byte until the expected *
             * header is matched.                                           */
            while (memcmp(read_buffer, header, HEADER_SIZE) != 0) {
                ssize_t       b_read;           // Bytes read in this iteration
                unsigned char next_char = '\n'; // Next char read

                // Print first HEADER_SIZE bytes of the read buffer for
                // debugging purposes
                fprintf(stderr, "Header did not match (current value: \n");
                fprintf(stderr, "%.*s).\n\n", HEADER_SIZE, read_buffer);

                // Shift all header content in the buffer one byte to the left
                memmove(read_buffer, read_buffer + 1, HEADER_SIZE - 1);
                
                // Read one more byte to the end of the buffer. However, since
                // there might be garbage characters at any time, we have to
                // do so in a loop...
                while (next_char == '\n') {
                    b_read = serial_read(uart_fd, &next_char, 1);
                    if (b_read == -1) {
                        fprintf(stderr, "Failed to read data from sensor "
                                "device (%d).\n", errno);
                        return(1);
                    }
               
                    // In case of EOF, jump directly to the shutdown routine
                    if (b_read == 0) {
                        fprintf(stderr, "Reached EOF.\n");
                        goto file_end;
                    }
                }

                // If we read a sensible character, fill the next header
                // version for comparison
                read_buffer[HEADER_SIZE - 1] = next_char;
            }

            /* Inner read loop: Read from device until record is filled.
             *
             * Things get a little tricky here: The sensor device sends data
             * in some randomly sized chunks, each one finished with a \n
             * character. We need to collect enough data until we can send a
             * complete record. To this extent, we have to filter out any
             * intermediate \n characters as they are no real payload.
             */
            bytes_read = 0;                 // Don't forget to reset the counter
            while (bytes_read < PAYLOAD_SIZE) {
                ssize_t b_read;             // Bytes read during this iteration
                size_t  len;                // Length of read operation

                len = PAYLOAD_SIZE - bytes_read;

                b_read = read(uart_fd, read_buffer + HEADER_SIZE + bytes_read, 
                              len);
                if (b_read == -1) {
                    fprintf(stderr, "Failed to read data from sensor device "
                            "(%d).\n", errno);
                    return(1);
                }
           
                // In case of EOF, jump directly to the shutdown routine
                if (b_read == 0) {
                    fprintf(stderr, "Reached EOF.\n");
                    goto file_end;
                }

                // Purge newlines from the read buffer, any amount of newlines
                // removed have to be filled with valid data (hence decrease
                // the read progress)
                bytes_read += b_read;
                bytes_read -= purge_newlines(read_buffer, RECORD_SIZE);
            }

            // Set a proper string termination character
            read_buffer[RECORD_SIZE] = '\0';

            fprintf(stderr, "Record: %s\n", read_buffer);
        
            SSL_write(ssl, read_buffer, RECORD_SIZE);
        }

file_end:
        fprintf(stderr, "\n==========\n");

        shutdownSSLCtx(ssl);
    }

    if (tpmRoT) tpmRoT->terminateTpm();

    return(0);
}
