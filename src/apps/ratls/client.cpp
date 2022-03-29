#define _CRT_SECURE_NO_WARNINGS

#define TLS1_3_CERT_MSG_EXT

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

#include <Tpm2.h>

using namespace Err;
using namespace TpmCpp;

RATLS::TpmRoT *tpmRoT = nullptr;

SSL_SESSION *currentSession = nullptr;

RATLS::RAClientContext raContext;

TpmCpp::ByteVec sealAuthValue = { 4,  43 ,1 , 34 };

// for testing purposes, client and server use the same PCR slots:
//  - PCR7: trusted computing base / OS
//  - PCR23: the app (either client or server)
std::vector<uint32_t> pcrSlotsToAttest = { 7, 23 };

std::vector<TPM2B_DIGEST> expectedPcrValues = {
    TPM2B_DIGEST({0x2b, 0x13, 0xad, 0xc4, 0xb1, 0xd4, 0x10, 0x79, 0x06, 0x9e, 0x99, 0x1c, 0x99,
                  0xbf, 0xbd, 0x47, 0x40, 0xa8, 0x18, 0x6f, 0x54, 0xee, 0x0f, 0xee, 0x97, 0xce,
                  0x6d, 0x33, 0x57, 0xeb, 0xcd, 0xaf}),
    TPM2B_DIGEST({0x01, 0x98, 0x58, 0x25, 0x82, 0x88, 0x9d, 0xb8, 0x64, 0xcf, 0x7f, 0x39, 0x3a,
                  0xfc, 0xb5, 0x5b, 0x30, 0x37, 0x80, 0xb5, 0x61, 0x06, 0x99, 0x2c, 0x23, 0x51,
                  0x0a, 0xd2, 0x07, 0x31, 0xfa, 0x1c})
};
/*std::vector<TPM2B_DIGEST> expectedPcrValues = {
    TPM2B_DIGEST({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
    TPM2B_DIGEST({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
};*/

std::vector<uint32_t> sealingPcrSlots = { 7, 23 };

SOCKET openConnection(char const *hostname, int port) {
    
    SOCKET sock = -1;
    struct addrinfo addrInfoHints;
    struct addrinfo *addrInfo = NULL;

    memset(&addrInfoHints, 0, sizeof(addrInfoHints));
    addrInfoHints.ai_family = AF_UNSPEC;
    addrInfoHints.ai_socktype = SOCK_STREAM;
    addrInfoHints.ai_protocol = IPPROTO_TCP;

    chk(getaddrinfo(hostname, std::to_string(port).c_str(),
                    &addrInfoHints, &addrInfo) == 0, "getaddrinfo");

    for (struct addrinfo *ai = addrInfo; ai != NULL; ai = ai->ai_next) {
    sock = chksys(socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol), "open socket");
        int res = connect(sock, ai->ai_addr, ai->ai_addrlen);
        if (res == 0)
            break;
        close(sock);
        sock = -1;
    }

    freeaddrinfo(addrInfo);

    return chk(sock, "connect to socket");
}

int verifyCB(int preverifyOk, X509_STORE_CTX *ctx) {
    return 1;
}

void doConnection(char const *serverAddress, SSL_CTX *ctx, bool attested, SSL_SESSION *session = nullptr) {
    //printf("\n\n=================================\n");

    SSL *ssl = SSL_new(ctx);

    BI::demoClient.setConnectionStatus(BI::DemoStatus::Connecting);
    BI::demoClient.setTlsStatus(BI::DemoStatus::Connecting, "");
    BI::demoClient.setAttestationStatus(BI::DemoStatus::Connecting, "", "", "");

    Benchmarking::startMeasure(Benchmarking::OpType::TCP);

    SOCKET connectSocket;
    try {
        connectSocket = openConnection(serverAddress, 4433);
    }
    catch (const std::runtime_error &e) {
        BI::demoClient.setConnectionStatus(BI::DemoStatus::Error);
        throw std::runtime_error(std::string("cannot connect to server: ") + e.what());
    }

    Benchmarking::stopMeasure(Benchmarking::OpType::TCP);

    SSL_set_fd(ssl, connectSocket);

    bool resume = false;
    if (session != nullptr && SSL_SESSION_is_resumable(session)) {
        int res = SSL_set_session(ssl, session);
        if (res != 1) {
            printf("%s\n", ERR_error_string(SSL_get_error(ssl, res), NULL));
            ERR_print_errors_fp(stderr);
            return;
        }
        resume = true;
    }

    if(attested)Benchmarking::measureSingleValue(resume ? Benchmarking::OpType::ResumedHandshake : Benchmarking::OpType::FullHandshake);
    else Benchmarking::measureSingleValue(resume ? Benchmarking::OpType::ResumedPureSSL : Benchmarking::OpType::FullPureSSL);

    if(attested)Benchmarking::startMeasure(resume ? Benchmarking::OpType::ResumedHandshake : Benchmarking::OpType::FullHandshake);
    else Benchmarking::startMeasure(resume ? Benchmarking::OpType::ResumedPureSSL : Benchmarking::OpType::FullPureSSL);

    int status = SSL_connect(ssl);
    if (status != 1) {
        if(attested)Benchmarking::stopMeasure(resume ? Benchmarking::OpType::ResumedHandshake : Benchmarking::OpType::FullHandshake);
        else Benchmarking::stopMeasure(resume ? Benchmarking::OpType::ResumedPureSSL : Benchmarking::OpType::FullPureSSL);

        printf("%s\n", ERR_error_string(SSL_get_error(ssl, status), NULL));
        ERR_print_errors_fp(stderr);
        return;
    }
    if(attested)Benchmarking::stopMeasure(resume ? Benchmarking::OpType::ResumedHandshake : Benchmarking::OpType::FullHandshake);
    else Benchmarking::stopMeasure(resume ? Benchmarking::OpType::ResumedPureSSL : Benchmarking::OpType::FullPureSSL);

    BI::demoClient.setConnectionStatus(BI::DemoStatus::Ok);
    BI::demoClient.setConnectionStatus(BI::DemoStatus::Active);

    if (SSL_shutdown(ssl) == 0) SSL_shutdown(ssl);

    SSL_free(ssl);

    closesocket(connectSocket);
    BI::demoClient.reset();
}

int callbackNewSession(SSL *ssl, SSL_SESSION *sess) {
    if (currentSession != nullptr) {
        SSL_SESSION_free(currentSession);
    }

    // Duplicate the session so that it is not invalidated after ssl is closed ungracefully
    currentSession = SSL_SESSION_dup(sess);

    return 1;
}

uint8_t *createRequestCB(size_t *outLen) {
    *outLen = 16;
    uint8_t *out = new uint8_t[*outLen];
    ByteVec b = Crypto::GetRand(*outLen);
    for (size_t i = 0; i < *outLen; i++) {
        out[i] = b[i];
    }

    return out;
}

RATLS::RAQuote* remoteAttestCB(uint8_t *nonce, size_t nonceLen) {
    if (BI::demoClient.clientIsDemo()) {
#ifdef RATLS_DEBUG_OUTPUT
        printf("[INFO: %d] Client, remoteAttestCB: fake attestation [DEMO_CLIENT]\n", __LINE__);
#endif
        RATLS::RAQuote* quoteRA = new RATLS::RAQuote();
        quoteRA->quoteData = new uint8_t[42];
        quoteRA->quoteDataLen = 42;
        return quoteRA;
    }
    return tpmRoT->remoteAttest(pcrSlotsToAttest, nonce, nonceLen);
}

bool checkQuoteCB(RATLS::RAQuote &raQuote, uint8_t *nonceExpected, size_t nonceExpectedLen) {
    bool ok = tpmRoT->checkQuote(raQuote, pcrSlotsToAttest, expectedPcrValues, nonceExpected, nonceExpectedLen);

    using namespace TpmCpp;
    std::string publicJson = std::string((char*)raQuote.quoteData);
    std::string quoteJson = std::string(((char*)raQuote.quoteData + publicJson.size() + 1));
    QuoteResponse quote;
    quote.Deserialize(SerializationType::JSON, quoteJson);

    TPMT_PUBLIC pubKey;
    pubKey.Deserialize(SerializationType::JSON, publicJson);

    //printf("%s%s", pubKey.ToString().c_str(), quote.ToString().c_str());

    if (ok) {
        BI::demoClient.setAttestationStatus(
            BI::DemoStatus::Ok,
            "01:02:03:04:05:06:07:08:09:0a:01:02:03:04:05:06",
            "b1:b2:b3:b4:b5:b6:b7:b8:b9:ba:b1:b2:b3:b4:b5:b6",
            "RATLS Demo");
    } else {
        BI::demoClient.setAttestationStatus(BI::DemoStatus::Error, "", "", "RATLS Demo");
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

int main(int argc, char const *argv[]) {
    try {
        Benchmarking::startMeasure(Benchmarking::OpType::Setup);

        setlinebuf(stdout);
        RATLS::TpmDevInfo tpmDevInfo = RATLS::TpmRoT::parseCommandLine(argc, argv);
        chk(tpmDevInfo.initMode != RATLS::TpmInitMode::Invalid, "no or invalid tpm init mode on command line");
        
        tpmRoT = chk(new RATLS::TpmRoT(tpmDevInfo, "ratls-test"), "init TPM");

        BI::demoClient.parseCommandLine(argc, argv);
        BI::demoClient.init("127.0.0.1", 5000);
        BI::demoClient.setVerbose(false);

        chk(argc > 1, "No server address specified");
        char const *serverAddress = argv[1];

        srand(time(0));

        Benchmarking::BenchmarkSetupData benchmarkData = Benchmarking::parseCommandLine(argc, argv);

        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_ciphers();
        SSL_load_error_strings();
        OPENSSL_add_all_algorithms_noconf();

        RATLS::setupRATLS();

        const SSL_METHOD *method;

        method = TLS_client_method();

        SSL_CTX *ctx = SSL_CTX_new(method);

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
        server_cert_file = chksys(fopen("/tls/fullchain.pem", "r"), "open cert chain file");
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

        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_STORE);

        long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1 | SSL_OP_NO_COMPRESSION;
        SSL_CTX_set_options(ctx, flags);
        
        SSL_CTX_set_ecdh_auto(ctx, 1);

        if (SSL_CTX_use_certificate_file(ctx, "/tls/fullchain.pem", SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, "/tls/privkey.pem", SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        SSL_CTX_use_certificate_chain_file(ctx, "/tls/fullchain.pem");

        if(benchmarkData.performBenchmarking) {
            printf("Running client benchmark with %d samples\n", benchmarkData.numSamples);
            printf("   %d attested hanndshakes\n", benchmarkData.numSamples);
            if(benchmarkData.resumeSessions) {
                printf(" + %d resumed handshakes\n", benchmarkData.numSamples);
            }
            if(benchmarkData.performPureSSLHandshakes) {
                printf(" + %d pure ssl handshakes\n", benchmarkData.numSamples);
            }
            if(benchmarkData.performPureSSLHandshakes && benchmarkData.resumeSessions) {
                printf(" + %d resumed pure ssl handshakes\n", benchmarkData.numSamples);
            }
        }

        Benchmarking::stopMeasure(Benchmarking::OpType::Setup);

        if(benchmarkData.performBenchmarking) {
            SSL_CTX_sess_set_new_cb(ctx, callbackNewSession);
            if(benchmarkData.performPureSSLHandshakes) {
                for (uint32_t i = 0; i < benchmarkData.numSamples; i++) {
                    doConnection(serverAddress, ctx, false);
                    if(benchmarkData.resumeSessions) {
                        doConnection(serverAddress, ctx, false, currentSession);
                    }
                }
            }

            raContext.onlyAllowRemoteAttestedSessionResumption = true;
            raContext.customVerifyCallback = verifyCB;
            raContext.createRequestCB = createRequestCB;
            raContext.remoteAttestCB = remoteAttestCB;
            raContext.checkQuoteCB = checkQuoteCB;
            raContext.sealSessionSecretCB = sealSessionSecretCB;
            raContext.unsealSessionSecretCB = unsealSessionSecretCB;
            raContext.maxSessionTicketsNum = 200;
            raContext.customNewSession = callbackNewSession;
            RATLS::enableClientRemoteAttestation(&raContext, ctx);

            ///printf("Performing Benchmark ... \n");
            for (uint32_t i = 0; i < benchmarkData.numSamples; i++) {
                doConnection(serverAddress, ctx, true);
                if(benchmarkData.resumeSessions) {
                    doConnection(serverAddress, ctx, true, currentSession);
                }
                //printf("Benchmark: %d/%d\n", i, benchmarkData.numSamples);
            }

            printf("\n    %7.3f ms SETUP\n", Benchmarking::getAverageTimeForMeasurement(Benchmarking::OpType::Setup));
            printf("avg %7.3f ms FULL PURE SSL\n", Benchmarking::getAverageTimeForMeasurement(Benchmarking::OpType::FullPureSSL));
            printf("avg %7.3f ms RESUMED PURE SSL\n", Benchmarking::getAverageTimeForMeasurement(Benchmarking::OpType::ResumedPureSSL));

            printf("avg %7.3f ms FULL ATTESTED HANDSHAKE\n", Benchmarking::getAverageTimeForMeasurement(Benchmarking::OpType::FullHandshake));
            printf("avg %7.3f ms RESUMED ATTESTED HANDSHAKE\n", Benchmarking::getAverageTimeForMeasurement(Benchmarking::OpType::ResumedHandshake));

            printf("\nOperations: \n");
            printf("avg %7.3f ms RA\n", Benchmarking::getAverageTimeForMeasurement(Benchmarking::OpType::RemoteAttest));
            printf("avg %7.3f ms CHECK QUOTE\n", Benchmarking::getAverageTimeForMeasurement(Benchmarking::OpType::CheckQuote));
            printf("avg %7.3f ms SEAL\n", Benchmarking::getAverageTimeForMeasurement(Benchmarking::OpType::Seal));
            printf("avg %7.3f ms UNSEAL\n", Benchmarking::getAverageTimeForMeasurement(Benchmarking::OpType::Unseal));

            printf("avg %7.3f SEALS PER HANDSHAKE\n", (double)Benchmarking::getSingleValue(Benchmarking::OpType::NumSeals) / (double)benchmarkData.numSamples);

            printf("\n");
            printf("   %3ld FULL PURE SSL\n", Benchmarking::getSingleValue(Benchmarking::OpType::FullPureSSL));
            printf("   %3ld RESUMED PURE SSL\n", Benchmarking::getSingleValue(Benchmarking::OpType::ResumedPureSSL));
            printf("   %3ld FULL ATTESTED HANDSHAKE\n", Benchmarking::getSingleValue(Benchmarking::OpType::FullHandshake));
            printf("   %3ld RESUMED ATTESTED HANDSHAKE\n", Benchmarking::getSingleValue(Benchmarking::OpType::ResumedHandshake));

            Benchmarking::writeBenchmarksToFile(benchmarkData.outputPath);
        } else {
            raContext.customVerifyCallback = verifyCB;
            raContext.createRequestCB = createRequestCB;
            raContext.remoteAttestCB = remoteAttestCB;
            raContext.checkQuoteCB = checkQuoteCB;
            raContext.sealSessionSecretCB = sealSessionSecretCB;
            raContext.unsealSessionSecretCB = unsealSessionSecretCB;
            raContext.maxSessionTicketsNum = 2;
            raContext.customNewSession = callbackNewSession;
            RATLS::enableClientRemoteAttestation(&raContext, ctx);
            doConnection(serverAddress, ctx, true);
        }

    }

    catch (const runtime_error& exc) {
        cerr << "ratls-test-client: " << exc.what() << "\nExiting...\n";
    }

    if(tpmRoT) tpmRoT->terminateTpm();

    return 0;
}
