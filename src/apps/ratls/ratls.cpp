#include "ratls.h"
#include "demo.h"

namespace RATLS {

static int NID_cert_ext_ra_quote = -1;

static int raContextDataIndex = -1;
static int raSessionFlagIndex = -1;

void setupRATLS() {
    NID_cert_ext_ra_quote = OBJ_create(CERT_EXT_RA_QUOTE, "RA Quote", "RA Quote");
    std::cout << NID_cert_ext_ra_quote << std::endl;

    raContextDataIndex = SSL_get_ex_new_index(0, (char*)"remote attestation context", NULL, NULL, NULL);
    raSessionFlagIndex = SSL_get_ex_new_index(0, (char*)"remote attestation session flag", NULL, NULL, NULL);
}

#ifndef TLS1_3_CERT_MSG_EXT
EVP_PKEY *generateRSAKeyPair(int bits) {
    EVP_PKEY *pk = nullptr;
    RSA *rsa = nullptr;
    BIGNUM *bigNum = nullptr;

    if ((pk = EVP_PKEY_new()) == nullptr) {
        goto err;
    }

    bigNum = BN_new();
    rsa = RSA_new();

    BN_set_word(bigNum, RSA_F4);

    if (RSA_generate_key_ex(rsa, bits, bigNum, nullptr) != 1) {
        goto err;
    }

    if (!EVP_PKEY_assign(pk, EVP_PKEY_RSA, rsa)) {
        goto err;
    }

    return pk;

err:
    if (rsa != nullptr) {
        RSA_free(rsa);
    }

    if (bigNum != nullptr) {
        BN_free(bigNum);
    }

    if (pk != nullptr) {
        EVP_PKEY_free(pk);
    }

    return nullptr;
}

X509 *generateSignedRAExtendedCert(EVP_PKEY *publicKey, EVP_PKEY *signingKey, X509 *intermediateCert, RAQuote &quote) {
    X509 *cert = nullptr;
    X509_NAME *name = nullptr;
    ASN1_OCTET_STRING *os = nullptr;
    int nid = 0;
    X509_EXTENSION *ex;

    if ((cert = X509_new()) == nullptr)
        goto err;

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 0);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), (long)60 * 60 * 24 * (10 * 365));
    X509_set_pubkey(cert, publicKey);

    name = X509_get_subject_name(cert);

    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"RA Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)"RA Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)"RA Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"RA Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)"RA Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"RA Test", -1, -1, 0);

    X509_set_issuer_name(cert, X509_get_subject_name(intermediateCert));

    os = ASN1_OCTET_STRING_new();
    nid = OBJ_txt2nid("2.5.29.70");
    ASN1_OCTET_STRING_set(os, (const unsigned char*)&quote, sizeof(RAQuote));
    ex = X509_EXTENSION_create_by_NID(NULL, nid, 0, os);
    X509_add_ext(cert, ex, -1);

    if (!X509_sign(cert, signingKey, EVP_sha256())) {
        goto err;
    }

    return cert;

err:
    if (cert != nullptr) {
        X509_free(cert);
    }

    if (name != nullptr) {
        X509_NAME_free(name);
    }

    return nullptr;
}

std::pair<X509*, EVP_PKEY*> generateSignedRAExtendedCert(int keyBits, EVP_PKEY *signingKey, X509 *intermediateCert, RAQuote &quote) {
    EVP_PKEY *pk = generateRSAKeyPair(keyBits);

    if (pk) return std::make_pair(generateSignedRAExtendedCert(pk, signingKey, intermediateCert, quote), pk);
    else return std::make_pair(nullptr, nullptr);
}

// hier generieren wir ein container certificate aus dem publickey (aus keyPair)
// signieren das ganze mit dem privatekey (aus keyPair)
X509 *generateSignedRAExtendedCert(EVP_PKEY *keyPair, X509 *intermediateCert, RAQuote &quote) {
    return generateSignedRAExtendedCert(keyPair, keyPair, intermediateCert, quote);
}
#endif

std::string sessionIdToStr(SSL *s) {
    unsigned int len = 0;
    const unsigned char *sessionId = SSL_SESSION_get_id(SSL_get_session(s), &len);
    std::string sessionIdStr = std::string((const char*)sessionId);
    return sessionIdStr;
}

std::string sessionIdToStr(SSL_SESSION *ss) {
    unsigned int len = 0;
    const unsigned char *sessionId = SSL_SESSION_get_id(ss, &len);
    std::string sessionIdStr = std::string((const char*)sessionId);
    return sessionIdStr;
}

int callbackAddExtensionRAClient(SSL *ssl, unsigned int extType,
    unsigned int context,
    const unsigned char** out,
    size_t *outlen, X509 *x,
    size_t chainidx,
    int *al, void *addArg) {

    if (extType == EXT_RA_REQ) {
        SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);
        RAClientContext *raContext = (RAClientContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

        if (!SSL_SESSION_is_resumable(SSL_get_session(ssl))) {
            if (raContext->expectedNonce != nullptr) {
                delete[] raContext->expectedNonce;
                raContext->expectedNonce = nullptr;
                raContext->expectedNonceLen = 0;
            }

            // Request remote attestation of server
            RARequestData d;
            size_t nonceLen;
            d.nonceData = raContext->expectedNonce = raContext->createRequestCB(&nonceLen);
            d.nonceDataLen = raContext->expectedNonceLen = nonceLen;

            *out = d.serialize(outlen);
#ifdef RATLS_DEBUG_OUTPUT
            std::cout << "[RA Out (ClientHello)] Requesting remote attestation from server with nonce " << (((uint8_t*)d.nonceData)[0]) << std::endl;
#endif
        }
        else {
            // dont request remote attestation if we are trying to resume the session
            return 0;
        }
    }

    if (extType == EXT_RA_RESUMPTION) {
        SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);
        RAClientContext *raContext = (RAClientContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

        if (SSL_SESSION_is_resumable(SSL_get_session(ssl))) {
            RASessionResumptionData sessionResumptionData;

            std::string sessionIdStr = sessionIdToStr(ssl);

            if (raContext->sessionTicketBySessionId.find(sessionIdStr) == raContext->sessionTicketBySessionId.end()) {
                if (raContext->onlyAllowRemoteAttestedSessionResumption) {
                    return 1;
                }

#ifdef RATLS_DEBUG_OUTPUT
                std::cout << "[RA SR In (ClientHello)] Session resumption canceled: no matching secret found for session" << std::endl;
#endif
                return 0;
            }

            RASessionTicket &ticket = raContext->sessionTicketBySessionId[sessionIdStr];

            size_t unsealedLength;
            uint8_t *unsealedSessionSecret = raContext->unsealSessionSecretCB(ticket.sealedData, ticket.sealedDataLength, &unsealedLength);
            if (unsealedSessionSecret == nullptr) {
                return 0;
            }

            memcpy(&sessionResumptionData.serverSecret, unsealedSessionSecret, unsealedLength);
            delete[] unsealedSessionSecret;
            delete[] ticket.sealedData;
            ticket.sealedData = nullptr;

#ifdef RATLS_DEBUG_OUTPUT
            std::cout << "[RA SR (ClientHello)] Unsealed session server secret: " << sessionResumptionData.serverSecret << std::endl;
#endif

            *out = sessionResumptionData.serialize(outlen);
        }
    }

#ifdef TLS1_3_CERT_MSG_EXT
    if (extType == EXT_RA_RES_TLS1_3) {
        SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);
        RAClientContext *raContext = (RAClientContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

        if (context == SSL_EXT_CLIENT_HELLO) {
            *out = new unsigned char[1];
            *outlen = 1;
#ifdef RATLS_DEBUG_OUTPUT
            std::cout << "[RA Out (ClientHello)] Appending placeholder extension to client hello so that the server can respond" << std::endl;
#endif
        }

        if (context == SSL_EXT_TLS1_3_CERTIFICATE && chainidx == 0) {
            // Fill / do remote attestion for the client
            RAQuote quote = raContext->remoteAttestCB(raContext->nonceRequested, raContext->nonceRequestedLen);

            *out = quote.serialize(outlen);

            delete[] quote.quoteData;
#ifdef RATLS_DEBUG_OUTPUT
            std::cout << "[RA Out (TLS1.3 ClientCertificate)] Remote attesting to server with nonce " << std::endl;
#endif
        }
    }
#endif

    return 1;
}

void callbackFreeExtensionRAClient(SSL *s, unsigned int extType,
    unsigned int context,
    const unsigned char *out,
    void *addArg) {

    if (extType == EXT_RA_REQ) {
        // free the buffer
        delete[] out;
    }

    if (extType == EXT_RA_RESUMPTION) {
        delete[] out;
    }

#ifdef TLS1_3_CERT_MSG_EXT
    if (extType == EXT_RA_RES_TLS1_3) {
        delete[] out;
    }
#endif

}

int callbackParseExtensionRAClient(SSL *ssl, unsigned int extType,
    unsigned int context,
    const unsigned char *in,
    size_t inlen, X509 *x,
    size_t chainidx,
    int *al, void *parseArg) {

    // only parse if session was not resumed
    if (extType == EXT_RA_REQ) {
        SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);
        RAClientContext *raContext = (RAClientContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

        RARequestData d;
        d.deserialize((uint8_t*)in, inlen);

        if (raContext->nonceRequested != nullptr) {
            delete[] raContext->nonceRequested;
            raContext->nonceRequested = nullptr;
            raContext->nonceRequestedLen = 0;
        }

        raContext->nonceRequested = d.nonceData;
        raContext->nonceRequestedLen = d.nonceDataLen;

#ifdef RATLS_DEBUG_OUTPUT
        std::cout << "[RA In (ServerHello)] Got remote attestation request from server" << std::endl;
#endif
    }

    // only parse the result and check the resumption secret if we really wanted to resume a session
    // so dont check this if we establish a new one
    if (extType == EXT_RA_RESUMPTION) {
        SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);
        RAClientContext *raContext = (RAClientContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

        if (context == SSL_EXT_TLS1_3_SERVER_HELLO) {
            std::string sessionIdStr = sessionIdToStr(ssl);

            if (raContext->sessionTicketBySessionId.find(sessionIdStr) == raContext->sessionTicketBySessionId.end()) {

#ifdef RATLS_DEBUG_OUTPUT
                std::cout << "[RA SR In (ServerHello)] Session resumption canceled: no matching secret found for session" << std::endl;
#endif
                return 0;
            }

            RASessionResumptionData sessionResumptionData;
            ///sessionResumptionData = *((RASessionResumptionData*)in);
            sessionResumptionData.deserialize((uint8_t*)in, inlen);

            if (raContext->sessionTicketBySessionId[sessionIdStr].clientSecret == sessionResumptionData.clientSecret) {
                // Session resumption remote attestation check
#ifdef RATLS_DEBUG_OUTPUT
                std::cout << "[RA SR In (ServerHello)] Session resumption successfully checked remote attestation" << std::endl;
#endif
                raContext->sessionTicketBySessionId.erase(sessionIdStr);

                return 1;
            }
            else {
                // Cancel handshake
#ifdef RATLS_DEBUG_OUTPUT
                std::cout << "[RA SR In (ServerHello)] Session resumption canceled: secrets didnt match" << std::endl;
#endif
                return 0;
            }
        }
        else if (context == SSL_EXT_TLS1_3_NEW_SESSION_TICKET) {
            RASessionResumptionData sessionResumptionData;
            //sessionResumptionData = *((RASessionResumptionData*)in);
            sessionResumptionData.deserialize((uint8_t*)in, inlen);

            // Session Ticket Data
            RASessionTicket &ticket = raContext->currentSessionTicket;

            ticket.sealedData = raContext->sealSessionSecretCB(sessionResumptionData.serverSecret, &ticket.sealedDataLength);
#ifdef RATLS_DEBUG_OUTPUT
            std::cout << "[RA SR (NewSessionTicket)] Sealed server secret " << sessionResumptionData.serverSecret << std::endl;
#endif
            ticket.clientSecret = sessionResumptionData.clientSecret;
            ticket.serverSecret = 0;

        }
    }

#ifdef TLS1_3_CERT_MSG_EXT
    if (extType == EXT_RA_RES_TLS1_3) {
        SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);
        RAClientContext *raContext = (RAClientContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

        // if we are parsing the servers certificate
        // and we are at the root certificate (chainidx == 0)
        if (context == SSL_EXT_TLS1_3_CERTIFICATE && chainidx == 0) {
            SSL_set_ex_data(ssl, raSessionFlagIndex, (void*)L"FLAG");

            RAQuote quote;
            quote.deserialize((uint8_t*)in, inlen);

            bool quoteOk = raContext->checkQuoteCB(quote, raContext->expectedNonce, raContext->expectedNonceLen);

#ifdef RATLS_DEBUG_OUTPUT
            printf("[RA In (TLS1.3 ServerCertificate)] Got attestation quote from server via tls1_3 cert msg extensions\n");
#endif

            delete[] quote.quoteData;

            if (!quoteOk) {
#ifdef RATLS_DEBUG_OUTPUT
                printf("[RA In (TLS1.3 ServerCertificate)] Quote not okay cancel handshake\n");
#endif
                return 0;
            }

#ifdef RATLS_DEBUG_OUTPUT
            printf("[RA In (TLS1.3 ServerCertificate)] Quote checked okay!\n");
#endif
        }

        if (context == SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
#ifdef RATLS_DEBUG_OUTPUT
            printf("[RA In (TLS1.3 CertificateRequest)] Remote attestation extension was correctly set in certificate request from server\n");
#endif
        }
    }
#endif

    return 1;
}

int callbackNewSession(SSL *ssl, SSL_SESSION *sess) {
    SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);

    RAServerContext *raContext = (RAServerContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

    if (raContext->sessionTicketBySessionId.size() > raContext->maxSessionTicketsNum) {
        raContext->popOldestSessionTicket();
    }

    raContext->currentSessionTicket.timeout = SSL_SESSION_get_timeout(sess);
    raContext->currentSessionTicket.ts = std::chrono::steady_clock::now();

    std::string sessionIdStr = sessionIdToStr(sess);
    raContext->sessionTicketBySessionId[sessionIdStr] = raContext->currentSessionTicket;

#ifdef RATLS_DEBUG_OUTPUT
    std::cout << "[RA SR] Session resumption entry created with secrets CS: " << raContext->currentSessionTicket.clientSecret << " Sealed SS " << "Buf" <<std::endl;
#endif

    if (raContext->customNewSession) {
        return raContext->customNewSession(ssl, sess);
    }

    return 1;
}

int callbackVerifyCertClient(int preverifyOk, X509_STORE_CTX *ctx) {
    // get ssl session from cert context
    SSL *ssl = (SSL*)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);

    BI::demoClient.setTlsStatus(BI::DemoStatus::Ok, "Barkhausen Institute");

    RAClientContext *raContext = (RAClientContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

    // is current cert the root certificate
    if (!SSL_get_ex_data(ssl, raSessionFlagIndex)) {
#ifdef RATLS_DEBUG_OUTPUT
        std::cout << "Handshake cancelled because server did not respond to RA Request" << std::endl;
#endif
        return 0;
    }

    if (raContext->customVerifyCallback) {
        return raContext->customVerifyCallback(preverifyOk, ctx);
    }
    else {
        return preverifyOk;
    }
}

void enableClientRemoteAttestation(RAClientContext *raContext, SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, callbackVerifyCertClient);
    SSL_CTX_set_ex_data(ctx, raContextDataIndex, raContext);

    SSL_CTX_sess_set_new_cb(ctx, callbackNewSession);

    SSL_CTX_add_custom_ext(ctx
        , EXT_RA_REQ, SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_2_SERVER_HELLO | SSL_EXT_TLS1_3_SERVER_HELLO
        , callbackAddExtensionRAClient
        , callbackFreeExtensionRAClient
        , raContext
        , callbackParseExtensionRAClient
        , raContext
    );

    SSL_CTX_add_custom_ext(ctx
        , EXT_RA_RESUMPTION, SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_NEW_SESSION_TICKET | SSL_EXT_TLS1_3_SERVER_HELLO
        , callbackAddExtensionRAClient
        , callbackFreeExtensionRAClient
        , raContext
        , callbackParseExtensionRAClient
        , raContext
    );

#ifdef TLS1_3_CERT_MSG_EXT
    SSL_CTX_add_custom_ext(ctx
        , EXT_RA_RES_TLS1_3, SSL_EXT_TLS1_3_CERTIFICATE | SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_CERTIFICATE_REQUEST
        , callbackAddExtensionRAClient
        , callbackFreeExtensionRAClient
        , raContext
        , callbackParseExtensionRAClient
        , raContext
    );
#endif
}

int callbackAddExtensionRAServer(SSL *ssl, unsigned int extType,
    unsigned int context,
    const unsigned char** out,
    size_t *outlen, X509 *x,
    size_t chainidx,
    int *al, void *addArg) {

    //std::cout << "[ADD] extensions callback for context " << context << " and extension type " << extType << " and chain idx " << chainidx << std::endl;

    if (extType == EXT_RA_REQ) {
        SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);
        RAServerContext *raContext = (RAServerContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

        if (raContext->forceClientRemoteAttestation) {
            if (raContext->expectedNonce != nullptr) {
                delete[] raContext->expectedNonce;
                raContext->expectedNonce = nullptr;
                raContext->expectedNonceLen = 0;
            }

            // Request remote attestation of client
            RARequestData d;
            //uint64_t pcrSlotMask;
            size_t nonceLen;
            d.nonceData = raContext->expectedNonce = raContext->createRequestCB(&nonceLen);
            d.nonceDataLen = raContext->expectedNonceLen = nonceLen;

            *out = d.serialize(outlen);
#ifdef RATLS_DEBUG_OUTPUT
            std::cout << "[RA Out (ServerHello)] Requesting RA from client with nonce " << std::endl;
#endif
        }
        else {
            return 0;
        }
    }

    if (extType == EXT_RA_RESUMPTION) {
        SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);
        RAServerContext *raContext = (RAServerContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

        if (context == SSL_EXT_TLS1_3_NEW_SESSION_TICKET) {
            std::cout << "Addextension SessionCallback" << std::endl;

            // Resumption Data
            RASessionResumptionData d;
            d.clientSecret = (rand() % UINT32_MAX);
            d.serverSecret = (rand() % UINT32_MAX);

            // Session Ticket Data

            raContext->currentSessionTicket.sealedData = raContext->sealSessionSecretCB(d.clientSecret, &raContext->currentSessionTicket.sealedDataLength);
#ifdef RATLS_DEBUG_OUTPUT
            std::cout << "[RA SR (NewSessionTicket)] Sealed client secret " << d.clientSecret << std::endl;
#endif
            raContext->currentSessionTicket.serverSecret = d.serverSecret;


            *out = d.serialize(outlen);

#ifdef RATLS_DEBUG_OUTPUT
            std::cout << "[RA SR Out (NewSessionTicket)] Session Resumption CS: " << d.clientSecret << " SS: " << d.serverSecret << std::endl;
#endif
        }
        else if (context == SSL_EXT_TLS1_3_SERVER_HELLO) {
            if (SSL_SESSION_is_resumable(SSL_get_session(ssl))) {
                std::string sessionIdStr = sessionIdToStr(ssl);

                if (raContext->sessionTicketBySessionId.find(sessionIdStr) == raContext->sessionTicketBySessionId.end()) {

#ifdef RATLS_DEBUG_OUTPUT
                    std::cout << "[RA SR Out (ServerHello)] Session resumption canceled: no matching secret found for session" << std::endl;
#endif
                    return 0;
                }

                RASessionTicket &ticket = raContext->sessionTicketBySessionId[sessionIdStr];
                
                ///uint32_t unsealedClientSecret = raContext->unsealSessionSecretCB(&ticket.sealedClientSecret, ticket.sealingData, ticket.sealingDataLength);

                uint32_t unsealedClientSecret;
                size_t unsealedLength;
                uint8_t *unsealedSessionSecret = raContext->unsealSessionSecretCB(ticket.sealedData, ticket.sealedDataLength, &unsealedLength);
                if (unsealedSessionSecret == nullptr) {
                    return 0;
                }

                memcpy(&unsealedClientSecret, unsealedSessionSecret, unsealedLength);
                delete[] unsealedSessionSecret;
                delete[] ticket.sealedData;
                ticket.sealedData = nullptr;

                raContext->sessionTicketBySessionId.erase(sessionIdStr);

#ifdef RATLS_DEBUG_OUTPUT
                std::cout << "[RA SR (ServerHello)] Unsealed session client secret: " << unsealedClientSecret << std::endl;
#endif

                RASessionResumptionData d;
                d.clientSecret = unsealedClientSecret;
                d.serverSecret = 0;

                *out = d.serialize(outlen);
            }
            else return 0;
        }

    }

#ifdef TLS1_3_CERT_MSG_EXT
    if (extType == EXT_RA_RES_TLS1_3) {
        SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);
        RAServerContext *raContext = (RAServerContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

        // if we are sending our certificate append the remote attestation evidence
        // and we are at the root certificate (chainidx == 0)
        if (context == SSL_EXT_TLS1_3_CERTIFICATE && chainidx == 0) {
            // Fill / do remote attestion for the client
            RAQuote quote = raContext->remoteAttestCB(raContext->nonceRequested, raContext->nonceRequestedLen);

            *out = quote.serialize(outlen);

            delete[] quote.quoteData;

#ifdef RATLS_DEBUG_OUTPUT
            std::cout << "[RA Out (TLS1.3 Certificate)] Remote attesting to client with nonce len: " << (int)*outlen << std::endl;
#endif
        }

        // if we are sending a certifcate request append an empty extension so the client can respond in its certificate
        // -> see specification
        if (context == SSL_EXT_TLS1_3_CERTIFICATE_REQUEST) {
            *out = new unsigned char[1];
            *outlen = 1;

#ifdef RATLS_DEBUG_OUTPUT
            std::cout << "[RA Out (TLS1.3 Certificate Request)] Appending placeholder extension to certificate request so that the client can respond" << std::endl;
#endif
        }

    }
#endif

    return 1;
}

void callbackFreeExtensionRAServer(SSL *s, unsigned int extType,
    unsigned int context,
    const unsigned char *out,
    void *add_arg) {

    if (extType == EXT_RA_REQ) {
        delete[] out;
    }

    if (extType == EXT_RA_RESUMPTION) {
        delete[] out;
    }

#ifdef TLS1_3_CERT_MSG_EXT
    if (extType == EXT_RA_RES_TLS1_3) {
        delete[] out;
    }
#endif
}

int callbackParseExtensionRAServer(SSL *ssl, unsigned int extType,
    unsigned int context,
    const unsigned char *in,
    size_t inlen, X509 *x,
    size_t chainidx,
    int *al, void *parseArg) {

    //std::cout << "[PARSE] extensions callback for context " << context << " and extension type " << extType << " and chain idx " << chainidx << std::endl;

    if (extType == EXT_RA_REQ) {
        SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);
        RAServerContext *raContext = (RAServerContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

        RARequestData d;
        d.deserialize((uint8_t*)in, inlen);

        if (raContext->nonceRequested != nullptr) {
            delete[] raContext->nonceRequested;
            raContext->nonceRequested = nullptr;
            raContext->nonceRequestedLen = 0;
        }

        raContext->nonceRequested = d.nonceData;
        raContext->nonceRequestedLen = d.nonceDataLen;
#ifdef RATLS_DEBUG_OUTPUT
        std::cout << "[RA In (ClientHello)] Got attestation request from client: (";
        std::cout << (((uint8_t*)raContext->nonceRequested)[0]) << std::endl;
#endif


#ifndef TLS1_3_CERT_MSG_EXT
        RAQuote quote;
        quote.nonce = d.nonce;
        // TODO Do remote attestation

        printf("\n\n=================================\n");
        printf("Generating RAExtension Cert\n");
        //std::pair<X509*, EVP_PKEY*> racert = generateRAExtendedCert(privateKey, quote);

        X509 *racert = generateSignedRAExtendedCert(publicKey, privateKey, cert, quote);
        X509_print_fp(stdout, racert);

        printf("\n\n=================================\n");
        printf("Verifying RAExtension certificate signature: %s \n", X509_verify(racert, publicKey) == 1 ? "valid" : "invalid");

        SSL_use_certificate(s, racert);
        SSL_use_PrivateKey(s, privateKey);

        /*X509 *racert = generateSignedCert(containerKeyPair, privateKey, cert, quote);
        X509_print_fp(stdout, racert);

        printf("\n\n=================================\n");
        printf("Verifying RAExtension certificate signature: %s \n", X509_verify(racert, publicKey) == 1 ? "valid" : "invalid");

        SSL_use_certificate(s, racert);
        SSL_use_PrivateKey(s, containerKeyPair);*/
#endif
    }

    // header only set if client set it in its client hello
    if (extType == EXT_RA_RESUMPTION) {
        SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);
        RAServerContext *raContext = (RAServerContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

        RASessionResumptionData sessionResumptionData;
        //sessionResumptionData = *((RASessionResumptionData*)in);
        sessionResumptionData.deserialize((uint8_t*)in, inlen);

        if (SSL_SESSION_is_resumable(SSL_get_session(ssl))) {
            uint32_t resumptionSecret = sessionResumptionData.serverSecret;

            std::string sessionIdStr = sessionIdToStr(ssl);
#ifdef RATLS_DEBUG_OUTPUT
            std::cout << "[RA SR In (ClientHello)] Session resumption check for server secret: " << resumptionSecret << std::endl;
#endif
            if (raContext->sessionTicketBySessionId.find(sessionIdStr) == raContext->sessionTicketBySessionId.end()) {

#ifdef RATLS_DEBUG_OUTPUT
                std::cout << "[RA SR In (ClientHello)] Session resumption canceled: no matching secret found for session" << std::endl;
#endif
                return 0;
            }

            if (raContext->sessionTicketBySessionId[sessionIdStr].serverSecret == resumptionSecret) {
                // Session resumption remote attestation check
#ifdef RATLS_DEBUG_OUTPUT
                std::cout << "[RA SR In (ClientHello)] Session resumption successfully checked remote attestation" << std::endl;
#endif
                return 1;
            }
            else {
                // Cancel handshake
#ifdef RATLS_DEBUG_OUTPUT
                std::cout << "[RA SR In (ClientHello)] Session resumption canceled: secrets didnt match" << std::endl;
#endif
                return 0;
            }
        }
    }

#ifdef TLS1_3_CERT_MSG_EXT
    if (extType == EXT_RA_RES_TLS1_3) {
        SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);
        RAServerContext *raContext = (RAServerContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

        if (context == SSL_EXT_TLS1_3_CERTIFICATE) {
            SSL_set_ex_data(ssl, raSessionFlagIndex, (void*)L"FLAG");

            //RAQuote quote = *(RAQuote*)in;

            RAQuote quote;
            quote.deserialize((uint8_t*)in, inlen);

            bool quoteOk = raContext->checkQuoteCB(quote, raContext->expectedNonce, raContext->expectedNonceLen);

#ifdef RATLS_DEBUG_OUTPUT
            printf("[RA In (TLS1.3 ClientCertificate)] Got attestation quote from client via tls1_3 cert msg extensions\n");
#endif

            delete[] quote.quoteData;

            if (!quoteOk) {
#ifdef RATLS_DEBUG_OUTPUT
                printf("[RA In (TLS1.3 ClientCertificate)] Quote not okay cancel handshake\n");
#endif
                return 0;
            }

#ifdef RATLS_DEBUG_OUTPUT
            printf("[RA In (TLS1.3 ClientCertificate)] Quote checked okay!\n");
#endif
        }

        if (context == SSL_EXT_CLIENT_HELLO) {
#ifdef RATLS_DEBUG_OUTPUT
            printf("[RA In (ClientHello)] Remote attestation cert ext was correctly set in client hello from client\n");
#endif          
}

    }
#endif

    return 1;
}

int callbackVerifiyCertServer(int preverifyOk, X509_STORE_CTX *ctx) {
    // get ssl session from cert context
    SSL *ssl = (SSL*)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    SSL_CTX *sslCtx = SSL_get_SSL_CTX(ssl);

    RAServerContext *raContext = (RAServerContext*)SSL_CTX_get_ex_data(sslCtx, raContextDataIndex);

    if (!SSL_get_ex_data(ssl, raSessionFlagIndex)) {
        if (raContext->forceClientRemoteAttestation) {

#ifdef RATLS_DEBUG_OUTPUT
            std::cout << "Handshake cancelled because client did not respond to RA Request" << std::endl;
#endif
            return 0;
        }
    }

    if (raContext->customVerifyCallback) {
        return raContext->customVerifyCallback(preverifyOk, ctx);
    }
    else {
        return preverifyOk;
    }
}

void enableServerRemoteAttestation(RAServerContext *raContext, SSL_CTX *ctx) {
    if (raContext->forceClientRemoteAttestation) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, callbackVerifiyCertServer);
    }

    SSL_CTX_sess_set_new_cb(ctx, callbackNewSession);
    SSL_CTX_set_ex_data(ctx, raContextDataIndex, raContext);

    SSL_CTX_add_custom_ext(ctx
        , EXT_RA_REQ, SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_2_SERVER_HELLO | SSL_EXT_TLS1_3_SERVER_HELLO
        , callbackAddExtensionRAServer
        , callbackFreeExtensionRAServer
        , raContext
        , callbackParseExtensionRAServer
        , raContext
    );

    SSL_CTX_add_custom_ext(ctx
        , EXT_RA_RESUMPTION, SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_NEW_SESSION_TICKET | SSL_EXT_TLS1_3_SERVER_HELLO
        , callbackAddExtensionRAServer
        , callbackFreeExtensionRAServer
        , raContext
        , callbackParseExtensionRAServer
        , raContext
    );

#ifdef TLS1_3_CERT_MSG_EXT
    SSL_CTX_add_custom_ext(ctx
        , EXT_RA_RES_TLS1_3, SSL_EXT_TLS1_3_CERTIFICATE | SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_CERTIFICATE_REQUEST
        , callbackAddExtensionRAServer
        , callbackFreeExtensionRAServer
        , raContext
        , callbackParseExtensionRAServer
        , raContext
    );
#endif
}

} // namespace RATLS
