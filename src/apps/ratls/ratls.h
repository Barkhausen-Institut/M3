#pragma once

/**

    If client or server remote attestation is enabled,
    SSL_CTX_set_verify should not be called on that context
    anymore.
    The customVerifyCallback in the RAServerContext and RAClientContext
    should be used instead.

**/

#define TLS1_3_CERT_MSG_EXT

#define RATLS_DEBUG_OUTPUT

#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <cassert>
#include <chrono>
#include <queue>

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/ocsp.h>
#include <openssl/cms.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define EXT_RA_REQ 420

#ifdef TLS1_3_CERT_MSG_EXT
#define EXT_RA_RES_TLS1_3 421
#endif

#define EXT_RA_RESUMPTION 422

#define CERT_EXT_RA_QUOTE "2.5.29.70"

namespace BigEndianPack {

static inline void pack4ByteInteger(uint8_t *dst, uint32_t value) {
    for (int i = 0; i < 4; i++) {
        dst[i] = (uint8_t)((value >> ((3 - i) * 8)) & 0xFF);
    }
}

static inline void pack8ByteInteger(uint8_t *dst, uint64_t value) {
    for (int i = 0; i < 8; i++) {
        dst[i] = (uint8_t)((value >> ((7 - i) * 8)) & 0xFF);
    }
}

static inline int unpack4ByteInteger(uint8_t *src) {
    return ((src[0] & 0xFF) << 24) | ((src[1] & 0xFF) << 16) | ((src[2] & 0xFF) << 8) | (src[3] & 0xFF);
}

static inline uint64_t unpack8ByteInteger(uint8_t *src) {
    unsigned long long result = 0;
    for (int i = 0; i < 8; i++) {
        result <<= 8;
        result |= (uint64_t)src[i];
    }
    return result;
}

} // namespace BigEndianPack

namespace RATLS {

struct RASessionTicket {
    uint32_t clientSecret;
    uint32_t serverSecret;
    
    std::chrono::steady_clock::time_point ts;
    long timeout;

    uint8_t *sealedData;
    size_t sealedDataLength;
};

class RASessionResumptionData {
private:
    size_t getSerializedLength() {
        return sizeof(uint32_t) * 2;
    }

public:
    uint32_t clientSecret;
    uint32_t serverSecret;

public:
    uint8_t *serialize(size_t *outLen) {
        *outLen = getSerializedLength();
        uint8_t *out = new uint8_t[*outLen];
        BigEndianPack::pack4ByteInteger(out, clientSecret);
        BigEndianPack::pack4ByteInteger(&out[4], serverSecret);
        return out;
    }

    void deserialize(uint8_t *serialized, size_t serializedLength) {
        clientSecret = BigEndianPack::unpack4ByteInteger(serialized);
        serverSecret = BigEndianPack::unpack4ByteInteger(&serialized[4]);
    }

};

class RARequestData {
private:
    size_t getSerializedLength() {
        return sizeof(uint32_t) + nonceDataLen;
    }

public:
    uint32_t nonceDataLen;
    uint8_t *nonceData = 0;

public:
    uint8_t *serialize(size_t *outLen) {
        *outLen = getSerializedLength();
        uint8_t *out = new uint8_t[*outLen];
        BigEndianPack::pack4ByteInteger(out, nonceDataLen);
        memcpy(&out[4], nonceData, nonceDataLen);
        return out;
    }

    void deserialize(uint8_t *serialized, size_t serializedLength) {
        nonceDataLen = BigEndianPack::unpack4ByteInteger(serialized);

        if (nonceDataLen > 0 && serializedLength - 4 == nonceDataLen) {
            nonceData = new uint8_t[nonceDataLen];
            memcpy(nonceData, &serialized[4], nonceDataLen);
        }
        else {
            nonceData = nullptr;
            nonceDataLen = 0;
        }
    }
};

class RAQuote {
private:
    size_t getSerializedLength() {
        return sizeof(uint32_t) + quoteDataLen;
    }

public:
    uint32_t quoteDataLen;
    uint8_t *quoteData;

public:
    uint8_t *serialize(size_t *outLen) {
        *outLen = getSerializedLength();
        uint8_t *out = new uint8_t[*outLen];
        BigEndianPack::pack4ByteInteger(out, quoteDataLen);
        memcpy(&out[4], quoteData, quoteDataLen);
        return out;
    }

    void deserialize(uint8_t *serialized, size_t serializedLength) {
        quoteDataLen = BigEndianPack::unpack4ByteInteger(serialized);

        if (quoteDataLen > 0 && serializedLength - 4 == quoteDataLen) {
            quoteData = new uint8_t[quoteDataLen];
            memcpy(quoteData, &serialized[4], quoteDataLen);
        }
        else {
            quoteData = nullptr;
            quoteDataLen = 0;
        }
    }
};

typedef RAQuote(*RACallbackRemoteAttest)(uint8_t *nonce, size_t nonceLen);

typedef uint8_t *(*RACallbackCreateRequest)(size_t *nonceLen);

typedef bool (*RACallbackCheckQuote)(RAQuote &quote, uint8_t *nonceExpected, size_t nonceExpectedLen);

typedef uint8_t *(*RACallbackSealSessionSecret)(uint32_t sessionSecret, size_t *sealedDataLength);

typedef uint8_t *(*RACallbackUnsealSessionSecret)(uint8_t *sealedData, size_t sealedDataLength, size_t *unsealedDataLength);

typedef int (*RACallbackCustomNewSession) (struct ssl_st *ssl, SSL_SESSION *sess);

class RAContext {
public:
    size_t expectedNonceLen = 0;
    uint8_t *expectedNonce = nullptr;
    size_t nonceRequestedLen = 0;
    uint8_t *nonceRequested = nullptr;

    RASessionTicket currentSessionTicket;

    size_t maxSessionTicketsNum = 1000;

    std::map<std::string, RASessionTicket> sessionTicketBySessionId;
    RACallbackRemoteAttest remoteAttestCB = nullptr;
    RACallbackCheckQuote checkQuoteCB = nullptr;
    RACallbackSealSessionSecret sealSessionSecretCB = nullptr;
    RACallbackUnsealSessionSecret unsealSessionSecretCB = nullptr;
    RACallbackCreateRequest createRequestCB = nullptr;

    SSL_verify_cb customVerifyCallback = nullptr;
    RACallbackCustomNewSession customNewSession = nullptr;
public:
    void popOldestSessionTicket() {
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();

        std::string oldestSessionId;
        long oldestTime = LONG_MAX;

        std::queue<std::string> timedOutSessionIds;

        for (std::pair<std::string, RASessionTicket> pair : sessionTicketBySessionId) {
            RASessionTicket &ticket = pair.second;
            long time = std::chrono::duration_cast<std::chrono::milliseconds>(now - ticket.ts).count();
            if (time < oldestTime) {
                oldestSessionId = pair.first;
                oldestTime = time;
            }

            if (time > ticket.timeout) {
                timedOutSessionIds.push(pair.first);
            }
        }

        // if no session tickets timedout erase the oldest one
        if (timedOutSessionIds.empty()) {
            auto it = sessionTicketBySessionId.find(oldestSessionId);
            if (it != sessionTicketBySessionId.end()) {
                delete [] it->second.sealedData;
                sessionTicketBySessionId.erase(it);
            }
        }
        else {
            // otherwise erase all the timed out tickets
            while (!timedOutSessionIds.empty()) {
                std::string sessionId = timedOutSessionIds.front();
                auto it = sessionTicketBySessionId.find(sessionId);
                if (it != sessionTicketBySessionId.end()) {
                    delete [] it->second.sealedData;
                    sessionTicketBySessionId.erase(it);
                }
                timedOutSessionIds.pop();
            }
        }
    }
};

class RAServerContext : public RAContext {
public:
    bool forceClientRemoteAttestation = false;
};

class RAClientContext : public RAContext {
public:
    bool onlyAllowRemoteAttestedSessionResumption = true;
};

void setupRATLS();

int callbackAddExtensionRAClient(SSL *ssl, unsigned int extType,
    unsigned int context,
    const unsigned char** out,
    size_t *outlen, X509 *x,
    size_t chainidx,
    int *al, void *addArg);

void callbackFreeExtensionRAClient(SSL *s, unsigned int extType,
    unsigned int context,
    const unsigned char *out,
    void *addArg);

int callbackParseExtensionRAClient(SSL *ssl, unsigned int extType,
    unsigned int context,
    const unsigned char *in,
    size_t inlen, X509 *x,
    size_t chainidx,
    int *al, void *parseArg);

int callbackNewSession(SSL *ssl, SSL_SESSION *sess);

int callbackVerifyCertClient(int preverifyOk, X509_STORE_CTX *ctx);

void enableClientRemoteAttestation(RAClientContext *raContext, SSL_CTX *ctx);

int callbackAddExtensionRAServer(SSL *ssl, unsigned int extType,
    unsigned int context,
    const unsigned char** out,
    size_t *outlen, X509 *x,
    size_t chainidx,
    int *al, void *addArg);

void callbackFreeExtensionRAServer(SSL *s, unsigned int extType,
    unsigned int context,
    const unsigned char *out,
    void *add_arg);

int callbackParseExtensionRAServer(SSL *ssl, unsigned int extType,
    unsigned int context,
    const unsigned char *in,
    size_t inlen, X509 *x,
    size_t chainidx,
    int *al, void *parseArg);

int callbackVerifiyCertServer(int preverifyOk, X509_STORE_CTX *ctx);

void enableServerRemoteAttestation(RAServerContext *raContext, SSL_CTX *ctx);

} // namespace RATLS
