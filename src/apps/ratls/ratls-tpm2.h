#pragma once

#include <vector>

#if defined(__m3__)
#include <Tpm2.h>
#else
#include <tss/Tpm2.h>
#endif

#include "ratls.h"

// ************************************************************************************************

namespace RATLS {

// ************************************************************************************************

typedef enum {
    Invalid = 0,
    Hardware = 1,
    Simulator = 2,
    Null = 3,
} TpmInitMode;

typedef struct {
    TpmInitMode initMode;
    std::string devName;
} TpmDevInfo;

// ************************************************************************************************

class TpmRoT {
public:
    TpmRoT(TpmDevInfo tpmDevInfo, std::string appName);
    void terminateTpm();

    static TpmDevInfo parseCommandLine(int &argc, char const *argv[]);

    RATLS::RAQuote* remoteAttest(std::vector<uint32_t> pcrSlots, void *nonce, size_t nonceLen);

    bool checkQuote(RATLS::RAQuote &raQuote, std::vector<uint32_t> pcrSlots,
                    std::vector<TpmCpp::TPM2B_DIGEST> expectedPcrSlotValues,
                    void *nonceExpected, size_t nonceExpectedLen);

    uint8_t *seal(TpmCpp::ByteVec authValue, std::vector<uint32_t> pcrSlots,
                  void *dataToSeal, int dataToSealLength, size_t *sealingDataLength);

    uint8_t *unseal(TpmCpp::ByteVec authValue, std::vector<uint32_t> &pcrSlots,
                    uint8_t *sealingData, size_t sealingDataLength, size_t *unsealedDataLength);

    void pcrExtend(int pcr, const std::vector<uint8_t> &data);
    void pcrReset(int pcr);
    std::vector<uint8_t> pcrRead(int pcr);

protected:
    bool initTpm(std::string appName);

    std::string objectFileName(std::string objName) const;

    template <typename OBJ>
    void saveObject(std::string objName, OBJ const &obj);
    
    template <typename OBJ>
    bool loadObject(std::string objName, OBJ &obj);

    TpmCpp::TPM_HANDLE getKeyFromSavedContext(std::string keyName);
    
    TpmCpp::TPM_HANDLE getStorageKey(std::string keyName);
    TpmCpp::TPM_HANDLE getAttestationKey(std::string keyName, TpmCpp::TPM_HANDLE parentKeyHandle);

    TpmCpp::Tpm2 tpm;
    TpmCpp::TpmDevice *device;
    TpmCpp::TPM_HANDLE storageKey;
    TpmCpp::TPM_HANDLE attestationKey;
    TpmDevInfo devInfo;
};

// ************************************************************************************************

} // namespace RATLS_TPM2
