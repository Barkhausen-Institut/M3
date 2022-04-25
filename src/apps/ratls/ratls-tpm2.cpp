#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <stdexcept>

#if defined(__m3__)
#include <Tpm2.h>
#else
#include <tss/Tpm2.h>
#endif

#include "errorhelper.h"
#include "ratls-tpm2.h"
#include "benchmark.h"

// ************************************************************************************************

using namespace Err;
using namespace TpmCpp;

namespace RATLS {

// ************************************************************************************************

TpmDevInfo TpmRoT::parseCommandLine(int &argc, char const *argv[]) {

    TpmDevInfo devInfo = { TpmInitMode::Invalid, "" };
    if (argc >= 3) {
        std::string mode = argv[1];
        std::string devName = argv[2];

        if (mode == "--tpm-null") {
            devInfo = { TpmInitMode::Null, devName };

#if ! defined(__m3__)
        } else if (mode == "--tpm-hardware") {
            devInfo = { TpmInitMode::Hardware, devName };

        } else if (mode == "--tpm-simulator") {
            devInfo = { TpmInitMode::Simulator, devName };
#endif
        }

        if (devInfo.initMode != TpmInitMode::Invalid) {
            // remove recognized commandline arguments to simplify argument handling
            // in calling program's main() function
            for (int i = 3; i < argc; i++)
                argv[i-2] = argv[i];
            argc -= 2;
        }
    }

    return devInfo;
}

std::string TpmRoT::objectFileName(std::string objName) const {

    std::string stateDir = "/var/lib/ratls-tpm2/";
    std::string devId = devInfo.devName;

    if (devId.find(stateDir) == 0)
        devId.replace(0, stateDir.length(), "");
    for (size_t i = 0; i < devId.length(); i++) {
        if (devId[i] == '/')
            devId[i] = '_';
    }

    return std::string(stateDir) + devId + "_" + objName;
}


template <typename OBJ>
void TpmRoT::saveObject(std::string objName, OBJ const &obj) {

    PlainTextSerializer s;
    obj.Serialize(s);

    int fd = chksys(open(objectFileName(objName).c_str(), O_WRONLY | O_CREAT, 0640), "open saved object file");
    chksys(write(fd, s.ToString().c_str(), s.ToString().length()), "write saved object file");
    chksys(close(fd), "close saved object file");
}


template <typename OBJ>
bool TpmRoT::loadObject(std::string objName, OBJ &obj) {

    // printf("%s\n", objectFileName(objName).c_str());
    int fd = open(objectFileName(objName).c_str(), O_RDONLY);
    if (fd < 0)
        return false;

    struct stat st;
    chksys(fstat(fd, &st), "stat saved object file");
    
    char *buf = new char[st.st_size];
    chksys(read(fd, buf, st.st_size), "read saved oject file");
    chksys(close(fd), "close saved object file");

    PlainTextSerializer s = std::string(buf);
    obj.Deserialize(s);

    return true;
}


TPM_HANDLE TpmRoT::getKeyFromSavedContext(std::string keyName) {

    TPM_HANDLE keyHandle;
    TPMS_CONTEXT keyCtx;

    if (loadObject(keyName + ".ctx", keyCtx)) {
        keyHandle = tpm.ContextLoad(keyCtx);
        // printf("%s:%d: %s.handle = %u\n",
        //        __FILE__, __LINE__,
        //        keyName.c_str(), keyHandle.handle);
    }

    return keyHandle;
}


TPM_HANDLE TpmRoT::getStorageKey(std::string keyName) {

    TPM_HANDLE keyHandle;

    if (loadObject(keyName + ".handle", keyHandle)) {
        printf("Restored persistent handle %u for %s\n", keyHandle.handle, keyName.c_str());
        return keyHandle;
    }

    // RSA primary storage key
    TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted | TPMA_OBJECT::fixedParent |
        TPMA_OBJECT::fixedTPM | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        {},
        TPMS_RSA_PARMS({ TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB }, TPMS_NULL_ASYM_SCHEME(), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());

    // ECC primary storage key
    // throws "Only RSA signature verificaion is supported" on quote checking
    // based on https://github.com/microsoft/TSS.MSR/blob/0f2516fca2cd9929c31d5450e39301c9bde43688/TSS.Java/src/samples/Samples.java#L993
    /*TPMT_PUBLIC storagePrimaryTemplate(TPM_ALG_ID::SHA1,
        TPMA_OBJECT::decrypt | TPMA_OBJECT::restricted | TPMA_OBJECT::fixedParent |
        TPMA_OBJECT::fixedTPM | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        {},
        TPMS_ECC_PARMS(
            { TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB },
            TPMS_NULL_ASYM_SCHEME(),
            TPM_ECC_CURVE::NIST_P256,
            TPMS_NULL_KDF_SCHEME()),
        TPMS_ECC_POINT());*/

    keyHandle = tpm.CreatePrimary(TPM_RH::OWNER, {}, storagePrimaryTemplate, {}, {}).handle;

    TPM_HANDLE persistentKeyHandle = TPM_HANDLE::Persistent(1000);
    tpm.EvictControl(TPM_RH::OWNER, keyHandle, persistentKeyHandle);

    saveObject(keyName + ".handle", persistentKeyHandle);

    return keyHandle;
}


TPM_HANDLE TpmRoT::getAttestationKey(std::string keyName, TPM_HANDLE parentKeyHandle) {

    TPM_HANDLE keyHandle;

    if (loadObject(keyName + ".handle", keyHandle)) {
        printf("Restored persistent handle %u for %s\n", keyHandle.handle, keyName.c_str());
        return keyHandle;
    }

    TPM2B_PRIVATE savedPrivate;
    TPMT_PUBLIC savedPublic;

    // RSA attestation key
    TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
        | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
        {},
        TPMS_RSA_PARMS({}, TPMS_SCHEME_RSASSA(TPM_ALG_ID::SHA256), 2048, 65537),
        TPM2B_PUBLIC_KEY_RSA());

    // ECC attestaion key
    // throws "Only RSA signature verificaion is supported" on quote checking
    /*TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
            TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
            | TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
            {},
            TPMS_ECC_PARMS(
                TPMT_SYM_DEF_OBJECT(),
                TPMS_SIG_SCHEME_ECDSA(TPM_ALG_ID::SHA1),
                TPM_ECC_CURVE::NIST_P256,
                TPMS_NULL_KDF_SCHEME()),
            TPMS_ECC_POINT());*/

    CreateResponse createResp = tpm.Create(parentKeyHandle, {}, templ, {}, {});
    keyHandle = tpm.Load(parentKeyHandle, createResp.outPrivate, createResp.outPublic);
    saveObject(keyName + ".pub", createResp.outPublic);

    TPM_HANDLE persistentKeyHandle = TPM_HANDLE::Persistent(1001);
    tpm.EvictControl(TPM_RH::OWNER, keyHandle, persistentKeyHandle);
    saveObject(keyName + ".handle", persistentKeyHandle);

    return keyHandle;
}

// ************************************************************************************************

TpmRoT::TpmRoT(TpmDevInfo tpmDevInfo, std::string appName) {
    device = nullptr;
    storageKey = attestationKey = 0;

    devInfo = tpmDevInfo;
    chk(initTpm(appName), "init TPM");
}

bool TpmRoT::initTpm(std::string appName) {

    switch (devInfo.initMode) {
        case TpmInitMode::Null:
            device = chk(new TpmNullDevice(), "new TpmNullDevice");
            break;
#if ! defined(__m3__)
        case TpmInitMode::Hardware:
            device = chk(new TpmCharDevice(devInfo.devName), "new TpmCharDevice");
            break;
        case TpmInitMode::Simulator:
            device = chk(new TpmUnixDevice(devInfo.devName), "new TpmUnixDevice");
            break;
#endif
        default:
            throw std::runtime_error("invalid init mode");
    }

    chk(device->Connect(), "TPM connect");

    tpm._SetDevice(*device);

    if (devInfo.initMode != TpmInitMode::Null) {
        storageKey = getStorageKey(appName + "-srk");
        attestationKey = getAttestationKey(appName + "-ak", storageKey);
    }

    return true;
}

// ************************************************************************************************

RATLS::RAQuote* TpmRoT::remoteAttest(std::vector<uint32_t> pcrSlots, void *nonce, size_t nonceLen) {

    Benchmarking::startMeasure(Benchmarking::OpType::RemoteAttest);

    TPM_ALG_ID bank = TPM_ALG_ID::SHA256;
    vector<TPMS_PCR_SELECTION> pcrsToQuote;
    for (uint32_t pcrSlot : pcrSlots) {
        pcrsToQuote.push_back(TPMS_PCR_SELECTION(bank, pcrSlot));
    }

    PCR_ReadResponse pcrVals = tpm.PCR_Read(pcrsToQuote);

    ByteVec nonceVec = ByteVec(nonceLen);
    memcpy(nonceVec.data(), (uint8_t*)nonce, nonceLen);

    QuoteResponse quote = tpm.Quote(attestationKey, nonceVec, TPMS_NULL_SIG_SCHEME(), pcrsToQuote);

    std::string quoteJson = quote.Serialize(SerializationType::JSON);
    //std::cout << quoteJson << std::endl;

    ReadPublicResponse createResp = tpm.ReadPublic(attestationKey);
    std::string publicJson = createResp.outPublic.Serialize(SerializationType::JSON);
    //std::cout << publicJson << std::endl;

    // Create the quote buffer
    RATLS::RAQuote* quoteRA = new RATLS::RAQuote();
    int len = publicJson.size() + 1 + quoteJson.size() + 1;

    quoteRA->quoteData = new uint8_t[len];

    // Pack public key json
    memcpy(quoteRA->quoteData, publicJson.c_str(), publicJson.size());
    ((char*)quoteRA->quoteData)[publicJson.size()] = '\0';

    // Pack the quote json
    memcpy(&((char*)quoteRA->quoteData)[1 + publicJson.size()], quoteJson.c_str(), quoteJson.size());
    ((char*)quoteRA->quoteData)[publicJson.size() + 1 + quoteJson.size()] = '\0';

    quoteRA->quoteDataLen = len;

    Benchmarking::stopMeasure(Benchmarking::OpType::RemoteAttest);

    return quoteRA;
}


bool TpmRoT::checkQuote(RATLS::RAQuote &raQuote, std::vector<uint32_t> pcrSlots,
                        std::vector<TpmCpp::TPM2B_DIGEST> expectedPcrSlotValues,
                        void *nonceExpected, size_t nonceExpectedLen) {

    Benchmarking::startMeasure(Benchmarking::OpType::CheckQuote);

    using namespace TpmCpp;
    std::string publicJson = std::string((char*)raQuote.quoteData);
    std::string quoteJson = std::string(((char*)raQuote.quoteData + publicJson.size() + 1));
    QuoteResponse quote;
    quote.Deserialize(SerializationType::JSON, quoteJson);

    TPMT_PUBLIC pubKey;
    pubKey.Deserialize(SerializationType::JSON, publicJson);

    // TODO check public key somehow
    //std::cout << "Checking quote: " << quote.ToString() << "\n for public key: " << pubKey.ToString() << std::endl;

    PCR_ReadResponse pcrVals;
    pcrVals.pcrValues = expectedPcrSlotValues;

    vector<TPMS_PCR_SELECTION> pcrsToQuote;
    for (int pcr : pcrSlots) {
        pcrsToQuote.push_back(TPMS_PCR_SELECTION(TPM_ALG_ID::SHA256, pcr));
    }
    pcrVals.pcrSelectionOut = pcrsToQuote;

    ByteVec nonce = ByteVec(nonceExpectedLen);
    memcpy(nonce.data(), nonceExpected, nonceExpectedLen);

    bool s = pubKey.ValidateQuote(pcrVals, nonce, quote);

    Benchmarking::stopMeasure(Benchmarking::OpType::CheckQuote);

    return s;
}

uint8_t *TpmRoT::seal(TpmCpp::ByteVec authValue, std::vector<uint32_t> pcrSlots,
                      void *dataToSeal, int dataToSealLength, size_t *sealingDataLength) {
    Benchmarking::measureSingleValue(Benchmarking::OpType::NumSeals);
    Benchmarking::startMeasure(Benchmarking::OpType::Seal);

    using namespace TpmCpp;

    TPM_ALG_ID bank = TPM_ALG_ID::SHA256;
    vector<TPMS_PCR_SELECTION> pcrSelection;
    for (uint32_t pcrSlot : pcrSlots) {
        pcrSelection.push_back(TPMS_PCR_SELECTION(bank, pcrSlot));
    }

    auto startPcrVal = tpm.PCR_Read(pcrSelection);
    auto currentValue = startPcrVal.pcrValues;
    PolicyTree policy = PolicyTree(PolicyPcr(currentValue, pcrSelection), PolicyPassword());
    TPM_HASH policyDigest = policy.GetPolicyDigest(TPM_ALG_ID::SHA256);

    TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
        TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM,
        policyDigest,
        TPMS_KEYEDHASH_PARMS(TPMS_NULL_SCHEME_KEYEDHASH()),
        TPM2B_DIGEST_KEYEDHASH());

    ByteVec dataToSealVec;
    dataToSealVec.resize(dataToSealLength);
    memcpy(dataToSealVec.data(), dataToSeal, dataToSealLength);

    TPMS_SENSITIVE_CREATE sensCreate(authValue, dataToSealVec);

    CreateResponse sealedObject = tpm.Create(storageKey, sensCreate, templ, {}, {});
    std::string sealedObjectJson = sealedObject.Serialize(SerializationType::JSON);

    uint8_t *sealingData = new uint8_t[sealedObjectJson.size()];
    *sealingDataLength = sealedObjectJson.size();
    memcpy(sealingData, sealedObjectJson.c_str(), sealedObjectJson.size());

    Benchmarking::stopMeasure(Benchmarking::OpType::Seal);

    return sealingData;
}


uint8_t *TpmRoT::unseal(TpmCpp::ByteVec authValue, std::vector<UINT32> &pcrSlots,
                        uint8_t *sealingData, size_t sealingDataLength, size_t *unsealedDataLength) {
    
    Benchmarking::startMeasure(Benchmarking::OpType::Unseal);

    using namespace TpmCpp;

    TPM_ALG_ID bank = TPM_ALG_ID::SHA256;
    vector<TPMS_PCR_SELECTION> pcrSelection;
    for (uint32_t pcrSlot : pcrSlots) {
        pcrSelection.push_back(TPMS_PCR_SELECTION(bank, pcrSlot));
    }

    std::string sealedObjectJson = std::string((char*)sealingData, sealingDataLength);

    CreateResponse sealedObject;
    bool deserialized = sealedObject.Deserialize(SerializationType::JSON, sealedObjectJson);
    TPM_HANDLE sealedKey = tpm.Load(storageKey, sealedObject.outPrivate, sealedObject.outPublic);
    sealedKey.SetAuth(authValue);

    auto startPcrVal = tpm.PCR_Read(pcrSelection);
    auto currentValue = startPcrVal.pcrValues;
    PolicyTree policy = PolicyTree(PolicyPcr(currentValue, pcrSelection), PolicyPassword());

    uint8_t *result = nullptr;
    *unsealedDataLength = 0;

    AUTH_SESSION sess = tpm.StartAuthSession(TPM_SE::POLICY, TPM_ALG_ID::SHA256);
    try {
        /*TPM_RC rc =*/ policy.Execute(tpm, sess);
        
        // And try to read the value
        ByteVec unsealedData = tpm[sess].Unseal(sealedKey);
        result = new uint8_t[unsealedData.size()];
        memcpy(result, unsealedData.data(), unsealedData.size());
        *unsealedDataLength = unsealedData.size();
    }
    catch (exception &exc) {
    }

    tpm.FlushContext(sess);
    tpm.FlushContext(sealedKey);

    Benchmarking::stopMeasure(Benchmarking::OpType::Unseal);

    return result;
}

void TpmRoT::pcrExtend(int pcr, const std::vector<uint8_t> &data) {

    TPM_HASH extend = TPM_HASH::FromHashOfData(TPM_ALG_ID::SHA256, data);
    tpm.PCR_Extend(TPM_HANDLE::Pcr(pcr), { extend });
}


void TpmRoT::pcrReset(int pcr) {

    tpm.PCR_Reset(TPM_HANDLE::Pcr(pcr));
}


std::vector<uint8_t> TpmRoT::pcrRead(int pcr) {

    vector<TPMS_PCR_SELECTION> pcrSelection;
    PCR_ReadResponse pcrResponse;

    pcrSelection.push_back(TPMS_PCR_SELECTION(TPM_ALG_ID::SHA256, pcr));
    pcrResponse = tpm.PCR_Read(pcrSelection);

    return pcrResponse.pcrValues[0];
}


void TpmRoT::terminateTpm() {
    if(storageKey) {
    //    tpm.FlushContext(storageKey);
    }
    
    if(attestationKey) {
    //    tpm.FlushContext(attestationKey);
    }
    
    if(device) {
        delete device;
        device = nullptr;
    }
}


// ************************************************************************************************

} // namespace RATLS_TPM2
