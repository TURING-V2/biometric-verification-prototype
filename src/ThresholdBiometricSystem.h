#ifndef THRESHOLD_BIOMETRIC_SYSTEM_H
#define THRESHOLD_BIOMETRIC_SYSTEM_H

#include "openfhe.h"
#include <string>
#include <vector>

struct AppConfig {
    uint32_t multDepth;
    size_t numVectors;
    size_t vecDim;
    size_t batchSize;
    double threshold;
    int numParties;
    int thresholdT;
};

class ThresholdBiometricSystem {
public:
    explicit ThresholdBiometricSystem(AppConfig config);
    void run();

private:
    void setupCKKS();

    void generateThresholdKeys();
    
    std::vector<std::vector<double>> generateTestVectors(size_t numVectors, size_t dimension);
    
    std::string encryptVectorDatabaseToFile(const std::vector<std::vector<double>>& vectors);
    
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> encryptQueryVector(const std::vector<double>& q);
    
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> computeCosineSimilarity(
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& query,
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& dbvec);
    
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> computeStreamingApproximation(
        const std::string& dbFilePath,
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& encQuery);

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> computeBatchApproximation(
        std::vector<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& sims);

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> pureAverage(
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& a,
        const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& b);

    double thresholdDecryptResult(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& encryptedResult);
    bool computeThresholdDecision(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& encryptedResult);

    double computePlaintextMaxSimilarity(const std::vector<double>& q, const std::vector<std::vector<double>>& db);
    
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> homomorphicSign(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& x);
    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> polyMax(const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& a, const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& b);

    AppConfig m_config;
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> m_cryptoContext;
    lbcrypto::PublicKey<lbcrypto::DCRTPoly> m_publicKey;
    
    // in a real system, secret key shares would be distributed.
    // For this simulation, we hold them locally and use a single aggregate key for decryption.
    std::vector<lbcrypto::PrivateKey<lbcrypto::DCRTPoly>> m_secretKeyShares;
    lbcrypto::PrivateKey<lbcrypto::DCRTPoly> m_simulationSecretKey;
};

#endif // THRESHOLD_BIOMETRIC_SYSTEM_H
