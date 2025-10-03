#include "ThresholdBiometricSystem.h"
#include <iostream>
#include <vector>
#include <random>
#include <chrono>
#include <fstream>
#include <cmath>
#include <stdexcept>
#include <iomanip>
#include <memory>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
using namespace std;

ThresholdBiometricSystem::ThresholdBiometricSystem(AppConfig config) : m_config(config) {
    setupCKKS();
    generateThresholdKeys();
}

void ThresholdBiometricSystem::setupCKKS() {
    cout << "Setting up CKKS..." << endl;

    CCParams<CryptoContextCKKSRNS> parameters;

    parameters.SetMultiplicativeDepth(m_config.multDepth);
    parameters.SetFirstModSize(60);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(m_config.batchSize);
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);

    m_cryptoContext = GenCryptoContext(parameters);
    m_cryptoContext->Enable(PKE);
    m_cryptoContext->Enable(KEYSWITCH);
    m_cryptoContext->Enable(LEVELEDSHE);
    m_cryptoContext->Enable(ADVANCEDSHE);
    m_cryptoContext->Enable(MULTIPARTY);

    cout << "* CKKS context created" << endl;
    cout << "  - Ring dimension: " << m_cryptoContext->GetRingDimension() << endl;
    cout << "  - Multiplicative depth budget: " << m_config.multDepth << endl;
    cout << "  - Scaling mod size: 50 bits" << endl;
}

void ThresholdBiometricSystem::generateThresholdKeys() {
    cout << "\nGenerating threshold key structure (" << m_config.thresholdT << "-out-of-" << m_config.numParties << ")..." << endl;

    auto mainKP = m_cryptoContext->KeyGen();
    m_publicKey = mainKP.publicKey;
    m_simulationSecretKey = mainKP.secretKey;

    m_cryptoContext->EvalMultKeyGen(mainKP.secretKey);

    // gen rotation keys needed for the dot product (summing slots)
    vector<int> rotationIndices;
    int maxRotation = min((int)m_config.vecDim, (int)m_cryptoContext->GetRingDimension()/2);
    for (int r = 1; r < maxRotation; r <<= 1) {
        rotationIndices.push_back(r);
    }
    m_cryptoContext->EvalRotateKeyGen(mainKP.secretKey, rotationIndices);
    
    m_secretKeyShares.clear();
    for (int i = 0; i < m_config.numParties; ++i) {
        m_secretKeyShares.push_back(m_cryptoContext->KeyGen().secretKey);
        cout << "  - Generated secret key share for party " << (i + 1) << " (simulated)" << endl;
    }
    cout << "* Key generation complete" << endl;
}

void ThresholdBiometricSystem::run() {
    cout << "\n" << string(60, '=') << endl;
    cout << "Privacy-First Biometric Verification Demo" << endl;
    cout << string(60, '=') << endl;
    cout << "Configuration: " << m_config.numVectors << " vectors x " << m_config.vecDim << "D" << endl;
    cout << "Streaming Batch Size: " << m_config.batchSize << endl;
    cout << "Max Depth: " << m_config.multDepth << endl;
    cout << "Approach: Polynomial Approximation of Maximum" << endl;

    auto totalStart = chrono::high_resolution_clock::now();
    auto database = generateTestVectors(m_config.numVectors, m_config.vecDim);
    auto query = generateTestVectors(1, m_config.vecDim)[0];

    cout << "\nComputing plaintext baseline..." << endl;
    auto ptStart = chrono::high_resolution_clock::now();
    double plaintextMax = computePlaintextMaxSimilarity(query, database);
    auto ptEnd = chrono::high_resolution_clock::now();
    cout << "* Plaintext max similarity: " << fixed << setprecision(8) << plaintextMax
         << " (took " << chrono::duration_cast<chrono::milliseconds>(ptEnd - ptStart).count() << "ms)" << endl;

    string dbFile = encryptVectorDatabaseToFile(database);
    auto encQuery = encryptQueryVector(query);

    database.clear();
    database.shrink_to_fit();
    query.clear();
    query.shrink_to_fit();

    cout << "\nRunning encrypted pipeline..." << endl;
    auto encStart = chrono::high_resolution_clock::now();
    Ciphertext<DCRTPoly> encResult = computeStreamingApproximation(dbFile, encQuery);
    auto encEnd = chrono::high_resolution_clock::now();

    cout << "* Encrypted pipeline finished (took "
         << chrono::duration_cast<chrono::seconds>(encEnd - encStart).count() << "s)" << endl;

    double encResultValue = thresholdDecryptResult(encResult);
    bool isUnique = (encResultValue < m_config.threshold);

    if (remove(dbFile.c_str()) != 0) {
        cerr << "Warning: Could not delete temporary file " << dbFile << endl;
    }

    auto totalEnd = chrono::high_resolution_clock::now();

    cout << "\n" << string(60, '=') << "\nRESULTS\n" << string(60, '=') << endl;
    cout << "Plaintext Max Similarity:  " << fixed << setprecision(8) << plaintextMax << endl;
    cout << "Encrypted Result:          " << fixed << setprecision(8) << encResultValue << endl;

    double absErr = fabs(plaintextMax - encResultValue);
    double relErr = absErr / (fabs(plaintextMax) + 1e-10) * 100;
    cout << "Absolute Error:            " << scientific << setprecision(4) << absErr << endl;
    cout << "Relative Error:            " << fixed << setprecision(2) << relErr << "%" << endl;
    double accuracy = (100.0 - relErr);
    cout << "Accuracy:                  " << fixed << setprecision(2) << accuracy << "%" << endl;

    cout << "\nFinal Decision: The query vector is " << (isUnique ? "UNIQUE" : "NOT UNIQUE") 
         << " (Threshold: " << m_config.threshold << ")" << endl;
    
    cout << "\nTotal runtime: " << chrono::duration_cast<chrono::seconds>(totalEnd - totalStart).count() << "s" << endl;
    cout << string(60, '=') << endl;
    
    if (accuracy < 90.0) {
        cout << "\nWARNING: Accuracy is below 90%. Consider adjusting parameters." << endl;
    }
}

vector<vector<double>> ThresholdBiometricSystem::generateTestVectors(size_t numVectors, size_t dimension) {
    cout << "\nGenerating " << numVectors << " unit-normalized " << dimension << "D vectors..." << endl;
    vector<vector<double>> vecs(numVectors, vector<double>(dimension));
    mt19937 gen(42);
    normal_distribution<double> dist(0.0, 1.0);

    for (size_t i = 0; i < numVectors; ++i) {
        double norm = 0.0;
        for (size_t j = 0; j < dimension; ++j) {
            vecs[i][j] = dist(gen);
            norm += vecs[i][j] * vecs[i][j];
        }
        norm = sqrt(norm);
        if (norm < 1e-10) norm = 1.0;
        for (size_t j = 0; j < dimension; ++j) vecs[i][j] /= norm;
    }
    cout << "* Vector generation complete." << endl;
    return vecs;
}

string ThresholdBiometricSystem::encryptVectorDatabaseToFile(const vector<vector<double>>& vectors) {
    cout << "\nEncrypting database to file (streaming)..." << endl;
    const string fname = "encrypted_db.bin";
    ofstream ofs(fname, ios::binary);
    if (!ofs) throw runtime_error("Failed to create file: " + fname);

    for (size_t i = 0; i < vectors.size(); ++i) {
        Plaintext pt = m_cryptoContext->MakeCKKSPackedPlaintext(vectors[i]);
        auto ct = m_cryptoContext->Encrypt(m_publicKey, pt);
        Serial::Serialize(ct, ofs, SerType::BINARY);
        if (!ofs.good()) {
            throw runtime_error("Serialization failed for vector " + to_string(i));
        }
    }
    cout << "* Database successfully encrypted to " << fname << endl;
    return fname;
}

Ciphertext<DCRTPoly> ThresholdBiometricSystem::encryptQueryVector(const vector<double>& q) {
    cout << "\nEncrypting query vector..." << endl;
    Plaintext pt = m_cryptoContext->MakeCKKSPackedPlaintext(q);
    auto ct = m_cryptoContext->Encrypt(m_publicKey, pt);
    cout << "* Query encrypted (level: " << ct->GetLevel() << ")" << endl;
    return ct;
}

Ciphertext<DCRTPoly> ThresholdBiometricSystem::computeCosineSimilarity(const Ciphertext<DCRTPoly>& query, const Ciphertext<DCRTPoly>& dbvec) {
    // element-wise multiplication
    auto prod = m_cryptoContext->EvalMult(query, dbvec);
    
    // sum all slots using rotation and addition
    Ciphertext<DCRTPoly> sum = prod;
    int maxRotation = min((int)m_config.vecDim, (int)m_cryptoContext->GetRingDimension()/2);
    
    for (int r = 1; r < maxRotation; r <<= 1) {
        auto rotated = m_cryptoContext->EvalRotate(sum, r);
        sum = m_cryptoContext->EvalAdd(sum, rotated);
    }
    return sum;
}

Ciphertext<DCRTPoly> ThresholdBiometricSystem::computeStreamingApproximation(const string& dbFilePath, const Ciphertext<DCRTPoly>& encQuery) {
    cout << "\nComputing maximum similarity via poly approximation..." << endl;
    ifstream ifs(dbFilePath, ios::binary);
    if (!ifs) throw runtime_error("Cannot open database file: " + dbFilePath);

    Ciphertext<DCRTPoly> globalMax = nullptr;
    vector<Ciphertext<DCRTPoly>> batchSims;
    batchSims.reserve(m_config.batchSize);

    size_t count = 0;
    size_t numBatches = 0;

    while (ifs.peek() != EOF) {
        Ciphertext<DCRTPoly> ct;
        Serial::Deserialize(ct, ifs, SerType::BINARY);
        if (ifs.fail()) break;

        auto sim = computeCosineSimilarity(encQuery, ct);
        batchSims.push_back(move(sim));
        count++;

        if (batchSims.size() == m_config.batchSize || ifs.peek() == EOF) {
            auto batchMax = computeBatchApproximation(batchSims);
            numBatches++;
            
            if (globalMax == nullptr) {
                globalMax = batchMax;
            } else {
                globalMax = polyMax(globalMax, batchMax);
            }
            batchSims.clear();
            
            if (count % 10 == 0) {
                cout << "  - Processed " << count << " vectors..." << endl;
            }
        }
    }

    cout << "* Computation complete. Processed " << count << " vectors in " << numBatches << " batches." << endl;
    return globalMax;
}

Ciphertext<DCRTPoly> ThresholdBiometricSystem::computeBatchApproximation(vector<Ciphertext<DCRTPoly>>& sims) {
    if (sims.empty()) throw runtime_error("Cannot process an empty batch.");
    
    // tournament-style reduction with poly max approximation
    while (sims.size() > 1) {
        vector<Ciphertext<DCRTPoly>> nextLevel;
        for (size_t i = 0; i < sims.size(); i += 2) {
            if (i + 1 < sims.size()) {
                if (sims[i]->GetLevel() >= m_config.multDepth - 3) {
                    // fall back to simple average if running out of depth
                    nextLevel.push_back(pureAverage(sims[i], sims[i+1]));
                } else {
                    nextLevel.push_back(polyMax(sims[i], sims[i+1]));
                }
            } else {
                nextLevel.push_back(sims[i]);
            }
        }
        sims = move(nextLevel);
    }
    return sims[0];
}

Ciphertext<DCRTPoly> ThresholdBiometricSystem::homomorphicSign(const Ciphertext<DCRTPoly>& x) {
    // simple polynomial approximation for sign function: sign(x) ~ 1.5x - 0.5x^3
    // degree-3 polynomial approximation
    auto x_cubed = m_cryptoContext->EvalMult(m_cryptoContext->EvalMult(x, x), x);
    auto term1 = m_cryptoContext->EvalMult(x, 1.5);
    auto term2 = m_cryptoContext->EvalMult(x_cubed, -0.5);
    return m_cryptoContext->EvalAdd(term1, term2);
}

Ciphertext<DCRTPoly> ThresholdBiometricSystem::polyMax(const Ciphertext<DCRTPoly>& a, const Ciphertext<DCRTPoly>& b) {
    auto diff = m_cryptoContext->EvalSub(a, b);
    auto sign_of_diff = homomorphicSign(diff);
    auto term1 = m_cryptoContext->EvalAdd(a, b);
    auto term2 = m_cryptoContext->EvalMult(sign_of_diff, diff);
    auto sum = m_cryptoContext->EvalAdd(term1, term2);

    return m_cryptoContext->EvalMult(sum, 0.5); //rescale
}

Ciphertext<DCRTPoly> ThresholdBiometricSystem::pureAverage(const Ciphertext<DCRTPoly>& a, const Ciphertext<DCRTPoly>& b) {
    auto sum = m_cryptoContext->EvalAdd(a, b);
    return m_cryptoContext->EvalMult(sum, 0.5);
}

double ThresholdBiometricSystem::thresholdDecryptResult(const Ciphertext<DCRTPoly>& encryptedResult) {
    cout << "\nSimulating threshold decryption..." << endl;
    cout << "Final ciphertext level: " << encryptedResult->GetLevel() << "/" << m_config.multDepth << endl;
    
    Plaintext pt;
    m_cryptoContext->Decrypt(m_simulationSecretKey, encryptedResult, &pt);
    pt->SetLength(1); // we only care about the first slot which holds the sum
    
    vector<double> vals = pt->GetRealPackedValue();
    if (vals.empty()) {
        cerr << "Warning: Decryption resulted in an empty plaintext." << endl;
        return 0.0;
    }
    
    double result = vals[0];
    cout << "  - Decrypted value: " << fixed << setprecision(8) << result << endl;
    return result;
}

bool ThresholdBiometricSystem::computeThresholdDecision(const Ciphertext<DCRTPoly>& encryptedResult) {
    double result = thresholdDecryptResult(encryptedResult);
    bool isUnique = result < m_config.threshold;
    cout << "* Threshold Check: " << result << " < " << m_config.threshold 
         << " -> " << (isUnique ? "UNIQUE" : "NOT UNIQUE") << endl;
    return isUnique;
}

double ThresholdBiometricSystem::computePlaintextMaxSimilarity(const vector<double>& q, const vector<vector<double>>& db) {
    double maxSim = -2.0;
    size_t maxIndex = 0;
    for (size_t idx = 0; idx < db.size(); ++idx) {
        double sim = 0.0;
        for (size_t i = 0; i < q.size(); ++i) {
            sim += q[i] * db[idx][i];
        }
        if (sim > maxSim) {
            maxSim = sim;
            maxIndex = idx;
        }
    }
    cout << "  - Max similarity found at index " << maxIndex << endl;
    return maxSim;
}
