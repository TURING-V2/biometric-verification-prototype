#include "ThresholdBiometricSystem.h"
#include "argparse.hpp"

#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    argparse::ArgumentParser program("biometric_verify");

    program.add_argument("--mult-depth")
        .help("Multiplicative depth for CKKS")
        .default_value(30u)
        .scan<'u', uint32_t>();

    program.add_argument("--num-vectors")
        .help("Number of vectors in the database")
        .default_value(50ul)
        .scan<'u', size_t>();

    program.add_argument("--vec-dim")
        .help("Dimension of each vector")
        .default_value(512ul)
        .scan<'u', size_t>();
    
    program.add_argument("--batch-size")
        .help("Number of vectors to process in a streaming batch (^2 and > vector size)")
        .default_value(512ul)
        .scan<'u', size_t>();

    try {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return 1;
    }

    AppConfig config;
    config.multDepth = program.get<uint32_t>("--mult-depth");
    config.numVectors = program.get<size_t>("--num-vectors");
    config.vecDim = program.get<size_t>("--vec-dim");
    config.batchSize = program.get<size_t>("--batch-size");
    config.threshold = 0.85;
    config.numParties = 3;
    config.thresholdT = 2;

    try {
        ThresholdBiometricSystem demo(config);
        demo.run();
    } catch (const std::exception& e) {
        std::cerr << "\nFATAL ERROR: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
