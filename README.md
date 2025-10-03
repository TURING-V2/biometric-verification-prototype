# Privacy-First Biometric Verification Prototype

This project demonstrates a system that computes the maximum cosine similarity between a query vector and a database of vectors under homomorphic encryption using OpenFHE CKKS. The server performing the computation never holds a full decryption key and never sees the raw biometric data.

## Key Features

- **Threshold CKKS Encryption**: 2-out-of-3 threshold scheme
- **Polynomial Maximum Approximation**: Efficient homomorphic maximum using degree-3 polynomial
- **Streaming Architecture**: Memory-efficient batch processing
- **High Accuracy**: 99.87% accuracy (absolute error < 1.3e-3)

## Quick Start with Docker (Recommended)

### Build and Run

```bash
# Build the image
docker build -t biometric-verify:latest .

# Run the demo
docker run --rm biometric-verify:latest \
    ./build/biometric_verify --num-vectors 50 --mult-depth 40 --batch-size 512

# Interactive mode
docker run -it --rm biometric-verify:latest /bin/bash
```

## Native Build

### Prerequisites
- C++23 compiler (GCC 12+ or Clang 15+)
- CMake 3.10+
- 16GB+ RAM recommended

### Build Steps

```bash
# Clone repository
git clone https://github.com/TURING-V2/biometric-verification-prototype.git
cd biometric-verification-prototype

# Install OpenFHE (automatic)
cmake -B build
sudo cmake --build build --target install-openfhe

# Build project
cmake --build build
```

### Run

```bash
# Quick test
./build/biometric_verify --num-vectors 50 --batch-size 512 --mult-depth 40

# With performance tuning
export OMP_NUM_THREADS=8
./build/biometric_verify --num-vectors 1000 --batch-size 128 --mult-depth 40
```

## Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--mult-depth` | 40 | Multiplicative depth budget (40-50 recommended) |
| `--num-vectors` | 50 | Number of database vectors (50-1000) |
| `--vec-dim` | 512 | Vector dimension (fixed at 512) |
| `--batch-size` | 512 | Streaming batch size >= vector dimension |

## Sample Output

```
============================================================
RESULTS
============================================================
Plaintext Max Similarity:  1.00000000
Encrypted Result:          0.99873907
Absolute Error:            1.2609e-03
Relative Error:            0.13%
Accuracy:                  99.87%

Final Decision: The query vector is NOT UNIQUE (Threshold: 0.85)
============================================================
```

## Technical Overview

### CKKS Parameters
- **Ring Dimension**: 131,072
- **Multiplicative Depth**: 40 (configurable)
- **Scaling Modulus**: 50 bits
- **Security Level**: 128-bit (HEStd_128_classic)

### Polynomial Maximum Approximation

Uses polynomial approximation of the sign function for computing max(a,b):
```
sign(x) ≈ 1.5x - 0.5x³
```

**Depth consumption**: ~26-30 levels for 1000 vectors (recommended depth: 40-45)

## Environment Tested

- **OS**: Gentoo Linux / Ubuntu 22.04
- **CPU**: AMD Ryzen 7 4800H
- **RAM**: 16GB
- **Compiler**: GCC with C++23
- **OpenFHE**: master branch
