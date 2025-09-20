# Privacy-First Biometric Verification Prototype

This project is a submission for Mercle's SDE hiring assignment. It demonstrates a system that computes the maximum cosine similarity between a query vector and a database of vectors under homomorphic encryption using the OpenFHE library. The core privacy guarantee is that the server performing the computation never holds a full decryption key and never sees the raw biometric data.

## Environment

The prototype was developed and tested on the following system:
- **OS:** Gentoo Linux x86_64
- **CPU:** AMD Ryzen 7 4800H (16) @ 4.300GHz
- **RAM:** 16GB
- **Kernel:** 6.14.4-gentoo
- **Compiler:** GCC (g++) with C++23 support

The CKKS parameters, particularly the multiplicative depth and batch size, have been conservatively chosen to run on systems with memory constraints (like 16GB RAM), which can be a significant bottleneck for FHE applications.

## Dependencies
- A C++23 compatible compiler (e.g., GCC 12+, Clang 15+)
- CMake (version 3.10+)
- **OpenFHE**: The project links against OpenFHE. The provided `CMakeLists.txt` includes a custom target to download and install it automatically.

## Build Instructions

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/TURING-V2/biometric-verification-prototype.git
    cd biometric-verification-prototype
    ```

2.  **Install OpenFHE (if not already installed):**
    This project includes a convenient CMake target to download the OpenFHE source and install it to `/usr/local/`. This may take a significant amount of time and requires root privileges for installation.
    ```bash
    cmake -B build
    sudo cmake --build build --target install-openfhe
    ```

3.  **Build the Project:**
    Once OpenFHE is installed, build the main executable.
    ```bash
    # If you didn't run the install target, configure first:
    # cmake -B build 
    
    cmake --build build
    ```
    The executable `biometric_verify` will be located in the `build/` directory.

## Running the Demo

You can run the full end-to-end demo using the custom `run` target, which uses default parameters tuned for a memory-constrained system.

```bash
cmake --build build --target run
```

This will:
1.  Generate 1,000 random 512-D vectors and a query vector.
2.  Compute the plaintext maximum cosine similarity as a baseline.
3.  Set up a threshold CKKS scheme.
4.  Encrypt the database and query.
5.  Run the encrypted computation pipeline to find an *approximation* of the maximum similarity.
6.  Simulate threshold decryption of the final result.
7.  Print an accuracy check and a final "unique/not-unique" decision.

### Customizing Parameters

You can also run the executable directly to override the default parameters:

```bash
./build/biometric_verify --num-vectors 500 --batch-size 10 --mult-depth 30
```

**Available Options:**
- `--mult-depth`: Multiplicative depth for CKKS. Higher values support more complex computations but drastically increase memory usage.
- `--num-vectors`: Number of vectors in the database.
- `--vec-dim`: Dimension of each vector (currently fixed at 512 in the code).
- `--batch-size`: Number of vectors to process in a single streaming batch to manage memory.

## Accuracy Check

The program automatically performs an accuracy check at the end of its run. It prints the following three lines:

```
Plaintext Max Similarity:  0.91234567
Encrypted Approx. Result: 0.91229999
Absolute Error:            4.5680e-05
```

The target absolute error of `< 1e-4` is primarily influenced by the approximation algorithm used for the maximum, not just CKKS noise. The current `weightedAverage` heuristic was chosen for its low depth consumption.
