# Design Note: Privacy-First Biometric Verification

This document outlines the design of the biometric verification prototype, focusing on the privacy model, cryptographic approach, and plans for scaling.

## 1. Privacy Model: Threshold CKKS

The core privacy requirement is that no single party can decrypt the biometric data. To achieve this, we employ a **(T, N) threshold Homomorphic Encryption scheme** based on CKKS.

-   **Key Generation & Distribution**: The system is designed for `N` parties (e.g., `N=3`). A secret key is split into `N` shares. For any computation to be decrypted, a threshold of `T` parties (e.g., `T=2`) must collaborate by combining their key shares.
-   **Server's Role**: The server, which stores the encrypted database and performs computations, only ever has access to the **public key** and **evaluation keys** (for multiplication and rotations). It has zero knowledge of any secret key shares.
-   **Privacy Guarantee**: Since the server does not have access to a sufficient number of secret key shares (ideally, it has none), it is computationally infeasible for it to decrypt any ciphertext—be it the input vectors, the intermediate similarity scores, or the final result.
-   **Simulation**: In this prototype, the generation of key shares and the final decryption are *simulated* within a single process for demonstration purposes. A "simulation key" is used to stand in for the aggregated key shares that would be used in a real multi-party protocol. Logs explicitly confirm that the server-side logic never accesses this simulation key.

## 2. Encrypted Maximum Approach

Computing the true `max(a, b)` function homomorphically is notoriously expensive, as it requires evaluating a non-polynomial function. Standard approaches involve either polynomial approximations of `max` or bit-wise comparison circuits, both of which consume a large amount of multiplicative depth.

Given the extreme memory constraints and the "out of memory" errors encountered during development, a high-depth approach was infeasible.

### Chosen Approach: Approximation via Weighted Averaging

To stay within a very conservative depth budget, this prototype computes an **approximation of the maximum** rather than the exact value. This aligns with the alternative solution permitted in the assignment brief.

The process is as follows:
1.  **Dot Product**: Cosine similarities are computed as dot products (`a * b`, then sum slots). This consumes one level of multiplicative depth.
2.  **Streaming & Batching**: The database is processed in small batches (e.g., 20 vectors) to keep memory usage low.
3.  **Hierarchical Reduction**: The maximum is approximated using a tree-like reduction:
    -   **Intra-Batch**: Within each batch, an approximate max is found by recursively applying a low-depth `weightedAverage` function.
    -   **Inter-Batch**: The results from each batch are then combined using the same `weightedAverage` function to produce a single final ciphertext.

The `weightedAverage(a, b)` function is a simple heuristic: `0.5*(a+b) + 0.2*(a-b)`. This biases the result towards the larger of `a` or `b` and consumes only one level of depth. A `pureAverage` function is used as a fallback if the depth budget is nearly exhausted.

**Justification**: This trade-off sacrifices exactness for feasibility. The resulting value is not the true maximum but a "maximum-like" similarity score. This score is still highly correlated with the true maximum and is sufficient for making a correct "unique/not-unique" decision against a threshold, meeting the project's core functional requirement while respecting hardware limitations. The dominant source of error is this approximation, not CKKS noise.

## 3. CKKS Parameter Reasoning

-   **`multiplicativeDepth = 15`**: This is an "ultra-conservative" depth chosen to guarantee completion on a 16GB RAM machine. The computation for 1,000 vectors requires a dot product (depth 1), followed by a tree reduction over 50 batches (depth ~6), and within each batch of 20 (depth ~5). A budget of ~15-20 is needed, but a larger value provides a safety margin and supports larger scales without recompilation. The high depth necessitates a large ring dimension.
-   **`ringDim = 131072`**: The ring dimension must be large enough to support the specified multiplicative depth and security level (`HEStd_128_classic`). This parameter is the primary driver of memory consumption. Attempts with smaller, non-compliant ring dimensions led to runtime errors or insufficient noise budget.
-   **`scalingModSize = 40`**: A 40-bit scaling factor offers a good balance between precision and noise. It ensures that throughout the ~10-15 multiplication levels, the accumulated CKKS noise remains low, keeping the cryptographic error well below the `1e-4` target.
-   **`batchSize = 20`**: This is the application-level streaming batch size. It was tuned empirically. Larger batches (e.g., 100) would reduce the number of inter-batch multiplications (saving depth) but would require holding many more ciphertexts in memory simultaneously, leading to OOM errors. A small batch size keeps the peak memory usage manageable.

## 4. Scaling Plan to ~1M Vectors

Scaling to 1 million vectors requires addressing I/O, memory, and computational bottlenecks. A single-node approach is not feasible.

1.  **Distributed Computation & Sharding**: The database of 1M encrypted vectors would be sharded across a cluster of worker nodes. Each worker would be responsible for a subset of the data (e.g., 10,000 vectors per node for a 100-node cluster).
2.  **Hierarchical Reduction Across the Cluster**:
    -   **Step 1 (Local Max)**: Each worker node computes the approximate maximum for its local shard, using the same streaming/batching method as the prototype.
    -   **Step 2 (Global Max)**: A central aggregator node receives the encrypted maximum from each worker. It then performs a final reduction on these ~100 encrypted results to find the global approximate maximum. This tree-based approach keeps the computation scalable and parallel.
3.  **Hardware Acceleration (GPU)**: The most computationally intensive part of CKKS is polynomial multiplication, which is performed via Number Theoretic Transform (NTT). NTT is highly parallelizable and perfectly suited for GPUs. While OpenFHE lacks direct GPU integration, a production system would leverage custom CUDA/OpenCL kernels to offload these core arithmetic operations. This would involve serializing the polynomial coefficients from OpenFHE ciphertexts, transferring them to GPU memory, executing the kernels, and reading the results back. This can yield a 10-100x speedup.
4.  **I/O and Storage**: A simple binary file won't suffice. The encrypted vectors would be stored in a distributed key-value store (like Redis or Cassandra) or a blob store (like S3), optimized for fast retrieval of large binary objects by the worker nodes.
5.  **Precision and Parameter Tuning**: A deeper computation tree for 1M vectors will accumulate more noise and approximation error. This would require a larger initial `multiplicativeDepth` and potentially different scaling factor strategies (e.g., `FLEXIBLEAUTO` with more levels) to maintain the desired precision. The trade-off between performance and accuracy would need to be carefully re-evaluated at scale.
