# Use Ubuntu 22.04 as base image for better OpenFHE compatibility
FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Build tools
    build-essential \
    cmake \
    git \
    wget \
    pkg-config \
    # OpenFHE dependencies
    libgmp-dev \
    libntl-dev \
    libomp-dev \
    # Additional utilities
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /tmp/build

# Clone and build OpenFHE from source (latest version)
RUN git clone --depth=1 https://github.com/openfheorg/openfhe-development.git \
    && cd openfhe-development \
    && mkdir build \
    && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release \
             -DBUILD_UNITTESTS=OFF \
             -DBUILD_EXAMPLES=OFF \
             -DBUILD_BENCHMARKS=OFF \
             -DCMAKE_INSTALL_PREFIX=/usr/local \
             -DWITH_OPENMP=ON \
             .. \
    && make -j$(($(nproc) / 2)) \
    && make install \
    && cd /tmp/build \
    && rm -rf openfhe-development

# Update library path
RUN ldconfig

# Set up application directory
WORKDIR /app

# Copy project files
COPY src/ src/
COPY third_party/ third_party/
COPY CMakeLists.txt .

# Create build directory and build the application
RUN mkdir build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release .. \
    && make -j$(($(nproc) / 2))

# Set environment variables for OpenMP
ENV OMP_NUM_THREADS=8
ENV OMP_DYNAMIC=true
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Set working directory to app root
WORKDIR /app

# Default command runs with recommended parameters
CMD ["./build/biometric_verify", "--num-vectors", "50", "--batch-size", "512", "--mult-depth", "40"]
