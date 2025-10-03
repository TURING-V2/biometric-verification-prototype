cmake_minimum_required(VERSION 3.10)
project(BiometricVerification LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -DDEBUG")
set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH};/usr/local/lib;/usr/local")

find_package(OpenFHE REQUIRED)
if (OpenFHE_FOUND)
    message(STATUS "OpenFHE found: ${OpenFHE_VERSION}")
    message(STATUS "OpenFHE include dirs: ${OpenFHE_INCLUDE}")
    message(STATUS "OpenFHE libraries: ${OpenFHE_LIBRARIES}")
else()
    message(FATAL_ERROR "OpenFHE not found. Install OpenFHE to /usr/local/")
endif()

add_executable(biometric_verify src/main.cpp src/ThresholdBiometricSystem.cpp)

target_include_directories(biometric_verify SYSTEM PRIVATE
    ${OpenFHE_INCLUDE}
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/binfhe
)

target_include_directories(biometric_verify PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

target_link_libraries(biometric_verify PRIVATE
    ${OpenFHE_LIBRARIES}
)

add_custom_target(run
    COMMAND ${CMAKE_COMMAND} -E env
        LD_LIBRARY_PATH=/usr/local/lib:$<TARGET_FILE_DIR:biometric_verify>
        $<TARGET_FILE:biometric_verify> --mult-depth 40 --num-vectors 50 --batch-size 512
    DEPENDS biometric_verify
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running biometric verification with default parameters"
)

add_custom_target(install-openfhe
    COMMAND git clone --depth=1 https://github.com/openfheorg/openfhe-development.git openfhe-src
    COMMAND ${CMAKE_COMMAND} -S openfhe-src -B openfhe-build -D BUILD_EXAMPLES=OFF -D BUILD_BENCHMARKS=OFF -D BUILD_TESTING=OFF
    COMMAND ${CMAKE_COMMAND} --build openfhe-build --target install -j$(HALF_NPROC)
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Installing OpenFHE"
)

add_custom_target(uninstall-openfhe
    COMMAND ${CMAKE_COMMAND} --build openfhe-build --target uninstall
    COMMAND ${CMAKE_COMMAND} -E rm -rf openfhe-src openfhe-build
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Uninstalling OpenFHE"
)

add_custom_target(clean-all
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/CMakeFiles
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/biometric_verify
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/CMakeCache.txt
    COMMENT "Cleaning build artifacts"
)

add_custom_target(clean-bin
    COMMAND /bin/sh -c "rm -f ${CMAKE_BINARY_DIR}/*.bin"
    COMMENT "Removing all .bin files in the build directory"
)
