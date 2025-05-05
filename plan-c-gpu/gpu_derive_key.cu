#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <cuda_runtime.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <vector>

// Size constants
#define SHA1_DIGEST_LENGTH 20
#define MD5_DIGEST_LENGTH 16

// Verification constants
#define ITERATIONS 4242
#define HASH_BUFFER_SIZE 64
#define MAX_PASSPHRASE_LENGTH 256
#define MAX_USER_ID_LENGTH 32
#define NUM_THREADS_PER_BLOCK 256
#define BATCH_SIZE 100000

// CrashPlan key constants
#define CRASHPLAN_KEY_LENGTH 56

// Device constant memory for commonly used values
__constant__ char d_passphrase[MAX_PASSPHRASE_LENGTH];
__constant__ int d_passphrase_len;
__constant__ unsigned char d_dataKeyChecksum[MD5_DIGEST_LENGTH];

// Simple CPU-side SHA1 hash function (multiple iterations)
void sha1_multi(const unsigned char *input, size_t input_len, unsigned char *output, int iterations) {
    SHA_CTX context;
    SHA1_Init(&context);
    SHA1_Update(&context, input, input_len);
    SHA1_Final(output, &context);
    
    for (int i = 0; i < iterations - 1; i++) {
        SHA1_Init(&context);
        SHA1_Update(&context, output, SHA1_DIGEST_LENGTH);
        SHA1_Final(output, &context);
    }
}

// Simple CPU-side helper to convert to hex
std::string bin_to_hex(const unsigned char* data, size_t len) {
    static const char hex_chars[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(len * 2);
    
    for (size_t i = 0; i < len; i++) {
        result.push_back(hex_chars[(data[i] & 0xF0) >> 4]);
        result.push_back(hex_chars[data[i] & 0x0F]);
    }
    
    return result;
}

// CUDA SHA-1 implementation (single block version)
__device__ void cuda_sha1_transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e;
    uint32_t m[80];
    
    // Initialize working variables
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    
    // Prepare message schedule
    #pragma unroll 16
    for (int i = 0; i < 16; i++) {
        m[i] = (buffer[i * 4] << 24) | (buffer[i * 4 + 1] << 16) | 
               (buffer[i * 4 + 2] << 8) | (buffer[i * 4 + 3]);
    }
    
    #pragma unroll 64
    for (int i = 16; i < 80; i++) {
        m[i] = (m[i-3] ^ m[i-8] ^ m[i-14] ^ m[i-16]);
        m[i] = (m[i] << 1) | (m[i] >> 31);
    }
    
    // Main loop
    #pragma unroll 20
    for (int i = 0; i < 20; i++) {
        uint32_t temp = ((a << 5) | (a >> 27)) + ((b & c) | ((~b) & d)) + e + m[i] + 0x5A827999;
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;
    }
    
    #pragma unroll 20
    for (int i = 20; i < 40; i++) {
        uint32_t temp = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + e + m[i] + 0x6ED9EBA1;
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;
    }
    
    #pragma unroll 20
    for (int i = 40; i < 60; i++) {
        uint32_t temp = ((a << 5) | (a >> 27)) + ((b & c) | (b & d) | (c & d)) + e + m[i] + 0x8F1BBCDC;
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;
    }
    
    #pragma unroll 20
    for (int i = 60; i < 80; i++) {
        uint32_t temp = ((a << 5) | (a >> 27)) + (b ^ c ^ d) + e + m[i] + 0xCA62C1D6;
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = temp;
    }
    
    // Update state
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

// CUDA device implementation of SHA1
__device__ void cuda_sha1(const uint8_t *input, size_t length, uint8_t output[20]) {
    uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    uint8_t buffer[64];
    size_t i;
    uint64_t bit_length = length * 8;
    
    // Process as many complete 64-byte blocks as possible
    for (i = 0; i + 64 <= length; i += 64) {
        memcpy(buffer, input + i, 64);
        cuda_sha1_transform(state, buffer);
    }
    
    // Process the final incomplete block
    size_t remaining = length - i;
    memcpy(buffer, input + i, remaining);
    
    // Padding
    buffer[remaining] = 0x80;
    
    if (remaining >= 56) {
        // Not enough space for the length, need another block
        memset(buffer + remaining + 1, 0, 64 - remaining - 1);
        cuda_sha1_transform(state, buffer);
        memset(buffer, 0, 56);
    } else {
        memset(buffer + remaining + 1, 0, 56 - remaining - 1);
    }
    
    // Append the length in bits (big-endian)
    for (i = 0; i < 8; i++) {
        buffer[56 + i] = (bit_length >> (56 - i * 8)) & 0xFF;
    }
    
    cuda_sha1_transform(state, buffer);
    
    // Output the hash
    for (i = 0; i < 5; i++) {
        output[i * 4] = (state[i] >> 24) & 0xFF;
        output[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        output[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        output[i * 4 + 3] = state[i] & 0xFF;
    }
}

// CUDA MD5 device implementation (simplified)
__device__ void cuda_md5(const uint8_t *input, size_t length, uint8_t output[16]) {
    // MD5 constants
    const uint32_t S[] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    
    const uint32_t K[] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    };
    
    // Initialize state (A,B,C,D)
    uint32_t a0 = 0x67452301;
    uint32_t b0 = 0xefcdab89;
    uint32_t c0 = 0x98badcfe;
    uint32_t d0 = 0x10325476;
    
    // Prepare padded message
    // Calculate the padded message length (multiple of 64 bytes)
    size_t newLen = ((length + 8) / 64 + 1) * 64;
    uint8_t *msg = new uint8_t[newLen];
    
    memset(msg, 0, newLen);
    memcpy(msg, input, length);
    
    // Append the "1" bit
    msg[length] = 0x80;
    
    // Append the length in bits (at the end of the block)
    uint64_t bitLen = length * 8;
    memcpy(&msg[newLen - 8], &bitLen, 8);
    
    // Main loop - process each 64-byte block
    for (size_t offset = 0; offset < newLen; offset += 64) {
        uint32_t M[16];
        
        // Get the current chunk
        for (int i = 0; i < 16; i++) {
            M[i] = msg[offset + i*4] | 
                  (msg[offset + i*4 + 1] << 8) |
                  (msg[offset + i*4 + 2] << 16) |
                  (msg[offset + i*4 + 3] << 24);
        }
        
        // Initialize hash values for this chunk
        uint32_t A = a0;
        uint32_t B = b0;
        uint32_t C = c0;
        uint32_t D = d0;
        
        // Main loop
        for (int i = 0; i < 64; i++) {
            uint32_t F, g;
            
            if (i < 16) {
                F = (B & C) | ((~B) & D);
                g = i;
            } else if (i < 32) {
                F = (D & B) | ((~D) & C);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                F = B ^ C ^ D;
                g = (3*i + 5) % 16;
            } else {
                F = C ^ (B | (~D));
                g = (7*i) % 16;
            }
            
            uint32_t temp = D;
            D = C;
            C = B;
            B = B + ((A + F + K[i] + M[g]) << S[i] | (A + F + K[i] + M[g]) >> (32 - S[i]));
            A = temp;
        }
        
        // Add chunk's hash to result
        a0 += A;
        b0 += B;
        c0 += C;
        d0 += D;
    }
    
    // Store the result
    for (int i = 0; i < 4; i++) {
        output[i] = (a0 >> (i*8)) & 0xFF;
        output[i+4] = (b0 >> (i*8)) & 0xFF;
        output[i+8] = (c0 >> (i*8)) & 0xFF;
        output[i+12] = (d0 >> (i*8)) & 0xFF;
    }
    
    delete[] msg;
}

// Calculate C42 SHA1 Hash (multiple iterations)
__device__ void cuda_c42_sha1_hash(const char* passphrase, int passphrase_len, 
                                  const char* user_id, int user_id_len,
                                  unsigned char output[SHA1_DIGEST_LENGTH]) {
    // Prepare input (salt + passphrase)
    unsigned char buffer[MAX_PASSPHRASE_LENGTH + MAX_USER_ID_LENGTH];
    
    // Copy user ID (salt) first
    for (int i = 0; i < user_id_len; i++) {
        buffer[i] = user_id[i];
    }
    
    // Copy passphrase
    for (int i = 0; i < passphrase_len; i++) {
        buffer[user_id_len + i] = passphrase[i];
    }
    
    // Initial hash
    cuda_sha1(buffer, user_id_len + passphrase_len, output);
    
    // Multiple iterations
    for (int i = 0; i < ITERATIONS - 1; i++) {
        cuda_sha1(output, SHA1_DIGEST_LENGTH, output);
    }
}

// Derive custom archive key (CrashPlan format)
__device__ void derive_custom_archive_key_v2(const char* user_id, int user_id_len,
                                           const char* passphrase, int passphrase_len,
                                           unsigned char output[CRASHPLAN_KEY_LENGTH]) {
    // First hash (normal passphrase)
    unsigned char hash1[SHA1_DIGEST_LENGTH];
    cuda_c42_sha1_hash(passphrase, passphrase_len, user_id, user_id_len, hash1);
    
    // Create a reversed passphrase
    char reversed_passphrase[MAX_PASSPHRASE_LENGTH];
    for (int i = 0; i < passphrase_len; i++) {
        reversed_passphrase[i] = passphrase[passphrase_len - 1 - i];
    }
    
    // Second hash (reversed passphrase)
    unsigned char hash2[SHA1_DIGEST_LENGTH];
    cuda_c42_sha1_hash(reversed_passphrase, passphrase_len, user_id, user_id_len, hash2);
    
    // Combine the hashes to form the key (concatenate)
    for (int i = 0; i < SHA1_DIGEST_LENGTH; i++) {
        output[i] = hash1[i];
        output[SHA1_DIGEST_LENGTH + i] = hash2[i];
    }
    
    // Pad with zeros or truncate if needed (56 bytes total)
    if (SHA1_DIGEST_LENGTH * 2 < CRASHPLAN_KEY_LENGTH) {
        for (int i = SHA1_DIGEST_LENGTH * 2; i < CRASHPLAN_KEY_LENGTH; i++) {
            output[i] = 0;
        }
    }
}

// Kernel for brute-forcing user IDs
__global__ void brute_force_kernel(int start_user_id, int* found_user_id) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    int current_user_id = start_user_id + tid;
    
    // Convert user ID to string
    char user_id_str[MAX_USER_ID_LENGTH];
    int user_id_len = 0;
    int temp = current_user_id;
    
    // Handle 0 case
    if (temp == 0) {
        user_id_str[0] = '0';
        user_id_len = 1;
    } else {
        // Count digits
        int digits = 0;
        int temp_copy = temp;
        while (temp_copy > 0) {
            digits++;
            temp_copy /= 10;
        }
        
        // Convert to string (backwards)
        user_id_len = digits;
        for (int i = digits - 1; i >= 0; i--) {
            user_id_str[i] = '0' + (temp % 10);
            temp /= 10;
        }
    }
    
    // Derive key
    unsigned char key[CRASHPLAN_KEY_LENGTH];
    derive_custom_archive_key_v2(user_id_str, user_id_len, d_passphrase, d_passphrase_len, key);
    
    // Calculate MD5 of the key
    unsigned char key_md5[MD5_DIGEST_LENGTH];
    cuda_md5(key, CRASHPLAN_KEY_LENGTH, key_md5);
    
    // Compare with target checksum
    bool match = true;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        if (key_md5[i] != d_dataKeyChecksum[i]) {
            match = false;
            break;
        }
    }
    
    // If match found, atomically update the result
    if (match && *found_user_id == 0) {
        atomicCAS(found_user_id, 0, current_user_id);
    }
}

int main(int argc, char **argv) {
    // Parse command line arguments
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <passphrase> <checksum_hex> [max_user_id]" << std::endl;
        std::cerr << "Example: " << argv[0] << " \"MySecret\" \"5D8C0210C2D84CABB3CEC8ADDE17EBF4\" 10000000" << std::endl;
        return 1;
    }
    
    // Get input parameters
    std::string passphrase = argv[1];
    std::string checksum_hex = argv[2];
    int max_user_id = (argc > 3) ? atoi(argv[3]) : 10000000;
    
    // Convert hex checksum to binary
    if (checksum_hex.length() != MD5_DIGEST_LENGTH * 2) {
        std::cerr << "Error: Checksum must be " << (MD5_DIGEST_LENGTH * 2) << " characters (MD5 in hex)" << std::endl;
        return 1;
    }
    
    unsigned char dataKeyChecksum[MD5_DIGEST_LENGTH];
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        unsigned int byte;
        sscanf(checksum_hex.c_str() + i*2, "%02x", &byte);
        dataKeyChecksum[i] = byte;
    }
    
    // Start timing
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // Copy data to device constants
    cudaMemcpyToSymbol(d_passphrase, passphrase.c_str(), passphrase.length());
    cudaMemcpyToSymbol(d_passphrase_len, &passphrase.length(), sizeof(int));
    cudaMemcpyToSymbol(d_dataKeyChecksum, dataKeyChecksum, MD5_DIGEST_LENGTH);
    
    // Allocate device memory for found user ID
    int *d_found_user_id;
    cudaMalloc(&d_found_user_id, sizeof(int));
    cudaMemset(d_found_user_id, 0, sizeof(int));
    
    // Host variable for result
    int found_user_id = 0;
    bool found = false;
    
    // Process in batches to avoid long-running kernels
    for (int batch_start = 1; batch_start <= max_user_id && !found; batch_start += BATCH_SIZE) {
        int batch_end = std::min(batch_start + BATCH_SIZE - 1, max_user_id);
        int batch_size = batch_end - batch_start + 1;
        
        // Calculate grid dimensions
        int blocks = (batch_size + NUM_THREADS_PER_BLOCK - 1) / NUM_THREADS_PER_BLOCK;
        
        // Launch kernel
        brute_force_kernel<<<blocks, NUM_THREADS_PER_BLOCK>>>(batch_start, d_found_user_id);
        
        // Check for kernel errors
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            std::cerr << "CUDA Error: " << cudaGetErrorString(err) << std::endl;
            break;
        }
        
        // Wait for kernel to finish
        cudaDeviceSynchronize();
        
        // Copy result back
        cudaMemcpy(&found_user_id, d_found_user_id, sizeof(int), cudaMemcpyDeviceToHost);
        
        // Check if found
        if (found_user_id != 0) {
            found = true;
            break;
        }
        
        // Status update every million IDs
        if (batch_start % 1000000 == 1) {
            std::cout << "Checked up to user ID " << batch_end << "..." << std::endl;
        }
    }
    
    // Free device memory
    cudaFree(d_found_user_id);
    
    // Stop timing
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    // Output results
    if (found) {
        std::cout << "Success! Found user ID: " << found_user_id << std::endl;
        
        // Derive the key again on CPU to verify and output
        std::string user_id_str = std::to_string(found_user_id);
        
        // Create buffer for SHA1 input (user_id + passphrase)
        unsigned char buffer[512];
        memcpy(buffer, user_id_str.c_str(), user_id_str.length());
        memcpy(buffer + user_id_str.length(), passphrase.c_str(), passphrase.length());
        
        // Calculate first hash
        unsigned char hash1[SHA1_DIGEST_LENGTH];
        sha1_multi(buffer, user_id_str.length() + passphrase.length(), hash1, ITERATIONS);
        
        // Reverse passphrase
        std::string reversed_passphrase(passphrase.rbegin(), passphrase.rend());
        
        // Buffer for second hash
        memcpy(buffer, user_id_str.c_str(), user_id_str.length());
        memcpy(buffer + user_id_str.length(), reversed_passphrase.c_str(), reversed_passphrase.length());
        
        // Calculate second hash
        unsigned char hash2[SHA1_DIGEST_LENGTH];
        sha1_multi(buffer, user_id_str.length() + reversed_passphrase.length(), hash2, ITERATIONS);
        
        // Combine hashes
        unsigned char final_key[CRASHPLAN_KEY_LENGTH];
        memcpy(final_key, hash1, SHA1_DIGEST_LENGTH);
        memcpy(final_key + SHA1_DIGEST_LENGTH, hash2, SHA1_DIGEST_LENGTH);
        
        // Pad if needed
        if (SHA1_DIGEST_LENGTH * 2 < CRASHPLAN_KEY_LENGTH) {
            memset(final_key + SHA1_DIGEST_LENGTH * 2, 0, CRASHPLAN_KEY_LENGTH - SHA1_DIGEST_LENGTH * 2);
        }
        
        // Output the key in hex format
        std::cout << "Key (hex): " << bin_to_hex(final_key, CRASHPLAN_KEY_LENGTH) << std::endl;
        
        // Verify the checksum
        unsigned char verify_md5[MD5_DIGEST_LENGTH];
        MD5(final_key, CRASHPLAN_KEY_LENGTH, verify_md5);
        
        std::cout << "Key checksum: " << bin_to_hex(verify_md5, MD5_DIGEST_LENGTH) << std::endl;
        std::cout << "Target checksum: " << checksum_hex << std::endl;
    } else {
        std::cout << "No matching user ID found within the specified range." << std::endl;
    }
    
    std::cout << "Execution time: " << duration.count() << " ms" << std::endl;
    
    return found ? 0 : 1;
}