# Makefile for GPU-accelerated Plan C key derivation

NVCC=nvcc
CC=g++
CUDA_PATH=/usr/local/cuda
CUDA_INCLUDE=$(CUDA_PATH)/include
CUDA_LIB=$(CUDA_PATH)/lib64

# CUDA compilation flags
NVCC_FLAGS=-O3 -arch=sm_89 --compiler-options -Wall

# Include paths
INCLUDES=-I$(CUDA_INCLUDE) -I/usr/include/openssl -I./

# Library paths and libraries
LIBS=-L$(CUDA_LIB) -lcuda -lcudart -lssl -lcrypto

# Main targets
all: gpu_derive_key

gpu_derive_key: gpu_derive_key.o
	$(NVCC) $(NVCC_FLAGS) $(INCLUDES) -o $@ $^ $(LIBS)

gpu_derive_key.o: gpu_derive_key.cu
	$(NVCC) $(NVCC_FLAGS) $(INCLUDES) -c $< -o $@

# Clean up build artifacts
clean:
	rm -f gpu_derive_key *.o

# Install to system path
install: gpu_derive_key
	cp gpu_derive_key /usr/local/bin/

.PHONY: all clean install