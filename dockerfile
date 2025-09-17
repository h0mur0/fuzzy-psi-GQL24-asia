FROM ubuntu:22.04

RUN apt-get update && \
apt-get install -y wget build-essential cmake git libtool iproute2 python3 sudo nasm libssl-dev libgmp-dev && \
rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN git config --global http.postbuffer 500M && git config --global https.postbuffer 500M

RUN git config --global http.proxy http://192.168.100.1:7897 && git config --global https.proxy http://192.168.100.1:7897

RUN git clone https://github.com/intel/pailliercryptolib.git && \
git clone https://github.com/osu-crypto/libOTe.git && \
git clone https://github.com/ql70ql70/Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping.git

WORKDIR /app/libOTe

RUN mkdir out 

WORKDIR /app/libOTe/out

RUN  wget https://archives.boost.io/release/1.86.0/source/boost_1_86_0.tar.bz2

WORKDIR /app/libOTe

RUN python3 build.py --all --boost --sodium && \
python3 build.py --install=./out/build/linux

WORKDIR /app/pailliercryptolib

RUN cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/path/to/install/ -DCMAKE_BUILD_TYPE=Release -DIPCL_TEST=OFF -DIPCL_BENCHMARK=OFF && \
cmake --build build -j 10 && \
cmake --build build --target install -j 10 && \
export IPCL_DIR=/path/to/install/lib/cmake/ipcl-2.0.0/

WORKDIR /app/Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping

RUN mkdir build

WORKDIR /app/Fuzzy-Private-Set-Intersection-from-Fuzzy-Mapping/build

RUN cmake .. && \
make
