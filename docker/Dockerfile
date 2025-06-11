FROM ubuntu:20.04

WORKDIR /workspace

# Install Mininet, Python and other required tools
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y curl dnsutils ifupdown iproute2 iptables iputils-ping \
       mininet net-tools tcpdump iperf3 xterm x11-xserver-utils python3 python3-pip graphviz libnanomsg-dev tcpreplay \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir graphviz matplotlib networkx mininet psutil ipaddr nnpy pandas \
       scikit-learn scikit-optimize scapy dpkt pyzmq jupyter

# Install bmv2 and p4c
# Source: https://github.com/p4lang/p4c?tab=readme-ov-file#ubuntu
RUN . /etc/lsb-release \
    && echo "deb https://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${DISTRIB_RELEASE}/ /" | tee /etc/apt/sources.list.d/home:p4lang.list \
    && curl -fsSL https://download.opensuse.org/repositories/home:p4lang/xUbuntu_${DISTRIB_RELEASE}/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/home_p4lang.gpg > /dev/null \
    && apt-get update \
    && apt-get install -y p4lang-p4c p4lang-bmv2 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install p4-utils and its dependencies, also updating the Mininet log.py file to a not yet released version
RUN apt-get update \
    && apt-get install -y git bridge-utils sudo \
    && git clone https://github.com/nsg-ethz/p4-utils.git \
    && cd p4-utils \
    && git reset --hard e02f06f1b79aa5da31f8849a6f6a9bafef0120d4 \
    && ./install.sh \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && curl https://raw.githubusercontent.com/mininet/mininet/6eb8973c0bfd13c25c244a3871130c5e36b5fbd7/mininet/log.py > /usr/local/lib/python3.8/dist-packages/mininet/log.py

# Install NIKSS, its dependencies, and the NIKSS Mininet library
RUN apt-get update \
    && apt-get install -y make cmake gcc libgmp-dev libelf-dev zlib1g-dev libjansson-dev \
    && git clone --recursive https://github.com/NIKSS-vSwitch/nikss.git \
    && cd nikss \
    && git reset --hard 1a077b3038acf8a32f17fcdfa35df975e7d89c61 \
    && ./build_libbpf.sh \
    && mkdir build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED=on .. \
    && make -j4 \
    && make install \
    && ldconfig \
    && make install_headers \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/local/lib/python3.8/dist-packages/nikss/mininet \
    && cp ../mininet/lib/nikss_mn.py /usr/local/lib/python3.8/dist-packages/nikss/mininet/nikss_mn.py

# Install p4c-ebpf from source, so that we can compile generated C code to eBPF byte code
# While we checkout the entire p4c repository, we only care about its eBPF backend (and its dependencies, e.g. BMv2)
RUN apt-get update \
    && apt-get install -y g++ automake libtool libgc-dev bison flex libfl-dev libboost-dev libboost-iostreams-dev \
       libboost-graph-dev llvm pkg-config clang \
    && git clone --recursive https://github.com/p4lang/p4c.git \
    && cd p4c \
    && git reset --hard 065481037623f0edb368b89a8c32659144f662e6 \
    && mkdir build && cd build \
    && cmake .. -DENABLE_GTESTS=OFF -DENABLE_P4TEST=OFF -DENABLE_P4C_GRAPHS=OFF -DENABLE_DPDK=OFF -DENABLE_UBPF=OFF \
    && make -j4 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
ENV P4C_ROOT=/workspace/p4c

# Install dependencies required for Grafana-based statistic visualization
# Grafana and InfluxDB 3 are not installed in this image, but they are also required for the statistics visualization.
#   They aren't included to save space, and they should probably be installed in a separate container.
RUN pip3 install --no-cache-dir influxdb3-python

# Install libraries maintained by us
RUN pip3 install --no-cache-dir "p4-api-bridge @ git+https://github.com/Trigary/p4-api-bridge.git"

# Raise "ulimit -l" to allow BPF programs requiring more memory
RUN echo "root             -       memlock         999000" >> /etc/security/limits.conf

WORKDIR /workspace/mnt

CMD ["/bin/bash"]
