#!/bin/bash
# Build only private dependencies; source archives must be supplied offline.
set -euo pipefail
task_root=/u3/melat
task_cmake="$task_root/cmake/cmake/data/bin/cmake"
export LD_LIBRARY_PATH="$task_root/deps/lib:$task_root/deps/lib64"
export PKG_CONFIG_PATH="$task_root/deps/lib/pkgconfig:$task_root/deps/lib64/pkgconfig"
mkdir -p "$task_root/build" "$task_root/deps"
cd "$task_root/build"
tar -xjf ../install/libgpg-error-1.47.tar.bz2
cd libgpg-error-1.47
./configure --prefix="$task_root/deps" --disable-doc
make -j8
make install
cd ..
tar -xjf ../install/libgcrypt-1.10.3.tar.bz2
cd libgcrypt-1.10.3
./configure --prefix="$task_root/deps" --with-libgpg-error-prefix="$task_root/deps" --disable-doc
make -j8
make install
cd ..
tar -xzf ../install/pcre2-10.42-source.tar.gz
cd pcre2-pcre2-10.42
./autogen.sh
CFLAGS='-O2 -std=gnu99' ./configure --prefix="$task_root/deps" --disable-cpp
make -j8
make install
cd ..
tar -xzf ../install/c-ares-1.19.1.tar.gz
"$task_cmake" -S c-ares-cares-1_19_1 -B cares-out -DCMAKE_INSTALL_PREFIX="$task_root/deps" -DCARES_SHARED=ON -DCARES_STATIC=OFF -DCARES_BUILD_TOOLS=OFF -DCARES_BUILD_TESTS=OFF
"$task_cmake" --build cares-out -j8
"$task_cmake" --install cares-out
mkdir -p glib-devel
cd glib-devel
rpm2cpio ../../install/glib2-devel-2.56.1-9.el7_9.x86_64.rpm | cpio -idm
cd ..
tar -xJf ../install/wireshark-4.2.2.tar.xz
"$task_root/python/bin/python3.12" "$task_root/app/deployment/centos7-safe-math.py" "$task_root/build/wireshark-4.2.2"
"$task_cmake" -S wireshark-4.2.2 -B wireshark-out \
 -DCMAKE_INSTALL_PREFIX="$task_root/wireshark" -DCMAKE_PREFIX_PATH="$task_root/deps" -DCMAKE_BUILD_TYPE=Release \
 -DGLIB2_MAIN_INCLUDE_DIR="$task_root/build/glib-devel/usr/include/glib-2.0" \
 -DGLIB2_INTERNAL_INCLUDE_DIR="$task_root/build/glib-devel/usr/lib64/glib-2.0/include" \
 -DGLIB2_LIBRARY=/usr/lib64/libglib-2.0.so.0 \
 -DGTHREAD2_LIBRARY=/usr/lib64/libgthread-2.0.so.0 -DGTHREAD2_INCLUDE_DIR="$task_root/build/glib-devel/usr/include/glib-2.0" \
 -DGMODULE2_LIBRARY=/usr/lib64/libgmodule-2.0.so.0 -DGMODULE2_INCLUDE_DIR="$task_root/build/glib-devel/usr/include/glib-2.0" \
 -DBUILD_wireshark=OFF -DBUILD_tshark=ON -DBUILD_editcap=ON -DBUILD_dumpcap=OFF -DBUILD_sharkd=OFF \
 -DBUILD_sshdump=OFF -DBUILD_ciscodump=OFF -DBUILD_wifidump=OFF -DBUILD_sdjournal=OFF \
 -DENABLE_PCAP=OFF -DENABLE_LUA=OFF -DENABLE_GNUTLS=OFF -DENABLE_KERBEROS=OFF -DENABLE_SMI=OFF -DENABLE_CAP=OFF
"$task_cmake" --build wireshark-out -j24
"$task_cmake" --install wireshark-out
"$task_root/wireshark/bin/tshark" --version
