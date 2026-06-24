# syntax=docker/dockerfile:1
#
# Bitcoin Core functional-test workload: builds an INSTRUMENTED bitcoind (+
# bitcoin-cli) and ships it with the upstream functional-test framework so the
# fuzzer can replay the interface_ipc_mining.py functional test across many
# deterministic timelines and surface intermittent failures a single CI run
# hides, while steering on edge coverage of bitcoind's code.
#
# Coverage: bitcoind is compiled with clang `-fsanitize-coverage=trace-pc-guard`
# and linked against the libpcguard -> libfeedback shim (+ `-Wl,--build-id`), so
# it registers a per-edge coverage buffer ("cov-<build-id>") the lab reads back.
# The shim NO-OPS outside bedrock (it probes the CPUID brand string, see
# guest/libvmcall.h), so the instrumented bitcoind run on the *build* host
# (e.g. depends/secp256k1 build-time tools, or anyone running the image
# directly) does not fault on the registration VMCALL. The shim objects
# themselves are built WITHOUT the coverage flag (or the hooks would recurse).
# Coverage uses the default `go-`-less prefix, so run the fuzzer with
# `--cov-prefix cov-` (or `--cov-prefix ""` to match every buffer).
#
# Dependencies come from Bitcoin Core's in-tree `depends` system (boost, the
# wallet's sqlite, and the Cap'n Proto IPC stack, all statically linked), so
# the runtime image needs no dev libs for those. clang is required: gcc does
# not implement trace-pc-guard. libvmcall.h / libfeedback.{h,c} / libpcguard.c
# / ready.c are staged into this build context by build.sh from guest/ (the
# single source of truth, outside the context).

ARG BITCOIN_REF=d84fc352cbc1363df5cd6024a22e73fc63283e4f

FROM debian:trixie-slim AS build
ENV DEBIAN_FRONTEND=noninteractive
# build-essential: g++/make/binutils (host toolchain + the uninstrumented shim
# and bedrock-ready; binutils' ld supplies --build-id and strip). clang: the
# trace-pc-guard instrumentor (trixie ships clang 19, new enough for Bitcoin
# Core's C++20). The rest are the depends system's documented host prereqs
# (cmake/curl/make/patch + bison/pkgconf/python3/xz-utils); git clones the repo.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git clang \
      build-essential cmake curl make patch \
      bison pkgconf python3 xz-utils \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Guest hypercall + coverage shim (staged by build.sh) and the ready helper.
COPY libvmcall.h libfeedback.h libfeedback.c libpcguard.c ready.c /src/

# bedrock-ready: issues the ready VMCALL so the lab can take the boot checkpoint.
# Static, no coverage.
RUN gcc -O2 -static -o /bedrock-ready ready.c

# Coverage runtime, built WITHOUT -fsanitize-coverage (plain clang). The shim
# objects are injected into the bitcoind/bitcoin-cli links below; -Wl,--build-id
# (also added there) is what lets libfeedback key the buffer on the build-id.
RUN mkdir -p /opt/shim \
 && clang -O2 -I/src -c libpcguard.c -o /opt/shim/libpcguard.o \
 && clang -O2 -I/src -c libfeedback.c -o /opt/shim/libfeedback.o

ARG BITCOIN_REF
RUN git clone --branch master https://github.com/bitcoin/bitcoin /bitcoin

# Build dependencies from the in-tree depends system. We keep boost (always),
# the wallet's sqlite (the functional-test framework expects a wallet-capable
# build: the shared regtest cache it mines removes an empty `wallets/` dir that a
# no-wallet bitcoind never creates), and the Cap'n Proto IPC stack (capnp +
# native_libmultiprocess/native_capnp): interface_ipc_mining.py drives bitcoind's
# multiprocess mining interface, which needs ENABLE_IPC compiled in. Trim
# everything else we don't run: Qt/GUI, QR, ZMQ, USDT tracepoints. The depends
# build also writes a CMake toolchain file the main build consumes; that
# toolchain turns the trimmed features OFF (and IPC ON) automatically (it keys
# off which dep packages were built), so we don't repeat those -D flags below.
WORKDIR /bitcoin/depends
RUN make -j"$(nproc)" NO_QT=1 NO_QR=1 NO_ZMQ=1 NO_USDT=1

# Configure + build the instrumented daemon. We pass the depends toolchain but
# OVERRIDE the compiler to clang (the toolchain's `if(NOT DEFINED ...)` guards
# let -D win) because trace-pc-guard is clang-only. No CMAKE_BUILD_TYPE: Bitcoin
# Core strips -DNDEBUG from every config (cmake/module/ProcessConfigurations.cmake),
# so asserts stay live regardless — `-O1 -g0` keeps the build fast and the binary
# small. The shim objects + --build-id + static libstdc++/libgcc go on the exe
# link (native-linux depends LDFLAGS are empty, so overriding loses nothing);
# -fno-sanitize-link-runtime stops clang auto-linking compiler-rt (libpcguard IS
# our trace-pc-guard runtime). BUILD_TESTS=OFF also drops bitcoin-tx/-util/-wallet
# and the unit tests we don't need. BUILD_BITCOIN_BIN stays at its ON default:
# interface_ipc_mining.py's `ipcbind` nodes are launched via the `bitcoin`
# wrapper (`bitcoin node -m ...`), which the test framework always uses instead
# of bitcoind directly whenever a node needs IPC (test_framework/util.py's
# Binaries._argv, need_ipc branch) — the wrapper then execs the multiprocess
# `bitcoin-node` binary (built automatically once ENABLE_IPC is on, see
# src/CMakeLists.txt's `if(ENABLE_IPC AND BUILD_DAEMON)` block) from its own
# directory, so both must ship alongside bitcoind/bitcoin-cli below.
WORKDIR /bitcoin
RUN TOOLCHAIN="$(ls /bitcoin/depends/*/toolchain.cmake | head -1)" \
 && cmake -B build --toolchain "$TOOLCHAIN" \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_C_FLAGS="-O1 -g0 -fsanitize-coverage=trace-pc-guard" \
      -DCMAKE_CXX_FLAGS="-O1 -g0 -fsanitize-coverage=trace-pc-guard" \
      -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc -fno-sanitize-link-runtime -Wl,--build-id /opt/shim/libpcguard.o /opt/shim/libfeedback.o" \
      -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF \
      -DENABLE_EXTERNAL_SIGNER=OFF \
 && cmake --build build -j"$(nproc)" --target bitcoind bitcoin-cli bitcoin bitcoin-node

# Strip in the build stage (binutils lives here, not the slim runtime). Stripping
# keeps the allocated .note.gnu.build-id note and the trace-pc-guard guard table,
# so coverage keying and recording still work.
RUN strip /bitcoin/build/bin/bitcoind /bitcoin/build/bin/bitcoin-cli \
          /bitcoin/build/bin/bitcoin /bitcoin/build/bin/bitcoin-node

FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
# python3 runs the functional-test framework (stdlib only, apart from pycapnp
# below). Same trixie release as the build stage so glibc matches the
# dynamically-linked binaries (libstdc++/libgcc are statically linked in).
# pycapnp (interface_ipc_mining.py's IPC client binding) isn't a Debian
# package, so it comes from PyPI as a prebuilt manylinux wheel for trixie's
# python3 (3.13) — no compiler needed, hence no --no-install-recommends dev
# libs. --break-system-packages: this image runs nothing but the test
# framework, so there's no system-Python state to protect.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && pip3 install --no-cache-dir --break-system-packages pycapnp

# The instrumented binaries. The framework resolves them from config.ini as
# {BUILDDIR}/bin/<name>, so they live under /opt/bitcoin/bin. bitcoin-node
# isn't looked up by the framework directly — the `bitcoin` wrapper execs it
# by relative path from its own directory — but it must ship alongside it.
COPY --from=build /bitcoin/build/bin/bitcoind     /opt/bitcoin/bin/bitcoind
COPY --from=build /bitcoin/build/bin/bitcoin-cli  /opt/bitcoin/bin/bitcoin-cli
COPY --from=build /bitcoin/build/bin/bitcoin       /opt/bitcoin/bin/bitcoin
COPY --from=build /bitcoin/build/bin/bitcoin-node  /opt/bitcoin/bin/bitcoin-node

# The functional-test framework + the test itself (pure-Python upstream tree),
# and the rpcauth helper config.ini points at (unused by this test, shipped for
# completeness / future drivers).
COPY --from=build /bitcoin/test/functional /opt/bitcoin/test/functional
COPY --from=build /bitcoin/share/rpcauth   /opt/bitcoin/share/rpcauth

# The .capnp IPC schema *sources* (not compiled into the binaries above):
# test_framework/ipc_util.py's load_capnp_modules() has pycapnp parse these
# directly at test runtime, under SRCDIR (== /opt/bitcoin), to build message
# types matching bitcoind's wire protocol.
COPY --from=build /bitcoin/src/ipc/capnp /opt/bitcoin/src/ipc/capnp
COPY --from=build /bitcoin/src/ipc/libmultiprocess/include/mp/proxy.capnp \
                   /opt/bitcoin/src/ipc/libmultiprocess/include/mp/proxy.capnp

# Minimal config.ini telling the framework where the binaries are and which
# components were compiled. The default --configfile is
# dirname(test_file)/../config.ini == this path, so drivers need not pass it.
# EXEEXT is empty on Linux. Components match the build above (wallet+cli+daemon
# +IPC on, everything else off) so any is_*_compiled()/skip_if_no_ipc()
# skip-guard resolves correctly.
RUN printf '%s\n' \
  '[environment]' \
  'CLIENT_NAME=Bitcoin Core' \
  'CLIENT_BUGREPORT=https://github.com/bitcoin/bitcoin/issues' \
  'SRCDIR=/opt/bitcoin' \
  'BUILDDIR=/opt/bitcoin' \
  'EXEEXT=' \
  'RPCAUTH=/opt/bitcoin/share/rpcauth/rpcauth.py' \
  '' \
  '[components]' \
  'ENABLE_WALLET=true' \
  'ENABLE_CLI=true' \
  'ENABLE_BITCOIND=true' \
  'BUILD_BITCOIN_TX=false' \
  'ENABLE_BITCOIN_UTIL=false' \
  'ENABLE_BITCOIN_CHAINSTATE=false' \
  'ENABLE_WALLET_TOOL=false' \
  'BUILD_BENCH=false' \
  'ENABLE_FUZZ_BINARY=false' \
  'ENABLE_ZMQ=false' \
  'ENABLE_EMBEDDED_ASMAP=true' \
  'ENABLE_EXTERNAL_SIGNER=false' \
  'ENABLE_USDT_TRACEPOINTS=false' \
  'ENABLE_IPC=true' \
  > /opt/bitcoin/test/config.ini

COPY --from=build /bedrock-ready /usr/local/bin/bedrock-ready

# The functional-test driver. `singleton_` marks it a unit/functional-test
# driver: on any timeline only one runs, with no other test driver alongside it
# (see workloads/README.md). Staged from the build context (committed in this dir).
COPY singleton_p2p_orphan_handling /opt/bedrock/drivers/singleton_p2p_orphan_handling
RUN chmod +x /opt/bedrock/drivers/singleton_p2p_orphan_handling

# Overridden by compose; a sane default so the container idles if run directly.
ENTRYPOINT ["/bin/sh", "-c", "sleep infinity"]
