// SPDX-License-Identifier: GPL-2.0
// Bitcoin Core functional-test workload helper.
//
// Issues bedrock's ready VMCALL so the lab can carve the initial checkpoint,
// then returns. The compose wrapper keeps the container (and thus the VM) alive
// afterwards with `sleep infinity`; lifetime is owned by the lab, which forks
// branches off the ready checkpoint and tears the tree down when the fuzzer
// exits. The lab execs a functional-test driver
// (/opt/bedrock/drivers/singleton_*) into this container on each iteration.

#include <stdio.h>

#include "libvmcall.h"

int main(void) {
    printf("bitcoin-functional: signaling bedrock VM ready...\n");
    vmcall_ready();
    return 0;
}
