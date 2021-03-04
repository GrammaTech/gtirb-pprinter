# This test ensures that we do not regress on the following issue:
# https://git.grammatech.com/rewriting/gtirb-pprinter/-/merge_requests/330
.globl main
main:
    vpaddq %zmm2, %zmm3, %zmm1 {%k1}{z}
    call exit
