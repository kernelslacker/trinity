#pragma once

int get_rand_bpf_fd(void);

#ifndef BPF_MAP_TYPE_LRU_HASH
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_LRU_PERCPU_HASH 10
#define BPF_MAP_TYPE_LPM_TRIE 11
#endif
#ifndef BPF_F_NO_COMMON_LRU
#define BPF_F_NO_COMMON_LRU     (1U << 1)
#endif
