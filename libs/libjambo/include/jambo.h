/**
 * @file jambo.h
 * @brief En-tête C ABI natif pour le micro-noyau JamboOS (jambostack/jambo-os)
 *
 * Fournit les définitions de constantes, codes d'erreur, types de capacités
 * et wrappers d'appels système pour les bibliothèques et exécutables C.
 */

#ifndef _JAMBO_H
#define _JAMBO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* === Types de base === */

typedef uint64_t jambo_handle_t;

#define JAMBO_HANDLE_NULL ((jambo_handle_t)0)

static inline uint32_t jambo_handle_index(jambo_handle_t h) {
    return (uint32_t)(h & 0xFFFFFFFF);
}

static inline uint32_t jambo_handle_generation(jambo_handle_t h) {
    return (uint32_t)(h >> 32);
}

/* === Codes d'erreur système === */

#define JAMBO_OK                    0
#define JAMBO_ERR_INVALID_HANDLE   -1
#define JAMBO_ERR_PERMISSION_DENIED -2
#define JAMBO_ERR_INVALID_ARGUMENT -3
#define JAMBO_ERR_OUT_OF_MEMORY    -4
#define JAMBO_ERR_BUFFER_TOO_SMALL -5
#define JAMBO_ERR_TIMED_OUT        -6
#define JAMBO_ERR_RESOURCE_BUSY    -7
#define JAMBO_ERR_NOT_SUPPORTED    -8
#define JAMBO_ERR_PEER_CLOSED      -9
#define JAMBO_ERR_BAD_ADDRESS      -10

/* === Masque de droits de capacité === */

#define JAMBO_RIGHT_READ       (1U << 0)
#define JAMBO_RIGHT_WRITE      (1U << 1)
#define JAMBO_RIGHT_EXECUTE    (1U << 2)
#define JAMBO_RIGHT_MAP        (1U << 3)
#define JAMBO_RIGHT_SEND       (1U << 4)
#define JAMBO_RIGHT_RECEIVE    (1U << 5)
#define JAMBO_RIGHT_DUPLICATE  (1U << 6)
#define JAMBO_RIGHT_TRANSFER   (1U << 7)
#define JAMBO_RIGHT_MANAGE     (1U << 8)
#define JAMBO_RIGHT_ALL        0x1FFU

/* === Numéros d'appels système (24 Syscalls) === */

#define JAMBO_SYS_CAP_DUP        1
#define JAMBO_SYS_CAP_DROP       2
#define JAMBO_SYS_CAP_TRANSFER   3

#define JAMBO_SYS_VMO_CREATE     4
#define JAMBO_SYS_VMO_MAP        5
#define JAMBO_SYS_VMO_UNMAP      6
#define JAMBO_SYS_VMO_PROTECT    7

#define JAMBO_SYS_PROCESS_CREATE 8
#define JAMBO_SYS_THREAD_CREATE  9
#define JAMBO_SYS_THREAD_START   10
#define JAMBO_SYS_THREAD_EXIT    11
#define JAMBO_SYS_THREAD_YIELD   12

#define JAMBO_SYS_CHANNEL_CREATE 13
#define JAMBO_SYS_CHANNEL_CALL   14
#define JAMBO_SYS_PORT_CREATE    15
#define JAMBO_SYS_PORT_WAIT      16
#define JAMBO_SYS_RING_SETUP     17
#define JAMBO_SYS_RING_ENTER     18
#define JAMBO_SYS_FUTEX_WAIT     19
#define JAMBO_SYS_FUTEX_WAKE     20

#define JAMBO_SYS_IRQ_BIND       21
#define JAMBO_SYS_IRQ_ACK        22
#define JAMBO_SYS_IOMMU_MAP      23
#define JAMBO_SYS_CLOCK_GETTIME  24

/* === Clés du vecteur auxiliaire ELF (Auxiliary Vector) System V ABI === */

#define JAMBO_AT_NULL    0
#define JAMBO_AT_IGNORE  1
#define JAMBO_AT_EXECFD  2
#define JAMBO_AT_PHDR    3
#define JAMBO_AT_PHENT   4
#define JAMBO_AT_PHNUM   5
#define JAMBO_AT_PAGESZ  6
#define JAMBO_AT_BASE    7
#define JAMBO_AT_FLAGS   8
#define JAMBO_AT_ENTRY   9
#define JAMBO_AT_NOTELF  10
#define JAMBO_AT_UID     11
#define JAMBO_AT_EUID    12
#define JAMBO_AT_GID     13
#define JAMBO_AT_EGID    14
#define JAMBO_AT_CLKTCK  17
#define JAMBO_AT_SECURE  23
#define JAMBO_AT_RANDOM  25

/* === Invocations brutes d'appels système === */

#if defined(__x86_64__)
static inline int64_t jambo_syscall6(uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t* out2) {
    int64_t ret;
    uint64_t ret2 = a3;
    __asm__ volatile (
        "syscall"
        : "=a"(ret), "+d"(ret2)
        : "a"((uint64_t)num), "D"(a1), "S"(a2), "r"((uint64_t)a4), "r"((uint64_t)a5), "r"((uint64_t)a6)
        : "rcx", "r11", "memory"
    );
    if (out2) *out2 = ret2;
    return ret;
}
#elif defined(__aarch64__)
static inline int64_t jambo_syscall6(uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t* out2) {
    register uint64_t x8 __asm__("x8") = (uint64_t)num;
    register uint64_t x0 __asm__("x0") = a1;
    register uint64_t x1 __asm__("x1") = a2;
    register uint64_t x2 __asm__("x2") = a3;
    register uint64_t x3 __asm__("x3") = a4;
    register uint64_t x4 __asm__("x4") = a5;
    register uint64_t x5 __asm__("x5") = a6;
    __asm__ volatile (
        "svc #0"
        : "+r"(x0), "+r"(x1)
        : "r"(x8), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory"
    );
    if (out2) *out2 = x1;
    return (int64_t)x0;
}
#endif

/* === Fonctions de confort === */

static inline int64_t jambo_thread_yield(void) {
    return jambo_syscall6(JAMBO_SYS_THREAD_YIELD, 0, 0, 0, 0, 0, 0, NULL);
}

static inline int64_t jambo_vmo_create(size_t size, uint32_t flags, jambo_handle_t* out_handle) {
    return jambo_syscall6(JAMBO_SYS_VMO_CREATE, (uint64_t)size, (uint64_t)flags, (uint64_t)(uintptr_t)out_handle, 0, 0, 0, NULL);
}

static inline int64_t jambo_vmo_map(jambo_handle_t proc, jambo_handle_t vmo, uint64_t vaddr, uint32_t prot) {
    return jambo_syscall6(JAMBO_SYS_VMO_MAP, proc, vmo, vaddr, (uint64_t)prot, 0, 0, NULL);
}

static inline int64_t jambo_vmo_unmap(jambo_handle_t proc, uint64_t vaddr, size_t size) {
    return jambo_syscall6(JAMBO_SYS_VMO_UNMAP, proc, vaddr, (uint64_t)size, 0, 0, 0, NULL);
}

static inline int64_t jambo_process_create(uint32_t flags, jambo_handle_t* out_proc) {
    return jambo_syscall6(JAMBO_SYS_PROCESS_CREATE, (uint64_t)flags, (uint64_t)(uintptr_t)out_proc, 0, 0, 0, 0, NULL);
}

static inline int64_t jambo_thread_create(jambo_handle_t proc, uint32_t flags, jambo_handle_t* out_thread) {
    return jambo_syscall6(JAMBO_SYS_THREAD_CREATE, proc, (uint64_t)flags, (uint64_t)(uintptr_t)out_thread, 0, 0, 0, NULL);
}

static inline int64_t jambo_thread_start(jambo_handle_t thread, uint64_t entry_point, uint64_t stack_pointer) {
    return jambo_syscall6(JAMBO_SYS_THREAD_START, thread, entry_point, stack_pointer, 0, 0, 0, NULL);
}

static inline int64_t jambo_thread_exit(int32_t exit_code) {
    return jambo_syscall6(JAMBO_SYS_THREAD_EXIT, (uint64_t)(int64_t)exit_code, 0, 0, 0, 0, 0, NULL);
}

static inline int64_t jambo_channel_create(uint32_t flags, jambo_handle_t* out1, jambo_handle_t* out2) {
    return jambo_syscall6(JAMBO_SYS_CHANNEL_CREATE, (uint64_t)flags, (uint64_t)(uintptr_t)out1, (uint64_t)(uintptr_t)out2, 0, 0, 0, NULL);
}

static inline int64_t jambo_channel_call(jambo_handle_t endpoint, const void* send_msg, void* recv_msg) {
    return jambo_syscall6(JAMBO_SYS_CHANNEL_CALL, endpoint, (uint64_t)(uintptr_t)send_msg, (uint64_t)(uintptr_t)recv_msg, 0, 0, 0, NULL);
}

static inline int64_t jambo_ring_setup(const void* ring_desc, jambo_handle_t* out_ring) {
    return jambo_syscall6(JAMBO_SYS_RING_SETUP, (uint64_t)(uintptr_t)ring_desc, (uint64_t)(uintptr_t)out_ring, 0, 0, 0, 0, NULL);
}

static inline int64_t jambo_ring_enter(jambo_handle_t ring, uint32_t to_submit, uint32_t min_complete) {
    return jambo_syscall6(JAMBO_SYS_RING_ENTER, ring, (uint64_t)to_submit, (uint64_t)min_complete, 0, 0, 0, NULL);
}

static inline int64_t jambo_futex_wait(const uint32_t* uaddr, uint32_t expected_val, uint64_t timeout_ns) {
    return jambo_syscall6(JAMBO_SYS_FUTEX_WAIT, (uint64_t)(uintptr_t)uaddr, (uint64_t)expected_val, timeout_ns, 0, 0, 0, NULL);
}

static inline int64_t jambo_futex_wake(const uint32_t* uaddr, uint32_t count) {
    return jambo_syscall6(JAMBO_SYS_FUTEX_WAKE, (uint64_t)(uintptr_t)uaddr, (uint64_t)count, 0, 0, 0, 0, NULL);
}

#ifdef __cplusplus
}
#endif

#endif /* _JAMBO_H */
