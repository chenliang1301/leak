// leak_detector_line.c - lightweight leak tracer that writes raw analysis file
//#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include "leak_common.h"

typedef struct {
    void *ptr;
    size_t size;
    void *caller; /* saved return address */
} alloc_info_t;

#define MAX_ALLOCS 10000
static alloc_info_t allocations[MAX_ALLOCS];
static int alloc_count = 0;

/* original functions */
static void* (*real_malloc)(size_t) = NULL;
static void (*real_free)(void*) = NULL;
static int (*real_close)(int) = NULL;

static void leak_line_do_init(void) {
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_close = dlsym(RTLD_NEXT, "close");
    if (getenv("LEAK_VERBOSE")) fprintf(stderr, "Leak detector initialized\n");
}

void __attribute__((constructor)) init_hooks() {
    leak_init_once(leak_line_do_init);
}

void __attribute__((destructor)) cleanup() {
    const char *outname = "leak_analysis.txt";

    int leak_count = 0;
    for (int i = 0; i < alloc_count; ++i) if (allocations[i].ptr != NULL) leak_count++;
    if (leak_count == 0) return;

    fprintf(stderr, "\n=== Memory Leak Report ===\n");
    fprintf(stderr, "分析文件: %s\n", outname);

    /* 只输出到当前路径下的 leak_analysis.txt，直接覆盖，无时间戳 */
    FILE *f = fopen(outname, "w");
    if (f) {
        fprintf(f, "#ptr size caller binary func\n");
        for (int i = 0; i < alloc_count; ++i) {
            if (allocations[i].ptr != NULL) {
                const char *bin = "-";
                const char *func = "-";
                Dl_info info;
                if (allocations[i].caller && dladdr(allocations[i].caller, &info) && info.dli_fname) {
                    bin = info.dli_fname;
                    func = info.dli_sname ? info.dli_sname : "-";
                    uintptr_t off = (uintptr_t)allocations[i].caller - (uintptr_t)info.dli_fbase;
                    fprintf(f, "%p %zu 0x%lx %s %s\n",
                            allocations[i].ptr,
                            allocations[i].size,
                            (unsigned long)off,
                            bin,
                            func);
                } else {
                    fprintf(f, "%p %zu %p %s %s\n",
                            allocations[i].ptr,
                            allocations[i].size,
                            allocations[i].caller ? allocations[i].caller : (void*)0,
                            bin,
                            func);
                }
            }
        }
        fclose(f);
    }

    /* also print simple report to stderr */
    for (int i = 0; i < alloc_count; ++i) {
        if (allocations[i].ptr != NULL) {
            fprintf(stderr, "Leak: %p (%zu bytes) [caller %p]\n",
                    allocations[i].ptr, allocations[i].size,
                    allocations[i].caller ? allocations[i].caller : (void*)0);
        }
    }
}

void* malloc(size_t size) {
    void *ptr = NULL;
    if (real_malloc) ptr = real_malloc(size);
    else ptr = NULL;

    if (alloc_count < MAX_ALLOCS) {
        allocations[alloc_count].ptr = ptr;
        allocations[alloc_count].size = size;
        /* use builtin return address (safe) */
        allocations[alloc_count].caller = __builtin_return_address(0);
        alloc_count++;
    }
    return ptr;
}

void free(void *ptr) {
    for (int i = 0; i < alloc_count; ++i) {
        if (allocations[i].ptr == ptr) {
            allocations[i].ptr = NULL;
            break;
        }
    }
    if (real_free) real_free(ptr);
}

int close(int fd) {
    if (real_close) return real_close(fd);
    return -1;
}