// leak_detector.c
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "leak_common.h"

typedef struct {
    void *ptr;
    size_t size;
    const char *file;
    int line;
} alloc_info_t;

#define MAX_ALLOCS 10000
static alloc_info_t allocations[MAX_ALLOCS];
static int alloc_count = 0;

// 获取原始函数指针
static void* (*real_malloc)(size_t) = NULL;
static void (*real_free)(void*) = NULL;
static int (*real_close)(int) = NULL;

static void leak_do_init(void) {
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_close = dlsym(RTLD_NEXT, "close");
}

void __attribute__((constructor)) init_hooks() {
    leak_init_once(leak_do_init);
}

void __attribute__((destructor)) cleanup() {
    int leak_count = 0;
    for (int i = 0; i < alloc_count; i++) if (allocations[i].ptr != NULL) leak_count++;
    if (leak_count == 0) return;

    fprintf(stderr, "\n=== Memory Leak Report ===\n");
    for (int i = 0; i < alloc_count; i++) {
        if (allocations[i].ptr != NULL) {
            fprintf(stderr, "Leak: %p (%zu bytes)\n", 
                   allocations[i].ptr, allocations[i].size);
        }
    }
}

void* malloc(size_t size) {
    void *ptr = real_malloc(size);
    
    if (alloc_count < MAX_ALLOCS) {
        allocations[alloc_count].ptr = ptr;
        allocations[alloc_count].size = size;
        allocations[alloc_count].file = "unknown";
        allocations[alloc_count].line = 0;
        alloc_count++;
    }
    
    return ptr;
}

void free(void *ptr) {
    for (int i = 0; i < alloc_count; i++) {
        if (allocations[i].ptr == ptr) {
            allocations[i].ptr = NULL; // 标记为已释放
            break;
        }
    }
    real_free(ptr);
}

int close(int fd) {
    fprintf(stderr, "Closing FD: %d\n", fd);
    return real_close(fd);
}