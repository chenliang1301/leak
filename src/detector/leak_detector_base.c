// leak_detector_base.c - leak tracer using backtrace to record callers
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
    #define MAX_CALLERS 32
    void *callers[MAX_CALLERS];
    int ncallers;
    const char *type;
} alloc_info_t;

#define MAX_ALLOCS 10000
static alloc_info_t allocations[MAX_ALLOCS];
static int alloc_count = 0;

/* original functions */
static void* (*real_malloc)(size_t) = NULL;
static void (*real_free)(void*) = NULL;
static void* (*real_calloc)(size_t, size_t) = NULL;
static void* (*real_realloc)(void*, size_t) = NULL;
static char* (*real_strdup)(const char*) = NULL;
static char* (*real_strndup)(const char*, size_t) = NULL;
static int (*real_close)(int) = NULL;
static FILE* (*real_fopen)(const char*, const char*) = NULL;
static int (*real_fclose)(FILE*) = NULL;

/* init: obtain real symbols */
static void leak_base_do_init(void) {
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_strdup = dlsym(RTLD_NEXT, "strdup");
    real_strndup = dlsym(RTLD_NEXT, "strndup");
    real_close = dlsym(RTLD_NEXT, "close");
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    real_fclose = dlsym(RTLD_NEXT, "fclose");
    if (getenv("LEAK_VERBOSE")) fprintf(stderr, "Extended leak detector initialized\n");
}

void __attribute__((constructor)) init_hooks() {
    leak_init_once(leak_base_do_init);
}

/* thread-local guard to avoid recursion when backtrace() (or other helpers)
 * cause allocations that would re-enter our wrappers. */
static __thread int leak_bt_guard = 0;

static void record_allocation(void *ptr, size_t size, const char *type) {
    if (!ptr) return;
    if (alloc_count >= MAX_ALLOCS) return;

    allocations[alloc_count].ptr = ptr;
    allocations[alloc_count].size = size;
    allocations[alloc_count].type = type;
    allocations[alloc_count].ncallers = 0;

    if (!leak_bt_guard) {
        leak_bt_guard = 1;
        void *btbuf[MAX_CALLERS];
        int n = backtrace(btbuf, MAX_CALLERS);
        if (n > 0) {
            int take = (n > MAX_CALLERS) ? MAX_CALLERS : n;
            for (int k = 0; k < take; ++k) allocations[alloc_count].callers[k] = btbuf[k];
            allocations[alloc_count].ncallers = take;
        }
        leak_bt_guard = 0;
    }

    alloc_count++;
}

static void remove_allocation(void *ptr) {
    for (int i = 0; i < alloc_count; ++i) {
        if (allocations[i].ptr == ptr) {
            allocations[i].ptr = NULL;
            break;
        }
    }
}

void __attribute__((destructor)) cleanup() {
    const char *outname = "leak_analysis.txt";

    FILE *f = fopen(outname, "w");
    if (!f) {
        for (int i = 0; i < alloc_count; ++i) {
            if (allocations[i].ptr != NULL) {
                fprintf(stderr, "Leak: %p (%zu bytes)\n", allocations[i].ptr, allocations[i].size);
            }
        }
        return;
    }

    fprintf(f, "#ptr size callers\n");
    for (int i = 0; i < alloc_count; ++i) {
        if (allocations[i].ptr == NULL) continue;
        char callers_buf[8192];
        callers_buf[0] = '\0';
        int first = 1;
        for (int j = 0; j < allocations[i].ncallers; ++j) {
            void *addr = allocations[i].callers[j];
            Dl_info info;
            char part[1024];
            if (addr && dladdr(addr, &info) && info.dli_fname) {
                uintptr_t off = (uintptr_t)addr - (uintptr_t)info.dli_fbase;
                snprintf(part, sizeof(part), "0x%lx@%s", (unsigned long)off, info.dli_fname);
            } else if (addr) {
                snprintf(part, sizeof(part), "0x%lx@-", (unsigned long)(uintptr_t)addr);
            } else {
                snprintf(part, sizeof(part), "0x0@-");
            }
            if (!first) strncat(callers_buf, ",", sizeof(callers_buf)-strlen(callers_buf)-1);
            strncat(callers_buf, part, sizeof(callers_buf)-strlen(callers_buf)-1);
            first = 0;
        }

        fprintf(f, "%p %zu %s\n",
                allocations[i].ptr,
                allocations[i].size,
                callers_buf);

        fprintf(stderr, "Leak: %p (%zu bytes)\n", allocations[i].ptr, allocations[i].size);
    }
    fclose(f);
}

/* Wrappers: ensure we don't record when leak_bt_guard is set */
void* malloc(size_t size) {
    if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");
    void *ptr = real_malloc ? real_malloc(size) : NULL;
    if (!leak_bt_guard) record_allocation(ptr, size, "malloc");
    return ptr;
}

void free(void *ptr) {
    if (!real_free) real_free = dlsym(RTLD_NEXT, "free");
    remove_allocation(ptr);
    if (real_free) real_free(ptr);
}

void* calloc(size_t nmemb, size_t size) {
    if (!real_calloc) real_calloc = dlsym(RTLD_NEXT, "calloc");
    void *ptr = real_calloc ? real_calloc(nmemb, size) : NULL;
    if (!leak_bt_guard) record_allocation(ptr, nmemb * size, "calloc");
    return ptr;
}

void* realloc(void *ptr, size_t size) {
    if (!real_realloc) real_realloc = dlsym(RTLD_NEXT, "realloc");
    remove_allocation(ptr);
    void *new_ptr = real_realloc ? real_realloc(ptr, size) : NULL;
    if (!leak_bt_guard) record_allocation(new_ptr, size, "realloc");
    return new_ptr;
}

char* strdup(const char *s) {
    if (!real_strdup) real_strdup = dlsym(RTLD_NEXT, "strdup");
    char *ptr = real_strdup ? real_strdup(s) : NULL;
    if (!leak_bt_guard) record_allocation(ptr, ptr ? strlen(ptr) + 1 : 0, "strdup");
    return ptr;
}

char* strndup(const char *s, size_t n) {
    if (!real_strndup) real_strndup = dlsym(RTLD_NEXT, "strndup");
    char *ptr = real_strndup ? real_strndup(s, n) : NULL;
    if (!leak_bt_guard) record_allocation(ptr, ptr ? strnlen(s, n) + 1 : 0, "strndup");
    return ptr;
}

int close(int fd) {
    if (!real_close) real_close = dlsym(RTLD_NEXT, "close");
    return real_close ? real_close(fd) : -1;
}

FILE* fopen(const char *pathname, const char *mode) {
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    FILE *file = real_fopen ? real_fopen(pathname, mode) : NULL;
    if (!leak_bt_guard) record_allocation(file, 0, "fopen");
    return file;
}

int fclose(FILE *stream) {
    if (!real_fclose) real_fclose = dlsym(RTLD_NEXT, "fclose");
    remove_allocation(stream);
    return real_fclose ? real_fclose(stream) : EOF;
}

void* aligned_alloc(size_t alignment, size_t size) {
    static void* (*real_aligned_alloc)(size_t, size_t) = NULL;
    if (!real_aligned_alloc) real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
    void *ptr = real_aligned_alloc ? real_aligned_alloc(alignment, size) : NULL;
    if (!leak_bt_guard) record_allocation(ptr, size, "aligned_alloc");
    return ptr;
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
    static int (*real_posix_memalign)(void**, size_t, size_t) = NULL;
    if (!real_posix_memalign) real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
    int result = real_posix_memalign ? real_posix_memalign(memptr, alignment, size) : ENOMEM;
    if (result == 0) {
        if (!leak_bt_guard) record_allocation(*memptr, size, "posix_memalign");
    }
    return result;
}