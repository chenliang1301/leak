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

typedef struct {
    void *ptr;
    size_t size;
    void *caller; /* saved return address */
    const char *type; /* allocation type for debugging */
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

void __attribute__((constructor)) init_hooks() {
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_strdup = dlsym(RTLD_NEXT, "strdup");
    real_strndup = dlsym(RTLD_NEXT, "strndup");
    real_close = dlsym(RTLD_NEXT, "close");
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    real_fclose = dlsym(RTLD_NEXT, "fclose");
    fprintf(stderr, "Extended leak detector initialized\n");
}

/* Helper function to record allocation */
static void record_allocation(void *ptr, size_t size, const char *type) {
    if (ptr && alloc_count < MAX_ALLOCS) {
        allocations[alloc_count].ptr = ptr;
        allocations[alloc_count].size = size;
        // 记录内存分配的调用者地址，使用GCC内置函数__builtin_return_address(0)获取当前函数的返回地址
        // 这有助于在检测内存泄漏时追踪是哪个函数发起了内存分配
        // 0表示获取当前函数的返回地址，1表示获取上一级函数的返回地址，以此类推
        allocations[alloc_count].caller = __builtin_return_address(0);
        allocations[alloc_count].type = type;
        alloc_count++;
    }
}

/* Helper function to remove allocation record */
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
    fprintf(stderr, "\n=== Memory Leak Report ===\n");
    fprintf(stderr, "分析文件: %s\n", outname);

    FILE *f = fopen(outname, "w");
    if (f) {
        fprintf(f, "#ptr size caller binary func type\n");
        int leak_count = 0;
        for (int i = 0; i < alloc_count; ++i) {
            if (allocations[i].ptr != NULL) {
                leak_count++;
                const char *bin = "-";
                const char *func = "-";
                Dl_info info;
                if (allocations[i].caller && dladdr(allocations[i].caller, &info) && info.dli_fname) {
                    bin = info.dli_fname;
                    func = info.dli_sname ? info.dli_sname : "-";
                    uintptr_t off = (uintptr_t)allocations[i].caller - (uintptr_t)info.dli_fbase;
                    fprintf(f, "%p %zu 0x%lx %s %s %s\n",
                            allocations[i].ptr,
                            allocations[i].size,
                            (unsigned long)off,
                            bin,
                            func,
                            allocations[i].type ? allocations[i].type : "unknown");
                } else {
                    fprintf(f, "%p %zu %p %s %s %s\n",
                            allocations[i].ptr,
                            allocations[i].size,
                            allocations[i].caller ? allocations[i].caller : (void*)0,
                            bin,
                            func,
                            allocations[i].type ? allocations[i].type : "unknown");
                }
            }
        }
        fclose(f);
        fprintf(stderr, "Total leaks found: %d\n", leak_count);
    } else {
        fprintf(stderr, "Failed to create analysis file: %s\n", strerror(errno));
    }

    /* also print simple report to stderr */
    for (int i = 0; i < alloc_count; ++i) {
        if (allocations[i].ptr != NULL) {
            fprintf(stderr, "Leak: %p (%zu bytes) [caller %p] type: %s\n",
                    allocations[i].ptr, allocations[i].size,
                    allocations[i].caller ? allocations[i].caller : (void*)0,
                    allocations[i].type ? allocations[i].type : "unknown");
        }
    }
}

/* Memory allocation functions */
void* malloc(size_t size) {
    void *ptr = real_malloc ? real_malloc(size) : NULL;
    record_allocation(ptr, size, "malloc");
    return ptr;
}

void free(void *ptr) {
    remove_allocation(ptr);
    if (real_free) real_free(ptr);
}

void* calloc(size_t nmemb, size_t size) {
    void *ptr = real_calloc ? real_calloc(nmemb, size) : NULL;
    record_allocation(ptr, nmemb * size, "calloc");
    return ptr;
}

void* realloc(void *ptr, size_t size) {
    /* Remove old pointer before realloc */
    remove_allocation(ptr);
    
    void *new_ptr = real_realloc ? real_realloc(ptr, size) : NULL;
    record_allocation(new_ptr, size, "realloc");
    return new_ptr;
}

char* strdup(const char *s) {
    char *ptr = real_strdup ? real_strdup(s) : NULL;
    record_allocation(ptr, ptr ? strlen(ptr) + 1 : 0, "strdup");
    return ptr;
}

char* strndup(const char *s, size_t n) {
    char *ptr = real_strndup ? real_strndup(s, n) : NULL;
    record_allocation(ptr, ptr ? strnlen(s, n) + 1 : 0, "strndup");
    return ptr;
}

/* File descriptor functions */
int close(int fd) {
    if (real_close) return real_close(fd);
    return -1;
}

FILE* fopen(const char *pathname, const char *mode) {
    FILE *file = real_fopen ? real_fopen(pathname, mode) : NULL;
    record_allocation(file, 0, "fopen"); // Size 0 for file pointers
    return file;
}

int fclose(FILE *stream) {
    remove_allocation(stream);
    return real_fclose ? real_fclose(stream) : EOF;
}

/* Optional: Add more functions as needed */
void* aligned_alloc(size_t alignment, size_t size) {
    static void* (*real_aligned_alloc)(size_t, size_t) = NULL;
    if (!real_aligned_alloc) {
        real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
    }
    
    void *ptr = real_aligned_alloc ? real_aligned_alloc(alignment, size) : NULL;
    record_allocation(ptr, size, "aligned_alloc");
    return ptr;
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
    static int (*real_posix_memalign)(void**, size_t, size_t) = NULL;
    if (!real_posix_memalign) {
        real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
    }
    
    int result = real_posix_memalign ? real_posix_memalign(memptr, alignment, size) : ENOMEM;
    if (result == 0) {
        record_allocation(*memptr, size, "posix_memalign");
    }
    return result;
}