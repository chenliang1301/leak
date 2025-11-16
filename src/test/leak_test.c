// leak_test.c - 内存泄漏测试程序（包含对齐分配测试）
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <malloc.h>  // 为posix_memalign

// 测试函数声明
void test_malloc_leak();
void test_calloc_leak(); 
void test_realloc_leak();
void test_strdup_leak();
void test_mixed_leak();
void test_file_leak();
void test_no_leak();
void test_edge_cases();
void test_aligned_alloc_leak();
void test_posix_memalign_leak();
void complex_nested_leak();

int main() {
    printf("=== 开始内存泄漏测试 ===\n");
    
    test_malloc_leak();           // 测试malloc泄漏
    test_calloc_leak();           // 测试calloc泄漏
    test_realloc_leak();          // 测试realloc泄漏
    test_strdup_leak();           // 测试strdup泄漏
    test_mixed_leak();            // 测试混合泄漏
    test_file_leak();             // 测试文件泄漏
    test_no_leak();               // 测试无泄漏情况
    test_edge_cases();            // 测试边界情况
    test_aligned_alloc_leak();    // 测试aligned_alloc泄漏
    test_posix_memalign_leak();   // 测试posix_memalign泄漏
    
    printf("=== 测试完成，请检查leak_analysis.txt ===\n");
    return 0;
}

// 测试malloc泄漏
void test_malloc_leak() {
    printf("测试malloc泄漏...\n");
    
    // 泄漏的内存
    void *leak1 = malloc(100);
    void *leak2 = malloc(256);
    void *leak3 = malloc(512);
    
    // 正常释放的内存
    void *normal = malloc(64);
    free(normal);
    
    // 故意不释放leak1, leak2, leak3
    (void)leak1; (void)leak2; (void)leak3;
}

// 测试calloc泄漏
void test_calloc_leak() {
    printf("测试calloc泄漏...\n");
    
    // 泄漏的calloc分配
    int *array_leak = calloc(50, sizeof(int));
    char *str_leak = calloc(100, sizeof(char));
    
    // 正常使用的calloc
    int *array_ok = calloc(10, sizeof(int));
    array_ok[0] = 42;
    free(array_ok);
    
    (void)array_leak; (void)str_leak;
}

// 测试realloc泄漏
void test_realloc_leak() {
    printf("测试realloc泄漏...\n");
    
    // 初始分配
    int *ptr = malloc(10 * sizeof(int));
    
    // 重新分配 - 这会泄漏原来的内存
    ptr = realloc(ptr, 100 * sizeof(int));
    
    // 再次重新分配 - 再次泄漏
    ptr = realloc(ptr, 200 * sizeof(int));
    
    // 故意不释放
    (void)ptr;
}

// 测试strdup泄漏
void test_strdup_leak() {
    printf("测试strdup泄漏...\n");
    
    char *str1 = strdup("这是一个泄漏的字符串");
    char *str2 = strdup("另一个泄漏的字符串");
    
    // 正常的strdup使用
    char *str3 = strdup("这个会被释放");
    free(str3);
    
    (void)str1; (void)str2;
}

// 测试混合泄漏
void test_mixed_leak() {
    printf("测试混合泄漏...\n");
    
    // 混合不同类型的分配
    void *mixed_leaks[] = {
        malloc(128),
        calloc(25, sizeof(double)),
        strdup("混合泄漏测试字符串"),
        malloc(64)
    };
    
    // 只释放其中一个
    free(mixed_leaks[1]);
    
    // 其他的泄漏
    (void)mixed_leaks;
}

// 测试文件泄漏
void test_file_leak() {
    printf("测试文件泄漏...\n");
    
    // 文件描述符泄漏
    int fd_leak = open("/dev/null", O_RDONLY);
    
    // 文件指针泄漏
    FILE *file_leak = fopen("/dev/null", "r");
    
    // 正常的文件操作
    FILE *file_ok = fopen("/dev/null", "r");
    if (file_ok) {
        fclose(file_ok);
    }
    
    (void)fd_leak; (void)file_leak;
}

// 测试无泄漏情况
void test_no_leak() {
    printf("测试无泄漏情况...\n");
    
    // 所有分配都被正确释放
    void *ptr1 = malloc(100);
    void *ptr2 = calloc(50, sizeof(char));
    char *str = strdup("临时字符串");
    int *array = malloc(25 * sizeof(int));
    
    // 正确释放所有内存
    free(ptr1);
    free(ptr2);
    free(str);
    free(array);
    
    // 文件操作也无泄漏
    FILE *file = fopen("/dev/null", "r");
    if (file) {
        fclose(file);
    }
}

// 测试边界情况
void test_edge_cases() {
    printf("测试边界情况...\n");
    
    // 分配0字节
    void *zero_alloc = malloc(0);
    if (zero_alloc) {
        free(zero_alloc); // 应该释放，即使是0字节
    }
    
    // 重复释放检测（这个会在运行时产生错误，但我们不测试这个）
    void *ptr = malloc(100);
    free(ptr);
    // free(ptr); // 这会导致double free，注释掉
    
    // 大内存分配
    void *big_alloc = malloc(1024 * 1024); // 1MB
    (void)big_alloc; // 泄漏这个大内存块
    
    // 很多小分配
    for (int i = 0; i < 10; i++) {
        void *small = malloc(8);
        if (i % 2 == 0) {
            free(small); // 释放一半
        }
        // 另一半泄漏
    }
}

// 测试aligned_alloc泄漏
void test_aligned_alloc_leak() {
    printf("测试aligned_alloc泄漏...\n");
    
    // 对齐分配泄漏
    void *aligned_leak1 = aligned_alloc(16, 256);  // 16字节对齐
    void *aligned_leak2 = aligned_alloc(32, 512);  // 32字节对齐
    void *aligned_leak3 = aligned_alloc(64, 1024); // 64字节对齐
    
    // 正常的对齐分配使用
    void *aligned_ok = aligned_alloc(128, 2048);
    if (aligned_ok) {
        // 使用对齐内存...
        memset(aligned_ok, 0, 2048);
        free(aligned_ok);
    }
    
    // 故意泄漏对齐分配的内存
    (void)aligned_leak1; (void)aligned_leak2; (void)aligned_leak3;
    
    // 测试页面对齐的大内存分配
    void *page_aligned_leak = aligned_alloc(4096, 8192); // 4K页面对齐
    (void)page_aligned_leak;
}

// 测试posix_memalign泄漏
void test_posix_memalign_leak() {
    printf("测试posix_memalign泄漏...\n");
    
    void *memalign_ptr1, *memalign_ptr2, *memalign_ptr3;
    
    // posix_memalign泄漏
    if (posix_memalign(&memalign_ptr1, 16, 256) == 0) {
        // 成功分配，但故意泄漏
    }
    
    if (posix_memalign(&memalign_ptr2, 32, 512) == 0) {
        // 成功分配，但故意泄漏  
    }
    
    if (posix_memalign(&memalign_ptr3, 64, 1024) == 0) {
        // 成功分配，但故意泄漏
    }
    
    // 正常的posix_memalign使用
    void *memalign_ok;
    if (posix_memalign(&memalign_ok, 128, 2048) == 0) {
        // 使用对齐内存...
        memset(memalign_ok, 0, 2048);
        free(memalign_ok);
    }
    
    // 测试复杂的对齐要求
    void *complex_align_leak;
    if (posix_memalign(&complex_align_leak, 256, 4096) == 0) {
        // 泄漏这个复杂对齐的内存
    }
    (void)complex_align_leak;
}

// 额外的复杂测试
void complex_nested_leak() {
    printf("测试嵌套泄漏...\n");
    
    typedef struct {
        int id;
        char *name;
        void *data;
        void *aligned_data;  // 对齐数据
    } leaky_struct_t;
    
    // 结构体内存泄漏
    leaky_struct_t *struct_leak = malloc(sizeof(leaky_struct_t));
    struct_leak->name = strdup("嵌套泄漏结构体");
    struct_leak->data = malloc(256);
    
    // 使用对齐分配为结构体成员
    if (posix_memalign(&struct_leak->aligned_data, 64, 512) == 0) {
        // 对齐数据分配成功，但整个结构体会泄漏
    }
    
    // 整个结构体泄漏（包括内部的name、data和aligned_data）
    (void)struct_leak;
    
    // 测试对齐分配的数组泄漏
    void *aligned_array[5];
    for (int i = 0; i < 5; i++) {
        if (posix_memalign(&aligned_array[i], 32, 128) == 0) {
            // 每个元素都分配成功，但整个数组会泄漏
        }
    }
    (void)aligned_array;
    
    // 混合使用不同对齐分配函数
    void *mixed_align_leaks[] = {
        aligned_alloc(16, 256),
        NULL, // 为posix_memalign预留
        aligned_alloc(64, 1024)
    };
    
    // 使用posix_memalign填充第二个元素
    if (posix_memalign(&mixed_align_leaks[1], 32, 512) == 0) {
        // 成功分配
    }
    
    // 整个混合数组泄漏
    (void)mixed_align_leaks;
}

// 在程序退出前调用复杂测试
void __attribute__((destructor)) final_test() {
    complex_nested_leak();
}