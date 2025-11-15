
#include <stdio.h>
#include <stdlib.h>

void leak_memory_level5() {
    void *ptr = NULL;
    for (int i = 0; i < 3; i++) {
        ptr = malloc(100);
        printf("Allocated memory at (level5): %p\n", ptr);
    }
    if (ptr)
    {
        free(ptr);
        printf("Freed memory at (level5): %p\n", ptr);
    }
    
}

void leak_memory_level4() {
    leak_memory_level5();
}

void leak_memory_level3() {
    leak_memory_level4();
}

void leak_memory_level2() {
    leak_memory_level3();
}

void leak_memory_level1() {
    leak_memory_level2();
}

void leak_memory() {
    leak_memory_level1();
}

int main() 
{        
    leak_memory();
    return 0;
}