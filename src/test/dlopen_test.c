/* dlopen_test.c
 * Spawn multiple threads that concurrently call dlopen()/dlclose()
 * to validate that library constructors run only once.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

typedef struct {
    const char *libpath;
    int loops;
    int id;
} thr_arg_t;

static void *worker(void *arg) {
    thr_arg_t *a = (thr_arg_t*)arg;
    for (int i = 0; i < a->loops; ++i) {
        void *h = dlopen(a->libpath, RTLD_NOW);
        if (!h) {
            fprintf(stderr, "thread %d: dlopen failed: %s\n", a->id, dlerror());
        } else {
            // Optionally lookup a symbol to exercise the handle
            dlerror();
            void *sym = dlsym(h, "malloc");
            (void)sym;
            dlclose(h);
        }
        // small sleep to increase interleaving
        usleep(1000);
    }
    return NULL;
}

int main(int argc, char **argv) {
    const char *lib = "build/libleak_detector_base.so";
    int threads = 8;
    int loops = 100;
    if (argc > 1) lib = argv[1];
    if (argc > 2) threads = atoi(argv[2]);
    if (argc > 3) loops = atoi(argv[3]);

    pthread_t *t = calloc(threads, sizeof(pthread_t));
    thr_arg_t *args = calloc(threads, sizeof(thr_arg_t));
    if (!t || !args) return 2;

    fprintf(stderr, "dlopen_test: lib=%s threads=%d loops=%d\n", lib, threads, loops);
    for (int i = 0; i < threads; ++i) {
        args[i].libpath = lib;
        args[i].loops = loops;
        args[i].id = i;
        if (pthread_create(&t[i], NULL, worker, &args[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    for (int i = 0; i < threads; ++i) {
        pthread_join(t[i], NULL);
    }

    fprintf(stderr, "dlopen_test: done\n");
    return 0;
}
