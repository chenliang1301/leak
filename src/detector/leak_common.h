/* leak_common.h
 * Small helper for detector constructors to ensure init runs once.
 */
#ifndef LEAK_COMMON_H
#define LEAK_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

/* Function: leak_init_once
 * Ensure the caller-provided callback runs only once per translation unit.
 * If the callback is NULL, the function simply performs the once-only
 * check and returns 1 on the first call, 0 otherwise.
 * Returns: 1 if this invocation performed initialization, 0 if init
 * had already occurred.
 */
static inline int leak_init_once(void (*cb)(void)) {
    static volatile int _leak_init_once = 0;
    if (!__sync_bool_compare_and_swap(&_leak_init_once, 0, 1)) {
        return 0;
    }
    if (cb) cb();
    return 1;
}

/* Backwards-compatible macro: call without a callback */
#define LEAK_INIT_ONCE() leak_init_once(NULL)

#ifdef __cplusplus
}
#endif

#endif /* LEAK_COMMON_H */
