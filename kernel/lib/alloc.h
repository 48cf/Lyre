#ifndef _LIB__ALLOC_H
#define _LIB__ALLOC_H

#include <stddef.h>
#include <mm/slab.h>

static inline void *alloc(size_t size) {
    return slab_alloc(size);
}

static inline void *realloc(void *addr, size_t size) {
    return slab_realloc(addr, size);
}

static inline void free(void *addr) {
    slab_free(addr);
}

#endif