#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <limine.h>
#include <lib/libc.k.h>
#include <lib/lock.k.h>
#include <lib/misc.k.h>
#include <mm/pmm.k.h>
#include <mm/slab.k.h>
#include <mm/vmm.k.h>

struct slab_entry {
    struct slab_entry *next;
};

struct slab {
    spinlock_t lock;
    size_t ent_size;
    struct slab_entry *first_free;
};

struct slab_header {
    struct slab *slab;
};

struct alloc_metadata {
    size_t pages;
    size_t size;
};

static struct slab slabs[8];

static inline struct slab *slab_for(size_t size) {
    for (size_t i = 0; i < SIZEOF_ARRAY(slabs); i++) {
        struct slab *slab = &slabs[i];
        if (slab->ent_size >= size) {
            return slab;
        }
    }
    return NULL;
}

static bool create_slab(struct slab *slab, size_t ent_size) {
    slab->lock = (spinlock_t)SPINLOCK_INIT;
    slab->ent_size = ent_size;
    slab->first_free = NULL;

    size_t header_offset = ALIGN_UP(sizeof(struct slab_header), ent_size);
    size_t available_size = PAGE_SIZE - header_offset;

    void *slab_phys = pmm_alloc_nozero(1);
    if (!slab_phys) {
        return false;
    }

    struct slab_header *slab_ptr = (struct slab_header *)(slab_phys + VMM_HIGHER_HALF);
    slab_ptr->slab = slab;

    void *entries = slab_phys + header_offset + VMM_HIGHER_HALF;
    for (size_t i = 0; i < available_size / ent_size; i++) {
        struct slab_entry *entry = (struct slab_entry *)(entries + ent_size * i);
        entry->next = slab->first_free;
        slab->first_free = entry;
    }

    return true;
}

static void *alloc_from_slab(struct slab *slab) {
    spinlock_acquire(&slab->lock);

    void *result = NULL;
    
allocate:
    if (slab->first_free != NULL) {
        struct slab_entry *entry = slab->first_free;
        slab->first_free = entry->next;
        result = entry;
    } else if (create_slab(slab, slab->ent_size)) {
        goto allocate;
    }

    if (result) {
        memset(result, 0, slab->ent_size);
    }

    spinlock_release(&slab->lock);
    return result;
}

static void free_in_slab(struct slab *slab, void *addr) {
    spinlock_acquire(&slab->lock);

    if (addr) {
        struct slab_entry *entry = addr;
        entry->next = slab->first_free;
        slab->first_free = entry;
    }

    spinlock_release(&slab->lock);
}

void slab_init(void) {
    for (size_t i = 0; i < SIZEOF_ARRAY(slabs); i++) {
        // Creates slabs for all power-of-2 block sizes between 8 and 1024
        create_slab(&slabs[i], 1 << (i + 3));
    }
}

void *slab_alloc(size_t size) {
    struct slab *slab = slab_for(size);
    if (slab != NULL) {
        return alloc_from_slab(slab);
    }

    size_t page_count = DIV_ROUNDUP(size, PAGE_SIZE);
    void *ret = pmm_alloc(page_count + 1);
    if (ret == NULL) {
        return NULL;
    }

    ret += VMM_HIGHER_HALF;
    struct alloc_metadata *metadata = (struct alloc_metadata *)ret;

    metadata->pages = page_count;
    metadata->size = size;

    return ret + PAGE_SIZE;
}

void *slab_realloc(void *addr, size_t new_size) {
    if (addr == NULL) {
        return slab_alloc(new_size);
    }

    if (((uintptr_t)addr & 0xfff) == 0) {
        struct alloc_metadata *metadata = (struct alloc_metadata *)(addr - PAGE_SIZE);
        if (DIV_ROUNDUP(metadata->size, PAGE_SIZE) == DIV_ROUNDUP(new_size, PAGE_SIZE)) {
            metadata->size = new_size;
            return addr;
        }

        void *new_addr = slab_alloc(new_size);
        if (new_addr == NULL) {
            return NULL;
        }

        if (metadata->size > new_size) {
            memcpy(new_addr, addr, new_size);
        } else {
            memcpy(new_addr, addr, metadata->size);
        }

        slab_free(addr);
        return new_addr;
    }

    struct slab_header *slab_header = (struct slab_header *)((uintptr_t)addr & ~0xffful);
    struct slab *slab = slab_header->slab;

    if (new_size > slab->ent_size) {
        void *new_addr = slab_alloc(new_size);
        if (new_addr == NULL) {
            return NULL;
        }

        memcpy(new_addr, addr, slab->ent_size);
        free_in_slab(slab, addr);
        return new_addr;
    }

    return addr;
}

void slab_free(void *addr) {
    if (addr == NULL) {
        return;
    }

    if (((uintptr_t)addr & 0xfff) == 0) {
        struct alloc_metadata *metadata = (struct alloc_metadata *)(addr - PAGE_SIZE);
        pmm_free((void *)metadata - VMM_HIGHER_HALF, metadata->pages + 1);
        return;
    }

    struct slab_header *slab_header = (struct slab_header *)((uintptr_t)addr & ~0xffful);
    free_in_slab(slab_header->slab, addr);
}
