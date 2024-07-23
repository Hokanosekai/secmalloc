#define _GNU_SOURCE

/**
 * @file my_secmalloc.c
 * @author Hokanosekai
 * 
 * @brief Implementation for my_secmalloc
 * 
 * This file contains all the logics for the private and public functions 
 * of the library.
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <signal.h>
#include <alloca.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <sys/mman.h>

// Include the private header file
#include "my_secmalloc.private.h"

static void    *data_pool = NULL;
static block_t *meta_pool = NULL;

static int i_is_env_initialized = 0;

size_t sz_META_POOL_MAX_ENTRIES;
size_t sz_DATA_POOL_PAGES;
size_t sz_DEBUG_PAGE_SIZE;
const char *s_OUTPUT;
size_t sz_PAGE_SIZE;
int i_DEBUG_LEVEL;

// Environment functions

const char *getenv_or_s(const char *name, const char *def)
{
    const char *value = getenv(name);
    return value ? value : def;
}

int getenv_or_i(const char *name, int def)
{
    const char *value = getenv(name);
    return value ? atoi(value) : def;
}

void init_env(void)
{
    // If the environment variables are already initialized, return
    if (i_is_env_initialized) {
        return;
    }

    i_is_env_initialized = 1;

    s_OUTPUT = getenv_or_s(ENV_OUTPUT, DEFAULT_OUTPUT);
    sz_DATA_POOL_PAGES = getenv_or_i(ENV_DATA_POOL_PAGES, DEFAULT_DATA_POOL_PAGES);
    sz_META_POOL_MAX_ENTRIES = getenv_or_i(ENV_META_POOL_MAX_ENTRIES, DEFAULT_META_POOL_MAX_ENTRIES);
    sz_DEBUG_PAGE_SIZE = getenv_or_i(ENV_DEBUG_PAGE_SIZE, DEFAULT_DEBUG_PAGE_SIZE);
    sz_PAGE_SIZE = getenv_or_i(ENV_PAGE_SIZE, DEFAULT_PAGE_SIZE);
    i_DEBUG_LEVEL = getenv_or_i(ENV_DEBUG, DEFAULT_DEBUG);

    debug_env();
}

// Outputs functions

void write_report(char *msg)
{
    if (!s_OUTPUT) {
        return;
    }

    int fd = open(s_OUTPUT, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    if (write(fd, msg, strlen(msg)) == -1) {
        perror("write");
        exit(EXIT_FAILURE);
    }

    close(fd);
}

const char *get_log_prefix(log_level_t level)
{
    switch (level) {
        case INF:
            return "INFO: ";
        case DBG:
            return "DEBUG: ";
        case ERR:
            return "ERROR: ";
        default:
            return "NONE: ";
    }
}

void msm_log(log_level_t level, const char *format, ...)
{
    if (level == DBG && i_DEBUG_LEVEL <= 0) {
        return;
    }

    va_list args;

    va_start(args, format);
    int size = vsnprintf(NULL, 0, format, args) + 1;
    va_end(args);

    if (size < 0) {
        perror("vsnprintf");
        exit(EXIT_FAILURE);
    }

    // Allocate memory on the stack
    char *buffer = (char *)alloca(size);
    if (!buffer) {
        perror("alloca");
        exit(EXIT_FAILURE);
    }

    va_start(args, format);
    vsnprintf(buffer, size, format, args);
    va_end(args);

    if (!buffer) {
        perror("vsnprintf");
        exit(EXIT_FAILURE);
    }

    const char *prefix = get_log_prefix(level);

    size_t prefix_len = strlen(prefix);
    size_t buffer_len = strlen(buffer);
    size_t total_len = prefix_len + buffer_len + 2;

    char *msg = (char *)alloca(total_len);
    if (!msg) {
        perror("alloca");
        exit(EXIT_FAILURE);
    }

    memcpy(msg, prefix, prefix_len);
    memcpy(msg + prefix_len, buffer, buffer_len);
    msg[total_len - 2] = '\n';
    msg[total_len - 1] = '\0';

    write_report(msg);

    // cleanup
    memset(buffer, 0, strlen(buffer));
    memset(msg, 0, strlen(msg));
}

// Debug functions

void debug_env(void)
{
    msm_log(DBG, "=============DEBUG ENV============");
    msm_log(DBG, "Meta pool max entries: %ld", sz_META_POOL_MAX_ENTRIES);
    msm_log(DBG, "Data pool pages: %ld", sz_DATA_POOL_PAGES);
    msm_log(DBG, "Debug page size: %ld", sz_DEBUG_PAGE_SIZE);
    msm_log(DBG, "Debug level: %d", i_DEBUG_LEVEL);
    msm_log(DBG, "Output file: %s", s_OUTPUT);
    msm_log(DBG, "Page size: %ld", sz_PAGE_SIZE);
    msm_log(DBG, "==================================");
    msm_log(DBG, "");
}

void debug_data_pool(void)
{
    msm_log(DBG, "data pool: %p: %ld b, %ld pages", data_pool, sz_PAGE_SIZE, sz_DATA_POOL_PAGES);

    if (i_DEBUG_LEVEL > 1) {
        msm_log(DBG, "    max  size: %ld b", get_data_pool_max_size());
        msm_log(DBG, "    used size: %ld b", get_data_pool_used_size());
        msm_log(DBG, "    free size: %ld b", get_data_pool_free_size());
    }
}

void debug_meta_pool()
{
    msm_log(DBG, "meta pool: %p: %ld b, %ld entries", meta_pool, sizeof(block_t), sz_META_POOL_MAX_ENTRIES);

    if (i_DEBUG_LEVEL > DEBUG_BASIC) {
        msm_log(DBG, "    max  size: %ld b", get_meta_pool_max_size());
        msm_log(DBG, "    used size: %ld b", get_meta_pool_used_size());
        msm_log(DBG, "    free size: %ld b", get_meta_pool_free_size());
        msm_log(DBG, "    block count: %ld", get_meta_pool_used_size() / sizeof(block_t));
    }

    if (i_DEBUG_LEVEL > DEBUG_ADVANCED) {
        msm_log(DBG, "    blocks:");
        block_t *current = get_first_block();

        while (current) {
            char *state = current->state == FREE ? "FREE" : current->state == BUSY ? "BUSY" : "NONE";

            msm_log(DBG, "        block %p (%p +%ld): %ld b, %s", current, data_pool, current->offset, current->size, state);
            msm_log(DBG, "            next: %p, prev: %p", current->next, get_block_prev(current));
            current = current->next;
        }
    }
}

void debug_block(block_t *block)
{
    if (!block) {
        msm_log(DBG, "block: (nil)");
        return;
    }

    char *state = block->state == FREE ? "FREE" : block->state == BUSY ? "BUSY" : "NONE";

    msm_log(DBG, "block: %p (%p +%ld) %ld b, %s", block, data_pool, block->offset, block->size, state);

    if (i_DEBUG_LEVEL > DEBUG_BASIC) {
        size_t canary_offset = block->offset + block->size;
        uint8_t *canary_ptr = (uint8_t *)((void *)data_pool + canary_offset);

        msm_log(DBG, "    next: %p, prev: %p", block->next, get_block_prev(block));
        msm_log(DBG, "    canary: %02x %d (%p)", block->canary, block->canary, canary_ptr);
    }

    if (i_DEBUG_LEVEL > DEBUG_ADVANCED) {
        debug_data_pool_block(block);
    }
}

void debug_data_pool_block(block_t *block)
{
    size_t page_start = 0;
    size_t page_end = (block->size / sz_DEBUG_PAGE_SIZE) + 2;

    msm_log(DBG, "    data (%ld sp, %ld ep):", page_start, page_end);

    for (size_t i = page_start; i < page_end; i++) {
        char buffer[1024];

        memset(buffer, 0, sizeof(buffer));

        size_t debug_page_offset = i * sz_DEBUG_PAGE_SIZE;
        char *data_ptr = (char *)((char *)get_block_data_ptr(block) + debug_page_offset);

        for (size_t j = 0; j < sz_DEBUG_PAGE_SIZE; j++) {
            snprintf(buffer + (j * 3), 4, "%02x ", *(uint8_t *)(data_ptr + j));
        }

        msm_log(DBG, "         %p: %s", data_ptr, buffer);
    }
}

// Data pool functions

int init_data_pool()
{
    msm_log(DBG, "Initializing data pool with %ld pages", sz_DATA_POOL_PAGES);

    // Possible data pool address
    void* p_possible_address = (void *)(meta_pool + get_meta_pool_max_size());

    // Allocate memory for the data pool
    data_pool = mmap(p_possible_address, get_data_pool_max_size(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    debug_data_pool();

    return data_pool != MAP_FAILED;
}

int expand_data_pool(size_t asked_pages)
{
    msm_log(DBG, "=========EXPAND DATA POOL=========");

    debug_data_pool();

    msm_log(DBG, "Expanding data pool to %ld pages", asked_pages);

    // Calculate the new data pool size
    size_t sz_new_data_pool_size = sz_PAGE_SIZE * asked_pages;

    // Allocate memory for the new data pool
    void *new_data_pool = mremap(data_pool, get_data_pool_max_size(), sz_new_data_pool_size, MREMAP_MAYMOVE);

    // Check if the new data pool is valid
    if (new_data_pool == MAP_FAILED) {
        perror("mremap");
        return 0;
    }

    // Check if the data pool moved to a new address
    if (new_data_pool != data_pool) {
        msm_log(DBG, "Data pool moved to new address: %p -> %p", data_pool, new_data_pool);
        perror("mremap");
        return 0;
    }

    // Assign the new data pool and update the data pool pages
    data_pool = new_data_pool;
    sz_DATA_POOL_PAGES = asked_pages;

    debug_data_pool();

    msm_log(DBG, "Data pool expanded successfully");
    msm_log(DBG, "==================================");

    return 1;
}

/*
int _shrink_data_pool(size_t size)
{
    log(DBG, "Shrinking data pool to %ld bytes", size);

    size_t page_size = get_page_size();

    // Allocate memory for the new data pool
    void *new_data_pool = mremap(data_pool, page_size * data_pool_pages, size, MREMAP_MAYMOVE);

    if (new_data_pool == MAP_FAILED) {
        perror("mremap");
        return 0;
    }

    if (new_data_pool != data_pool) {
        log(DBG, "Data pool moved to new address: %p", new_data_pool);
        return 0;
    }

    data_pool = new_data_pool;
    log(DBG, "Data pool shrunk successfully");

    return 1;
}
*/

void check_data_pool_size(size_t size)
{
    size_t data_pool_size = get_data_pool_max_size();
    size_t required_size = get_data_pool_used_size() + (size + 1);

    msm_log(DBG, "Required size: %ld, Data pool size: %ld", required_size, data_pool_size);

    // Check if the data pool is large enough to hold the requested size
    if (required_size < data_pool_size) {
        msm_log(DBG, "No need to expand data pool");
        return;
    }

    msm_log(DBG, "Expanding data pool");

    // Calculate the new amount of pages required
    size_t new_required_pages = (required_size / sz_PAGE_SIZE) + 1;

    msm_log(DBG, "New pages required: %ld", new_required_pages);

    if (!expand_data_pool(new_required_pages)) {
        msm_log(ERR, "Failed to expand data pool");
        exit(EXIT_FAILURE);
    }
}

size_t get_data_pool_max_size()
{
    return sz_PAGE_SIZE * sz_DATA_POOL_PAGES;
}

size_t get_data_pool_used_size()
{
    size_t total_size = 0;
    block_t *current = meta_pool;


    while (current) {
        total_size += current->size + 1;
        current = current->next;
    }

    return total_size == 0 ? 0 : total_size - 1; // -1 to remove the last canary
}

size_t get_data_pool_free_size()
{
    return get_data_pool_max_size() - get_data_pool_used_size();
}

void *get_data_pool()
{
    return data_pool;
}

// Metadata pool functions

int init_meta_pool()
{
    msm_log(DBG, "Initializing meta pool with %ld entries", sz_META_POOL_MAX_ENTRIES);

    // Allocate memory for the meta pool
    meta_pool = mmap(NULL, get_meta_pool_max_size(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    debug_meta_pool();

    return meta_pool != MAP_FAILED;
}

size_t get_meta_pool_max_size()
{
    return sz_META_POOL_MAX_ENTRIES * sizeof(block_t);
}

size_t get_meta_pool_used_size()
{
    block_t *first = get_first_block();
    block_t *last = get_last_block();
    return (size_t)((char *)last - (char *)first);
}

size_t get_meta_pool_free_size()
{
    return get_meta_pool_max_size() - get_meta_pool_used_size();
}

// Global pool functions

void init_pools(void)
{
    if (data_pool && meta_pool) {
        return;
    }

    msm_log(DBG, "============INIT POOLS============");
    msm_log(DBG, "Initializing memory pools...");

    // Initialize the meta and data pools
    if (!init_meta_pool() || !init_data_pool()) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    msm_log(DBG, "Memory pools initialized successfully");
    msm_log(DBG, "==================================");
    msm_log(DBG, "");
}

// Block functions

block_t *get_block_next(block_t *block)
{
    if (!block->next) {
        return (block_t *)((void *)block + sizeof(block_t));
    }
    return block->next;
}

block_t *get_block_prev(block_t *block)
{
    block_t *prev = NULL;
    block_t *current = meta_pool;

    while (current) {
        if (current == block) {
            return prev;
        }

        prev = current;
        current = current->next;
    }

    return NULL;
}

void *get_block_data_ptr(block_t *block)
{
    return (void *)((char *)data_pool + block->offset);
}

block_t *get_block(void *ptr)
{
    size_t offset = (char *)ptr - (char *)data_pool;
    msm_log(DBG, "Getting block for offset %ld (%p)", offset, ptr);

    block_t *current = get_first_block();

    while (current) {
        if (current->offset == offset) {
            return current;
        }

        current = current->next;
    }

    return NULL;
}

block_t *get_last_block(void)
{
    block_t *current = meta_pool;

    while (current->next) {
        current = current->next;
    }

    return current;
}

block_t *get_first_block(void)
{
    return meta_pool;
}

block_t *get_free_block(size_t size)
{
    msm_log(DBG, "Finding free block for %ld bytes", size);
    block_t *current = meta_pool;

    // Find the first free block that is large enough to hold the requested size
    while (current) {
        // Skip busy blocks
        if (current->state != FREE) {
            current = current->next;
            continue;
        }

        // If the current block is not initialized, return it
        if (current->size == 0) {
            msm_log(DBG, "Not initialized block found: %p", current);
            return current;
        }

        // If the current block size is larger than the requested size, return it
        if (current->size >= size) {
            msm_log(DBG, "Free block found: %p, %ld b, %d", current, current->size, current->state);
            return current;
        }

        current = current->next;
    }

    msm_log(DBG, "Free block found: %p, %ld b, %d", current, current->size, current->state);

    return current;
}

void free_block(block_t *block)
{
    memset(block, 0, sizeof(block_t));
}

void merge_blocks(block_t *block)
{
    msm_log(DBG, "===========MERGE BLOCK============");
    msm_log(DBG, "Merging block %p", block);

    // Find the previous and next blocks
    block_t *prev = get_block_prev(block);
    block_t *next = get_block_next(block);

    char *prev_state = prev ? prev->state == FREE ? "FREE" : "BUSY" : "NONE";
    char *next_state = next ? next->state == FREE ? "FREE" : "BUSY" : "NONE";

    msm_log(DBG, "Searching for block to merge with %p", block);
    msm_log(DBG, "Prev: %p (%s), Next: %p (%s)", prev, prev_state, next, next_state);

    // If the next block is free, merge it with the current block
    if (next && next->state == FREE && next->size > 0) {

        if (next->offset == block->offset + (block->size + 1)) {

            //msm_log(ERR, "Double free detected at %p (%p +%ld) and next %p (%p +%ld)", block, data_pool, block->offset, next, data_pool, next->offset);
            msm_log(ERR, "Contiguous free blocks detected at %p and next %p", (void *)(data_pool + block->offset), (void *)(data_pool + next->offset));
            msm_log(DBG, "Merging block %p with next %p", block, next);

            // Adjust the size of the current block
            block->size += next->size;

            // Set the next block of the current block to the next block of the next block
            block->next = next->next;

            // Free the next block (merged one)
            free_block(next);
        } else {
            msm_log(DBG, "Next %p isn't contiguous of %p", next, block);
        }
    } else {
        msm_log(DBG, "No next block to merge with %p", block);
    }

    // If the previous block is free, merge it with the current block
    if (prev && prev->state == FREE) {

        if (prev->offset + (prev->size + 1) == block->offset) {

        msm_log(ERR, "Contiguous free blocks detected at %p and previous %p", (void *)(data_pool + block->offset), (void *)(data_pool + prev->offset));
        msm_log(DBG, "Merging block %p with previous %p", block, prev);

        // Adjust the size of the previous block
        prev->size += block->size;

        // Set the next block of the previous block to the next block of the current block
        prev->next = block->next;

        // Free the current block (merged one)
        free_block(block);
        } else {
            msm_log(DBG, "Prev %p isn't contiguous of %p", prev, block);
        }
    } else {
        msm_log(DBG, "No previous block to merge with %p", block);
    }

    msm_log(DBG, "Block %p merged", block);
    msm_log(DBG, "==================================");
}

block_t *split_block(block_t *block, size_t size)
{
    msm_log(DBG, "===========SPLIT BLOCK============");

    // We need to split the block into two blocks, one for the requested size
    // and the other for the remaining size, so we need to allocate a new block
    block_t *new = get_last_block();
    if (!new) {
        msm_log(ERR, "Failed to allocate memory for new block");
        msm_log(DBG, "==================================");
        return NULL;
    }

    // Initialize the new block
    new->size = block->size - size;
    new->state = FREE;
    new->next = get_block_next(new);
    new->offset = block->offset + (size + 1);
    new->canary = generate_canary();

    debug_block(new);
    debug_block(block);

    // Update the current one, by setting the new size and by generating a 
    // new canary value
    block->size = size;
    block->canary = generate_canary();

    // If the new block has a previous block, set the next block of the previous block
    block_t *prev = get_block_prev(new);
    prev->next = new;

    msm_log(DBG, "Block %p split into %p and %p", block, block, new);
    msm_log(DBG, "==================================");

    return block;
}

// Canary functions

uint8_t generate_canary()
{
    // Open /dev/urandom to generate a random canary value
    int i_fd = open("/dev/urandom", O_RDONLY);
    if (i_fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // Generate a random offset to read a random byte from /dev/urandom
    int i_random_offset = rand() % (sz_PAGE_SIZE - 1);

    // Seek to a random offset from the end of the file
    if (lseek(i_fd, -i_random_offset, SEEK_END) == -1) {
        perror("lseek");
        exit(EXIT_FAILURE);
    }

    // Read a random byte from /dev/urandom
    uint8_t ui8_canary;
    if (read(i_fd, &ui8_canary, sizeof(uint8_t)) == -1) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    close(i_fd);

    return ui8_canary;
}

void set_canary(block_t *block)
{
    size_t canary_offset = block->offset + block->size;
    uint8_t *canary_ptr = (uint8_t *)((void *)data_pool + canary_offset);

    msm_log(DBG, "Setting canary %d -> (%p)", block->canary, canary_ptr);

    *canary_ptr = block->canary;

    debug_block(block);
}

int check_canary(block_t *block)
{
    size_t canary_offset = block->offset + block->size;
    uint8_t *canary_ptr = (uint8_t *)((void *)data_pool + canary_offset);

    msm_log(DBG, "Checking canary (%p) %d == %d", canary_ptr, *canary_ptr, block->canary);

    if (*canary_ptr != block->canary) {
        msm_log(ERR, "canary error %d != %d at %p", *canary_ptr, block->canary, canary_ptr);
        return 0;
    }

    return 1;
}

// Exit functions

void detect_memory_leaks(void) {
    msm_log(DBG, "==============EXIT===============");
    msm_log(DBG, "Detecting memory leaks...");

    size_t total_size = 0;
    size_t total_blocks = 0;

    block_t *current = get_first_block();

    while (current) {
        if (current->state == BUSY) {
            msm_log(ERR, "Memory leak detected at %p (%p +%ld) of %ld bytes", current, data_pool, current->offset, current->size);

            total_size += current->size;
            total_blocks++;
        }

        current = current->next;
    }

    msm_log(INF, "Memory leaks detected: %ld blocks, %ld bytes", total_blocks, total_size);
    msm_log(DBG, "==================================");
}

__attribute__((constructor)) void init() {
    atexit(detect_memory_leaks);
}

// Memory functions

size_t            next_hexa_base(size_t size)
{
    return (size % 16 ? size + 16 - (size % 16) : size);
}

void *my_malloc(size_t size)
{
    size = next_hexa_base(size);
    // Initialize the environment variables
    init_env();

    // Initialize the memory pools
    init_pools();

    msm_log(DBG, "==============MALLOC==============");


    if (i_DEBUG_LEVEL > DEBUG_ADVANCED) {
        debug_meta_pool();
        debug_data_pool();
    }

    // check for invalid size
    if (size <= 0) {
        msm_log(ERR, "Invalid size: %ld", size);
        msm_log(DBG, "==================================");
        msm_log(DBG, "");
        return NULL;
    }

    msm_log(DBG, "Allocating memory for %ld bytes", size);

    // Check if the data pool is large enough to hold the requested size
    check_data_pool_size(size);

    // Find a free block that is large enough to hold the requested size
    block_t *block = get_free_block(size);

    debug_block(block);

    // If the free block size is larger than the requested size, split the block
    if (block->size > size) {
        msm_log(DBG, "Block %p is larger than the requested size, splitting block", block);
        split_block(block, size);

    // If the free block found is the last block, initialize it
    } else if (block->size == 0) {
        // Initialize the block
        block->size = size;
        block->canary = generate_canary();
        block->next = get_block_next(block);
        block->offset = get_data_pool_used_size() - (size + 1);

        // Some test about a block checksum, to validate the integrity of the
        // metadata pool blocks.
        //int i_checksum = (size_t)meta_pool ^ block->size ^ block->offset ^ block->canary ^ (size_t)block->next;
        //msm_log(DBG, "checksum: %d", i_checksum);

    // If the free block size is equal to the requested size, no need to split the block
    } else {
        msm_log(DBG, "Block %p is already the right size", block);
    }

    // Update the block state
    block->state = BUSY;

    // Set the canary value at the end of the allocated block
    set_canary(block);

    char *data_ptr = get_block_data_ptr(block);

    msm_log(INF, "Operation: malloc, Size: %ld, Address: %p", size, data_ptr);

    msm_log(DBG, "==================================");
    msm_log(DBG, "");
    return (void *)data_ptr;
}

void my_free(void *ptr)
{
    msm_log(DBG, "===============FREE===============");

    if (i_DEBUG_LEVEL > DEBUG_ADVANCED) {
        debug_meta_pool();
        debug_data_pool();
    }

    // If the pointer is NULL, return
    if (!ptr) {
        msm_log(ERR, "Invalid pointer: %p", ptr);
        msm_log(DBG, "==================================");
        msm_log(DBG, "");
        return;
    }

    msm_log(DBG, "Freeing memory at address %p", ptr);

    // Find the block associated with the pointer
    block_t *block = get_block(ptr);

    // If the block is NULL, return
    if (!block) {
        msm_log(ERR, "Invalid pointer passed to free: %p", ptr);
        msm_log(DBG, "==================================");
        msm_log(DBG, "");
        return;
    }

    // If the block is already free, return
    // This is a double free detection
    if (block->state == FREE) {
        msm_log(ERR, "Double free detected at %p", ptr);
        msm_log(ERR, "Aborting...");
        msm_log(DBG, "==================================");
        msm_log(DBG, "");

        // send SIGABRT signal to the process
        //raise(SIGABRT);

        return;
    }

    debug_block(block);

    // Check if the canary value is correct, if not, return
    // This condition prevents from heap overflow
    if (!check_canary(block)) {
        msm_log(ERR, "Heap overflow detected at address %p", ptr);
        msm_log(DBG, "Canary value mismatch detected at address %p", ptr);
        //raise(SIGABRT);
    }

    msm_log(INF, "Operation: free, Size: %ld, Address: %p", block->size, ptr);

    // Set the block state to free
    block->state = FREE;

    // See if we can merge the block with the previous and next blocks
    merge_blocks(block);

    /*size_t page_size = get_page_size();

    // Check if the data pool needs to be shrunk
    //size_t data_pool_size = _get_data_pool_size();
    size_t data_pool_free_space = _get_data_pool_free_space();

    if (data_pool_free_space == page_size && data_pool_pages > 1) {
        if (!_shrink_data_pool(page_size)) {
            _log(ERR, "Failed to shrink data pool");
        }
    }

    // Check if the meta pool needs to be shrunk
    //size_t meta_pool_size = _get_meta_pool_size();
    size_t meta_pool_free_space = _get_meta_pool_free_space();

    if (meta_pool_free_space == page_size && meta_pool_pages > 1) {
        if (!_shrink_meta_pool(page_size)) {
            _log(ERR, "Failed to shrink meta pool");
        }
    }*/

    msm_log(DBG, "==================================");
    msm_log(DBG, "");
}

void *my_calloc(size_t nmemb, size_t size)
{
    msm_log(DBG, "==============CALLOC==============");

    // Calculate the total size to allocate
    size_t total_size = nmemb * size;

    msm_log(DBG, "Allocating memory for %ld elements of size %ld", nmemb, size);

    if (i_DEBUG_LEVEL > DEBUG_ADVANCED) {
        debug_meta_pool();
        debug_data_pool();
    }

    // Allocate memory for the total size
    void *ptr = my_malloc(total_size);

    // Initialize the allocated memory to 0
    if (ptr != NULL) {
        memset(ptr, 0, total_size);
    }

    msm_log(INF, "Operation: calloc, Size: %ld, Address: %p", total_size, ptr);
    msm_log(DBG, "==================================");
    msm_log(DBG, "");

    return ptr;
}

void *my_realloc(void *ptr, size_t size)
{
    msm_log(DBG, "=============REALLOC==============");

    if (i_DEBUG_LEVEL > DEBUG_ADVANCED) {
        debug_meta_pool();
        debug_data_pool();
    }

    msm_log(DBG, "Reallocating memory for %ld bytes at %p", size, ptr);

    // If the pointer is NULL, equivalent to malloc(size)
    if (!ptr) {
        msm_log(DBG, "ptr is NULL, equivalent to malloc(%ld)", size);
        msm_log(DBG, "==================================");
        msm_log(DBG, "");
        return my_malloc(size);
    }

    // If the size is 0, equivalent to free(ptr)
    if (size == 0) {
        msm_log(DBG, "size is 0, equivalent to free(%p)", ptr);
        msm_log(DBG, "==================================");
        msm_log(DBG, "");
        my_free(ptr);
        return NULL;
    }

    // Find the block associated with the pointer
    block_t *block = get_block(ptr);

    debug_block(block);

    // If the block is NULL, return
    if (!block) {
        msm_log(ERR, "Invalid pointer passed to realloc: %p", ptr);
        msm_log(DBG, "==================================");
        msm_log(DBG, "");
        return NULL;
    }

    // Check if the canary value is correct, if not, return
    // This condition prevents from heap overflow
    if (!check_canary(block)) {
        msm_log(ERR, "Canary value mismatch detected at address %p", ptr);
        msm_log(DBG, "==================================");
        msm_log(DBG, "");
        return NULL;
    }

    msm_log(DBG, "Reallocating memory at address %p to %ld bytes", ptr, size);

    size_t old_size = block->size;

    // If the new size is smaller than the current size, split the block
    if (size < block->size) {
        msm_log(DBG, "New size is smaller than the current size, splitting block");
        split_block(block, size);

    // If the new size is equal to the current size, no need to reallocate
    } else if (size == block->size) {
        msm_log(DBG, "New size is equal to the current size, no need to reallocate");
        block->size = size;

    // If the new size is larger than the current size, merge the block
    } else {
        msm_log(DBG, "New size is larger than the current size, merging block");

        // We allocate a new block with the requested size
        void *new_ptr = my_malloc(size);

        // Set the block state to free
        block->state = FREE;

        debug_block(get_block(new_ptr));

        // copy the data from the old block to the new block
        msm_log(DBG, "Copying data from %p to %p", ptr, new_ptr);
        memcpy(new_ptr, ptr, old_size);

        msm_log(INF, "Operation: realloc, Size: %ld, Address: %p", size, new_ptr);
        msm_log(DBG, "==================================");
        msm_log(DBG, "");

        return new_ptr;
    }

    // Set the canary value at the end of the allocated block
    set_canary(block);

    debug_block(block);

    void *new_ptr = get_block_data_ptr(block);

    msm_log(INF, "Operation: realloc, Size: %ld, Address: %p", size, new_ptr);

    msm_log(DBG, "==================================");
    msm_log(DBG, "");

    return new_ptr;
}

// If the DYNAMIC macro is defined, we want to override the default malloc functions with our custom functions.
#ifdef DYNAMIC

void *malloc(size_t size)
{
    return my_malloc(size);
}

void free(void *ptr)
{
    my_free(ptr);
}

void *calloc(size_t nmemb, size_t size)
{
    return my_calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size)
{
    return my_realloc(ptr, size);
}

#endif
