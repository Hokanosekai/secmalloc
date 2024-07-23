#include <criterion/criterion.h>
#include <stdio.h>
#include "my_secmalloc.private.h"
#include <sys/mman.h>

// Default test
Test(mmap, default) {
    void *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    cr_assert(ptr != NULL);
    int res = munmap(ptr, 4096);
    cr_assert(res == 0);
}

void setup_env(void) {
    setenv("MSM_OUTPUT", "", 1);
    setenv("MSM_DEBUG", "0", 1);
    setenv("MSM_META_POOL_MAX_ENTRIES", "100000", 1);
    setenv("MSM_DATA_POOL_PAGES", "2", 1);
    setenv("MSM_PAGE_SIZE", "4096", 1);
    setenv("MSM_DEBUG_PAGE_SIZE", "16", 1);
}

/// Environment

/**
 * Test for getenv_or_s function
 */
Test(my_secmalloc, test_getenv_or_s) {
    setenv("TEST_ENV_VAR", "test_value", 1);
    cr_assert_str_eq(getenv_or_s("TEST_ENV_VAR", "default_value"), "test_value");
    cr_assert_str_eq(getenv_or_s("NON_EXISTENT_ENV_VAR", "default_value"), "default_value");
}

/**
 * Test for getenv_or_i function
 */
Test(my_secmalloc, test_getenv_or_i) {
    setenv("TEST_ENV_VAR", "10", 1);
    cr_assert_eq(getenv_or_i("TEST_ENV_VAR", 5), 10);
    cr_assert_eq(getenv_or_i("NON_EXISTENT_ENV_VAR", 5), 5);
}

/**
 * Test default environment variables
 * 
 * - Check the output file
 * - Check the debug level
 * - Check the Meta pool max entries
 * - Check the Data pool pages count
 * - Check the page size
 * - Check the debug page size
 * 
 * @note This test can fail if the environment variables are set
 */
Test(my_secmalloc, test_init_env_default) {
    init_env();

    // Check output file
    cr_assert_eq(s_OUTPUT, NULL, "Invalid output file");
    // Check debug level
    cr_assert_eq(i_DEBUG_LEVEL, 0, "Invalid debug level");
    // Check Meta pool max entries
    cr_assert_eq(sz_META_POOL_MAX_ENTRIES, 1e5, "Invalid Meta pool max entries");
    // Check Data pool page size
    cr_assert_eq(sz_DATA_POOL_PAGES, 2, "Invalid Data pool page size");
    // Check page size
    cr_assert_eq(sz_PAGE_SIZE, 4096, "Invalid page size");
    // Check debug page size
    cr_assert_eq(sz_DEBUG_PAGE_SIZE, 16, "Invalid debug page size");
}

/**
 * Test custom environment variables
 * 
 * - Check the output file
 * - Check the debug level
 * - Check the Meta pool max entries
 * - Check the Data pool pages count
 * - Check the page size
 * - Check the debug page size
 * 
 * @note This test can fail if the environment variables are set
 */
Test(my_secmalloc, test_init_env_custom) {

    setenv("MSM_OUTPUT", "output.log", 1);
    setenv("MSM_DEBUG", "2", 1);
    setenv("MSM_META_POOL_MAX_ENTRIES", "1000", 1);
    setenv("MSM_DATA_POOL_PAGES", "4", 1);
    setenv("MSM_PAGE_SIZE", "4096", 1);
    setenv("MSM_DEBUG_PAGE_SIZE", "32", 1);

    init_env();

    // Check output file
    cr_assert(s_OUTPUT != NULL, "Invalid output file");
    // Check debug level
    cr_assert_eq(i_DEBUG_LEVEL, 2, "Invalid debug level");
    // Check Meta pool max entries
    cr_assert_eq(sz_META_POOL_MAX_ENTRIES, 1000, "Invalid Meta pool max entries");
    // Check Data pool page size
    cr_assert_eq(sz_DATA_POOL_PAGES, 4, "Invalid Data pool page size");
    // Check page size
    cr_assert_eq(sz_PAGE_SIZE, 4096, "Invalid page size");
    // Check debug page size
    cr_assert_eq(sz_DEBUG_PAGE_SIZE, 32, "Invalid debug page size");
}


/// Logging

/**
 * Test the get_log_prefix function
 * 
 * - Test with INFO log level
 * - Test with DEBUG log level
 * - Test with ERROR log level
 * - Test with an invalid log level
 */
Test(my_secmalloc, test_get_log_prefix) {
    cr_assert_str_eq(get_log_prefix(INF), "INFO: ");
    cr_assert_str_eq(get_log_prefix(DBG), "DEBUG: ");
    cr_assert_str_eq(get_log_prefix(ERR), "ERROR: ");
    cr_assert_str_eq(get_log_prefix(999), "NONE: "); // Test with an invalid log level
}

/// Metadata pool

/**
 * Test for meta_pool_size function
 */
Test(my_secmalloc, test_meta_pool_size) {
    sz_META_POOL_MAX_ENTRIES = 1000;
    cr_assert_eq(get_meta_pool_max_size(), 1000 * sizeof(block_t));

    setenv("MSM_META_POOL_MAX_ENTRIES", "1000", 1);

    my_malloc(12);
    my_malloc(12);

    cr_assert_eq(get_meta_pool_used_size(), 2 * sizeof(block_t));
    cr_assert_eq(get_meta_pool_free_size(), 1000 * sizeof(block_t) - 2 * sizeof(block_t));
}

/**
 * Test on the metadata pool
 * 
 * - Pool size (asserted size 4096)
 * - Pool content (asserted to had one not initialized block)
 */
Test(my_secmalloc, test_init_meta_pool) {
    setup_env();

    init_env();
    int ok = init_meta_pool();

    cr_assert_eq(ok, 1, "Failed to init meta pool");

    // Check the metadata pool size
    cr_assert_eq(get_meta_pool_max_size(), 1e5 * sizeof(block_t), "Invalid metadata pool size");
    // Check the metadata pool used size
    cr_assert_eq(get_meta_pool_used_size(), 0, "Invalid metadata pool used size");
    // Check Last block
    block_t *last_block = get_last_block();
    cr_assert_eq(last_block->state, FREE, "Last block is not free");
    cr_assert_eq(last_block->next, NULL, "Last block is not the last one");
}

/// Data pool

/**
 * Test for data_pool_size function
 */
Test(my_secmalloc, test_data_pool_size) {
    sz_PAGE_SIZE = 4096;
    sz_DATA_POOL_PAGES = 10;
    cr_assert_eq(get_data_pool_max_size(), 40960);

    setenv("MSM_PAGE_SIZE", "4096", 1);
    setenv("MSM_DATA_POOL_PAGES", "10", 1);

    my_malloc(12);
    my_malloc(12);

    cr_assert_eq(get_data_pool_used_size(), 32 + 2); // 2 canaries and 2 blocks padded to 16 bytes
    cr_assert_eq(get_data_pool_free_size(), 40960 - 32 - 2);
}


/**
 * Test on the data pool
 * 
 * - Pool size (asserted size 8192)
 */
Test(my_secmalloc, test_init_data_pool) {
    init_env();
    int ok = init_data_pool();

    cr_assert_eq(ok, 1, "Failed to init data pool");

    // Check the data pool size
    cr_assert_eq(get_data_pool_max_size(), 8192, "Invalid data pool size");
    // Check the data pool used size
    cr_assert_eq(get_data_pool_used_size(), 0, "Invalid data pool used size");
}

/// my_malloc

/**
 * Test my_malloc with a size of 0
 */
Test(my_secmalloc, test_my_malloc_zero) {
    void *ptr = my_malloc(0);
    cr_assert(ptr == NULL, "Failed to alloc");
}

/**
 * Test my_malloc with a simple size
 * 
 * - Check Last block
 * - Check First block
 */
Test(my_secmalloc, test_my_malloc_simple) {
    void *ptr = my_malloc(12);
    cr_assert(ptr != NULL, "Failed to alloc");

    // Check Last block
    block_t *last_block = get_last_block();
    cr_assert_eq(last_block->state, FREE, "Last block is not free");
    cr_assert_eq(last_block->next, NULL, "Last block is not the last one");

    // Check First block
    // allocated size + 1 canary
    // next = meta_pool + sizeof(block_t)
    block_t *first_block = get_first_block();
    cr_assert_eq(first_block->state, BUSY, "First block is not busy");
    cr_assert_eq(first_block->next, last_block, "First block is not the first one");
    cr_assert_eq(first_block->size, 16, "First block size is invalid");
    size_t ptr_offset = (size_t) ptr - (size_t)get_data_pool();
    cr_assert_eq(first_block->offset, ptr_offset, "First block data is invalid");
}

/**
 * Test my_malloc and write the allocated memory
 */
Test(my_secmalloc, test_my_malloc_write_past) {
    void *ptr = my_malloc(12);
    cr_assert(ptr != NULL, "Failed to alloc");
    strcpy(ptr, "Hello World");
    cr_assert_str_eq(ptr, "Hello World");
}

/**
 * Test my_malloc with a size of 4096
 * 
 * - Check Last block
 * - Check First block
 */
Test(my_secmalloc, test_my_malloc_page_size) {
    void *ptr = my_malloc(4096);
    cr_assert(ptr != NULL, "Failed to alloc");

    // Check Last block
    block_t *last_block = get_last_block();
    cr_assert_eq(last_block->state, FREE, "Last block is not free");
    cr_assert_eq(last_block->next, NULL, "Last block is not the last one");

    // Check First block
    // allocated size + 1 canary
    // next = meta_pool + sizeof(block_t)
    block_t *first_block = get_first_block();
    cr_assert_eq(first_block->state, BUSY, "First block is not busy");
    cr_assert_eq(first_block->next, last_block, "First block is not the first one");
    cr_assert_eq(first_block->size, 4096, "First block size is invalid");
    size_t ptr_offset = (size_t) ptr - (size_t)get_data_pool();
    cr_assert_eq(first_block->offset, ptr_offset, "First block data is invalid");
}

/**
 * Test my_malloc with multiple allocations
 */
Test(my_secmalloc, test_my_malloc_multiple) {
    void *ptr1 = my_malloc(12);
    void *ptr2 = my_malloc(12);
    void *ptr3 = my_malloc(12);
    void *ptr4 = my_malloc(12);

    cr_assert(ptr1 != NULL, "Failed to alloc");
    cr_assert(ptr2 != NULL, "Failed to alloc");
    cr_assert(ptr3 != NULL, "Failed to alloc");
    cr_assert(ptr4 != NULL, "Failed to alloc");

    my_free(ptr1);
    my_free(ptr2);
    my_free(ptr3);
    my_free(ptr4);
}

/**
 * Test my_malloc with a remap of the data pool
 * 
 * - Check Last block
 * - Check First block
 */
Test(my_secmalloc, test_my_malloc_remap) {
    void *ptr1 = my_malloc(6000);
    void *ptr2 = my_malloc(6000);

    cr_assert(ptr1 != NULL, "Failed to alloc");
    cr_assert(ptr2 != NULL, "Failed to alloc");

    // Check Last block
    block_t *last_block = get_last_block();
    cr_assert_eq(last_block->state, FREE, "Last block is not free");
    cr_assert_eq(last_block->next, NULL, "Last block is not the last one");

    // Check First block
    block_t *first_block = get_first_block();

    cr_assert_eq(first_block->state, BUSY, "First block is not busy");
    cr_assert_eq(first_block->size, 6000, "First block size is invalid");
    size_t ptr_offset = (size_t) ptr1 - (size_t)get_data_pool();
    cr_assert_eq(first_block->offset, ptr_offset, "First block data is invalid");

    my_free(ptr1);
    my_free(ptr2);
}

/**
 * Test my_malloc with fragmentation
 * 
 * - Check Last block
 * - Check First block
 */
Test(my_secmalloc, test_my_malloc_fragmentation) {
    void *ptr1 = my_malloc(1000);
    void *ptr2 = my_malloc(4096);
    void *ptr3 = my_malloc(1000);

    cr_assert(ptr1 != NULL, "Failed to alloc");
    cr_assert(ptr2 != NULL, "Failed to alloc");
    cr_assert(ptr3 != NULL, "Failed to alloc");

    // Write strings in those
    strncpy(ptr1, "Hello", 6);
    strncpy(ptr2, "World", 6);
    strncpy(ptr3, "!", 2);

    // Check Last block
    block_t *last_block = get_last_block();
    cr_assert_eq(last_block->state, FREE, "Last block is not free");
    cr_assert_eq(last_block->next, NULL, "Last block is not the last one");

    // Check First block
    block_t *first_block = get_first_block();

    cr_assert_eq(first_block->state, BUSY, "First block is not busy");
    cr_assert_eq(first_block->size, 1008, "First block size is invalid"); // because of the padding to 16 bytes
    size_t ptr_offset = (size_t) ptr1 - (size_t)get_data_pool();
    cr_assert_eq(first_block->offset, ptr_offset, "First block data is invalid");

    // Check the written strings
    cr_assert_eq(strcmp(ptr1, "Hello"), 0);
    cr_assert_eq(strcmp(ptr2, "World"), 0);
    cr_assert_eq(strcmp(ptr3, "!"), 0);

    my_free(ptr1);
    my_free(ptr2);
    my_free(ptr3);
}

/// my_free

/**
 * Test my_free with a NULL pointer
 */
Test(my_secmalloc, test_my_free_null) {
    my_free(NULL);
}

/**
 * Test my_free with a simple pointer
 */
Test(my_secmalloc, test_my_free_simple) {
    void *ptr = my_malloc(12);
    cr_assert(ptr != NULL, "Failed to alloc");

    my_free(ptr);
}

/// my_realloc

/**
 * Test my_realloc with a NULL pointer
 * 
 * - Check the returned pointer
 * - Check the new block size
 */
Test(my_secmalloc, test_my_realloc_null) {
    void *ptr = my_realloc(NULL, 12);
    cr_assert(ptr != NULL, "Failed to realloc");

    block_t *block = get_first_block();
    cr_assert_eq(block->size, 16, "Invalid block size");

    my_free(ptr);
}

/**
 * Test my_realloc with a simple pointer and a size of 0
 * 
 * - Check the returned pointer
 * - Check the new block size
 * - Check the metadata pool used size
 * - Check the data pool used size
 */
Test(my_secmalloc, test_my_realloc_zero) {
    void *ptr = my_malloc(12);
    cr_assert(ptr != NULL, "Failed to alloc");

    void *new_ptr = my_realloc(ptr, 0);
    cr_assert(new_ptr == NULL, "Failed to realloc");

    cr_assert_eq(get_meta_pool_used_size(), sizeof(block_t), "Invalid metadata pool used size");

    cr_assert_eq(get_data_pool_used_size(), 16 + 1, "Invalid data pool used size");
}

/**
 * Test my_realloc with a simple pointer
 * 
 * - Check the returned pointer
 * - Check the new block size
 * - Check the metadata pool used size
 * - Check the data pool used size
 */
Test(my_secmalloc, test_my_realloc_simple) {
    void *ptr = my_malloc(12);
    cr_assert(ptr != NULL, "Failed to alloc");

    void *new_ptr = my_realloc(ptr, 24);
    cr_assert(new_ptr != NULL, "Failed to realloc");

    block_t *block = get_block(new_ptr);
    cr_assert_eq(block->size, 32, "Invalid block size");

    cr_assert_eq(get_meta_pool_used_size(), 2 * sizeof(block_t), "Invalid metadata pool used size");

    cr_assert_eq(get_data_pool_used_size(), 48 + 2, "Invalid data pool used size");

    my_free(new_ptr);
}

/**
 * Test my_realloc with a simple pointer and a smaller size
 * 
 * - Check the returned pointer
 * - Check the new block size
 * - Check the metadata pool used size
 * - Check the data pool used size
 */
Test(my_secmalloc, test_my_realloc_smaller) {
    void *ptr = my_malloc(24);
    cr_assert(ptr != NULL, "Failed to alloc");

    void *new_ptr = my_realloc(ptr, 12);
    cr_assert(new_ptr != NULL, "Failed to realloc");

    block_t *block = get_block(new_ptr);
    cr_assert_eq(block->size, 12, "Invalid block size");

    block_t *block2 = get_block(ptr);
    cr_assert_eq(block2->size, 12, "Invalid block size");

    cr_assert_eq(get_meta_pool_used_size(), 2 * sizeof(block_t), "Invalid metadata pool used size");

    cr_assert_eq(get_data_pool_used_size(), 32 + 2, "Invalid data pool used size");

    my_free(new_ptr);
}

/**
 * Test my_realloc with writing data
 * 
 * - Check the returned pointer
 * - Check the data written
 */
Test(my_secmalloc, test_my_realloc_write) {
    void *ptr = my_malloc(12);
    cr_assert(ptr != NULL, "Failed to alloc");

    strcpy(ptr, "Hello World");

    void *new_ptr = my_realloc(ptr, 24);
    cr_assert(new_ptr != NULL, "Failed to realloc");

    cr_assert_str_eq(new_ptr, "Hello World");

    my_free(new_ptr);
}

/// my_calloc

/**
 * Test my_calloc with a size of 0
 * 
 * - Check the returned pointer
 */
Test(my_secmalloc, test_my_calloc_zero) {
    void *ptr = my_calloc(0, 12);
    cr_assert(ptr == NULL, "Failed to calloc");
}

/**
 * Test my_calloc with a simple size
 * 
 * - Check the returned pointer
 * - Check the block size
 * - Check the metadata pool used size
 * - Check the data pool used size
 */
Test(my_secmalloc, test_my_calloc_simple) {
    void *ptr = my_calloc(1, 12);
    cr_assert(ptr != NULL, "Failed to calloc");

    block_t *block = get_block(ptr);
    cr_assert_eq(block->size, 16, "Invalid block size");

    cr_assert_eq(get_meta_pool_used_size(), sizeof(block_t), "Invalid metadata pool used size");

    cr_assert_eq(get_data_pool_used_size(), 16 + 1, "Invalid data pool used size");

    my_free(ptr);
}

/// Canaries

/**
 * Test the canaries
 * 
 * - Check the canaries
 */
Test(my_secmalloc, test_canaries) {
    void *ptr = my_malloc(12);
    cr_assert(ptr != NULL, "Failed to alloc");

    block_t *block = get_block(ptr);

    uint8_t *canary = (uint8_t *) ptr + block->size;

    cr_assert_eq(block->canary, *canary, "Invalid canary");

    my_free(ptr);
}

/// Security

/**
 * Test heap overflow
 */
Test(my_secmalloc, test_heap_overflow) {
    void *ptr = my_malloc(12);
    cr_assert(ptr != NULL, "Failed to alloc");

    char *data = (char *)ptr;
    data[13] = 'A';

    // This should not crash
    my_free(ptr);
}

/**
 * Test double free detection
 */
Test(my_secmalloc, test_double_free_detection) {
    void *ptr = my_malloc(12);
    cr_assert(ptr != NULL, "Failed to alloc");

    my_free(ptr);

    // Double free
    my_free(ptr);
}