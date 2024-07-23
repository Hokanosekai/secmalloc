#ifndef _SECMALLOC_PRIVATE_H
#define _SECMALLOC_PRIVATE_H

/**
 * @file my_secmalloc.private.h
 * @author Hokanosekai
 * 
 * @brief Private header file for the my_secmalloc implementation
 * 
 * This file contains the private functions and structures used by the
 * my_secmalloc implementation.
 * 
 * The functions and structures defined in this file are not meant to be
 * used outside of the my_secmalloc implementation.
 */

#include <stdint.h>

// Include the public header file
#include "my_secmalloc.h"

/**
 * @brief Debug levels
 * 
 * The debug levels is used to know wich debug level is activated.
 * 
 * @note DEBUG_NONE: No debug (default)
 * @note DEBUG_BASIC: Only basic debug, such as memory actions, block actions, etc.
 * @note DEBUG_ADVANCED: Advanced debug, adding pools and blocks information, etc.
 * @note DEBUG_ALL: All debug, including memory dump, etc.
 */
#define DEBUG_NONE      0
#define DEBUG_BASIC     1
#define DEBUG_ADVANCED  2
#define DEBUG_ALL       3

/**
 * @brief Default values
 * 
 * The default values for the pages count of the data pool, the meta pool
 * max entries, the page size, the output file and the debug flag.
 */
#define DEFAULT_DATA_POOL_PAGES         2 // 1
#define DEFAULT_META_POOL_MAX_ENTRIES   1e5 // 100000
#define DEFAULT_DEBUG_PAGE_SIZE         16 // 16 bytes
#define DEFAULT_PAGE_SIZE               4096 // 4096 bytes
#define DEFAULT_OUTPUT                  NULL // No output file by default
#define DEFAULT_DEBUG                   0 // No debug by default

/**
 * @brief Environment variables
 *
 * The environment variables used to set the pages count of the data pool,
 * the meta pool max entries, the page size, the output file and the debug flag.
 */
#define ENV_META_POOL_MAX_ENTRIES   "MSM_META_POOL_MAX_ENTRIES"
#define ENV_DATA_POOL_PAGES         "MSM_DATA_POOL_PAGES"
#define ENV_DEBUG_PAGE_SIZE         "MSM_DEBUG_PAGE_SIZE"
#define ENV_PAGE_SIZE               "MSM_PAGE_SIZE"
#define ENV_OUTPUT                  "MSM_OUTPUT"
#define ENV_DEBUG                   "MSM_DEBUG"

/**
 * @brief Global variables
 *
 * The global variables used to store the pages count of the data pool,
 * the meta pool max entries, the page size, the output file and the debug flag.
 */
extern size_t sz_META_POOL_MAX_ENTRIES;
extern size_t sz_DATA_POOL_PAGES;
extern size_t sz_DEBUG_PAGE_SIZE;
extern size_t sz_PAGE_SIZE;
extern const char* s_OUTPUT;
extern int i_DEBUG_LEVEL;

/**
 * @brief Log levels
 * @enum log_level
 *
 * The log levels used to print messages to the output file.
 */
typedef enum {
    INF, // Informational purposes
    DBG, // Debugging purposes
    ERR  // Error purposes
} log_level_t;

/**
 * @brief Block states
 * @enum block_state
 *
 * The block states used to keep track of the memory blocks.
 */
typedef enum {
    FREE, // Block is free
    BUSY  // Block is allocated
} block_state_t;

/**
 * @brief Block structure
 * @struct block
 *
 * The block structure used to keep track of the allocated memory areas and their metadata.
 *
 * @var size The size of the memory block
 * @var offset The offset of the memory block
 * @var canary The canary value of the memory block
 * @var next The next block in the memory pool
 * @var state The state of the memory block
 */
typedef struct block {
    size_t size;
    size_t offset;
    uint8_t canary;
    struct block* next;
    block_state_t state;
} block_t;

// Environment functions

/**
 * @brief Get string from environment variable or default value
 *
 * A helper function to get the value of an environment variable or a default value as a string
 *
 * @param name The name of the environment variable
 * @param def The default value to return if the environment variable is not set
 *
 * @return The value of the environment variable or the default value
 */
const char* getenv_or_s(const char *env_var, const char *default_value);

/**
 * @brief Get integer from environment variable or default value
 *
 * A helper function to get the value of an environment variable or a default value as an integer
 *
 * @param name The name of the environment variable
 * @param def The default value to return if the environment variable is not set
 *
 * @return The value of the environment variable or the default value
 */
int getenv_or_i(const char *env_var, int default_value);

/**
 * @brief Initializes the environment variables.
 * 
 * This function is responsible for initializing the environment variables
 * required.
 * 
 * @return void
 * 
 * @see getenv_or_s
 * @see getenv_or_i
 */
void init_env(void);

// Output functions

/**
 * @brief Write to the output file
 * 
 * A helper function to write a message to the output file.
 * 
 * @param msg The message to write to the output file
 * 
 * @return void
 */
void write_report(char *msg);

/**
 * @brief Get the log prefix
 * 
 * A helper function to get the log prefix based on the log level.
 * 
 * @param level The log level
 * 
 * @return The log prefix
 * 
 * @see log_level_t
 * @see msm_log
 */
const char *get_log_prefix(log_level_t level);

/**
 * @brief Log a message
 * 
 * A helper function to log a message to the output file.
 * 
 * @param level The log level
 * @param format The format of the message
 * @param ... The arguments of the message
 * 
 * @return void
 * 
 * @see log_level_t
 * @see get_log_prefix
 */
void msm_log(log_level_t level, const char *format, ...);

// Debug functions

void debug_env(void);

/**
 * @brief Debug the data pool
 * 
 * A helper function to debug the data pool.
 * 
 * @note This function is used for debugging purposes
 * @note The print format is:
 * 
 * data pool <data_pool>: <page_size> b, <nb_pages> pages
 *    max  size: <max_size> b
 *    used size: <used_size> b
 *    free size: <free_size> b
 * 
 * @note Depending on the debug level, the logged infos can differ from
 * this format.
 * 
 * @return void
 */
void debug_data_pool(void);

/**
 * @brief Debug the metadata pool
 * 
 * A helper function to debug the metadata pool.
 * 
 * @note This function is used for debugging purposes
 * @note The print format is:
 * 
 * meta pool <meta_pool>: <block_size> b, <entries> entries
 *    max  size: <max_size> b
 *    used size: <used_size> b
 *    free size: <free_size> b
 * 
 * @note Depending on the debug level, the logged infos can differ from
 * this format.
 * 
 * @return void
 */
void debug_meta_pool(void);

/**
 * @brief Debug a block
 * 
 * A helper function to debug a metadata block.
 * 
 * @note This function is used for debugging purposes
 * @note The print format is:
 * 
 * block: <block_ptr> (<data_ptr> + <offset>): <size> b, <state>
 *    next: <next>, prev: <prev>
 *    canary: <canary_hex> <canary_int> (<canary_ptr>)
 *    data (<page_start> sp, <end_page> ep):
 *          <pool_ptr + 0>: 00 00 00 00 00 00 ...
 *          <pool_ptr + x>: 00 00 00 00 00 00 ...
 * 
 * @note Depending on the debug level, the logged infos can differ from
 * this format.
 * 
 * @param block The meta pool block
 * 
 * @return void
 * 
 * @see debug_data_pool_block
 * @see block_t
 */
void debug_block(block_t *block);

/**
 * @brief Debug the block data
 * 
 * A helper function to debug the data stored behind a block.
 * 
 * @note This function is used for debugging purposes
 * @note The print format is:
 * 
 * data (<page_start> sp, <end_page> ep):
 *       <pool_ptr + 0>: 00 00 00 00 00 00 ...
 *       <pool_ptr + x>: 00 00 00 00 00 00 ...
 * 
 * @param block The meta pool block
 * 
 * @return void
 * 
 * @see block_t
 */
void debug_data_pool_block(block_t *block);

// Data pool functions

/**
 * @brief Initialize the data pool
 * 
 * A function to initialize the data pool.
 * 
 * @note This method call the `mmap` syscall to allocate a new area for the
 * data pool. The data pool must keep the same pointer all the time during the
 * process life. So, to do it we place the data pool behind the metadata pool
 * pointer offseted by his size.
 * 
 * @return 1 on success, 0 on failure
 * 
 * @see mmap
 */
int init_data_pool(void);

/**
 * @brief Expand the data pool
 * 
 * A function to expand the data pool by allocating additional pages.
 * 
 * @note This method call the `mremap` syscall, that we used to expand our
 * data pool. Normally, the returned pointer is the same as before, if not the 
 * process will exit.
 * 
 * @param asked_pages The number of pages to allocate
 * 
 * @return 1 on success, 0 on failure
 * 
 * @see mremap
 */
int expand_data_pool(size_t asked_pages);

/**
 * @brief Check the data pool size
 * 
 * A function to check if the data pool needs to be expanded. If the data pool
 * is full, the function calls expand_data_pool to allocate additional pages.
 * 
 * @param size The size to check
 * 
 * @return void
 * 
 * @see expand_data_pool
 */
void check_data_pool_size(size_t size);

/**
 * @brief Get the maximum size of the data pool
 * 
 * A function to get the maximum size of the data pool in bytes.
 * 
 * @return The maximum size of the data pool
 */
size_t get_data_pool_max_size(void);

/**
 * @brief Get the used size of the data pool
 * 
 * A function to get the used size of the data pool in bytes.
 * 
 * @return The used size of the data pool
 */
size_t get_data_pool_used_size(void);

/**
 * @brief Get the free size of the data pool
 * 
 * A function to get the free size of the data pool in bytes.
 * 
 * @return The free size of the data pool
 */
size_t get_data_pool_free_size(void);

/**
 * @brief Get the data pool pointer
 * 
 * A function to get the data pool pointer.
 * 
 * @return The data pool pointer
 */
void *get_data_pool(void);

// Meta pool functions

/**
 * @brief Initialize the meta pool
 * 
 * A function to initialize the meta pool.
 * 
 * @note This method initialize the metadata pool by calling the `mmap` syscall
 * to allocate a default area. 
 * 
 * @return 1 on success, 0 on failure
 * 
 * @see mmap
 */
int init_meta_pool(void);

/**
 * @brief Get the maximum size of the meta pool
 * 
 * A function to get the maximum size of the meta pool in bytes. Basically, 
 * the metadata max entries times the size of a block.
 * 
 * @return The maximum size of the meta pool
 */
size_t get_meta_pool_max_size(void);

/**
 * @brief Get the used size of the meta pool
 * 
 * A function to get the used size of the meta pool in bytes. Basically, the 
 * number of blocks stored in the metadata pool times the size of a block.
 * 
 * @return The used size of the meta pool
 */
size_t get_meta_pool_used_size(void);

/**
 * @brief Get the free size of the meta pool
 * 
 * A function to get the free size of the meta pool in bytes. Basically, the
 * metadata pool max size minus the used size.
 * 
 * @note 
 * 
 * @return The free size of the meta pool
 */
size_t get_meta_pool_free_size(void);

// Global pool functions

/**
 * @brief Initialize the data and meta pools
 * 
 * A function to initialize the data and meta pools.
 * 
 * @return void
 * 
 * @see init_data_pool
 * @see init_meta_pool
 */
void init_pools(void);

// Block functions

/**
 * @brief Get the previous block of a block
 * 
 * A function to get the previous block of the passed block.
 * 
 * @param block The current block
 * 
 * @return The previous block of the current block
 * 
 * @see block_t
 */
block_t *get_block_prev(block_t *block);

/**
 * @brief Get the next block of a block
 * 
 * A function to get the next block of the passed block.
 * 
 * @param block The current block
 * 
 * @return The next block of the current block
 * 
 * @see block_t
 */
block_t *get_block_next(block_t *block);

/**
 * @brief Get the data pointer of a block
 * 
 * A function to get the data pointer of a block.
 * 
 * @note The data pointer is the pointer to the data of the block, not the
 * block itself. In fact, the pointer is calculated by adding the block offset
 * to the data pool pointer (base address).
 * 
 * @param block The block
 * 
 * @return The data pointer of the block
 * 
 * @see block_t
 */
void *get_block_data_ptr(block_t *block);

/**
 * @brief Get the block containing a given pointer
 * 
 * A function to get the block containing a given pointer.
 * 
 * @note To find the block corresponding to a pointer, we first calculate the
 * offset of the pointer from the base address of the data pool. Then, we
 * iterate over the blocks in the memory pool to find the block that contains
 * the calculated offset.
 * 
 * @param ptr The pointer
 * 
 * @return The block containing the pointer
 * 
 * @see block_t
 */
block_t *get_block(void *ptr);

/**
 * @brief Get the last block in the memory pool
 * 
 * A function to get the last block in the memory pool.
 * 
 * @return The last block in the memory pool
 * 
 * @see block_t
 */
block_t *get_last_block(void);

/**
 * @brief Get the first block in the memory pool
 * 
 * A function to get the first block in the memory pool. Basically, returning
 * the metadata pool pointer.
 * 
 * @return The first block in the memory pool
 * 
 * @see block_t
 */
block_t *get_first_block(void);

/**
 * @brief Get a free block of a given size
 * 
 * A function to get a free block of a given size.
 * 
 * @note This method iterates over the metadata pool to find a free block of
 * the given size. If a free block is found, the function returns the block.
 * A free block is a block that has the state FREE or has a size greater or
 * equal than the requested size or the size is 0.
 * 
 * @param size The size of the block
 * 
 * @return A free block of the given size, or NULL if no free block is available
 * 
 * @see block_t
 */
block_t *get_free_block(size_t size);

/**
 * @brief Free a block
 * 
 * A function to free a block.
 * 
 * @note The block remain FREE, because the block is just memset to 0.
 * 
 * @param block The block to free
 * 
 * @return void
 * 
 * @see block_t
 */
void free_block(block_t *block);

/**
 * @brief Merge adjacent free blocks
 * 
 * A function to merge adjacent free blocks.
 * 
 * @note The method must be used to merge the blocks marked has free belong to
 * the passed one. Such as, the previous and the next ones. If there is no
 * blocks to merge with we just free the block.
 * 
 * @param block The block to merge
 * 
 * @return void
 * 
 * @see block_t
 */
void merge_blocks(block_t *block);

/**
 * @brief Split a block into two blocks
 * 
 * A function to split a block into two blocks.
 * 
 * @note This method is used to split a free block with a greater size than
 * the requested size. The passed block will be updated with the new size and
 * passed to busy state, then we create a new free block at the end of the 
 * metadata block list with the remaining size.
 * 
 * @param block The block to split
 * @param size The size of the first block
 * 
 * @return The second block created by the split
 * 
 * @see block_t
 */
block_t *split_block(block_t *block, size_t size);

// Canary functions

/**
 * @brief Generate a canary value
 * 
 * A function to generate a canary value.
 * 
 * @note The canary value is a random value used to prevent from heap overflow.
 * By placing the canary value at the end of the allocated memory block, we can
 * detect if the memory block has been overflowed when the block is freed.
 * 
 * @note The generation of the canary is done by opening /dev/urandom and reading a byte at a random offset of the end of the file. By using this method we can generate a random canary value for each block.
 * 
 * @return The generated canary value
 * 
 */
uint8_t generate_canary(void);

/**
 * @brief Set the canary value of a block
 * 
 * A function to set the canary value of a block.
 * 
 * @param block The block
 * 
 * @return void
 * 
 * @see block_t
 */
void set_canary(block_t *block);

/**
 * @brief Check the canary value of a block
 * 
 * A function to check the canary value of a block.
 * 
 * @param block The block
 * 
 * @return 1 if the canary value is valid, 0 otherwise
 * 
 * @see block_t
 */
int check_canary(block_t *block);

// Exit functions

/**
 * @brief Detect memory leaks
 * 
 * A function to detect memory leaks. A memory leak is detected if there are
 * any allocated blocks that have not been freed when the program exits.
 * 
 * @note The function iterates over the blocks in the memory pool and checks
 * if any block is still allocated. If a block is still allocated, the function
 * logs an error message to the output file.
 * 
 * @return void
 * 
 * @see my_malloc
 * @see my_free
 * @see my_calloc
 * @see my_realloc
 */
void detect_memory_leaks(void);

// Memory functions

/**
 * @brief Allocate memory
 * 
 * A function to allocate memory.
 * 
 * 
 * @param size The size of the memory to allocate
 * 
 * @return A pointer to the allocated memory, or NULL if the allocation fails
 */
void *my_malloc(size_t size);

/**
 * @brief Free memory
 * 
 * A function to free memory.
 * 
 * @param ptr The pointer to the memory to free
 * 
 * @return void
 */
void my_free(void *ptr);

/**
 * @brief Allocate and initialize memory
 * 
 * A function to allocate and initialize memory.
 * 
 * @param nmemb The number of elements to allocate
 * @param size The size of each element
 * 
 * @return A pointer to the allocated and initialized memory, or NULL if the allocation fails
 */
void *my_calloc(size_t nmemb, size_t size);

/**
 * @brief Reallocate memory
 * 
 * A function to reallocate memory.
 * 
 * @param ptr The pointer to the memory to reallocate
 * @param size The new size of the memory
 * 
 * @return A pointer to the reallocated memory, or NULL if the reallocation fails
 */
void *my_realloc(void *ptr, size_t size);

#endif
