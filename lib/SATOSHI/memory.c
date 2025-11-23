#include "btc/memory.h"
#include <Arduino.h>
#include <stdio.h>
#include <stdlib.h>
#include <esp_err.h>

void* btc_malloc_internal(size_t size);
void* btc_calloc_internal(size_t count, size_t size);
void* btc_realloc_internal(void *ptr, size_t size);
void btc_free_internal(void* ptr);

static const btc_mem_mapper default_mem_mapper = {btc_malloc_internal, btc_calloc_internal, btc_realloc_internal, btc_free_internal};
static btc_mem_mapper current_mem_mapper = {btc_malloc_internal, btc_calloc_internal, btc_realloc_internal, btc_free_internal};

void btc_mem_set_mapper_default()
{
    current_mem_mapper = default_mem_mapper;
}

void btc_mem_set_mapper(const btc_mem_mapper mapper)
{
    current_mem_mapper = mapper;
}

void* btc_malloc(size_t size)
{
    return current_mem_mapper.btc_malloc(size);
}

void* btc_calloc(size_t count, size_t size)
{
    return current_mem_mapper.btc_calloc(count, size);
}

void* btc_realloc(void *ptr, size_t size)
{
    return current_mem_mapper.btc_realloc(ptr, size);
}

void btc_free(void* ptr)
{
    current_mem_mapper.btc_free(ptr);
}

void* btc_malloc_internal(size_t size)
{
    void* result;

    if ((result = ps_malloc(size))) { /* assignment intentional */
        return (result);
    } else {
        printf("memory overflow: malloc failed in btc_malloc len=%d",size);
        printf("  Exiting Program.\n");
        ESP_ERROR_CHECK(ESP_ERR_NO_MEM);

        return (0);
    }
}

void* btc_calloc_internal(size_t count, size_t size)
{
    void* result;

    if ((result = ps_calloc(count, size))) { /* assignment intentional */
        return (result);
    } else {
        printf("memory overflow: calloc failed in btc_calloc [%d].",size);
        printf("  Exiting Program.\n");
        ESP_ERROR_CHECK(ESP_ERR_NO_MEM);

        return (0);
    }
}

void* btc_realloc_internal(void *ptr, size_t size)
{
    void* result;

    if ((result = ps_realloc(ptr, size))) { /* assignment intentional */
        return (result);
    } else {
        printf("memory overflow: realloc failed in btc_realloc.[%d]",size);
        printf("  Exiting Program.\n");
        ESP_ERROR_CHECK(ESP_ERR_NO_MEM);

        return (0);
    }
}

void btc_free_internal(void* ptr)
{
     free(ptr);
}

volatile void *btc_mem_zero(volatile void *dst, size_t len)
{
    volatile char *buf;
    for (buf = (volatile char *)dst;  len;  buf[--len] = 0);
    return dst;
}

void memzero(void *s, size_t n)
{
	memset(s, 0, n);
}