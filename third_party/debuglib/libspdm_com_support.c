/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

#include "internal/libspdm_common_lib.h"

#if LIBSPDM_DEBUG_PRINT_ENABLE
void libspdm_internal_dump_hex_str(const uint8_t *data, size_t size)
{
    size_t index;
    for (index = 0; index < size; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%02x", (size_t)data[index]));
    }
}

void libspdm_internal_dump_data(const uint8_t *data, size_t size)
{
    size_t index;
    for (index = 0; index < size; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%02x ", (size_t)data[index]));
    }
}

void libspdm_internal_dump_hex(const uint8_t *data, size_t size)
{
    size_t index;
    size_t count;
    size_t left;

    #define COLUMN_SIZE (16 * 2)

    count = size / COLUMN_SIZE;
    left = size % COLUMN_SIZE;
    for (index = 0; index < count; index++) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%04x: ", index * COLUMN_SIZE));
        LIBSPDM_INTERNAL_DUMP_DATA(data + index * COLUMN_SIZE, COLUMN_SIZE);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }

    if (left != 0) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "%04x: ", index * COLUMN_SIZE));
        LIBSPDM_INTERNAL_DUMP_DATA(data + index * COLUMN_SIZE, left);
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "\n"));
    }
}

#endif /* LIBSPDM_DEBUG_PRINT_ENABLE */
