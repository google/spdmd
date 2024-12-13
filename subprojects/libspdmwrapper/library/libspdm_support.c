/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "spdm_conn_internal.h"

#ifdef DEBUG  // Check if DEBUG is defined for debug build
  #define MAX_LOG_LEVEL LOG_DEBUG
#else
  #define MAX_LOG_LEVEL LOG_ERR  // only allow errors in production
#endif

static bool log_opened = false;

void debug_log(int log_level, const char *format, ...) {
  if (!log_opened) {
    setlogmask (LOG_UPTO (MAX_LOG_LEVEL)); // set mask based on build type
    openlog ("libspdmwrapper", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    log_opened = true;
  }

  if (log_level <= MAX_LOG_LEVEL) {
    va_list args;
    va_start(args, format);
    vsyslog(log_level, format, args);
    va_end(args);
  }
}

void dump_data(const uint8_t *buffer, size_t buffer_size) {
  size_t index;

  for (index = 0; index < buffer_size; index++) {
    debug_log(LOG_DEBUG, "%02x ", buffer[index]);
  }
}

void *copy_mem(void *dest_buf, const void *src_buf, uint32_t len) {
  volatile uint8_t *ptr_dest;
  volatile uint8_t *ptr_src;

  ptr_dest = (uint8_t *)dest_buf;
  ptr_src = (uint8_t *)src_buf;
  while (len-- != 0) {
    *(ptr_dest++) = *(ptr_src++);
  }

  return dest_buf;
}

/* need by libspdm/os_stub/spdm_device_secret_lib_sample/lib.c */
void libspdm_dump_hex_str(const uint8_t *buffer, size_t buffer_size) {
  size_t index;

  for (index = 0; index < buffer_size; index++) {
    debug_log(LOG_DEBUG, "%02x", buffer[index]);
  }
}

/* support reading local certificates */
bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size) {
  FILE *fp_in;
  size_t temp_result;
  long pos;

  if ((fp_in = fopen(file_name, "rb")) == NULL) {
    debug_log(LOG_ERR, "Unable to open file %s\n", file_name);
    *file_data = NULL;
    return false;
  }

  fseek(fp_in, 0, SEEK_END);
  pos = ftell(fp_in);
  if (pos == -1) {
    debug_log(LOG_ERR, "Unable to get the file size %s\n", file_name);
    *file_data = NULL;
    fclose(fp_in);
    return false;
  }

  *file_size = (size_t)pos;

  *file_data = (void *)malloc(*file_size);
  if (NULL == *file_data) {
    debug_log(LOG_ERR, "No sufficient memory to allocate %s\n", file_name);
    fclose(fp_in);
    return false;
  }

  fseek(fp_in, 0, SEEK_SET);
  temp_result = fread(*file_data, 1, *file_size, fp_in);
  if (temp_result != *file_size) {
    debug_log(LOG_ERR, "Read input file error %s", file_name);
    free((void *)*file_data);
    fclose(fp_in);
    return false;
  }

  fclose(fp_in);

  return true;
}

bool libspdm_write_output_file(const char *file_name, const void *file_data,
                               size_t file_size) {
  FILE *fp_out;

  if ((fp_out = fopen(file_name, "w+b")) == NULL) {
    debug_log(LOG_ERR, "Unable to open file %s\n", file_name);
    return false;
  }

  if (file_size != 0) {
    if ((fwrite(file_data, 1, file_size, fp_out)) != file_size) {
      debug_log(LOG_ERR, "Write output file error %s\n", file_name);
      fclose(fp_out);
      return false;
    }
  }

  fclose(fp_out);

  return true;
}
