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

#ifndef _SPDM_CONN_INTERNAL_H_
#define _SPDM_CONN_INTERNAL_H_

/* record transcript support is required for verifying measurements */
#ifndef LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#define LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT 1
#endif

/* for vsyslog() from <syslog.h> */
#define __USE_MISC  1

/* libspdm include/ */
#include "hal/base.h"
#include "hal/library/memlib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"
#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_crypt_lib.h"

#include <stdarg.h>
#include <syslog.h>

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

// to get spdm_connection from spdm_context
#ifndef container_of
#define container_of(ptr, type, member)                                        \
	(type *)((char *)(ptr)-offsetof(type, member))
#endif

#define ctx_to_conn(c)                                      \
    container_of((c), struct spdm_connection, m_spdm_context)

void debug_log(int log_level, const char *format, ...);

/**
 * The interfaces listed here needs to be implemented in a device-specific
 * way, depending on whether it is using SOCKET to emulate a SPDM connection,
 * or using MCTP, or PCIe DOE as the transport layer.
 * 
 * The interfaces defined here are for internal use only.
 */

struct spdm_connection;
typedef struct spdm_connection spdm_conn_t;

/* initialize spdm_conn transport layer */
libspdm_return_t spdm_transport_init(spdm_conn_t *spdm_conn);

/* helper function */
void dump_data(const uint8_t *buffer, size_t buffer_size);
void *copy_mem(void *dest_buf, const void *src_buf, uint32_t len);
libspdm_return_t spdm_do_vca(spdm_conn_t *spdm_conn);
bool clone_l1l2_with_sig(void *context,
                         libspdm_session_info_t *session_info,
                         const void *sig,
                         size_t sig_size);

/* support read/write certs file */
bool libspdm_read_input_file(const char *file_name, void **file_data,
                             size_t *file_size);

bool libspdm_write_output_file(const char *file_name, const void *file_data,
                               size_t file_size);

libspdm_return_t spdm_device_send_message(void *spdm_context,
                                          size_t request_size, const void *request,
                                          uint64_t timeout);
libspdm_return_t spdm_device_receive_message(void *spdm_context,
                                             size_t *response_size,
                                             void **response,
                                             uint64_t timeout);

libspdm_return_t spdm_device_acquire_sender_buffer (
    void *context, void **msg_buf_ptr);

void spdm_device_release_sender_buffer (
    void *context, const void *msg_buf_ptr);

libspdm_return_t spdm_device_acquire_receiver_buffer (
    void *context, void **msg_buf_ptr);

void spdm_device_release_receiver_buffer (
    void *context, const void *msg_buf_ptr);

bool spdm_cma_calculate_l1l2_with_msg_log(libspdm_context_t *spdm_context,
                            void *log_msg_buffer,
                            size_t buffer_size,
                            libspdm_l1l2_managed_buffer_t *l1l2);

#endif // _SPDM_CONN_INTERNAL_H_
