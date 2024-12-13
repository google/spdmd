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

#include <string.h>

#include "spdm_conn.h"
#include "mctp_transport.h"
#include "pcie_doe_transport.h"
#include "spdm_conn_internal.h"

libspdm_return_t spdm_device_acquire_sender_buffer(void *context,
                                                   void **msg_buf_ptr) {
  spdm_conn_t *conn = ((libspdm_context_t *)context)->conn;
  LIBSPDM_ASSERT(conn != NULL);
  LIBSPDM_ASSERT(!conn->m_send_receive_buffer_acquired);

  *msg_buf_ptr = conn->m_send_receive_buffer;
  libspdm_zero_mem(conn->m_send_receive_buffer,
                   sizeof(conn->m_send_receive_buffer));
  conn->m_send_receive_buffer_acquired = true;
  return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_sender_buffer(void *context, const void *msg_buf_ptr) {
  spdm_conn_t *conn = ((libspdm_context_t *)context)->conn;
  LIBSPDM_ASSERT(conn != NULL);
  LIBSPDM_ASSERT(conn->m_send_receive_buffer_acquired);
  LIBSPDM_ASSERT(msg_buf_ptr == conn->m_send_receive_buffer);
  conn->m_send_receive_buffer_acquired = false;
  return;
}

libspdm_return_t spdm_device_acquire_receiver_buffer(void *context,
                                                     void **msg_buf_ptr) {
  spdm_conn_t *conn = ((libspdm_context_t *)context)->conn;
  LIBSPDM_ASSERT(conn != NULL);
  LIBSPDM_ASSERT(!conn->m_send_receive_buffer_acquired);
  *msg_buf_ptr = conn->m_send_receive_buffer;
  libspdm_zero_mem(conn->m_send_receive_buffer,
                   sizeof(conn->m_send_receive_buffer));
  conn->m_send_receive_buffer_acquired = true;
  return LIBSPDM_STATUS_SUCCESS;
}

void spdm_device_release_receiver_buffer(void *context,
                                         const void *msg_buf_ptr) {
  spdm_conn_t *conn = ((libspdm_context_t *)context)->conn;
  LIBSPDM_ASSERT(conn != NULL);
  LIBSPDM_ASSERT(conn->m_send_receive_buffer_acquired);
  LIBSPDM_ASSERT(msg_buf_ptr == conn->m_send_receive_buffer);
  conn->m_send_receive_buffer_acquired = false;
  return;
}

libspdm_return_t spdm_device_send_message(void *spdm_context,
                                          size_t request_size,
                                          const void *request,
                                          uint64_t timeout) {
  libspdm_return_t ret;
  spdm_conn_t *spdm_conn = ((libspdm_context_t *)spdm_context)->conn;

  if (spdm_conn->m_use_transport_layer == TRANSPORT_TYPE_PCI_DOE) {
    ret = spdm_device_send_message_doe(spdm_context, request_size, request,
                                       timeout);
  } else if (spdm_conn->m_use_transport_layer == TRANSPORT_TYPE_MCTP) {
    ret = spdm_device_send_message_mctp(spdm_context, request_size, request,
                                        timeout);
  } else {
    debug_log(LOG_ERR, "Unsupported transport protocol, only support DOE|MCTP!");
    ret = LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  return ret;
}

libspdm_return_t spdm_device_receive_message(void *spdm_context,
                                             size_t *response_size,
                                             void **response,
                                             uint64_t timeout) {
  libspdm_return_t ret;
  spdm_conn_t *spdm_conn = ((libspdm_context_t *)spdm_context)->conn;

  if (spdm_conn->m_use_transport_layer == TRANSPORT_TYPE_PCI_DOE) {
    ret = spdm_device_receive_message_doe(spdm_context, response_size,
                                          response, timeout);
  } else if (spdm_conn->m_use_transport_layer == TRANSPORT_TYPE_MCTP) {
    ret = spdm_device_receive_message_mctp(spdm_context, response_size,
                                           response, timeout);
  } else {
    debug_log(LOG_ERR, "Unsupported transport protocol, only support DOE|MCTP!");
    ret = LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  return ret;
}

/* callback function provided by spdm requester to copy l1l2 log */
bool clone_l1l2_with_sig(void *context,
                         libspdm_session_info_t *session_info,
                         const void *sig,
                         size_t sig_size) {
  bool result;
  libspdm_return_t status;
  result = libspdm_calculate_l1l2(
      (libspdm_context_t *)context,
      session_info,
      &((spdm_conn_t *)((libspdm_context_t *)context)->conn)->clone_l1l2);
  if (result == false) {
    debug_log(LOG_ERR, "Error! Clone l1l2 failed!\n");
    return false;
  }

  status = libspdm_append_managed_buffer(
      &((spdm_conn_t *)((libspdm_context_t*)context)->conn)->clone_l1l2,
      sig,
      sig_size);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    debug_log(LOG_ERR, "Error! Append sigature to l1l2 failed with 0x%x!\n", status);
    return false;
  }

  return true;
}
