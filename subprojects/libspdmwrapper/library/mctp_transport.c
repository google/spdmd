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

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/mctp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "spdm_conn.h"
#include "spdm_conn_internal.h"
#include "mctp_transport.h"

libspdm_return_t spdm_device_send_message_mctp(void *spdm_context,
                                               size_t request_size,
                                               const void *req,
                                               uint64_t UNUSED(timeout)) {
  spdm_conn_t *spdm_conn = ((libspdm_context_t *)spdm_context)->conn;
  struct sockaddr_mctp addr = {0};
  ssize_t rc;
  uint8_t *ptr = (uint8_t*)req;

  addr.smctp_family = AF_MCTP;
  addr.smctp_addr.s_addr = spdm_conn->mctp_eid;
  addr.smctp_network = spdm_conn->mctp_nid;
  addr.smctp_type = MCTP_MSG_TYPE_SPDM;
  addr.smctp_tag = MCTP_TAG_OWNER;

  if (spdm_conn->mctp_socket < 0) {
    debug_log(LOG_ERR, "%s socket not setup correctly!\n", __func__);
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  if (request_size > LIBSPDM_SENDER_BUFFER_SIZE) {
    debug_log(LOG_ERR, "%s msg size bigger than buffer size :0x%x!\n", __func__,
              request_size);
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  // debug_log(LOG_ERR, "%s send buf (size:%d): %x %x %x %x\n", __func__, request_size,
  // ptr[0], ptr[1], ptr[2], ptr[3]);
  // dump_data(ptr, 4);

  // libspdm/include/library/spdm_transport_mctp_lib.h
  /* Required sender/receive buffer in device io.
   * +-------+--------+---------------------------+------+--+------+---+--------+-----+
   * | TYPE  |TransHdr|      EncryptionHeader     |AppHdr|  |Random|MAC|AlignPad|FINAL|
   * |       |        |SessionId|SeqNum|Len|AppLen|      |  |      |   |        |     |
   * +-------+--------+---------------------------+------+  +------+---+--------+-----+
   * | MCTP  |    1   |    4    |   2  | 2 |   2  |   1  |  |  32  | 16|   0    |  60 |
   * +-------+--------+---------------------------+------+--+------+---+--------+-----+
   */
  // https://github.com/DMTF/libspdm/issues/2664
  // kernel mctp API (e.g. sendto() here also add TYPE field to the req.
  // To work around the extra TYPE field, we need to right shift the pointer
  // and modify the size.
  ptr++;
  rc = sendto(spdm_conn->mctp_socket, ptr, request_size - 1, 0,
              (struct sockaddr *)&addr, sizeof(addr));
  if (rc < 0) {
    debug_log(LOG_ERR, "%s socket sendto failed!\n", __func__);
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_device_receive_message_mctp(void *spdm_context,
                                                  size_t *resp_size,
                                                  void **resp,
                                                  uint64_t timeout_us) {
  spdm_conn_t *spdm_conn = ((libspdm_context_t *)spdm_context)->conn;
  struct sockaddr_mctp addr = {0};
  socklen_t addrlen = sizeof(addr);
  uint8_t recv_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
  ssize_t length;
  int status;
  struct timeval timeout;

  if (spdm_conn->mctp_socket < 0) {
    debug_log(LOG_ERR, "%s socket not setup correctly!\n", __func__);
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  timeout.tv_sec = timeout_us / 1000000;
  timeout.tv_usec = timeout_us % 1000000;
  status = setsockopt(spdm_conn->mctp_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  if (status < 0) {
    debug_log(LOG_ERR, "setsockopt() failed with %lld usec!\n", timeout_us);
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  /**
   * when use mctp kernel api, the payload here are raw spdm msg, there is no
   * need for a lower bound length check for mctp header and tail.
   * LIBSPDM_STATUS_BUSY_PEER will cause a retry inside libspdm for RETRY
   * times configged in libspdm
   */
  length = recv(spdm_conn->mctp_socket, NULL, 0, MSG_PEEK | MSG_TRUNC);
  if (length <= 0 || length > LIBSPDM_MAX_SPDM_MSG_SIZE) {
    if (errno == EWOULDBLOCK || errno == EAGAIN)
      debug_log(LOG_ERR, "%s recv() timed out(val:%lld us)\n", __func__, timeout_us);
    else
      debug_log(LOG_ERR, "%s recv() failed! length: 0x%x\n", __func__, length);
    return LIBSPDM_STATUS_BUSY_PEER;
  }

  // libspdm/include/library/spdm_transport_mctp_lib.h
  /* Required sender/receive buffer in device io.
   * +-------+--------+---------------------------+------+--+------+---+--------+-----+
   * | TYPE  |TransHdr|      EncryptionHeader     |AppHdr|  |Random|MAC|AlignPad|FINAL|
   * |       |        |SessionId|SeqNum|Len|AppLen|      |  |      |   |        |     |
   * +-------+--------+---------------------------+------+  +------+---+--------+-----+
   * | MCTP  |    1   |    4    |   2  | 2 |   2  |   1  |  |  32  | 16|   0    |  60 |
   * +-------+--------+---------------------------+------+--+------+---+--------+-----+
   */
  // https://github.com/DMTF/libspdm/issues/2664
  // kernel mctp API (e.g. sendto() here also add TYPE field to the req.
  // To work around the extra TYPE field, we need to right shift the pointer,
  // set the msg TYPE field and modify the size.
  recv_buf[0] = MCTP_MSG_TYPE_SPDM;
  length = recvfrom(spdm_conn->mctp_socket, (uint8_t *)&recv_buf[1], length, MSG_TRUNC,
                    (struct sockaddr *)&addr, &addrlen);
  if (length <= 0 || length > LIBSPDM_MAX_SPDM_MSG_SIZE) {
    if (errno == EWOULDBLOCK || errno == EAGAIN)
      debug_log(LOG_ERR, "%s recvfrom() timed out\n", __func__);
    else
      debug_log(LOG_ERR, "%s recvfrom() failed! length: 0x%x\n", __func__, length);
    return LIBSPDM_STATUS_BUSY_PEER;
  }

  // Add one byte due to the msg TYPE field.
  *resp_size = length + 1;
  copy_mem(*resp, recv_buf, *resp_size);

  return LIBSPDM_STATUS_SUCCESS;
}

// initialize mctp transport layer
libspdm_return_t set_up_spdm_connection_for_mctp(spdm_conn_t *spdm_conn) {
  if (spdm_conn == NULL ||
      spdm_conn->m_use_transport_layer != TRANSPORT_TYPE_MCTP)
    return LIBSPDM_STATUS_INVALID_STATE_PEER;

  // domain:AF_MCTP, type:UDP/SOCK_DGRAM, protocol:IP/0
  spdm_conn->mctp_socket = socket(AF_MCTP, SOCK_DGRAM, 0);
  if (spdm_conn->mctp_socket < 0) {
    debug_log(LOG_ERR, "%s socket open failed!\n", __func__);
    return LIBSPDM_STATUS_INVALID_STATE_PEER;
  }

  // Default socket buffer send/recv size is around 208K.
  // spdm_buffer size is 0x1100/0x1200 + transport header, no need to
  // bother setsocketopt() for buffer size adjustment.
  // If we hit an buf size issue, see libpldm/src/transport/socket.c

  return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t tear_down_spdm_connection_for_mctp(spdm_conn_t *spdm_conn) {
  if (spdm_conn == NULL)
    return LIBSPDM_STATUS_INVALID_STATE_PEER;

  // close socket for mctp
  if (spdm_conn->mctp_socket >= 0)
    close(spdm_conn->mctp_socket);

  // de-initialize spdm context
  if (spdm_conn->m_spdm_context != NULL) {
    libspdm_deinit_context(spdm_conn->m_spdm_context);
    free(spdm_conn->m_spdm_context);
    spdm_conn->m_spdm_context = NULL;
  }

  if(spdm_conn->m_scratch_buffer != NULL)
    free(spdm_conn->m_scratch_buffer);

  free(spdm_conn);

  return LIBSPDM_STATUS_SUCCESS;
}
