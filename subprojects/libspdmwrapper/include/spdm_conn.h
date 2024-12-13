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

#ifndef _SPDM_CONN_H_
#define _SPDM_CONN_H_

#include "unistd.h"
#include "errno.h"
#include "sys/socket.h"
#include "pcie_doe.h"   /* struct pcie_dev */
#include "stdbool.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

typedef int SOCKET;

/* definition of libspdm_l1l2_managed_buffer_t */
#ifndef LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT
#define LIBSPDM_RECORD_TRANSCRIPT_DATA_SUPPORT 1
#endif

/* libspdm_return_t */
#include "internal/libspdm_common_lib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_return_status.h"

/* transport layer */
#define TRANSPORT_TYPE_NONE 0x00
#define TRANSPORT_TYPE_MCTP 0x01
#define TRANSPORT_TYPE_PCI_DOE 0x02
#define TRANSPORT_TYPE_TCP 0x03

#define LIBSPDM_TRANSPORT_HEADER_SIZE 64
#define LIBSPDM_TRANSPORT_TAIL_SIZE 64

/* define common LIBSPDM_TRANSPORT_ADDITIONAL_SIZE. It should be the biggest
 * one. */
#define LIBSPDM_TRANSPORT_ADDITIONAL_SIZE \
  (LIBSPDM_TRANSPORT_HEADER_SIZE + LIBSPDM_TRANSPORT_TAIL_SIZE)

#if LIBSPDM_TRANSPORT_ADDITIONAL_SIZE < LIBSPDM_NONE_TRANSPORT_ADDITIONAL_SIZE
#error LIBSPDM_TRANSPORT_ADDITIONAL_SIZE is smaller than the required size in NONE
#endif
#if LIBSPDM_TRANSPORT_ADDITIONAL_SIZE < LIBSPDM_TCP_TRANSPORT_ADDITIONAL_SIZE
#error LIBSPDM_TRANSPORT_ADDITIONAL_SIZE is smaller than the required size in TCP
#endif
#if LIBSPDM_TRANSPORT_ADDITIONAL_SIZE < \
    LIBSPDM_PCI_DOE_TRANSPORT_ADDITIONAL_SIZE
#error LIBSPDM_TRANSPORT_ADDITIONAL_SIZE is smaller than the required size in PCI_DOE
#endif
#if LIBSPDM_TRANSPORT_ADDITIONAL_SIZE < LIBSPDM_MCTP_TRANSPORT_ADDITIONAL_SIZE
#error LIBSPDM_TRANSPORT_ADDITIONAL_SIZE is smaller than the required size in MCTP
#endif

#ifndef LIBSPDM_SENDER_BUFFER_SIZE
#define LIBSPDM_SENDER_BUFFER_SIZE (0x1100 + LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif
#ifndef LIBSPDM_RECEIVER_BUFFER_SIZE
#define LIBSPDM_RECEIVER_BUFFER_SIZE \
  (0x1200 + LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#endif

/* Maximum size of a single SPDM message.
 * It matches DataTransferSize in SPDM specification. */
#define LIBSPDM_SENDER_DATA_TRANSFER_SIZE \
  (LIBSPDM_SENDER_BUFFER_SIZE - LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE \
  (LIBSPDM_RECEIVER_BUFFER_SIZE - LIBSPDM_TRANSPORT_ADDITIONAL_SIZE)
#define LIBSPDM_DATA_TRANSFER_SIZE LIBSPDM_RECEIVER_DATA_TRANSFER_SIZE

#if (LIBSPDM_SENDER_BUFFER_SIZE > LIBSPDM_RECEIVER_BUFFER_SIZE)
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_SENDER_BUFFER_SIZE
#else
#define LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE LIBSPDM_RECEIVER_BUFFER_SIZE
#endif

/* Maximum size of a large SPDM message.
 * If chunk is unsupported, it must be same as DATA_TRANSFER_SIZE.
 * If chunk is supported, it must be larger than DATA_TRANSFER_SIZE.
 * It matches MaxSPDMmsgSize in SPDM specification. */
#ifndef LIBSPDM_MAX_SPDM_MSG_SIZE
#define LIBSPDM_MAX_SPDM_MSG_SIZE 0x1200
#endif

#define MAX_MEASUREMENTS_BUF_SIZE 0x4000 /* TODO:16KB */
#define MAX_PCI_BDF_LEN       32
#define MAX_FNAME_LEN         41

#ifndef MCTP_MSG_TYPE_SPDM
#define MCTP_MSG_TYPE_SPDM    5
#endif

typedef uint8_t mctp_eid_t;
typedef uint8_t mctp_nid_t;

#define SPDM_INIT_MAX_CONN_RETRY_TIMES            5
#define MAX_REQUEST_RETRY_TIMES         5
#define REQUEST_RETRY_DELAY_TIME        10000    // 10ms delay

/* According to SPDM spec, RTT refers to the maximum value shall be the worst
 * case total time for the complete transmission and delivery of an SPDM
 * message round trip at the transport layer(s). The actual value for this
 * parameter is transport- or media-specific.
 */
#define DEFAULT_RTT                     2000000
/* 6 seconds to mitigate slow SPDM response (b/360923191, b/33526823) */
#define MCTP_RTT                        6000000
#define PCIE_DOE_RTT                    2000000

/**
 * struct spdm_connection manages connection with one device;
 * Each conn is associated with only one spdm_context. All the other "m_xxx"
 * variables are intermediate states cached by the connection.
 */
typedef struct spdm_connection {
  /* spdm settings */
  uint8_t m_use_version;
  uint8_t m_use_secured_message_version;

  /* connection status */
  bool is_connected;

  /* resource managed per connection */
  void *m_spdm_context;

  void *m_scratch_buffer;
  uint8_t m_receive_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
  uint8_t m_send_receive_buffer[LIBSPDM_MAX_SENDER_RECEIVER_BUFFER_SIZE];
  size_t m_send_receive_buffer_size;
  bool m_send_receive_buffer_acquired;

  /* pcie-doe specific fields */
  struct pcie_dev pdev;
  char dev_filename[MAX_FNAME_LEN];
  char doe_bdf[MAX_PCI_BDF_LEN];
  uint32_t m_doe_base_addr;

  /* mctp specific fields */
  mctp_eid_t mctp_eid;
  mctp_nid_t mctp_nid;
  SOCKET mctp_socket;

  /* connection should record its own transport/device layer handlers */
  uint32_t m_use_transport_layer;

  /* setting of algo, cap, sess, etc. */
  uint32_t m_use_requester_capability_flags;
  uint32_t m_use_peer_capability_flags;
  uint8_t m_use_basic_mut_auth;

  uint8_t m_use_measurement_summary_hash_type;
  uint8_t m_support_measurement_spec;
  uint32_t m_support_measurement_hash_algo;

  uint32_t m_support_hash_algo;
  uint32_t m_support_asym_algo;
  uint16_t m_support_req_asym_algo;
  uint16_t m_support_dhe_algo;
  uint16_t m_support_aead_algo;
  uint16_t m_support_key_schedule_algo;

  uint8_t m_support_other_params_support;

  uint8_t m_session_policy;
  uint8_t m_end_session_attributes;

  /* cached spdm states: alg, cert slot, etc. */
  uint8_t m_other_slot_id;

  uint32_t m_use_hash_algo;
  uint32_t m_use_measurement_hash_algo;
  uint32_t m_use_asym_algo;
  uint16_t m_use_req_asym_algo;

  /* L1L2 log buffer for measurements verification */
  libspdm_l1l2_managed_buffer_t l1l2;

  /* l1l2 cloned from libspdm before signature verification */
  libspdm_l1l2_managed_buffer_t clone_l1l2;
} spdm_conn_t;

/* transport layer specific config */
libspdm_return_t preconfig_spdm_connection_for_pcie_doe(spdm_conn_t *spdm_conn,
                                                        const char *doe_bdf);
libspdm_return_t preconfig_spdm_connection_for_mctp(spdm_conn_t *spdm_conn,
                                                    mctp_eid_t mctp_eid,
                                                    mctp_nid_t mctp_nid);
libspdm_return_t preconfig_spdm_connection_for_socket_emu_doe(
    spdm_conn_t *spdm_conn, uint16_t port_number);

/* transport layer neutral preconfig */
libspdm_return_t preconfig_spdm_connection_generic(spdm_conn_t *spdm_conn,
                                                   const char *minimum_mea_hash,
                                                   const char *minimum_asym);

/* manage spdm connection */
libspdm_return_t set_up_spdm_connection(spdm_conn_t *spdm_conn);
libspdm_return_t tear_down_spdm_connection(spdm_conn_t *spdm_conn);

/**
 * This function is called by the dbus daemon to get certificate from
 * device, according to SPDM spec, the cert from spdm responder is in DER
 * format.
 * @spdm_conn: spdm connection;
 * @cert_buf: buffer to hold der format cert;
 * @buf_len: buffer length, check if the coming cert can fit in the buffer;
 * @cert_len: set the actual length of cert;
 * @return: status: error if can't get cert or cert can't fit in cert_buf;
 */
libspdm_return_t spdm_cma_get_certificate(spdm_conn_t *spdm_conn,
                                          uint8_t *cert_buf, size_t buf_len,
                                          size_t *cert_len);

/**
 * This function is called by the dbus daemon to get signed measurements from
 * device.
 * @slot_id: slot Id of the certificate to be used for signing the measurements.
 * @nonce: a 32 byte nonce.
 * @indices: an array of index for the measurement blocks to be measured.
 * @indices_len: length of indices array.
 *
 * Note, L2 logged in spdm_conn->l1l2.
 */
libspdm_return_t spdm_cma_get_signed_measurements(spdm_conn_t *spdm_conn,
                                                  size_t slot_id,
                                                  uint8_t *nonce,
                                                  size_t *indices,
                                                  size_t indices_len);

#endif
