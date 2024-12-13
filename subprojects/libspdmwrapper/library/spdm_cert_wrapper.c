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
                                          size_t *cert_len) {
  libspdm_return_t status;
  void *context;

  uint8_t slot_mask;
  uint8_t slot_id;
  uint8_t total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];
  size_t cert_chain_size;
  uint8_t cert_chain[LIBSPDM_MAX_CERT_CHAIN_SIZE];
  uint8_t index;
  size_t hash_size = 0;

  context = spdm_conn->m_spdm_context;

  status = spdm_do_vca(spdm_conn);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    debug_log(LOG_ERR, "%s: re-initialize SPDM Connection(redo VCA) Failed!\n",
               __func__);
    return status;
  }

#if (LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)

  libspdm_zero_mem(total_digest_buffer, sizeof(total_digest_buffer));
  cert_chain_size = sizeof(cert_chain);
  libspdm_zero_mem(cert_chain, sizeof(cert_chain));

  // Do not retry for get digest as it may mess up the device states, retry
  // spdm_cma_get_certificate() function. 
  status = libspdm_get_digest(context, NULL, &slot_mask, total_digest_buffer);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    debug_log(LOG_ERR,
      "Error with get digest, status: 0x%x!\n", status);
    return status;
  }

  // Initialize m_other_slot_id as 0 (invalid) to make sure it does not pick up
  // random value if the system does not use other slot id
  spdm_conn->m_other_slot_id = 0;
  for (index = 1; index < SPDM_MAX_SLOT_COUNT; index++) {
    if ((slot_mask & (1 << index)) != 0) {
      spdm_conn->m_other_slot_id = index;
    }
  }

  /* non-zero other slot id override slot 0 */
  slot_id = 0;
  if(spdm_conn->m_other_slot_id != 0)
    slot_id = spdm_conn->m_other_slot_id;

  status = libspdm_get_certificate(context, NULL, slot_id, &cert_chain_size,
                                   cert_chain);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    debug_log(LOG_ERR,
      "Error: get certificate status 0x%x!, slot id: %d\n", status, slot_id);

    /**
     * Upload certchain to the remote verifier even if we see cert
     * format or integrity error.
     */
    if (status == LIBSPDM_STATUS_VERIF_FAIL ||
      status == LIBSPDM_STATUS_VERIF_NO_AUTHORITY) {
      debug_log(LOG_ERR, "Cert format error here, ignore it!\n");
    } else {
      debug_log(LOG_ERR, "Non-format cert error, can't ignore!\n");
      return status;
    }
  }

  /**
   * Extract DER formatted cert data from spdm response.
   * cert_chain format
   * | Length(2) | Reserved(2) | RootHash(H) | Certificates |
   */
  hash_size = libspdm_get_hash_size(spdm_conn->m_use_hash_algo);

  if (cert_buf == NULL || cert_len == NULL || buf_len == 0 ||
      cert_chain_size > buf_len) {
    debug_log(LOG_ERR, 
        "Error: cert can't fit in cert_buf! cert_buf: %p, cert_len:%p, "
        "buf_len:%lu, cert_chain_size:%lu\n",
        (void *)cert_buf, (void *)cert_len, buf_len, cert_chain_size);
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  memcpy(cert_buf, cert_chain + 4 + hash_size, cert_chain_size - 4 - hash_size);

  *cert_len = cert_chain_size - 4 - hash_size;
#endif /*(LIBSPDM_ENABLE_CAPABILITY_CERT_CAP && \
          LIBSPDM_ENABLE_CAPABILITY_CHAL_CAP)*/

  return LIBSPDM_STATUS_SUCCESS;
}
