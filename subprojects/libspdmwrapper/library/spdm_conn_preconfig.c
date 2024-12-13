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

libspdm_return_t preconfig_spdm_connection_for_pcie_doe(spdm_conn_t *spdm_conn,
                                                        const char *doe_bdf) {
  size_t len;
  if (spdm_conn == NULL || doe_bdf == NULL)
    return LIBSPDM_STATUS_INVALID_PARAMETER;

  len = strlen(doe_bdf);
  if (len > MAX_PCI_BDF_LEN) {
    debug_log(LOG_ERR, "%s: doe_bdf exceeds MAX_PCI_BDF_LEN!\n", __func__);
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  strcpy(spdm_conn->doe_bdf, doe_bdf);
  spdm_conn->m_use_transport_layer = TRANSPORT_TYPE_PCI_DOE;

  return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t preconfig_spdm_connection_for_mctp(spdm_conn_t *spdm_conn,
                                                    mctp_eid_t mctp_eid,
                                                    mctp_nid_t mctp_nid) {
  if (spdm_conn == NULL) return LIBSPDM_STATUS_INVALID_PARAMETER;

  spdm_conn->mctp_eid = mctp_eid;
  spdm_conn->mctp_nid = mctp_nid;
  spdm_conn->m_use_transport_layer = TRANSPORT_TYPE_MCTP;
  return LIBSPDM_STATUS_SUCCESS;
}

// code snippets from DMTF spdm-emu
// https://github.com/DMTF/spdm-emu/blob/main/spdm_emu/spdm_emu_common/spdm_emu.c
typedef struct {
  uint32_t value;
  char *name;
} value_string_entry_t;

value_string_entry_t m_measurement_hash_value_string_table[] = {
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY, "RAW_BIT"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, "SHA_256"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384, "SHA_384"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512, "SHA_512"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256, "SHA3_256"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384, "SHA3_384"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512, "SHA3_512"},
    {SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256, "SM3_256"},
};

value_string_entry_t m_asym_value_string_table[] = {
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048, "RSASSA_2048"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072, "RSASSA_3072"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096, "RSASSA_4096"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048, "RSAPSS_2048"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072, "RSAPSS_3072"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096, "RSAPSS_4096"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256, "ECDSA_P256"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384, "ECDSA_P384"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521, "ECDSA_P521"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256, "SM2_P256"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519, "EDDSA_25519"},
    {SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448, "EDDSA_448"},
};

bool get_value_from_name(const value_string_entry_t *table, size_t entry_count,
                         const char *name, uint32_t *value) {
  size_t index;

  for (index = 0; index < entry_count; index++) {
    if (strcmp(name, table[index].name) == 0) {
      *value = table[index].value;
      return true;
    }
  }
  return false;
}

/**
 * Configure requester's version/cap/etc before setting up the spdm
 * connection. No transport-layer specific config here.
 * Note, hardcode config for now, should switch to config file.
 */
libspdm_return_t preconfig_spdm_connection_generic(spdm_conn_t *spdm_conn,
                                                   const char *minimum_mea_hash,
                                                   const char *minimum_asym) {
  uint32_t m_use_measurement_hash, m_use_asym_algo;

  /* set default minimum requirements for SPDM measurement hash and asym algo */
  m_use_measurement_hash =
      SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384;

  m_use_asym_algo = SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384;

  if (minimum_mea_hash != NULL &&
      !get_value_from_name(
          m_measurement_hash_value_string_table,
          LIBSPDM_ARRAY_SIZE(m_measurement_hash_value_string_table),
          minimum_mea_hash, &m_use_measurement_hash)) {
    debug_log(LOG_ERR, "Failed to get minimum requirement for measurement hash!\n");
    debug_log(LOG_ERR, "Use default: TPM_ALG_SHA_384! \n");
  }

  if (minimum_asym != NULL &&
      !get_value_from_name(m_asym_value_string_table,
                           LIBSPDM_ARRAY_SIZE(m_asym_value_string_table),
                           minimum_asym, &m_use_asym_algo)) {
    debug_log(LOG_ERR, "Failed to get minimum requirement for asym algo!\n");
    debug_log(LOG_ERR, "Use default: ECDSA_ECC_NIST_P384! \n");
  }

  spdm_conn->m_use_version = SPDM_MESSAGE_VERSION_11;
  spdm_conn->m_use_secured_message_version = 0;

  /* resource buffer status initlization */
  spdm_conn->m_send_receive_buffer_acquired = false;

  spdm_conn->m_use_requester_capability_flags =
      (0 |
       /* conflict with
        *   SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP
        */
       SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
       SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP |
       /* SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP |
       SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP |
       SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP |
       SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP |
       SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER |
       SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP |
       SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP |
       SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP |
       SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP |
       SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP | */
       /* SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP |
          conflict with
          SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP   */
       0);

  spdm_conn->m_use_peer_capability_flags = 0;
  /*
   * 0
   * 1
   */
  spdm_conn->m_use_basic_mut_auth = 0;

  /*
   * SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH,
   * SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH,
   * SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH
   */
  spdm_conn->m_use_measurement_summary_hash_type =
      SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH;

  /*
   * SPDM_MEASUREMENT_SPECIFICATION_DMTF,
   */
  spdm_conn->m_support_measurement_spec = SPDM_MEASUREMENT_SPECIFICATION_DMTF;
  /* SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512,
   * SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384,
   * SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256,
   * SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512,
   * SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384,
   * SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256,
   * SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY,
   */
  // m_use_measurement_hash;
  spdm_conn->m_support_measurement_hash_algo =
      SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512 |
      SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384 |
      SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256;

  /*
   * SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512,
   * SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384,
   * SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256,
   */
  spdm_conn->m_support_hash_algo =
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512 |
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384 |
      SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256;

  /*
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
   */
  spdm_conn->m_support_asym_algo =
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096 |
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  //    m_use_asym_algo;

  /*
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
   * SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
   */
  spdm_conn->m_support_req_asym_algo =
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072 |
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048 |
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072 |
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048 |
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384 |
      SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256;
  /*
   * SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096,
   * SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072,
   * SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048,
   * SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1,
   * SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1,
   * SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1,
   */
  spdm_conn->m_support_dhe_algo = SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1 |
                                  SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1 |
                                  SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072 |
                                  SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048;
  /*
   * SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM,
   * SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM,
   * SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305,
   */
  spdm_conn->m_support_aead_algo =
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM |
      SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305;
  /*
   * SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH,
   */
  spdm_conn->m_support_key_schedule_algo =
      SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH;
  /*
   * SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1,
   */
  spdm_conn->m_support_other_params_support =
      SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;

  spdm_conn->m_session_policy =
      SPDM_KEY_EXCHANGE_REQUEST_SESSION_POLICY_TERMINATION_POLICY_RUNTIME_UPDATE;

  spdm_conn->m_end_session_attributes =
      SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR;

  debug_log(LOG_INFO, "cap flags: 0x%x\n", spdm_conn->m_use_requester_capability_flags);

  return LIBSPDM_STATUS_SUCCESS;
}
