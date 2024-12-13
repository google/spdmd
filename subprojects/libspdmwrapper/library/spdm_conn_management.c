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

/* redo VERSION/CAPABILITIES/ALGORITHM cmds to reset L1/L2 */
libspdm_return_t spdm_do_vca(spdm_conn_t *spdm_conn) {
  libspdm_return_t status;
  int retry_cnt;

  do {
    status = libspdm_init_connection(
        spdm_conn->m_spdm_context,
        false /* GET_VERSION_ONLY */);
    if (!LIBSPDM_STATUS_IS_ERROR(status))
      break;
    else
      debug_log(LOG_ERR, "libspdm_init_connection error(retry cnt:%d):0x%x\n",
        retry_cnt, (uint32_t)status);
  } while (retry_cnt++ < SPDM_INIT_MAX_CONN_RETRY_TIMES);

  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    debug_log(LOG_ERR,
      "libspdm_init_connection error! retry reached max:%d, status: 0x%x\n",
      retry_cnt, (uint32_t)status);
    return status;
  }

  return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t set_up_spdm_connection(spdm_conn_t *spdm_conn) {
  void *spdm_context;
  libspdm_return_t status;
  libspdm_data_parameter_t parameter;
  uint8_t data8;
  uint16_t data16;
  uint32_t data32;
  uint64_t data64;
  size_t data_size;
  spdm_version_number_t spdm_version;
  size_t scratch_buffer_size;
  uint32_t responder_capabilities_flag;

  spdm_conn->m_spdm_context = (void *)malloc(libspdm_get_context_size());
  if (spdm_conn->m_spdm_context == NULL) {
    return LIBSPDM_STATUS_INVALID_PARAMETER;
  }
  spdm_context = spdm_conn->m_spdm_context;

  /**
   * linking conn to context so that device io functions can find
   * per-connection resources via context.
   */
  libspdm_init_context(spdm_context);
  ((libspdm_context_t *)spdm_context)->conn = spdm_conn;

  /**
   * To handle real device, send/recieve functions are specified here.
   */
  libspdm_register_device_io_func(spdm_context, spdm_device_send_message,
                                  spdm_device_receive_message);

  if (spdm_conn->m_use_transport_layer == TRANSPORT_TYPE_MCTP) {
    libspdm_register_transport_layer_func(
        spdm_context, LIBSPDM_MAX_SPDM_MSG_SIZE, LIBSPDM_TRANSPORT_HEADER_SIZE,
        LIBSPDM_TRANSPORT_TAIL_SIZE, libspdm_transport_mctp_encode_message,
        libspdm_transport_mctp_decode_message);
  } else if (spdm_conn->m_use_transport_layer ==
             TRANSPORT_TYPE_PCI_DOE) {
    libspdm_register_transport_layer_func(
        spdm_context, LIBSPDM_MAX_SPDM_MSG_SIZE, LIBSPDM_TRANSPORT_HEADER_SIZE,
        LIBSPDM_TRANSPORT_TAIL_SIZE, libspdm_transport_pci_doe_encode_message,
        libspdm_transport_pci_doe_decode_message);
  } else {
    status = LIBSPDM_STATUS_INVALID_PARAMETER;
    goto done;
  }
  libspdm_register_device_buffer_func(
      spdm_context, LIBSPDM_SENDER_BUFFER_SIZE, LIBSPDM_RECEIVER_BUFFER_SIZE,
      spdm_device_acquire_sender_buffer, spdm_device_release_sender_buffer,
      spdm_device_acquire_receiver_buffer, spdm_device_release_receiver_buffer);

  scratch_buffer_size =
      libspdm_get_sizeof_required_scratch_buffer(spdm_context);
  spdm_conn->m_scratch_buffer = (void *)malloc(scratch_buffer_size);
  if (spdm_conn->m_scratch_buffer == NULL) {
    status = LIBSPDM_STATUS_INVALID_PARAMETER;
    goto done;
  }
  libspdm_set_scratch_buffer(spdm_context, spdm_conn->m_scratch_buffer,
                             scratch_buffer_size);

  /* Initialize callback function to clone l1l2 buffer */
  ((libspdm_context_t *)spdm_context)->callback_clone_l1l2_with_sig =
      clone_l1l2_with_sig;

  if (!libspdm_check_context(spdm_context)) {
    status = LIBSPDM_STATUS_INVALID_PARAMETER;
    goto done;
  }

  if (spdm_conn->m_use_version != 0) {
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    spdm_version = spdm_conn->m_use_version << SPDM_VERSION_NUMBER_SHIFT_BIT;
    libspdm_set_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                     &spdm_version, sizeof(spdm_version));
  }

  libspdm_zero_mem(&parameter, sizeof(parameter));
  parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

  data8 = 0;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                   &parameter, &data8, sizeof(data8));
  data32 = spdm_conn->m_use_requester_capability_flags;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                   &data32, sizeof(data32));
  if (spdm_conn->m_use_transport_layer == TRANSPORT_TYPE_MCTP)
    data64 = MCTP_RTT;
  else if (spdm_conn->m_use_transport_layer == TRANSPORT_TYPE_PCI_DOE)
    data64 = PCIE_DOE_RTT;
  else
    data64 = DEFAULT_RTT;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_CAPABILITY_RTT_US,
                   &parameter, &data64, sizeof(data64));

  /* config max retry and delay_time */
  data8 = MAX_REQUEST_RETRY_TIMES;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_REQUEST_RETRY_TIMES, &parameter,
                   &data8, sizeof(data8));
  data64 = REQUEST_RETRY_DELAY_TIME;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_REQUEST_RETRY_DELAY_TIME, &parameter,
                   &data64, sizeof(data64));

  data8 = spdm_conn->m_support_measurement_spec;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                   &data8, sizeof(data8));
  data32 = spdm_conn->m_support_asym_algo;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                   &data32, sizeof(data32));
  data32 = spdm_conn->m_support_hash_algo;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                   &data32, sizeof(data32));
  data16 = spdm_conn->m_support_dhe_algo;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                   &data16, sizeof(data16));
  data16 = spdm_conn->m_support_aead_algo;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                   &data16, sizeof(data16));
  data16 = spdm_conn->m_support_req_asym_algo;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                   &data16, sizeof(data16));
  data16 = spdm_conn->m_support_key_schedule_algo;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter, &data16,
                   sizeof(data16));
  data8 = spdm_conn->m_support_other_params_support;
  libspdm_set_data(spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                   &data8, sizeof(data8));

  // spdm_tranport_init() assumes spdm_conn->spdm_context already initialized.
  status = spdm_transport_init(spdm_conn);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    debug_log(LOG_ERR, "Fail to set up spdm connection\n");
    goto done;
  }

  /**
   * TODO(b/360923191): mctp socket may timeout due to hardware issue,
   * implement retry logic here for spdm_do_vca.
   * spdm_do_vca will do VCA(Version/Capability/Algorithm);
   * SPDM command like VCA has its builtin retry for command failure.
   * This is an extra layer of mitigation when timeout happens.
   */
  status = spdm_do_vca(spdm_conn);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    debug_log(LOG_ERR,
      "libspdm_init_connection error! status: 0x%x\n", (uint32_t)status);
    goto done;
  }

  if (spdm_conn->m_use_version == 0) {
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    data_size = sizeof(spdm_version);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                     &spdm_version, &data_size);
    spdm_conn->m_use_version = spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT;
  }

  /*get responder_capabilities_flag*/
  libspdm_zero_mem(&parameter, sizeof(parameter));
  parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
  data_size = sizeof(data32);
  libspdm_get_data(spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                   &data32, &data_size);
  responder_capabilities_flag = data32;

  /* check responder supported capabilities */
  if (((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP &
       responder_capabilities_flag) == 0) ||
      ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP &
       responder_capabilities_flag) == 0) ||
      ((SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP &
       responder_capabilities_flag) == 0)) {
    debug_log(LOG_ERR, "Responder does not support CERT|CHAL|MEAS CAP!");
    status = LIBSPDM_STATUS_UNSUPPORTED_CAP;
    goto done;
  }

  data_size = sizeof(data32);
  libspdm_get_data(spdm_context, LIBSPDM_DATA_CONNECTION_STATE, &parameter,
                   &data32, &data_size);
  LIBSPDM_ASSERT(data32 == LIBSPDM_CONNECTION_STATE_NEGOTIATED);

  data_size = sizeof(data32);
  libspdm_get_data(spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO, &parameter,
                   &data32, &data_size);
  spdm_conn->m_use_measurement_hash_algo = data32;
  data_size = sizeof(data32);
  libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                   &data32, &data_size);
  spdm_conn->m_use_asym_algo = data32;
  data_size = sizeof(data32);
  libspdm_get_data(spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                   &data32, &data_size);
  spdm_conn->m_use_hash_algo = data32;
  data_size = sizeof(data16);
  libspdm_get_data(spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                   &data16, &data_size);
  spdm_conn->m_use_req_asym_algo = data16;

  return LIBSPDM_STATUS_SUCCESS;

done:
  if (spdm_conn->m_scratch_buffer != NULL) {
    free(spdm_conn->m_scratch_buffer);
    spdm_conn->m_scratch_buffer = NULL;
  }
  free(spdm_conn->m_spdm_context);
  spdm_conn->m_spdm_context = NULL;
  return status;
}

libspdm_return_t spdm_transport_init(spdm_conn_t *spdm_conn) {
  libspdm_return_t ret;
  spdm_conn->is_connected = false;

  if (spdm_conn->m_use_transport_layer == TRANSPORT_TYPE_PCI_DOE)
    ret = set_up_spdm_connection_for_doe(spdm_conn);
  else if (spdm_conn->m_use_transport_layer == TRANSPORT_TYPE_MCTP)
    ret = set_up_spdm_connection_for_mctp(spdm_conn);
  else {
    debug_log(LOG_ERR, "Unsupported transport protocol, only support DOE|MCTP!");
    ret = LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  if (ret == LIBSPDM_STATUS_SUCCESS) spdm_conn->is_connected = true;

  return ret;
}

libspdm_return_t tear_down_spdm_connection(spdm_conn_t *spdm_conn) {
  libspdm_return_t ret;

  if (spdm_conn->m_use_transport_layer == TRANSPORT_TYPE_PCI_DOE)
    ret = tear_down_spdm_connection_for_doe(spdm_conn);
  else if (spdm_conn->m_use_transport_layer == TRANSPORT_TYPE_MCTP)
    ret = tear_down_spdm_connection_for_mctp(spdm_conn);
  else {
    debug_log(LOG_ERR, "Unsupported transport protocol, only support DOE|MCTP!");
    ret = LIBSPDM_STATUS_INVALID_PARAMETER;
  }

  return ret;
}
