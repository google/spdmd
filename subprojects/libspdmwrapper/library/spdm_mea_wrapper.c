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
 * calculate l1l2 with external log buffer.
 */
bool spdm_cma_calculate_l1l2_with_msg_log(libspdm_context_t *spdm_context,
                                          void *msg_log_buffer,
                                          size_t buffer_size,
                                          libspdm_l1l2_managed_buffer_t *l1l2) {
  libspdm_return_t status;

  libspdm_init_managed_buffer(l1l2, sizeof(l1l2->buffer));

  if ((spdm_context->connection_info.version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >
      SPDM_MESSAGE_VERSION_11) {
    /* Need append VCA since 1.2 script*/

    // debug_log(LOG_ERR, "message_a data :\n");
    // LIBSPDM_INTERNAL_DUMP_HEX(
    //    libspdm_get_managed_buffer(&spdm_context->transcript.message_a),
    //    libspdm_get_managed_buffer_size(&spdm_context->transcript.message_a));
    status = libspdm_append_managed_buffer(
        l1l2, libspdm_get_managed_buffer(&spdm_context->transcript.message_a),
        libspdm_get_managed_buffer_size(&spdm_context->transcript.message_a));
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
      debug_log(LOG_ERR, "calculate l1l2 failed! append message_a error!");
      return false;
    }
  }

  status = libspdm_append_managed_buffer(l1l2, msg_log_buffer, buffer_size);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    debug_log(LOG_ERR, "calculate l1l2 failed! append msg log buffer error!");
    return false;
  }

  return true;
}

/**
 * Note, an external verifier may not trust the spdm requester running on BMC,
 * and would like to verify the L1L2 by themselves. That's why an externally
 * provided nonce is provided here.
 * libspdm_get_measurements() will do the verification of measurements
 * signature and clear the message_m buffer after internal verification.
 * see library/spdm_requester_lib/libspdm_req_get_measurements.c#L452C9-L452C61.
 * To support external verifier, we need to record the measurements messages
 * by ourselve and build the l1l2 by ourselve, too.
 * Refer to libspdm/library/spdm_common_lib/libspdm_com_crypto_service.c#L195
 * for l1l2 calculation. We mimic it to calculate l1l2 based on our message
 * buffer.
 * This function is called by the dbus daemon to get signed measurements from
 * device.
 * @slot_id: slot Id of the certificate to be used for signing the measurements.
 * @nonce: a 32 byte nonce.
 * @indices: an array of index for the measurement blocks to be measured.
 * @indices_len: length of indices array.
 */
libspdm_return_t spdm_cma_get_signed_measurements(spdm_conn_t *conn,
                                                  size_t slot_id,
                                                  uint8_t *nonce,
                                                  size_t *indices,
                                                  size_t indices_len) {
  void *context;
  libspdm_return_t status;

  uint8_t i;
  uint8_t number_of_block;
  uint32_t received_number_of_block;
  uint32_t one_measurement_record_length;
  uint8_t one_measurement_record[LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
  uint8_t request_attribute;
  uint8_t requester_nonce_in[SPDM_NONCE_SIZE];
  uint8_t requester_nonce[SPDM_NONCE_SIZE];
  uint8_t responder_nonce[SPDM_NONCE_SIZE];
  uint8_t opaque_data[SPDM_MAX_OPAQUE_DATA_SIZE];
  size_t opaque_data_size = sizeof(opaque_data);

  /* log buffer for external verification */
  bool result;
  uint8_t msg_log_buffer[8 * LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE];
  size_t log_buffer_size;

  /**
   * nonce can be NULL according to Redfish SPEC DSP2046 v2022.3
   * libspdm will generate one if not provided here.
   */
  if (!indices || indices_len == 0) {
    debug_log(LOG_ERR, "%s: unexpected parameters\n", __func__);
    status = LIBSPDM_STATUS_INVALID_PARAMETER;
    return status;
  }

  /**
   * libspdm_init_connection will do VCA(Version/Capability/Algorithm)
   * For now, remote verifier may want to send measurements request
   * continuously, however, SPDM responder won't reset L1/L2 buffer if no VCA
   * is exchanged between every sequence of GET_MEASUREMENTS requests.
   * Redo VCA here to reset transcript buffer on the fw side.
   * Note, it gets clarified that in SPDM1.4, the completion of
   * GET_MEASUREMENTS w/ signature will reinitialize L1/L2 calculation.
   * https://github.com/DMTF/libspdm/issues/2726
   */
  status = spdm_do_vca(conn);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    debug_log(LOG_ERR, "%s: re-initialize SPDM Connection(redo VCA) Failed!\n",
               __func__);
    return status;
  }

  context = conn->m_spdm_context;

  /*
   * 0
   * SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED
   */
  request_attribute = 0;

  /* initialize log buffer and start logging */
  libspdm_init_msg_log(context, msg_log_buffer, sizeof(msg_log_buffer));
  libspdm_set_msg_log_mode(context, LIBSPDM_MSG_LOG_MODE_ENABLE);

  uint8_t max_number_of_block = 0;
  /**
   * query the total number of blocks available and check whether the requested
   * indices are within the range.
   */
  status = libspdm_get_measurement(
      context, NULL, request_attribute,
      SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
      slot_id & 0xF, NULL, &number_of_block, NULL, NULL);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    debug_log(LOG_ERR, "Get measurement block num failed! status:0x%x\n", status);
    goto done;
  }
  /* Note, number_of_block will be overwrite for each get_measurement call */
  max_number_of_block = number_of_block;

  received_number_of_block = 0;
  for (i = 0; i < indices_len; i++) {
    /**
     * check index range:
     *   0: reserved for query number of measurement block, see SPDM spec;
     *   255 is also valid for requesting all measurement blocks
     *   1 - N: valid (2 <= N <= 254);
     *   N+ : invalid (exclude 255).
     */
    if (indices[i] == 0 ||
           (indices[i] != 0xff && indices[i] > max_number_of_block))
    {
      debug_log(LOG_ERR, "Error! Invalid measurement block index: %u max: %d\n",
        indices[i], max_number_of_block);
      status = LIBSPDM_STATUS_INVALID_PARAMETER;
      break;
    }

    /* 2. query measurement one by one
     * get signature in last message only.
     * For SPDM 1.1, L1L2 does not include VCA.
     * Note, according to SPDM Spec 1.2 & 1.3
     * (see
     * https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.3.0.pdf,
     * P116, L516) Signature = SPDMsign(PrivKey, L1, "measurements signing");
     * Where L1/L2 = Concatenate(VCA, GET_MEASUREMENTS_REQUEST1,
     * MEASUREMENTS_RESPONSE1, ..., GET_MEASUREMENTS_REQUESTn-1,
     * MEASUREMENTS_RESPONSEn-1, GET_MEASUREMENTS_REQUESTn,
     * MEASUREMENTS_RESPONSEn) REQ1 - REQn-1 no signature required REQn
     * signature required We return the whole L2 back to Notar for verification.
     */
    one_measurement_record_length = sizeof(one_measurement_record);
    if (i == indices_len - 1) {
      /* generate signature with designated nonce */
      request_attribute =
          SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;

      /* initialize nonce */
      for (int index = 0; index < SPDM_NONCE_SIZE; index++) {
        requester_nonce[index] = 0x00;
        responder_nonce[index] = 0x00;
      }

      /* copy nonce if it is provided, otherwise it will be generated by
       * libspdm */
      if (nonce != NULL) {
        for (int index = 0; index < SPDM_NONCE_SIZE; index++)
            requester_nonce_in[index] = nonce[index];
      }

      status = libspdm_get_measurement_ex(
          context, NULL, request_attribute, indices[i], slot_id & 0xF, NULL,
          &number_of_block, &one_measurement_record_length,
          one_measurement_record, (nonce == NULL) ? NULL: requester_nonce_in,
          requester_nonce, responder_nonce, opaque_data, &opaque_data_size);

      if (LIBSPDM_STATUS_IS_ERROR(status)) {
        if (status == LIBSPDM_STATUS_VERIF_FAIL ||
          status == LIBSPDM_STATUS_VERIF_NO_AUTHORITY) {
          debug_log(LOG_ERR, "Measurements format error here, ignore it!\n");
        } else {
          debug_log(LOG_ERR, "libspdm_get_measurement_ex non-format err:0x%x, i:%d, len:%d!\n",
            status, i, indices_len);
          break;
        }
      }
    } else {
      status = libspdm_get_measurement(
          context, NULL, request_attribute, indices[i], slot_id & 0xF, NULL,
          &number_of_block, &one_measurement_record_length,
          one_measurement_record);

      if (LIBSPDM_STATUS_IS_ERROR(status)) {
          debug_log(LOG_ERR, "get measurement failed, i:%d, indices_len:%d!\n", i,
            indices_len);
        break;
      }
    }

    received_number_of_block += 1;
  }

  if (received_number_of_block != indices_len) {
    debug_log(LOG_ERR, "get measurement failed! not receiving all blocks "
      "#block:%d, indices_len:%d!\n", received_number_of_block, indices_len);
    goto done;
  }

  /* get log size */
  log_buffer_size = libspdm_get_msg_log_size(context);

  result = spdm_cma_calculate_l1l2_with_msg_log(context, msg_log_buffer,
                                                log_buffer_size, &conn->l1l2);
  if (!result) {
    status = LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    debug_log(LOG_ERR, "calculate l1l2 failed!");
    goto done;
  }

  /* Note, we can safely return here. All we need from get measurements is
   * the conn->l1l2 Log, which can be calculated from spdm_context. */
  status = LIBSPDM_STATUS_SUCCESS;

done:
  /* stop logging */
  libspdm_reset_msg_log(context);

  return status;
}
