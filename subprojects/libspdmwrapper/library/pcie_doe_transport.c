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

#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "pcie_doe.h"
#include "spdm_conn.h"
#include "spdm_conn_internal.h"
#include "pcie_doe_transport.h"

static char *pci_filter_parse_slot(struct pcie_dev *f, char *str);

libspdm_return_t avy_pci_config_write_dw(spdm_conn_t *spdm_conn, uint64_t addr,
                                         uint32_t data) {
  if (spdm_conn == NULL) return LIBSPDM_STATUS_INVALID_PARAMETER;

  ssize_t num = pwrite(spdm_conn->pdev.pdev, &data, sizeof(uint32_t), addr);
  if (num == -1) return LIBSPDM_STATUS_INVALID_STATE_PEER;  // DOE write error

  return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t avy_pci_config_read_dw(spdm_conn_t *spdm_conn, uint64_t addr,
                                        uint32_t *data) {
  if (spdm_conn == NULL || data == NULL)
    return LIBSPDM_STATUS_INVALID_PARAMETER;

  ssize_t num = pread(spdm_conn->pdev.pdev, data, sizeof(uint32_t), addr);
  if (num == -1) return LIBSPDM_STATUS_INVALID_STATE_PEER;  // DOE read error

  return LIBSPDM_STATUS_SUCCESS;
}

#define SLEEP_TIME                  1000 /* usleep 1000 us */
#define MAX_DOE_STATUS_RETRY        6
libspdm_return_t spdm_device_send_message_doe(void *spdm_context,
                                              size_t request_size,
                                              const void *req,
                                              uint64_t UNUSED(timeout)) {
  spdm_conn_t *spdm_conn = ((libspdm_context_t *)spdm_context)->conn;
  libspdm_return_t pci_res;
  int32_t idx;
  uint32_t doe_status = 0;
  int count;

  count = 0;
  do {
    pci_res = avy_pci_config_read_dw(
      spdm_conn, spdm_conn->m_doe_base_addr + PCIE_DOE_STATUS, &doe_status);
    if (LIBSPDM_STATUS_IS_ERROR(pci_res)) {
      debug_log(LOG_ERR, "read DOE STATUS fail! status: 0x%x\n", pci_res);
      return pci_res;
    }

    if (doe_status & PCIE_DOE_STATUS_ERR) {
      debug_log(LOG_ERR, "Error in doe_status: %x\n", doe_status);
      return LIBSPDM_STATUS_INVALID_STATE_PEER;
    }

    usleep(SLEEP_TIME);
    if (++count > MAX_DOE_STATUS_RETRY) {
      debug_log(LOG_ERR, "Read reach max retry (%d)! doe_status: 0x%x!\n",
        MAX_DOE_STATUS_RETRY, doe_status);
      return LIBSPDM_STATUS_INVALID_STATE_PEER;
    }
  } while (doe_status & PCIE_DOE_STATUS_BUSY);

  for (idx = 0; idx < (int32_t)(request_size / 4); idx++) {
    pci_res = avy_pci_config_write_dw(
        spdm_conn, spdm_conn->m_doe_base_addr + PCIE_DOE_WR_DATA_MBOX,
        ((uint32_t *)req)[idx]);
    if (LIBSPDM_STATUS_IS_ERROR(pci_res)) {
      debug_log(LOG_ERR, "Write DOE MAILBOX fail with status: 0x%x!\n",
        pci_res);
      return pci_res;
    }
  }

  pci_res = avy_pci_config_write_dw(
      spdm_conn, spdm_conn->m_doe_base_addr + PCIE_DOE_CTRL, PCIE_DOE_CTRL_GO);
  if (LIBSPDM_STATUS_IS_ERROR(pci_res)) {
    debug_log(LOG_ERR, "Set GO bit fail with 0x%x\n", pci_res);
    return pci_res;
  }

  return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_device_receive_message_doe(void *spdm_context,
                                                 size_t *resp_size, void **resp,
                                                 uint64_t UNUSED(timeout)) {
  spdm_conn_t *spdm_conn = ((libspdm_context_t *)spdm_context)->conn;
  libspdm_return_t pci_res;
  uint32_t recv_buf[LIBSPDM_MAX_SPDM_MSG_SIZE];
  uint32_t recv_buf_cnt = 0, doe_status = 0;
  int count;

  count = 0;
  do {
    pci_res = avy_pci_config_read_dw(spdm_conn,
      spdm_conn->m_doe_base_addr + PCIE_DOE_STATUS, &doe_status);
    if (LIBSPDM_STATUS_IS_ERROR(pci_res)) {
      debug_log(LOG_ERR, "read DOE STATUS fail! status: 0x%x\n", pci_res);
      return pci_res;
    }

    usleep(SLEEP_TIME);
    if (++count > MAX_DOE_STATUS_RETRY) {
      debug_log(LOG_ERR, "Retry reach max(%d) times, doe_status: 0x%x!\n",
        MAX_DOE_STATUS_RETRY, doe_status);
      return LIBSPDM_STATUS_INVALID_STATE_PEER;
    }
  } while ((!(doe_status & PCIE_DOE_STATUS_DO_RDY)) ||
         (doe_status & PCIE_DOE_STATUS_BUSY));

  while (doe_status & PCIE_DOE_STATUS_DO_RDY) {
    pci_res = avy_pci_config_read_dw(
        spdm_conn, spdm_conn->m_doe_base_addr + PCIE_DOE_RD_DATA_MBOX,
        recv_buf + recv_buf_cnt);
    if (LIBSPDM_STATUS_IS_ERROR(pci_res)) {
      debug_log(LOG_ERR, "Read DOE_RD_DATA MBOX fail! status: 0x%x\n", pci_res);
      return pci_res;
    }

    recv_buf_cnt++;

    pci_res = avy_pci_config_write_dw(
        spdm_conn, spdm_conn->m_doe_base_addr + PCIE_DOE_RD_DATA_MBOX, 0x0);
    if (LIBSPDM_STATUS_IS_ERROR(pci_res)) {
      debug_log(LOG_ERR, "Write DOE_RD_DATA MBOX fail! status: 0x%x\n", pci_res);
      return pci_res;
    }

    pci_res = avy_pci_config_read_dw(
        spdm_conn, spdm_conn->m_doe_base_addr + PCIE_DOE_STATUS, &doe_status);
    if (LIBSPDM_STATUS_IS_ERROR(pci_res)) {
      debug_log(LOG_ERR, "read DOE STATUS fail! status: 0x%x\n", pci_res);
      return pci_res;
    }
  }

  *resp_size = recv_buf_cnt * 4;
  copy_mem(*resp, recv_buf, *resp_size);

  return LIBSPDM_STATUS_SUCCESS;
}

/* Ref: pciutils/lib/filter.c */
/* Slot filter syntax: [[[domain]:][bus]:][slot][.[func]] */
static char *pci_filter_parse_slot(struct pcie_dev *f, char *str) {
  char *colon = strrchr(str, ':');
  char *dot = strchr((colon ? colon + 1 : str), '.');
  char *mid = str;
  char *e, *bus, *colon2;

  if (colon) {
    *colon++ = 0;
    mid = colon;
    colon2 = strchr(str, ':');

    if (colon2) {
      *colon2++ = 0;
      bus = colon2;
      if (str[0] && strcmp(str, "*")) {
        long int x = strtol(str, &e, 16);
        if ((e && *e) || (x < 0 || x > 0x7fffffff)) {
          return "Invalid domain number";
        }
        f->domain = x;
      }
    } else
      bus = str;

    if (bus[0] && strcmp(bus, "*")) {
      long int x = strtol(bus, &e, 16);
      if ((e && *e) || (x < 0 || x > 0xff)) {
        return "Invalid bus number";
      }
      f->bus = x;
    }
  }

  if (dot) {
    *dot++ = 0;
  }

  if (mid[0] && strcmp(mid, "*")) {
    long int x = strtol(mid, &e, 16);
    if ((e && *e) || (x < 0 || x > 0x1f)) {
      return "Invalid slot number";
    }
    f->slot = x;
  }

  if (dot && dot[0] && strcmp(dot, "*")) {
    long int x = strtol(dot, &e, 16);
    if ((e && *e) || (x < 0 || x > 7)) {
      return "Invalid function number";
    }
    f->func = x;
  }
  return NULL;
}

/**
 * Parse pcie device bdf and get sysfs config path
 * Note, doe_bdf should be set up in spdm_conn data structure already.
 */
bool parse_pcie_doe_bdf(spdm_conn_t *spdm_conn) {
  if (spdm_conn == NULL) return false;

  char *err = pci_filter_parse_slot(&spdm_conn->pdev, spdm_conn->doe_bdf);
  if (err != NULL) {
    debug_log(LOG_ERR, "Error: %s\n", err);
    return false;
  }

  sprintf(spdm_conn->dev_filename,
          "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/config",
          spdm_conn->pdev.domain, spdm_conn->pdev.bus, spdm_conn->pdev.slot,
          spdm_conn->pdev.func);

  return true;
}

/**
 * For PCIe DOE, it does DOE discovery.
 */
libspdm_return_t set_up_spdm_connection_for_doe(spdm_conn_t *spdm_conn) {
  libspdm_return_t ret;
  size_t resp_size;
  uint32_t cap_offset = 0, pci_reg;
  bool protocol_found = false;
  bool bdf_parsed = false;

  DOE_DISCOVERY_REQUEST_MINE m_doe_req = {
      {
          PCI_DOE_VENDOR_ID_PCISIG, PCI_DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY, 0,
          sizeof(m_doe_req) / sizeof(uint32_t),  // Length
      },
      {
          0,  // Index
      },
  };

  /**
   * TODO(b/272309562)
   * For CXL MEM Type 3 Device on QEMU
   * BDF: 0000:0d:00.0
   * VID: 0x8086
   * DID: 0x0d93
   */
  if (spdm_conn->m_use_transport_layer == TRANSPORT_TYPE_PCI_DOE) {
    bdf_parsed = parse_pcie_doe_bdf(spdm_conn);
    if (!bdf_parsed) return LIBSPDM_STATUS_INVALID_PARAMETER;

    spdm_conn->pdev.pdev = open(spdm_conn->dev_filename, O_RDWR);
    if (spdm_conn->pdev.pdev < 0) {
      debug_log(LOG_ERR, "Fail to open %s\n", spdm_conn->dev_filename);
      return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    DOE_DISCOVERY_RESPONSE_MINE doe_resp = {0};
    void *doe_resp_ptr = &doe_resp;

    for (cap_offset = PCIE_EXT_CAP_OFFSET; cap_offset;
         cap_offset = PCI_EXT_CAP_NEXT(pci_reg)) {
      ret = avy_pci_config_read_dw(spdm_conn, cap_offset, &pci_reg);
      if (LIBSPDM_STATUS_IS_ERROR(ret)) {
        debug_log(LOG_ERR, "Config Read error, ret:0x%x\n", ret);
        goto done;
      }

      if (PCI_EXT_CAP_ID(pci_reg) == PCI_EXT_CAP_ID_DOE) {
        spdm_conn->m_doe_base_addr = cap_offset;

        // DOE Discovery
        do {
          ret = spdm_device_send_message_doe(spdm_conn->m_spdm_context,
                                       sizeof(m_doe_req), &m_doe_req, 0);
          if (LIBSPDM_STATUS_IS_ERROR(ret)) {
            debug_log(LOG_ERR, "spdm_device_send_message error, ret:0x%x\n", ret);
            break;
          }

          ret = spdm_device_receive_message_doe(spdm_conn->m_spdm_context, &resp_size,
                                          &doe_resp_ptr, 0);
          if (LIBSPDM_STATUS_IS_ERROR(ret)) {
            debug_log(LOG_ERR, "spdm_device_receive_message error, ret:0x%x\n", ret);
            break;
          }

          if (doe_resp_ptr != NULL) {
            debug_log(LOG_ERR, "DOE Response vendor=%d obj_type=%d\n",
                      (int)doe_resp.DoeHeader.VendorId,
                      (int)doe_resp.DoeDiscoveryResponse.data_object_type);

            if (doe_resp.DoeHeader.VendorId == PCI_DOE_VENDOR_ID_PCISIG &&
                doe_resp.DoeDiscoveryResponse.data_object_type ==
                    PCI_DOE_DATA_OBJECT_TYPE_SECURED_SPDM) {
              protocol_found = true;
              break;
            }

            m_doe_req.DoeDiscoveryRequest.index =
                doe_resp.DoeDiscoveryResponse.next_index;
          }
        } while (doe_resp_ptr != NULL &&
                 doe_resp.DoeDiscoveryResponse.next_index != 0);

        if (protocol_found) {
          break;
        }
      }  // end-of-if PCI_EXT_CAP_ID_DOE
    }  // end-of-for

    if (!spdm_conn->m_doe_base_addr) {
      debug_log(LOG_ERR, "DOE Capability not found\n");
      goto done;
    } else if (!protocol_found) {
      debug_log(LOG_ERR, "SPDM protocol not found\n");
      goto done;
    }
  }  // end-of-if TRANSPORT_TYPE_PCI_DOE

  return LIBSPDM_STATUS_SUCCESS;

done:
  return LIBSPDM_STATUS_INVALID_STATE_PEER;
}

libspdm_return_t tear_down_spdm_connection_for_doe(spdm_conn_t *spdm_conn) {
  if (spdm_conn == NULL)
    return LIBSPDM_STATUS_INVALID_PARAMETER;

  // close doe device file
  if (spdm_conn->dev_filename[0] != '\0') {
    if (close(spdm_conn->pdev.pdev) == -1) {
      debug_log(LOG_ERR, "close doe dev file failed! errno: 0x%x\n", errno);
    }
  }

  // free memory buffer for context
  if (spdm_conn->m_spdm_context != NULL) {
    libspdm_deinit_context(spdm_conn->m_spdm_context);
    free(spdm_conn->m_spdm_context);
  }

  // free memory buffer for scratch buffer
  if (spdm_conn->m_scratch_buffer != NULL)
    free(spdm_conn->m_scratch_buffer);

  free(spdm_conn);

  return LIBSPDM_STATUS_SUCCESS;
}
