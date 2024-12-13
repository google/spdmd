// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <dirent.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <stdlib.h>
#include <string.h>

#include <format>
#include <fstream>
#include <sstream>
#include <tuple>
#include <vector>

extern "C" {
#include <pcie_doe.h>
#include <spdm_conn.h>
#include <spdm_conn_internal.h>
#include <pcie_doe_transport.h>

// TODO: IF VENDOR FOO SUPPORT LOOPBACK, REPLACE VENDOR ID WITH FOO VENDOR ID
#define PCI_DOE_VENDOR_ID_FOO                    0xabcd
#define PCI_DOE_DATA_OBJECT_TYPE_FOO_LOOPBACK    0

// Test Loopback: bytes in, same bytes out.
#define LOOPBACK_TEST_DATA_SIZE  0x100  // 256 bytes, DOE aligned

// random uint8_t number for test
#define LOOPBACK_FIRST_BYTE      101
#define LOOPBACK_LAST_BYTE       121

typedef struct {
  uint8_t loopback_req[LOOPBACK_TEST_DATA_SIZE];
} pci_doe_loopback_request_t;

typedef struct {
  uint8_t loopback_resp[LOOPBACK_TEST_DATA_SIZE];
} pci_doe_loopback_response_t;

typedef struct {
  PCI_DOE_DATA_OBJECT_HEADER DoeHeader;
  pci_doe_loopback_request_t DoeLoopbackRequest;
} DOE_LOOPBACK_REQUEST_MINE;

typedef struct {
  PCI_DOE_DATA_OBJECT_HEADER DoeHeader;
  pci_doe_loopback_response_t DoeLoopbackResponse;
} DOE_LOOPBACK_RESPONSE_MINE;

/**
 * When testing on QEMU with emulated DOE, which does not support DOE
 * LOOPBACK, it waits on config read forever!
 */
libspdm_return_t doe_discovery_loopback(spdm_conn_t* spdm_conn) {
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
          0,         /* Index */
          {0, 0, 0}, /* Reserved uint8[3] : all initialized to 0 */
      },
  };

  if (spdm_conn->m_use_transport_layer == SOCKET_TRANSPORT_TYPE_PCI_DOE) {
    bdf_parsed = parse_pcie_doe_bdf(spdm_conn);
    if (!bdf_parsed) return LIBSPDM_STATUS_INVALID_PARAMETER;

    spdm_conn->pdev.pdev = open(spdm_conn->dev_filename, O_RDWR);
    if (spdm_conn->pdev.pdev < 0) {
      debug_log(LOG_ERR, "Fail to open %s\n", spdm_conn->dev_filename);
      return LIBSPDM_STATUS_INVALID_PARAMETER;
    }

    DOE_DISCOVERY_RESPONSE_MINE doe_resp = {};
    void* doe_resp_ptr = &doe_resp;

    for (cap_offset = PCIE_EXT_CAP_OFFSET; cap_offset;
         cap_offset = PCI_EXT_CAP_NEXT(pci_reg)) {
      ret = avy_pci_config_read_dw(spdm_conn, cap_offset, &pci_reg);
      if (LIBSPDM_STATUS_IS_ERROR(ret)) {
        debug_log(LOG_ERR, "Config read error, ret:0x%x\n", ret);
        return LIBSPDM_STATUS_INVALID_STATE_PEER;
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
            debug_log(LOG_INFO, "DOE Response vendor=%d obj_type=%d\n",
                   (int)doe_resp.DoeDiscoveryResponse.vendor_id,
                   (int)doe_resp.DoeDiscoveryResponse.data_object_type);

            // Loopback found
            if (doe_resp.DoeDiscoveryResponse.vendor_id == PCI_DOE_VENDOR_ID_FOO &&
                doe_resp.DoeDiscoveryResponse.data_object_type ==
                    PCI_DOE_DATA_OBJECT_TYPE_FOO_LOOPBACK) {
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
      return LIBSPDM_STATUS_INVALID_STATE_PEER;
    } else if (!protocol_found) {
      debug_log(LOG_ERR, "Loopback protocol not found\n");
      return LIBSPDM_STATUS_INVALID_STATE_PEER;
    }
  }  // end-of-if SOCKET_TRANSPORT_TYPE_PCI_DOE

  return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t doe_loopback_test(spdm_conn_t* spdm_conn) {
  uint8_t *preq, *presp;
  size_t resp_size, i;
  bool matched = false;
  libspdm_return_t ret;

  DOE_LOOPBACK_REQUEST_MINE m_doe_req = {
      {
          PCI_DOE_VENDOR_ID_FOO, PCI_DOE_DATA_OBJECT_TYPE_FOO_LOOPBACK, 0,
          sizeof(m_doe_req) / sizeof(uint32_t),  // Length
      },
      {},  // data initialized to zeroes
  };
  DOE_LOOPBACK_RESPONSE_MINE doe_resp = {};
  void* doe_resp_ptr = &doe_resp;

  // set magic value in request, loopback response expect the same value
  m_doe_req.DoeLoopbackRequest.loopback_req[0] = LOOPBACK_FIRST_BYTE;
  m_doe_req.DoeLoopbackRequest.loopback_req[LOOPBACK_TEST_DATA_SIZE - 1] =
      LOOPBACK_LAST_BYTE;

  ret = spdm_device_send_message_doe(spdm_conn->m_spdm_context, sizeof(m_doe_req),
                               &m_doe_req, 0);
  if (LIBSPDM_STATUS_IS_ERROR(ret)) {
    debug_log(LOG_ERR, "spdm_device_send_message error, ret:0x%x\n", ret);
    return ret;
  }

  ret = spdm_device_receive_message_doe(spdm_conn->m_spdm_context, &resp_size,
                                  &doe_resp_ptr, 0);
  if (LIBSPDM_STATUS_IS_ERROR(ret)) {
    debug_log(LOG_ERR, "spdm_device_receive_message error, ret:0x%x\n", ret);
    return ret;
  }

  matched = false;
  if (doe_resp_ptr != NULL) {
    if (resp_size == sizeof(m_doe_req)) {  // check response size
      preq = (uint8_t*)&m_doe_req;
      presp = static_cast<uint8_t*>(doe_resp_ptr);
      matched = true;
      for (i = 0; i < resp_size; i++) {  // check response content
        debug_log(LOG_INFO, " idx: 0x%lx, req: 0x%x, resp: 0x%x  \n", i, preq[i], presp[i]);
        if (preq[i] != presp[i]) {
          matched = false;
        }
      }
    } else {
      matched = false;

      debug_log(LOG_ERR, "resp_size(0x%lx) and resq length(0x%lx) not equal!\n", resp_size, sizeof(m_doe_req));

      preq = (uint8_t*)&m_doe_req;
      presp = static_cast<uint8_t*>(doe_resp_ptr);
      // check response content
      for (i = 0; i < resp_size || i < sizeof(m_doe_req); i++) {
        if (i < resp_size && i < sizeof(m_doe_req)) {
          debug_log(LOG_ERR, " idx: 0x%lx, req: 0x%x, resp: 0x%x  \n", i, preq[i], presp[i]);
        } else if (i < resp_size && i >= sizeof(m_doe_req))  {
          // resp_size > req_lengh
          debug_log(LOG_ERR, " idx: 0x%lx, req: N/A, resp: 0x%x  \n", i, presp[i]);
        } else if (i >= resp_size && i < sizeof(m_doe_req))  {
          // resp_size > req_lengh
          debug_log(LOG_ERR, " idx: 0x%lx, req: 0x%x, resp: N/A  \n", i, preq[i]);
        } else {
          debug_log(LOG_ERR, " should not reach here!\n");
        }
      }
    }
  }

  if (matched)
    return LIBSPDM_STATUS_SUCCESS;
  else
    return LIBSPDM_STATUS_INVALID_STATE_PEER;
} // doe_loopback_test

} // end-of-extern "C"

constexpr const char* SpdmMeasurementHash = "SHA_384";
constexpr const char* SpdmAsymAlgo = "ECDSA_P384";
// QEMU CXL DOE Emulation PF0 8086:0d93
// TODO: Add Device VendorId:DeviceId here so that they can be detected
// by this test.
constexpr const char* DOEVidDidList = "8086:0d93";

using namespace std;

// return a list of tuples (vendorId, deviceId)
vector<tuple<uint16_t, uint16_t>> parseDeviceIds(const string& input) {
  vector<tuple<uint16_t, uint16_t>> deviceIds;

  stringstream ss(input);
  string segment;

  while (
      getline(ss, segment, ',')) {  // Split by commas into vendor:device pairs
    size_t colonPos = segment.find(':');

    if (colonPos != string::npos) {
      uint16_t vendorId, deviceId;

      // Extract vendor ID (Assumes hexadecimal format)
      stringstream vendorSs(segment.substr(0, colonPos));
      vendorSs >> hex >> vendorId;

      // Extract device ID (Assumes hexadecimal format)
      stringstream deviceSs(segment.substr(colonPos + 1));
      deviceSs >> hex >> deviceId;

      deviceIds.push_back(make_tuple(vendorId, deviceId));
    } else {
      cout << std::format("Invalid format in segment: {}", segment) << endl;
      return deviceIds;
    }
  }

  return deviceIds;
}

// return a vector of matching devices' BDF info
vector<string> pciDeviceLookUp(uint16_t vid, uint16_t did) {
  const char* pci_path = "/sys/bus/pci/devices";
  vector<string> res;

  DIR* dir = opendir(pci_path);
  if (!dir) {
    cout << std::format("Error opening PCI directory: {}", pci_path) << endl;
    return res;
  }

  struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    // Skip "." and ".." entries
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    string device_path = string(pci_path) + "/" + entry->d_name;

    // Read vendor ID
    ifstream vendor_file(device_path + "/vendor");
    uint16_t vendor_id;
    vendor_file >> hex >> vendor_id;

    // Read device ID
    ifstream device_file(device_path + "/device");
    uint16_t device_id;
    device_file >> hex >> device_id;

    // Check for match
    if (vendor_id == vid && device_id == did) {
      res.push_back(string(entry->d_name));
      cout << std::format("DOE Device Found:{}", entry->d_name) << endl;
    }
  }

  closedir(dir);
  return res;
}

// pick one pci device that has doe and test doe discovery
TEST(TransportSetUp, testDoeDiscoverySpdm) {
  libspdm_return_t status;
  std::string deviceIdsStr(DOEVidDidList);
  std::vector<std::tuple<uint16_t, uint16_t>> deviceIds =
      parseDeviceIds(deviceIdsStr);

  if (deviceIds.empty()) {
    cout << "No deviceId provided, skip test!" << endl;
    GTEST_SKIP();
  }

  std::vector<std::string> allBdfs;
  for (const auto& [vendorId, deviceId] : deviceIds) {
    auto bdfs = pciDeviceLookUp(vendorId, deviceId);
    if (!bdfs.empty())
      allBdfs.insert(allBdfs.end(), bdfs.begin(), bdfs.end());
  }

  if (allBdfs.empty()) {
    cout << "No devices that implement PCI DOE SPDM found. Skip test!"
         << endl;
    GTEST_SKIP();
  }

  for (auto bdf : allBdfs) {
    spdm_conn_t* spdm_conn = (spdm_conn_t*)malloc(sizeof(spdm_conn_t));
    ASSERT_NE(spdm_conn, nullptr);
    memset(spdm_conn, 0, sizeof(spdm_conn_t));

    // pick one bdf for testing
    status = preconfig_spdm_connection_for_pcie_doe(spdm_conn, bdf.c_str());
    ASSERT_EQ(LIBSPDM_STATUS_IS_ERROR(status), false);

    status = preconfig_spdm_connection_generic(spdm_conn, SpdmMeasurementHash,
                                               SpdmAsymAlgo);
    ASSERT_EQ(LIBSPDM_STATUS_IS_ERROR(status), false);

    spdm_conn->m_spdm_context = (void*)malloc(libspdm_get_context_size());
    ASSERT_NE(spdm_conn->m_spdm_context, nullptr);

    libspdm_init_context(spdm_conn->m_spdm_context);
    ((libspdm_context_t*)spdm_conn->m_spdm_context)->conn = spdm_conn;

    // only test transport init: doe discovery for spdm support 
    status = spdm_transport_init(spdm_conn);
    EXPECT_EQ(LIBSPDM_STATUS_IS_ERROR(status), false);

    // release the doe object file after testing.
    status = tear_down_spdm_connection(spdm_conn);
    EXPECT_EQ(LIBSPDM_STATUS_IS_ERROR(status), false);
  }
}

/* This test Foo DOE implementation with Loopback support */
/* On QEMU with emulated DOE, which does not support Loopback, it may hangs on
 * waiting for the pci config read forever */
TEST(TransportSetUp, testFooDoeLoopback) {
  libspdm_return_t status;
  std::string deviceIdsStr(DOEVidDidList);
  std::vector<std::tuple<uint16_t, uint16_t>> deviceIds =
      parseDeviceIds(deviceIdsStr);

  if (deviceIds.empty()) {
    cout << "No deviceId provided, skip test!" << endl;
    GTEST_SKIP();
  }

  std::vector<std::string> allBdfs;
  for (const auto& [vendorId, deviceId] : deviceIds) {
    auto bdfs = pciDeviceLookUp(vendorId, deviceId);
    if (!bdfs.empty())
      allBdfs.insert(allBdfs.end(), bdfs.begin(), bdfs.end());
  }

  if (allBdfs.empty()) {
    cout << "No devices that implement Foo DOE Loopback found. Skip test!"
         << endl;
    GTEST_SKIP();
  }

  for (auto bdf : allBdfs) {
    spdm_conn_t* spdm_conn = (spdm_conn_t*)malloc(sizeof(spdm_conn_t));
    ASSERT_NE(spdm_conn, nullptr);
    memset(spdm_conn, 0, sizeof(spdm_conn_t));

    // pick one bdf for testing
    status = preconfig_spdm_connection_for_pcie_doe(spdm_conn, bdf.c_str());
    ASSERT_EQ(LIBSPDM_STATUS_IS_ERROR(status), false);

    status = preconfig_spdm_connection_generic(spdm_conn, SpdmMeasurementHash,
                                               SpdmAsymAlgo);
    ASSERT_EQ(LIBSPDM_STATUS_IS_ERROR(status), false);

    spdm_conn->m_spdm_context = (void*)malloc(libspdm_get_context_size());
    ASSERT_NE(spdm_conn->m_spdm_context, nullptr);

    libspdm_init_context(spdm_conn->m_spdm_context);
    ((libspdm_context_t*)spdm_conn->m_spdm_context)->conn = spdm_conn;

    status = doe_discovery_loopback(spdm_conn);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
      cout << "Device does not implement DOE Loopback. Skip it!" << endl;
      GTEST_SKIP();
    }

    status = doe_loopback_test(spdm_conn);
    EXPECT_EQ(LIBSPDM_STATUS_IS_ERROR(status), false);

    status = tear_down_spdm_connection(spdm_conn);
    EXPECT_EQ(LIBSPDM_STATUS_IS_ERROR(status), false);
  }
}
