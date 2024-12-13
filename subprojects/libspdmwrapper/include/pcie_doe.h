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

#ifndef _PCIE_DOE_H_
#define _PCIE_DOE_H_

#include <stdint.h>
#include <industry_standard/spdm.h>
#include <industry_standard/pcidoe.h>

/* Extended Capabilities (PCI-X 2.0 and Express) */
#define PCI_EXT_CAP_ID(header)      (header & 0x0000ffff)
#define PCI_EXT_CAP_VER(header)     ((header >> 16) & 0xf)
#define PCI_EXT_CAP_NEXT(header)    ((header >> 20) & 0xffc)

#define PCIE_EXT_CAP_OFFSET     0x100
#define PCI_EXT_CAP_ID_DOE      0x2e    /*  Data Object Exchange */

/* DOE Capabilities Register */
#define PCIE_DOE_CAP            0x04
#define  PCIE_DOE_CAP_INTR_SUPP 0x00000001
/* DOE Control Register  */
#define PCIE_DOE_CTRL           0x08
#define  PCIE_DOE_CTRL_ABORT    0x00000001
#define  PCIE_DOE_CTRL_INTR_EN  0x00000002
#define  PCIE_DOE_CTRL_GO       0x80000000
/* DOE Status Register  */
#define PCIE_DOE_STATUS         0x0c
#define  PCIE_DOE_STATUS_BUSY   0x00000001
#define  PCIE_DOE_STATUS_INTR   0x00000002
#define  PCIE_DOE_STATUS_ERR    0x00000004
#define  PCIE_DOE_STATUS_DO_RDY 0x80000000
/* DOE Write Data Mailbox Register  */
#define PCIE_DOE_WR_DATA_MBOX   0x10
/* DOE Read Data Mailbox Register  */
#define PCIE_DOE_RD_DATA_MBOX   0x14

//
// DOE header
//
typedef struct {
  uint16_t   VendorId;
  uint8_t    DataObjectType;
  uint8_t    Reserved;
  // Length of the data object being transfered in number of DW, including the header (2 DW)
  // It only includes bit[0~17], bit[18~31] are reserved.
  // A value of 00000h indicate 2^18 DW == 2^20 byte.
  uint32_t   Length;
} PCI_DOE_DATA_OBJECT_HEADER;

///
/// DOE Discovery request
///
typedef struct {
  PCI_DOE_DATA_OBJECT_HEADER  DoeHeader;
  pci_doe_discovery_request_t   DoeDiscoveryRequest;
} DOE_DISCOVERY_REQUEST_MINE;

///
/// DOE Discovery response
///
typedef struct {
  PCI_DOE_DATA_OBJECT_HEADER  DoeHeader;
  pci_doe_discovery_response_t  DoeDiscoveryResponse;
} DOE_DISCOVERY_RESPONSE_MINE;

struct pcie_dev {
    int pdev;
    int domain;
    int bus;
    int slot;
    int func;
};

#endif /* _PCIE_DOE_H */
