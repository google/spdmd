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

#ifndef _PCIE_DOE_TRANSPORT_H_
#define _PCIE_DOE_TRANSPORT_H_

#include <stdint.h>
#include <stddef.h>

libspdm_return_t spdm_device_send_message_doe(void *spdm_context,
                                              size_t req_size,
                                              const void *req,
                                              uint64_t timeout);

libspdm_return_t spdm_device_receive_message_doe(void *spdm_context,
                                                 size_t *resp_size,
                                                 void **resp,
                                                 uint64_t timeout);

libspdm_return_t set_up_spdm_connection_for_doe(spdm_conn_t *spdm_conn);
libspdm_return_t tear_down_spdm_connection_for_doe(spdm_conn_t *spdm_conn);

/* pcie doe config read/write */
libspdm_return_t avy_pci_config_read_dw(spdm_conn_t *spdm_conn, uint64_t addr,
                                        uint32_t *data);
libspdm_return_t avy_pci_config_write_dw(spdm_conn_t *spdm_conn, uint64_t addr,
                                         uint32_t data);
bool parse_pcie_doe_bdf(spdm_conn_t *spdm_conn);

#endif //_PCIE_DOE_TRANSPORT_H_
