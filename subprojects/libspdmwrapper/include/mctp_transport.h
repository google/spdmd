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

#ifndef _MCTP_TRANSPORT_H_
#define _MCTP_TRANSPORT_H_

#include <stdint.h>
#include <stddef.h>

libspdm_return_t spdm_device_send_message_mctp(void *spdm_context,
                                              size_t req_size,
                                              const void *req,
                                              uint64_t timeout);

libspdm_return_t spdm_device_receive_message_mctp(void *spdm_context,
                                                 size_t *resp_size,
                                                 void **resp,
                                                 uint64_t timeout);

libspdm_return_t set_up_spdm_connection_for_mctp(spdm_conn_t *spdm_conn);
libspdm_return_t tear_down_spdm_connection_for_mctp(spdm_conn_t *spdm_conn);

#endif //_MCTP_TRANSPORT_H_
