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

#include "doe_attester.hpp"

#include <iostream>
#include <phosphor-logging/log.hpp>

#include "spdmd_config.h"

using namespace phosphor::logging;

namespace spdm_attester {

SpdmAttesterDOE::SpdmAttesterDOE(sdbusplus::bus::bus& bus,
                                 const std::string& deviceId, const std::string& chassisId,
                                 const std::string& protectedComponentObjPath,
                                 const std::string& doeDevBdf)
    : SpdmAttester(bus, deviceId, chassisId, protectedComponentObjPath),
      doeDevBdf_(doeDevBdf) {
  libspdm_return_t status;
  spdm_conn_t* spdm_conn = (spdm_conn_t*)malloc(sizeof(spdm_conn_t));

  if (spdm_conn == NULL) {
    log<level::ERR>("ERROR! Out of memory!\n");
    return;
  }

  status = preconfig_spdm_connection_for_pcie_doe(spdm_conn,
                                               this->doeDevBdf_.c_str());
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    log<level::ERR>("Failed to config spdm connection for PCIe DOE!");
    free(spdm_conn);
    return;
  }

  status = preconfig_spdm_connection_generic(spdm_conn, SpdmMeasurementHash,
                                          SpdmAsymAlgo);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    log<level::ERR>("Failed to config generic spdm connection!");
    free(spdm_conn);
    return;
  }

  status = set_up_spdm_connection(spdm_conn);
  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    log<level::ERR>("Failed to set up spdm connection!");
    free(spdm_conn);
    return;
  }

  this->spdm_conn_ = spdm_conn;

  log<level::INFO>("SPDM DOE Attester created!");

  return;
};  // SpdmAttesterDOE()

SpdmAttesterDOE::~SpdmAttesterDOE() {
  libspdm_return_t status;
  if (this->spdm_conn_ != NULL) {
    status = tear_down_spdm_connection(this->spdm_conn_);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
      log<level::ERR>("Error happened while tear down spdm connection!");
    }
  }

  log<level::INFO>("SPDM DOE Attester destroyed!");
};
}  // namespace spdm_attester
