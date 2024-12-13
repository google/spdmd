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

#pragma once
#include <boost/optional.hpp>
#include <certificate.hpp>
#include <component_integrity.hpp>
#include <sdbusplus/bus.hpp>
#include <string>
#include <trusted_component.hpp>

// spdm requester library header for connection management
extern "C" {
#include <spdm_conn.h>
}

namespace spdm_attester {
constexpr char const* baseCertObjPath = "/xyz/openbmc_project/certs/";
constexpr char const* baseComponentIntegrityObjPath =
    "/xyz/openbmc_project/ComponentIntegrity/";
constexpr char const* baseChassisObjPath = "/xyz/openbmc_project/Chassis/";

class SpdmAttester {
 public:
  SpdmAttester(sdbusplus::bus::bus& bus, const std::string& deviceId,
               const std::string& chassisId, const std::string& protectedComponentObjPath);
  bool populateCertChain(void);
  bool setUpComponentIntegrityObj(const uint64_t lastUpdated);
  bool setUpTrustedComponentObj(
      const std::string& manufacturer, const std::string& SN, const
      std::string& uuid,
      const sdbusplus::xyz::openbmc_project::Inventory::Item::server::
          TrustedComponent::ComponentAttachType type);
  bool initializeComponentIntegrityObjAssociations(void);
  bool initializeTrustedComponentObjAssociations(
      const std::string& activeSoftwareObjPath, const std::string& oldSoftwareObjPath);

  // public members
  spdm_conn_t* spdm_conn_;
  sdbusplus::bus::bus& bus_;

 private:
  std::string deviceId_;
  std::string chassisId_;
  std::string protectedComponentObjPath_;
  std::string deviceCertChainId_;
  std::string deviceCertChainObjPath_;
  std::string componentIntegrityObjPath_;
  std::string trustedComponentObjPath_;
  // component to be protected, GPU, PCIe Switch, etc.
  boost::optional<
      std::shared_ptr<phosphor::component_integrity::ComponentIntegrity>>
      componentIntegrity_;
  boost::optional<
      std::shared_ptr<phosphor::trusted_component::TrustedComponent>>
      trustedComponent_;
  boost::optional<std::shared_ptr<phosphor::certificate::Certificate>> cert_;
  boost::optional<std::shared_ptr<sdbusplus::server::manager::manager>>
      componentIntegrityObjManager_;
  boost::optional<std::shared_ptr<sdbusplus::server::manager::manager>>
      trustedComponentObjManager_;
  boost::optional<std::shared_ptr<sdbusplus::server::manager::manager>>
      certObjManager_;
};

}  // namespace spdm_attester
