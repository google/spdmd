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

#include <functional>
#include <memory>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <string_view>
#include <xyz/openbmc_project/Association/Definitions/server.hpp>
#include <xyz/openbmc_project/Attestation/ComponentIntegrity/server.hpp>
#include <xyz/openbmc_project/Attestation/IdentityAuthentication/server.hpp>
#include <xyz/openbmc_project/Attestation/MeasurementSet/server.hpp>
#include <xyz/openbmc_project/Certs/Certificate/server.hpp>

extern "C" {
#include "spdm_conn.h"
}

namespace internal {
using ComponentIntegrityInterface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Association::server::Definitions,
    sdbusplus::xyz::openbmc_project::Attestation::server::ComponentIntegrity,
    sdbusplus::xyz::openbmc_project::Attestation::server::
        IdentityAuthentication,
    sdbusplus::xyz::openbmc_project::Attestation::server::MeasurementSet>;
}  // namespace internal

namespace phosphor::component_integrity {

/** @class ComponentIntegrity
 *  @brief OpenBMC ComponentIntegrity entry implementation.
 *  @details A concrete implementation of
 *    xyz.openbmc_project.Attestation.ComponentIntegrity DBus API
 *    xyz.openbmc_project.Attestation.IdentityAuthentication DBus API
 *    xyz.openbmc_project.Attestation.MeasurementSet DBus API
 */
class ComponentIntegrity : public internal::ComponentIntegrityInterface {
 public:
  ComponentIntegrity() = delete;
  ComponentIntegrity(const ComponentIntegrity&) = delete;
  ComponentIntegrity& operator=(const ComponentIntegrity&) = delete;
  ComponentIntegrity(ComponentIntegrity&&) = delete;
  ComponentIntegrity& operator=(ComponentIntegrity&&) = delete;
  virtual ~ComponentIntegrity();

  /** @brief Constructor for the ComponentIntegrity Object
   *  @param[in] bus - Bus to attach to.
   *  @param[in] objPath - Object path to attach to
   *  @param[in] enabled - Whether ComponentIntegrity is enabled
   *  @param[in] type - The security protocol type
   *  @param[in] typeVersion - The version of the security protocol
   *  @param[in] lastUpdated - The time of the last update component.
   */
  ComponentIntegrity(sdbusplus::bus::bus& bus, const char* path, bool enabled,
                     spdm_conn_t* spdm_conn,
                     const sdbusplus::xyz::openbmc_project::Attestation::server::
                         ComponentIntegrity::SecurityTechnologyType type,
                     const std::string& typeVersion, const uint64_t lastUpdated,
                     sdbusplus::xyz::openbmc_project::Attestation::server::
                         IdentityAuthentication::VerificationStatus status);

  /** @brief Implementation for SPDMGetSignedMeasurements
   *  This method generates an SPDM cryptographic signed statement
   *  over the given nonce and measurements of the SPDM Responder.
   *
   *  @param[in] measurementIndices - An array of indices that identify
   *             the measurement blocks to sign.
   *  @param[in] nonce - A 32-byte hex-encoded string that is signed
   *             with the measurements. The value should be unique.
   *  @param[in] slotId - The slot identifier for the certificate containing
   *             the private key to generate the signature over the
   * measurements.
   *
   *  @return measurementResponse[std::tuple<sdbusplus::message::object_path,
   *          std::string, std::string, std::string, std::string, std::string>]
   *          - The response will contain a struct with following fields:
   *          Certificate, HashingAlgorithm, PublicKey, SignedMeasurements,
   *          SignedAlgorithm, Version. Among them, Certificate refers to
   *          certificate object corresponding to the SPDM slot identifier
   *          that can be used to validate the signature.
   */
  std::tuple<sdbusplus::message::object_path, std::string, std::string,
             std::string, std::string, std::string>
  spdmGetSignedMeasurements(std::vector<size_t> measurementIndices,
                            std::string nonce, size_t slotId) override;

 private:
  spdm_conn_t* spdm_conn;
};

}  // namespace phosphor::component_integrity
