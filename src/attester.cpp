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

#include "attester.hpp"

#include <systemd/sd-event.h>

#include <boost/asio.hpp>
#include <boost/stacktrace.hpp>
#include <certificate.hpp>
#include <iostream>
#include <memory>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdeventplus/event.hpp>
#include <string>
#include <vector>
#include <format>

#include "spdmd_config.h"
#include "support.hpp"

using namespace phosphor::logging;

namespace spdm_attester {

using AssociationList =
    std::vector<std::tuple<std::string, std::string, std::string>>;

SpdmAttester::SpdmAttester(sdbusplus::bus::bus& bus, const std::string& deviceId,
                           const std::string& chassisId,
                           const std::string& protectedComponentObjPath)
    : bus_(bus),
      deviceId_(deviceId),
      chassisId_(chassisId),
      protectedComponentObjPath_(protectedComponentObjPath) {
  // derive cert chain object name from device Id, assuming 1:1 mapping
  this->deviceCertChainId_ = std::format("{}_PemCertChain", deviceId);

  this->deviceCertChainObjPath_ = std::format(
      "{}chassis/{}/{}_PemCertChain", baseCertObjPath, chassisId, deviceId);

  // derive componentIntegrity obj path from chassis and deviceId
  // Observed same deviceId under different chassis
  this->componentIntegrityObjPath_ = std::format(
      "{}CI_{}_{}", baseComponentIntegrityObjPath, chassisId, deviceId);

  // derive trustedComponent obj path from chassisId and deviceId
  this->trustedComponentObjPath_ = std::format(
      "{}{}/TrustedComponents/TC_{}", baseChassisObjPath, chassisId, deviceId);

  // to be initialized by child class
  this->spdm_conn_ = NULL;
}

std::string getVersionStr(const uint8_t spdm_version) {
  std::string version;
  switch (spdm_version) {
    case SPDM_MESSAGE_VERSION_10:
      version = "1.0";
      break;
    case SPDM_MESSAGE_VERSION_11:
      version = "1.1";
      break;
    case SPDM_MESSAGE_VERSION_12:
      version = "1.2";
      break;
    case SPDM_MESSAGE_VERSION_13:
      version = "1.3";
      break;
    default:
      version = "Unknown SPDM Version";
  }

  return version;
}

// This assumes an estabilished connection with device
bool SpdmAttester::populateCertChain(void) {
  libspdm_return_t status;
  uint8_t derCert[LIBSPDM_MAX_CERT_CHAIN_SIZE];
  size_t certSize;
  int retryCnt;

  /* check connection status */
  if (this->spdm_conn_ == NULL || this->spdm_conn_->is_connected == false) {
    log<level::ERR>("Connection not set up yet!");
    return false;
  }

  try {
    auto certObjManager = std::make_shared<sdbusplus::server::manager::manager>(
        this->bus_, this->deviceCertChainObjPath_.c_str());
    this->certObjManager_ = certObjManager;
  } catch (const sdbusplus::exception::SdBusError& e) {
    log<level::ERR>(std::format("ERROR! {}\n", e.what()).c_str());
    return false;
  }

  retryCnt = 0;
  do {
    status = spdm_cma_get_certificate(this->spdm_conn_, derCert,
                                      LIBSPDM_MAX_CERT_CHAIN_SIZE, &certSize);
    if (LIBSPDM_STATUS_IS_ERROR(status)) {
      log<level::ERR>(std::format(
        "Get certificate failed! retry:{:d}, status:{:x}\n", retryCnt, status).c_str());
    }
  } while(LIBSPDM_STATUS_IS_ERROR(status) && retryCnt++ < MAX_REQUEST_RETRY_TIMES);

  if (LIBSPDM_STATUS_IS_ERROR(status)) {
    log<level::ERR>(std::format(
      "Get certificate failed! retry reached max retries:{:d}, status:{:x}\n",
      MAX_REQUEST_RETRY_TIMES, status).c_str());
    return false;
  }

  // build pem cert chain str from byte array
  std::vector<uint8_t> derCertVec(derCert, derCert + certSize);
  std::string pemChainStr = der_chain_to_pem(derCertVec);

  try {
    auto cert = std::make_shared<phosphor::certificate::Certificate>(
        this->bus_, this->deviceCertChainObjPath_.c_str(), pemChainStr);
    this->cert_ = cert;
  } catch (const sdbusplus::exception::SdBusError& e) {
    log<level::ERR>(std::format("ERROR! dev cert chain object path: {}\n",
      this->deviceCertChainObjPath_).c_str());
    log<level::ERR>(std::format("ERROR! {}\n", e.what()).c_str());
    return false;
  }

  return true;
}

// Create ComponentIntegrity D-Bus object for the protected component
bool SpdmAttester::setUpComponentIntegrityObj(const uint64_t lastUpdated) {
  /* check connection status */
  if (this->spdm_conn_ == NULL || this->spdm_conn_->is_connected == false) {
    log<level::ERR>("ERROR! Connection not set up yet!\n");
    return false;
  }

  try {
    auto componentIntegrityObjManager =
        std::make_shared<sdbusplus::server::manager::manager>(
            this->bus_, this->componentIntegrityObjPath_.c_str());
    this->componentIntegrityObjManager_ = componentIntegrityObjManager;
  } catch (const sdbusplus::exception::SdBusError& e) {
    log<level::ERR>(std::format("ERROR! {}\n", e.what()).c_str());
    return false;
  }

  auto type = sdbusplus::xyz::openbmc_project::Attestation::server::
      ComponentIntegrity::SecurityTechnologyType::SPDM;

  std::string typeVersion = getVersionStr(this->spdm_conn_->m_use_version);

  // TODO: hardcode it for now as only attestation requester knows the status.
  auto verificationStatus = sdbusplus::xyz::openbmc_project::Attestation::
      server::IdentityAuthentication::VerificationStatus::Success;

  try {
    auto componentIntegrity =
        std::make_shared<phosphor::component_integrity::ComponentIntegrity>(
            this->bus_, this->componentIntegrityObjPath_.c_str(), true,
            this->spdm_conn_, type, typeVersion, lastUpdated,
            verificationStatus);
    this->componentIntegrity_ = componentIntegrity;
  } catch (const sdbusplus::exception::SdBusError& e) {
    log<level::ERR>(std::format("ERROR! {}\n", e.what()).c_str());
    return false;
  }

  return true;
}

// Create TrustedComponent D-Bus object for the protected component
bool SpdmAttester::setUpTrustedComponentObj(
    const std::string& manufacturer, const std::string& SN, const std::string& uuid,
    const sdbusplus::xyz::openbmc_project::Inventory::Item::server::TrustedComponent::
        ComponentAttachType type) {
  /* check connection status */
  if (this->spdm_conn_ == NULL || this->spdm_conn_->is_connected == false) {
    log<level::ERR>("ERROR! Connection not set up yet!\n");
    return false;
  }

  try {
    auto trustedComponentObjManager =
        std::make_shared<sdbusplus::server::manager::manager>(
            this->bus_, this->trustedComponentObjPath_.c_str());
    this->trustedComponentObjManager_ = trustedComponentObjManager;
  } catch (const sdbusplus::exception::SdBusError& e) {
    log<level::ERR>(std::format("ERROR! {}\n", e.what()).c_str());
    return false;
  }

  try {
    auto trustedComponent =
        std::make_shared<phosphor::trusted_component::TrustedComponent>(
            this->bus_, this->trustedComponentObjPath_.c_str(), manufacturer,
            SN, type, uuid);
    this->trustedComponent_ = trustedComponent;
  } catch (const sdbusplus::exception::SdBusError& e) {
    log<level::ERR>(std::format("ERROR! {}\n", e.what()).c_str());
    return false;
  }

  return true;
}

// Initialize ComponentIntegrity D-Bus object associations
bool SpdmAttester::initializeComponentIntegrityObjAssociations(void) {
  // No report for requester (namely BMC) certificate, no use case
  // {"requester_identified_by","identifying", bmcCertpath}
  auto componentIntegrityAssocs = AssociationList{
      {"reporting", "reported_by", this->trustedComponentObjPath_},
      {"authenticating", "authenticated_by", this->protectedComponentObjPath_},
      {"responder_identified_by", "identifying",
       this->deviceCertChainObjPath_}};

  if (this->componentIntegrity_.has_value())
    this->componentIntegrity_.value()->associations(componentIntegrityAssocs);
  else {
    log<level::ERR>("ERROR! componentIntegrity not initialized yet!\n");
    return false;
  }
  return true;
}

// Initialize TrustedComponent D-Bus object associations
bool SpdmAttester::initializeTrustedComponentObjAssociations(
    const std::string& activeSoftwareObjPath, const std::string& oldSoftwareObjPath) {
  auto trustedComponentAssocs = AssociationList{
      {"reported_by", "reporting", this->componentIntegrityObjPath_},
      {"protecting", "protected_by", this->protectedComponentObjPath_},
      {"integrated_into", "contains", this->protectedComponentObjPath_},
      {"actively_running", "actively_runs_on", activeSoftwareObjPath},
      {"runs", "runs_on", oldSoftwareObjPath}};

  if (this->trustedComponent_.has_value())
    this->trustedComponent_.value()->associations(trustedComponentAssocs);
  else {
    log<level::ERR>("ERROR! trustedComponent not initialized yet!\n");
    return false;
  }

  return true;
}

}  // namespace spdm_attester
