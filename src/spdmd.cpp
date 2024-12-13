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

#include <systemd/sd-event.h>

#include <boost/asio.hpp>
#include <boost/stacktrace.hpp>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iostream>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdeventplus/event.hpp>
#include <string>
#include <vector>
#include <tuple>

#include "attester.hpp"
#include "certificate.hpp"
#include "component_integrity.hpp"
#include "doe_attester.hpp"
#include "mctp_attester.hpp"
#include "spdmd_config.h"
#include "support.hpp"
#include "trusted_component.hpp"

using namespace phosphor::logging;
using namespace spdm_attester;

// To hold pointers to heap-allocated doeAttesters.
std::vector<std::shared_ptr<SpdmAttesterDOE>> DoeAttesters;
std::vector<std::shared_ptr<SpdmAttesterMCTP>> MctpAttesters;

void setupPcieDoeDevices(sdbusplus::bus_t& bus) {
  // configurable through meson option 'spdm-doe-vid-did-list'
  std::string deviceIdsStr(DOEVidDidList);
  std::vector<std::tuple<uint16_t, uint16_t>> deviceIds =
      parseDeviceIds(deviceIdsStr);
  if (deviceIdsStr.empty() || deviceIds.empty()) {
    log<level::INFO>("Warning! DOEVidDidList is empty!");
    return;
  }

  // a list of device BDFs that match the given DOE device Vid:Did
  std::vector<std::string> bdfVec;
  std::vector<std::string> devDbusPaths;
  std::map<std::string, std::string> bdfToDevPath;

  // get all matching BDFs from different Vid:Did pairs.
  for (const auto& [vendorId, deviceId] : deviceIds) {
    auto bdfs = pciDeviceLookUp(vendorId, deviceId);
    auto paths = getPCIeDeviceObjPath(vendorId, deviceId);

    bdfVec.insert(bdfVec.end(), bdfs.begin(), bdfs.end());
    devDbusPaths.insert(devDbusPaths.end(), paths.begin(), paths.end());

    if (devDbusPaths.size() != bdfVec.size()) {
      log<level::ERR>(
          std::format("Error! #BDF({})  != #DBus-Objects({})!",
          bdfVec.size(), devDbusPaths.size()).c_str());
      log<level::ERR>(
          std::format("Vid: 0x{:x}, Did: 0x{:x}", vendorId, deviceId).c_str());
      return;
    }
  }

  bdfToDevPath = createMapFromVectors(bdfVec, devDbusPaths);

  for (auto& bdf : bdfVec) {
    // device is also the protectedComponent
    auto protectedObjPath = bdfToDevPath[bdf];

    // extract device id and use it to derive other names
    std::filesystem::path p(protectedObjPath);
    auto deviceId = p.filename().string();

    // D-Bus inventory path may contain chassis id information
    auto chassisId = getDeviceChassisIdFromInventoryPath(protectedObjPath);

    // SpdmAttester can fetch device Certificate and
    // create ComponentIntegrity and TrustedComponent D-Bus Object.
    auto doeAttester = std::make_shared<SpdmAttesterDOE>(
        bus, deviceId, chassisId, protectedObjPath, bdf);

    bool ret = doeAttester->populateCertChain();
    if (!ret) {
      log<level::ERR>(
          std::format("Error! Fetch certificate failed (bdf:{}).", bdf)
              .c_str());
      continue;
    }

    uint64_t lastUpdated = getDevFirmwareLastUpdateTime(protectedObjPath);
    ret = doeAttester->setUpComponentIntegrityObj(lastUpdated);
    if (!ret) {
      log<level::ERR>(
          std::format("Error! Create ComponentIntegrity failed(bdf: {}).", bdf)
              .c_str());
      continue;
    }

    ret = doeAttester->initializeComponentIntegrityObjAssociations();
    if (!ret) {
      log<level::ERR>(std::format("Error! initialize ComponentIntegrity "
                                  "Associations failed(bdf: {}).",
                                  bdf)
                          .c_str());
      continue;
    }

    std::unordered_map<std::string, std::string> assetAttrs;
    assetAttrs = getDevAssetAttributes(protectedObjPath);

    // TODO(b/355068455)
    // We need a generic approach to get attach type info from
    // device. Here for DOE, it is more likey to be Integrated(iRoT).
    auto attachType = sdbusplus::xyz::openbmc_project::Inventory::Item::server::
        TrustedComponent::ComponentAttachType::Integrated;
    ret = doeAttester->setUpTrustedComponentObj(assetAttrs["Manufacturer"],
                                                assetAttrs["SN"],
                                                assetAttrs["UUID"], attachType);
    if (!ret) {
      log<level::ERR>(
          std::format("Error! Create TrustedComponent failed(bdf: {}).", bdf)
              .c_str());
      continue;
    }

    // TODO(b/355068455)
    // add support for get active/old software path
    // For now, hardcode software id for testing purpose.
    auto activeSoftwareObjPath =
        std::string("/xyz/openbmc_project/software/e0d90bc5");
    auto oldSoftwareObjPath =
        std::string("/xyz/openbmc_project/software/e0d90bc5");
    ret = doeAttester->initializeTrustedComponentObjAssociations(
        activeSoftwareObjPath, oldSoftwareObjPath);
    if (!ret) {
      log<level::ERR>(
          std::format(
              "Initialize TrustedComponent Associations failed(bdf: {}).", bdf)
              .c_str());
      continue;
    }

    DoeAttesters.push_back(doeAttester);

    log<level::INFO>(
        std::format("Create SpdmAttesterDOE successfully (bdf: {}).", bdf)
            .c_str());
  }
}

void setupSocketEmuPcieDoeDevices([[maybe_unused]] sdbusplus::bus_t& bus) {
  // TODO (low priority)
}

void setupMCTPDevices([[maybe_unused]] sdbusplus::bus_t& bus) {
  std::string confFile(SpdmdMctpI2cBindingConf);

  std::vector<std::tuple<std::string, std::string, uint8_t, uint8_t>> spdmMctpInfo =
    parseMctpConfigAndFilterSpdm(confFile);
  if (spdmMctpInfo.empty() || confFile.empty()) {
    log<level::INFO>("Warning! Found no MCTP devices that support SPDM!");
    return;
  }

  // tuple format (ChassisId, DeviceId, MctpNid, MctpEid)
  for (auto& mctpInfo : spdmMctpInfo) {
    // device is also the protectedComponent
    auto chassisId = std::get<0>(mctpInfo);
    auto deviceId = std::get<1>(mctpInfo);
    uint8_t mctpNid = std::get<2>(mctpInfo);
    uint8_t mctpEid = std::get<3>(mctpInfo);

    auto protectedObjPath =
      std::format("/xyz/openbmc_project/inventory/system/board/{}/{}",
                   chassisId, deviceId);

    // SpdmAttester can fetch device Certificate and
    // create ComponentIntegrity and TrustedComponent D-Bus Object.
    auto mctpAttester = std::make_shared<SpdmAttesterMCTP>(
        bus, deviceId, chassisId, protectedObjPath, mctpNid, mctpEid);

    bool ret = mctpAttester->populateCertChain();
    if (!ret) {
      log<level::ERR>(
          std::format("Error! Fetch certificate failed (nid:{}, eid:{}).",
            mctpNid, mctpEid).c_str());
      continue;
    }

    uint64_t lastUpdated = getDevFirmwareLastUpdateTime(protectedObjPath);
    ret = mctpAttester->setUpComponentIntegrityObj(lastUpdated);
    if (!ret) {
      log<level::ERR>(
          std::format("Error! Create ComponentIntegrity failed(nid:{}, eid:{}).",
            mctpNid, mctpEid).c_str());
      continue;
    }

    ret = mctpAttester->initializeComponentIntegrityObjAssociations();
    if (!ret) {
      log<level::ERR>(std::format("Error! initialize ComponentIntegrity "
                                  "Associations failed(nid:{}, eid:{}).",
                                  mctpNid, mctpEid).c_str());
      continue;
    }

    std::unordered_map<std::string, std::string> assetAttrs;
    assetAttrs = getDevAssetAttributes(protectedObjPath);

    // TODO(b/355068455)
    // We need a generic approach to get attach type info from
    // device. Here for MCTP, it is more likey to be Integrated(iRoT).
    auto attachType = sdbusplus::xyz::openbmc_project::Inventory::Item::server::
        TrustedComponent::ComponentAttachType::Integrated;
    ret = mctpAttester->setUpTrustedComponentObj(assetAttrs["Manufacturer"],
                                                assetAttrs["SN"],
                                                assetAttrs["UUID"], attachType);
    if (!ret) {
      log<level::ERR>(
          std::format("Error! Create TrustedComponent failed(Nid:{}, Eid:{}).",
              mctpNid, mctpEid).c_str());
      continue;
    }

    // TODO(b/355068455)
    // add support for get active/old software path
    // For now, hardcode software id for testing purpose.
    auto activeSoftwareObjPath =
        std::string("/xyz/openbmc_project/software/e0d90bc5");
    auto oldSoftwareObjPath =
        std::string("/xyz/openbmc_project/software/e0d90bc5");
    ret = mctpAttester->initializeTrustedComponentObjAssociations(
        activeSoftwareObjPath, oldSoftwareObjPath);
    if (!ret) {
      log<level::ERR>(
          std::format(
              "Initialize TrustedComponent Associations failed(Nid:{}, Eid:{}).",
              mctpNid, mctpEid).c_str());
      continue;
    }

    MctpAttesters.push_back(mctpAttester);

    log<level::INFO>(
        std::format("Create SpdmAttesterMCTP successfully (Nid:{}, Eid:{}).",
                    mctpNid, mctpEid).c_str());
  }

}

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
  static boost::asio::io_context ioc;
  static auto conn = std::make_shared<sdbusplus::asio::connection>(ioc);
  bool stable;

  std::string confFile(SpdmdMctpI2cBindingConf);

  // TODO(b/357625263) : remove this fix once spdmd switch to signal driven
  // model. For now, we will blindly wait and check for mctp config file, even
  // when there is no MCTP devices. We should move on even if no conf file
  // exists.
  if (!confFile.empty()) {
    stable = waitForConfigFileStability(confFile,
                                      120, // stablized for 2 min
                                      5, // retry at most 5 times
                                      60); // wait for 1 min before retry
    if (!stable) {
      log<level::ERR>(
          format("Error! MCTP Conf file not exists: {}", confFile).c_str());
    } else
      log<level::INFO>("MCTPI2cBindingConf file stablized!");
  } else
    log<level::INFO>("MCTPI2cBindingConf file not exists!");

  conn->request_name("xyz.openbmc_project.SPDM");
  sdbusplus::asio::object_server server = sdbusplus::asio::object_server(conn);
  sdbusplus::bus_t& bus = static_cast<sdbusplus::bus_t&>(*conn);

  log<level::INFO>("spdmd started!");

  setupPcieDoeDevices(bus);
  setupSocketEmuPcieDoeDevices(bus);
  setupMCTPDevices(bus);

  ioc.run();

  log<level::INFO>("spdmd exited!");

  return 0;
}
