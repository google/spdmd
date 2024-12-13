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

#include <bit>
#include <functional>
#include <memory>
#include <sdbusplus/server/object.hpp>
#include <string>
#include <string_view>
#include <xyz/openbmc_project/Association/Definitions/server.hpp>
#include <xyz/openbmc_project/Common/UUID/server.hpp>
#include <xyz/openbmc_project/Inventory/Decorator/Asset/server.hpp>
#include <xyz/openbmc_project/Inventory/Item/TrustedComponent/server.hpp>

namespace internal {
using TrustedComponentInterface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Association::server::Definitions,
    sdbusplus::xyz::openbmc_project::Inventory::Item::server::TrustedComponent,
    sdbusplus::xyz::openbmc_project::Inventory::Decorator::server::Asset,
    sdbusplus::xyz::openbmc_project::Common::server::UUID>;
}  // namespace internal

namespace phosphor::trusted_component {

/** @class TrustedComponent
 *  @brief OpenBMC TrustedComponent entry implementation.
 *  @details A concrete implementation for the
 *  xyz.openbmc_project.TrustedComponent DBus API
 */
class TrustedComponent : public internal::TrustedComponentInterface {
 public:
  TrustedComponent() = delete;
  TrustedComponent(const TrustedComponent&) = delete;
  TrustedComponent& operator=(const TrustedComponent&) = delete;
  TrustedComponent(TrustedComponent&&) = delete;
  TrustedComponent& operator=(TrustedComponent&&) = delete;
  virtual ~TrustedComponent();

  /** @brief Constructor for the TrustedComponent Object
   *  @param[in] bus - Bus to attach to.
   *  @param[in] path - Object path to attach to
   *  @param[in] manufacture - Manufacturer name
   *  @param[in] serialNumber - Device SN
   *  @param[in] type - Device attachment type, integrated or discrete
   *  @param[in] uuid - Device UUID
   */
  TrustedComponent(sdbusplus::bus::bus& bus, const char* path,
                   const std::string& manufacturer, const std::string& serialNumber,
                   const sdbusplus::xyz::openbmc_project::Inventory::Item::server::
                       TrustedComponent::ComponentAttachType type,
                   const std::string& uuid);
};

}  // namespace phosphor::trusted_component
