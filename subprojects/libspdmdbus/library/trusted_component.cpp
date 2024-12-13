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

#include "trusted_component.hpp"

#include <algorithm>
#include <array>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>

namespace phosphor::trusted_component {
namespace {
using ::phosphor::logging::level;
using ::phosphor::logging::log;
}  // namespace

TrustedComponent::TrustedComponent(
    sdbusplus::bus::bus& bus, const char* path, const std::string& manufacturer,
    const std::string& serialNumber,
    const sdbusplus::xyz::openbmc_project::Inventory::Item::server::TrustedComponent::
        ComponentAttachType type,
    const std::string& uuid)
    : internal::TrustedComponentInterface(bus, path, action::defer_emit) {
  this->manufacturer(manufacturer);
  this->serialNumber(serialNumber);
  this->trustedComponentType(type);
  this->uuid(uuid);

  log<level::INFO>("TrustedComponent Instance Created!");

  return;
}

TrustedComponent::~TrustedComponent() {
  log<level::INFO>("TrustedComponent Instance Destroyed!");
}

}  // namespace phosphor::trusted_component
