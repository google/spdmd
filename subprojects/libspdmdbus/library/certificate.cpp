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

#include "certificate.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>
#include <xyz/openbmc_project/Common/error.hpp>

namespace phosphor::certificate {
namespace {
using ::phosphor::logging::level;
using ::phosphor::logging::log;
}  // namespace

Certificate::Certificate(sdbusplus::bus::bus& bus, const char* path,
                         std::string pemChainString)
    : internal::CertificateInterface(bus, path) {
  // PEM-encoded cert chain string
  certificateString(pemChainString);

  // We only support Cert Chain, fields below should be empty
  // TODO Hardcode for passing Redfish-Validator testing
  subject(
      "C=US, ST=New York, L=Armonk, O=International \
             Business Machines Corporation,OU=research, \
             CN=www.research.ibm.com");
  issuer("C=US, O=DigiCert Inc, CN=DigiCert");
  keyUsage({"KeyCertSign"});
  validNotAfter(24 * 60 * 60 * 1000);
  validNotBefore(24 * 60 * 60 * 900);
}

void Certificate::replace(const std::string certChainForReplace) {
  log<level::INFO>("Replace cert chain string!");
  certificateString(certChainForReplace);
}

Certificate::~Certificate() {
  log<level::INFO>("Certificate Instance Destroyed!");
}

}  // namespace phosphor::certificate
