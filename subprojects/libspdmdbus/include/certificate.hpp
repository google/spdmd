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
#include <xyz/openbmc_project/Certs/Certificate/server.hpp>
#include <xyz/openbmc_project/Certs/Replace/server.hpp>

namespace internal {
using CertificateInterface = sdbusplus::server::object_t<
    sdbusplus::xyz::openbmc_project::Certs::server::Certificate,
    sdbusplus::xyz::openbmc_project::Certs::server::Replace>;
}  // namespace internal

namespace phosphor::certificate {

/** @class Certificate
 */
class Certificate : public internal::CertificateInterface {
 public:
  Certificate() = delete;
  Certificate(const Certificate&) = delete;
  Certificate& operator=(const Certificate&) = delete;
  Certificate(Certificate&&) = delete;
  Certificate& operator=(Certificate&&) = delete;
  virtual ~Certificate();

  /** @brief Constructor for the Certificate Object
   *  @param[in] bus - Bus to attach to.
   *  @param[in] path - Object path to attach to.
   *  @param[in] pemchain - Certificate chain pem string.
   */
  Certificate(sdbusplus::bus::bus& bus, const char* path, std::string pemchain);

  /** @brief Validate certificate and replace the existing certificate
   *  @param[in] pemchain - Certificate str.
   */
  void replace(const std::string pemchain) override;
};

}  // namespace phosphor::certificate
