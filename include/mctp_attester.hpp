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
#include "attester.hpp"
#include "spdmd_config.h"

namespace spdm_attester {
class SpdmAttesterMCTP : public SpdmAttester {
 public:
  SpdmAttesterMCTP(sdbusplus::bus::bus& bus, const std::string& deviceId,
                   const std::string& chassisId,
                   const std::string& protectedComponentObjPath,
                   const uint8_t mctpEid, const uint8_t mctpNid);

  virtual ~SpdmAttesterMCTP();
 private:
  uint8_t mctpEid_;
  uint8_t mctpNid_;
};

}  // namespace spdm_attester
