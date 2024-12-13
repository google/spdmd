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
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

std::vector<std::string> pciDeviceLookUp(uint16_t vid, uint16_t did);
std::vector<std::tuple<uint16_t, uint16_t>> parseDeviceIds(
    const std::string& input);
uint64_t getLastUpdatedTimeStamp(void);
std::vector<std::string> getPCIeDeviceObjPath(uint16_t vendorid,
                                              uint16_t deviceId);
std::map<std::string, std::string> createMapFromVectors(
    const std::vector<std::string>& keys,
    const std::vector<std::string>& values);
std::string getDeviceChassisIdFromInventoryPath(std::string& devpath);
uint64_t getDevFirmwareLastUpdateTime(std::string& devpath);
std::unordered_map<std::string, std::string> getDevAssetAttributes(
    std::string& devpath);

bool waitForConfigFileStability(const std::string& filePath,
                                int stableDurationSeconds,
                                int maxRetries,
                                int retryIntervalSeconds);

// cert encoding conversion
std::string der_to_pem(const std::vector<unsigned char>& der_bytes);
std::string der_chain_to_pem(const std::vector<unsigned char>& der_bytes);
std::string base64_encode(const std::string& input);
std::vector<std::tuple<std::string, std::string, uint8_t, uint8_t>>
  parseMctpConfigAndFilterSpdm(std::string& confFile);
bool checkMctpMsgType(uint8_t mctpNid, uint8_t mcptEid, uint8_t msgType);
