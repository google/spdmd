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

#include "support.hpp"

#include <dirent.h>
#include <string.h>

#include <boost/asio/io_context.hpp>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iostream>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/message.hpp>
#include <sdbusplus/timer.hpp>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <variant>
#include <vector>
#include <xyz/openbmc_project/Common/error.hpp>
#include <chrono>
#include <thread>
#include <filesystem>

extern "C" {
#include <spdm_conn.h>
#include <internal/libspdm_crypt_lib.h>
}

using namespace std;
using namespace phosphor::logging;
using namespace sdbusplus;

static const char b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

string base64_encode(const string& input) {
  string output;
  int val = 0, valb = -6;
  for (unsigned char c : input) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      output.push_back(b64_alphabet[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) {
    output.push_back(b64_alphabet[(val << 8) >> (valb + 8) & 0x3F]);
  }
  while (output.size() % 4) {
    output.push_back('=');
  }
  return output;
}

string der_chain_to_pem(const vector<unsigned char>& der_bytes) {
  const uint8_t* certp;
  bool ret;
  size_t chain_len;
  size_t cert_len;
  int32_t index;
  size_t cur_len;

  chain_len = der_bytes.size();
  index = 0;
  cur_len = 0;
  string cert_string = "";
  string pem_chain = "";
  while (cur_len < chain_len) {
    ret = libspdm_x509_get_cert_from_cert_chain(der_bytes.data(), chain_len,
                                                index, &certp, &cert_len);
    if (!ret) {
      log<level::ERR>(std::format(
        "Error when get {:d} cert from certchain, status: 0x{:x}!",
	index, ret).c_str());
      log<level::ERR>(std::format(
        "Return partially converted PEM Chain: {}.\n",pem_chain).c_str());
      return pem_chain;
    }

    cert_string = "";
    // append one cert
    cert_string += "-----BEGIN CERTIFICATE-----\n";
    cert_string += base64_encode(string(certp, certp + cert_len)) + "\n";
    cert_string += "-----END CERTIFICATE-----\n";

    // der cert order: root, intermediate, leaf
    // pem cert order: leaf, intermediate, root
    pem_chain = cert_string + pem_chain;

    cur_len += cert_len;
    index += 1;
  }

  return pem_chain;
}

string der_to_pem(const vector<unsigned char>& der_bytes) {
  string pem_string = "-----BEGIN CERTIFICATE-----\n";
  pem_string +=
      base64_encode(string(der_bytes.begin(), der_bytes.end())) + "\n";
  pem_string += "-----END CERTIFICATE-----\n";
  return pem_string;
}

// return a list of tuples (vendorId, deviceId)
vector<tuple<uint16_t, uint16_t>> parseDeviceIds(const string& input) {
  vector<tuple<uint16_t, uint16_t>> deviceIds;

  stringstream ss(input);
  string segment;

  while (
      getline(ss, segment, ',')) {  // Split by commas into vendor:device pairs
    size_t colonPos = segment.find(':');

    if (colonPos != string::npos) {
      uint16_t vendorId, deviceId;

      // Extract vendor ID (Assumes hexadecimal format)
      stringstream vendorSs(segment.substr(0, colonPos));
      vendorSs >> hex >> vendorId;

      // Extract device ID (Assumes hexadecimal format)
      stringstream deviceSs(segment.substr(colonPos + 1));
      deviceSs >> hex >> deviceId;

      deviceIds.push_back(make_tuple(vendorId, deviceId));
    } else {
      log<level::ERR>(
          std::format("Invalid format in segment: {}", segment).c_str());
      return deviceIds;
    }
  }

  return deviceIds;
}

// return a vector of matching devices' BDF info
vector<string> pciDeviceLookUp(uint16_t vid, uint16_t did) {
  const char* pci_path = "/sys/bus/pci/devices";
  vector<string> res;

  DIR* dir = opendir(pci_path);
  if (!dir) {
    log<level::ERR>(
        std::format("Error opening PCI directory: {}", pci_path).c_str());
    return res;
  }

  struct dirent* entry;
  while ((entry = readdir(dir)) != NULL) {
    // Skip "." and ".." entries
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
      continue;
    }

    string device_path = string(pci_path) + "/" + entry->d_name;

    // Read vendor ID
    ifstream vendor_file(device_path + "/vendor");
    uint16_t vendor_id;
    vendor_file >> hex >> vendor_id;

    // Read device ID
    ifstream device_file(device_path + "/device");
    uint16_t device_id;
    device_file >> hex >> device_id;

    // Check for match
    if (vendor_id == vid && device_id == did) {
      res.push_back(string(entry->d_name));
      log<level::INFO>(
          std::format("DOE Device Found:{}", entry->d_name).c_str());
    }
  }

  closedir(dir);
  return res;
}

// TODO: should get the ts from the associated firmware
// fake it for now as no consumer and no fw yet.
uint64_t getLastUpdatedTimeStamp(void) {
  tm tm{};
  tm.tm_year = 2023 - 1900;  // 2023
  tm.tm_mon = 3 - 1;         // March
  tm.tm_mday = 8;            // 8th
  tm.tm_hour = 12;
  tm.tm_min = 10;
  tm.tm_isdst = 0;  // Not daylight saving
  time_t timestamp_value = mktime(&tm);
  auto lastUpdated = *(uint64_t*)&timestamp_value;

  return lastUpdated;
}

using GetSubTreeType =
    vector<pair<string, vector<pair<string, vector<string>>>>>;
using message = sdbusplus::message_t;

// TODO: We assume the following dbus object has been created, however,
// it is not guaranteed for other devices.
vector<string> getPCIeDeviceObjPath(uint16_t vendorId, uint16_t deviceId) {
  // setup connection to dbus
  auto b = bus::new_default_system();
  GetSubTreeType inventoryItems;
  vector<string> matchedPaths;

  try {
    auto m =
        b.new_method_call("xyz.openbmc_project.ObjectMapper",
                          "/xyz/openbmc_project/object_mapper",
                          "xyz.openbmc_project.ObjectMapper", "GetSubTree");
    m.append(
        "/xyz/openbmc_project/inventory/", 0,
        array<const char*, 1>{"xyz.openbmc_project.Inventory.Item.PCIeDevice"});
    auto reply = b.call(m);

    inventoryItems = reply.unpack<GetSubTreeType>();
  } catch (const sdbusplus::exception::SdBusError& e) {
    log<level::ERR>(std::format("D-Bus Error: {}", e.what()).c_str());
    return matchedPaths;
  }

  // Process Objects
  for (const auto& [objectPath, services] : inventoryItems) {
    // Given we filter services by specifying interface name,
    // there should be only one matching service.
    string serviceName = services.begin()->first;
    // Check Vendor ID
    for (int i = 0; i < 8; ++i) {
      string propertyVid = "Function" + to_string(i) + "VendorId";
      auto propertyVidProxy =
          b.new_method_call(objectPath.c_str(), serviceName.c_str(),
                            "org.freedesktop.DBus.Properties", "Get");
      propertyVidProxy.append("xyz.openbmc_project.Inventory.Item.PCIeDevice",
                              propertyVid);

      string propertyDid = "Function" + to_string(i) + "DeviceId";
      auto propertyDidProxy =
          b.new_method_call(objectPath.c_str(), objectPath.c_str(),
                            "org.freedesktop.DBus.Properties", "Get");
      propertyDidProxy.append("xyz.openbmc_project.Inventory.Item.PCIeDevice",
                              propertyDid);

      try {
        uint64_t to = 1000;  // 1000 us
        auto vidValueReply = b.call(propertyVidProxy, to);
        auto didValueReply = b.call(propertyDidProxy, to);
        uint16_t vidStoredValue = vidValueReply.unpack<uint16_t>();
        uint16_t didStoredValue = didValueReply.unpack<uint16_t>();

        if (vidStoredValue == vendorId && didStoredValue == deviceId) {
          matchedPaths.push_back(objectPath);
          break;
        }
      } catch (const sdbusplus::exception::SdBusError& e) {
        log<level::ERR>(
            std::format("Error getting property: {}", e.what()).c_str());
      }
    }
  }

  return matchedPaths;
}

// TODO(b/319494175)
// There is no universal approach to map device bdf to D-Bus inventory path
map<string, string> createMapFromVectors(const vector<string>& keys,
                                         const vector<string>& values) {
  // Precondition: Vectors have equal length
  map<string, string> resultMap;
  if (keys.size() != values.size()) {
    log<level::ERR>("Error: Vectors must have equal length.");
    return resultMap;
  }

  // Iterate through the vectors and insert key-value pairs
  for (size_t i = 0; i < keys.size(); ++i) {
    resultMap[keys[i]] = values[i];
  }

  return resultMap;
}

// TODO: extract chassis from object path
string getDeviceChassisIdFromInventoryPath(string& devpath) {
  size_t lastSlash = devpath.find_last_of('/');
  string chassisObjPath;
  string chassisId;
  if (lastSlash == string::npos) {
    log<level::ERR>(std::format("DeviceId not Found! Devpath {}", devpath).c_str());
    return "";
  }

  chassisObjPath = devpath.substr(0, lastSlash);
  lastSlash = chassisObjPath.find_last_of('/');
  if (lastSlash == string::npos) {
    log<level::ERR>(std::format("ChassisId not Found! Devpath {}", devpath).c_str());
    return "";
  }

  chassisId = chassisObjPath.substr(lastSlash + 1);
  log<level::DEBUG>(std::format("ChassisId:{}, Devpath:{}", chassisId, devpath).c_str());
  return chassisId;
}

// Use devpath to get associated Firmware D-Bus obj and check last updated time.
// TODO: hardcode update time for test only
uint64_t getDevFirmwareLastUpdateTime(string& devpath) {
  uint64_t lastUpdated = getLastUpdatedTimeStamp();
  log<level::DEBUG>(
      std::format("LastUpdate: {}, Devpath: {}", lastUpdated, devpath).c_str());
  return lastUpdated;
}

// Get device trusted component's manufacturer, SN, uuid
// TODO: hardcode it for test only
unordered_map<string, string> getDevAssetAttributes(string& devpath) {
  unordered_map<string, string> assetAttrs;
  assetAttrs["Manufacturer"] = "Manufacturer-ABC";
  assetAttrs["SN"] = "SN-12345678";
  assetAttrs["UUID"] = "UUID-abcd12345678";

  log<level::DEBUG>(std::format("Devpath: {}", devpath).c_str());

  return assetAttrs;
}

bool checkMctpMsgType(uint8_t mctpNid, uint8_t mctpEid, uint8_t msgType) {
  log<level::INFO>(std::format("check msg type {:d} {:d} {:d}", mctpNid, mctpEid, msgType).c_str());
  // Connect to the system D-Bus
  auto bus = sdbusplus::bus::new_default();

  // Specify the service name, object path, and interface
  const std::string service = "xyz.openbmc_project.MCTP";
  const std::string objectPath =
    std::format("/xyz/openbmc_project/mctp/{:d}/{:d}",
                                    mctpNid, mctpEid);
  const std::string interface = "xyz.openbmc_project.MCTP.Endpoint";
  // Create a D-Bus object proxy
  auto methodCall = bus.new_method_call(service.c_str(),
                                        objectPath.c_str(),
                                        "org.freedesktop.DBus.Properties",
                                        "Get");
  methodCall.append(interface.c_str(), "SupportedMessageTypes");

  // Invoke the method call
  std::variant<std::vector<uint8_t>> supportedMessageTypes;
  try {
    auto reply = bus.call(methodCall);
    reply.read(supportedMessageTypes);
  } catch (const sdbusplus::exception::SdBusError& e) {
    log<level::ERR>(std::format("D-Bus Error: {}", e.what()).c_str());
    return false;
  }

  std::vector<uint8_t> supportedTypes =
    std::get<std::vector<uint8_t>>(supportedMessageTypes);
  if(supportedTypes.empty()){
    log<level::ERR>(std::format(
      "SupportedMessageTypes is empty for {:s}!", objectPath).c_str());
    return false;
  }

  bool found = false;
  // check if msgType is in supportedTypes
  for (auto t: supportedTypes) {
    if (t == msgType) {
      found = true;
      break;
    }
  }

  return found;
}

bool waitForConfigFileStability(const std::string& filePath,
                                int stableDurationSeconds,
                                int maxRetries,
                                int retryIntervalSeconds) {
  std::filesystem::path file(filePath);
  int retryCount = 0;

  while (true) {
    if (std::filesystem::exists(file)) {
      auto lastModifiedTime = std::filesystem::last_write_time(file);
      std::this_thread::sleep_for(std::chrono::seconds(stableDurationSeconds));

      // Check if file hasn't been modified since sleep
      if (std::filesystem::last_write_time(file) == lastModifiedTime) {
        return true; // File is stable
      }
    }

    // Check if the retry count is exceeded
    if (retryCount >= maxRetries) {
      log<level::ERR>(std::format(
        "Error: File not found or not stable after retries.").c_str());
      return false;
    }

    // Increment retry count and wait for retry interval
    retryCount++;
    std::this_thread::sleep_for(std::chrono::seconds(retryIntervalSeconds));
  }
}

// parse the /var/run/mctp/mctp-i2c-binding.conf, format as below:
//   # object_path i2c_bus address mctp_net mctp_eid
//   /xyz/openbmc_project/inventory/system/board/{ChassisId}/{DeviceId}
//      {I2C_BusId} {I2C_Addr} {MctpNid} {MctpEid}
// filter out each mctp device that supports SPDM messageType
// return tuple of format (ChassisId, DeviceId, MctpNid, MctpEid)
// Note, DeviceId under different ChassisId can be the same.
vector<tuple<string, string, uint8_t, uint8_t>>
  parseMctpConfigAndFilterSpdm(string& confFile) {
  vector<tuple<string, string, uint8_t, uint8_t>> parsedData;
  string line;
  ifstream file;

  // we expect confFile to be already stablized here.
  if (std::filesystem::exists(confFile)) {
    file.open(confFile);
  } else {
    log<level::ERR>(
        format("Error! conf file not exists: {}", confFile).c_str());
    return parsedData;
  }

  // Skip the header line
  getline(file, line);

  while (getline(file, line)) {
    istringstream iss(line);
    string path, deviceName, chassisName;
    int i2cBus, address, mctpNid, mctpEid;

    // Read fields
    iss >> path >> i2cBus >> address >> mctpNid >> mctpEid;
    sdbusplus::message::object_path objPath(path);

    deviceName = objPath.filename();
    if (deviceName.empty()) {
      log<level::ERR>(
          format("Error parse mctp device name from path: {}", path).c_str());
      continue;
    }

    chassisName = objPath.parent_path().filename();
    if (chassisName.empty()) {
      log<level::ERR>(
          format("Error parse chassis name from path: {}", path).c_str());
      continue;
    }

    log<level::INFO>(
        format("Parsed one entry from {:s}:\n {:s}: {:s} {:s} {:d} {:d}",
          confFile, path, chassisName, deviceName, mctpNid, mctpEid).c_str());

    if (checkMctpMsgType(static_cast<uint8_t>(mctpNid),
                         static_cast<uint8_t>(mctpEid),
                         MCTP_MSG_TYPE_SPDM))
      parsedData.push_back(make_tuple(chassisName, deviceName, mctpNid, mctpEid));
  }

  return parsedData;
}
