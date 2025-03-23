#ifndef MCP_VALIDATOR_H
#define MCP_VALIDATOR_H

#include <json/json.h>
#include <string>
#include <vector>
#include <regex>
#include <unordered_map>
#include <unordered_set>

namespace MCPValidator {
	// Common utility functions
	bool isValidJsonRpc(const Json::Value& request);
	bool isValidId(const Json::Value& id);
	bool isValidMethod(const Json::Value& request, const std::string& expectedMethod);
	bool hasValidParams(const Json::Value& request);
	bool isValidVersion(const std::string& version, const std::string& pattern);
	bool isValidIp(const std::string& ip);
	bool isValidUuid(const std::string& uuid);
	bool isValidErrorCode(int code);
}

#endif // MCP_VALIDATOR_H
