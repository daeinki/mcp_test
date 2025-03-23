#include "MCPValidator.h"

namespace MCPValidator {
	bool isValidJsonRpc(const Json::Value& request)
	{
		return request.isMember("jsonrpc") && 
				request["jsonrpc"].isString() && 
				request["jsonrpc"].asString() == "2.0";
	}

	bool isValidId(const Json::Value& id) {
		return id.isString() || id.isInt() || id.isNull();
	}

	bool isValidMethod(const Json::Value& request, const std::string& expectedMethod)
	{
		return request.isMember("method") && 
				request["method"].isString() && 
				request["method"].asString() == expectedMethod;
	}

	bool hasValidParams(const Json::Value& request) {
		return request.isMember("params") && request["params"].isObject();
	}

	bool isValidVersion(const std::string& version, const std::string& pattern)
	{
		std::regex versionRegex(pattern);
		return std::regex_match(version, versionRegex);
	}

	bool isValidIp(const std::string& ip)
	{
		std::regex ipRegex("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
		return std::regex_match(ip, ipRegex);
	}

	bool isValidUuid(const std::string& uuid)
	{
		std::regex uuidRegex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
		return std::regex_match(uuid, uuidRegex);
	}

	bool isValidErrorCode(int code)
	{
		// JSON-RPC 2.0 표준 오류 코드 범위: -32768 ~ -32000
		return (code >= -32768 && code <= -32000);
	}
}
