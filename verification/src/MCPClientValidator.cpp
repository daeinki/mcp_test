#include "MCPClientValidator.h"

MCPClientValidator::MCPClientValidator()
{
	supportedVersionPattern = "^1\\.[0-9]+\\.[0-9]+$";

	registeredTools = {
		"geo_locator", "code_review", "data_analyzer"
	};

	allowedUriSchemas = {
		"postgres", "mysql", "file", "http", "https"
	};

	registeredTemplates = {
		"code_review", "data_analysis", "summary"
	};
}

bool MCPClientValidator::containsSqlInjection(const std::string& query)
{
	std::vector<std::string> patterns = {
		"--", ";--", ";", "/*", "*/", "@@", "@", 
		"char", "nchar", "varchar", "exec", "execute"
	};

	for (const auto& pattern : patterns) {
		if (query.find(pattern) != std::string::npos) {
			return true;
		}
	}
	return false;
}

bool MCPClientValidator::isValidUriSchema(const std::string& uri)
{
	size_t pos = uri.find(":");
	if (pos == std::string::npos) return false;

	std::string schema = uri.substr(0, pos);
	return allowedUriSchemas.find(schema) != allowedUriSchemas.end();
}

bool MCPClientValidator::verifyInitializeRequest(Json::Value& request)
{
	// Basic JSON-RPC validation
	if (!MCPValidator::isValidJsonRpc(request)) {
		std::cerr << "Invalid JSON-RPC format" << std::endl;
		return false;
	}

	// ID validation
	if (!request.isMember("id") || !MCPValidator::isValidId(request["id"])) {
		std::cerr << "Invalid or missing request ID" << std::endl;
		return false;
	}

	// Method validation
	if (!MCPValidator::isValidMethod(request, "initialize")) {
		std::cerr << "Invalid or missing method" << std::endl;
		return false;
	}

	// Params validation
	if (!MCPValidator::hasValidParams(request)) {
		std::cerr << "Invalid or missing params" << std::endl;
		return false;
	}

	// protocolVersion validation
	Json::Value& params = request["params"];
	if (!params.isMember("protocolVersion") || !params["protocolVersion"].isString()) {
		std::cerr << "Missing or invalid protocolVersion" << std::endl;
		return false;
	}

	std::string version = params["protocolVersion"].asString();
	if (!MCPValidator::isValidVersion(version, supportedVersionPattern)) {
		std::cerr << "Unsupported protocol version: " << version << std::endl;
		return false;
	}

	// clientInfo validation
	if (!params.isMember("clientInfo") || !params["clientInfo"].isObject()) {
		std::cerr << "Missing or invalid clientInfo" << std::endl;
		return false;
	}

	Json::Value& clientInfo = params["clientInfo"];
	if (!clientInfo.isMember("name") || !clientInfo["name"].isString() ||
		!clientInfo.isMember("version") || !clientInfo["version"].isString()) {
		std::cerr << "Missing required fields in clientInfo" << std::endl;
		return false;
	}

	return true;
}

bool MCPClientValidator::verifyCallToolRequest(Json::Value& request)
{
	// Basic JSON-RPC validation
	if (!MCPValidator::isValidJsonRpc(request)) return false;
	if (!request.isMember("id") || !MCPValidator::isValidId(request["id"])) return false;
	if (!MCPValidator::isValidMethod(request, "callTool")) return false;
	if (!MCPValidator::hasValidParams(request)) return false;

	// Tool name validation
	Json::Value& params = request["params"];
	if (!params.isMember("name") || !params["name"].isString()) {
		std::cerr << "Missing or invalid tool name" << std::endl;
		return false;
	}

	std::string toolName = params["name"].asString();
	if (registeredTools.find(toolName) == registeredTools.end()) {
		std::cerr << "Unknown tool: " << toolName << std::endl;
		return false;
	}

	// Arguments validation
	if (!params.isMember("arguments") || !params["arguments"].isObject()) {
		std::cerr << "Missing or invalid arguments" << std::endl;
		return false;
	}

	// Tool-specific validation
	if (toolName == "geo_locator") {
		Json::Value& args = params["arguments"];
		if (!args.isMember("ip") || !args["ip"].isString()) {
			std::cerr << "Missing IP argument for geo_locator" << std::endl;
			return false;
		}
		
		std::string ip = args["ip"].asString();
		if (!MCPValidator::isValidIp(ip)) {
			std::cerr << "Invalid IP format: " << ip << std::endl;
			return false;
		}
	}

	return true;
}

bool MCPClientValidator::verifyGetResourceRequest(Json::Value& request)
{
	// Basic JSON-RPC validation
	if (!MCPValidator::isValidJsonRpc(request)) return false;
	if (!request.isMember("id") || !MCPValidator::isValidId(request["id"])) return false;
	if (!MCPValidator::isValidMethod(request, "getResource")) return false;
	if (!MCPValidator::hasValidParams(request)) return false;

	// URI validation
	Json::Value& params = request["params"];
	if (!params.isMember("uri") || !params["uri"].isString()) {
		std::cerr << "Missing or invalid URI" << std::endl;
		return false;
	}

	std::string uri = params["uri"].asString();
	if (!isValidUriSchema(uri)) {
		std::cerr << "Invalid or disallowed URI schema: " << uri << std::endl;
		return false;
	}

	// Query validation (Prevent SQL injection)
	if (params.isMember("query") && params["query"].isString()) {
		std::string query = params["query"].asString();
		if (containsSqlInjection(query)) {
			std::cerr << "Potential SQL injection detected" << std::endl;
			return false;
		}
	}

	return true;
}

bool MCPClientValidator::verifyGenerateRequest(Json::Value& request)
{
	// Basic JSON-RPC validation
	if (!MCPValidator::isValidJsonRpc(request)) return false;
	if (!request.isMember("id") || !MCPValidator::isValidId(request["id"])) return false;
	if (!MCPValidator::isValidMethod(request, "generate")) return false;
	if (!MCPValidator::hasValidParams(request)) return false;

	// Template validation
	Json::Value& params = request["params"];
	if (!params.isMember("template") || !params["template"].isString()) {
		std::cerr << "Missing or invalid template" << std::endl;
		return false;
	}

	std::string templateName = params["template"].asString();
	if (registeredTemplates.find(templateName) == registeredTemplates.end()) {
		std::cerr << "Unknown template: " << templateName << std::endl;
		return false;
	}

	// Variables validation
	if (!params.isMember("variables") || !params["variables"].isObject()) {
		std::cerr << "Missing or invalid variables" << std::endl;
		return false;
	}

	// Template-specific validation
	if (templateName == "code_review") {
		Json::Value& vars = params["variables"];
		if (vars.isMember("complexity") && vars["complexity"].isInt()) {
			int complexity = vars["complexity"].asInt();
			if (complexity < 1 || complexity > 5) {
				std::cerr << "Complexity must be between 1 and 5" << std::endl;
				return false;
			}
		}
	}

	return true;
}

bool MCPClientValidator::verifyCreateStreamRequest(Json::Value& request)
{
	// Basic JSON-RPC validation
	if (!MCPValidator::isValidJsonRpc(request)) return false;
	if (!request.isMember("id") || !MCPValidator::isValidId(request["id"])) return false;
	if (!MCPValidator::isValidMethod(request, "createStream")) return false;
	if (!MCPValidator::hasValidParams(request)) return false;

	// Session ID validation
	Json::Value& params = request["params"];
	if (!params.isMember("session_id") || !params["session_id"].isString()) {
		std::cerr << "Missing or invalid session_id" << std::endl;
		return false;
	}

	std::string sessionId = params["session_id"].asString();
	if (!MCPValidator::isValidUuid(sessionId)) {
		std::cerr << "Invalid UUID format for session_id: " << sessionId << std::endl;
		return false;
	}

	// QoS validation
	if (params.isMember("qos") && params["qos"].isObject()) {
		Json::Value& qos = params["qos"];
		if (qos.isMember("bandwidth") && qos["bandwidth"].isInt()) {
			int bandwidth = qos["bandwidth"].asInt();
			// Client performance limit check (e.g., max 10Mbps)
			if (bandwidth > 10000000) {
				std::cerr << "Requested bandwidth exceeds client limit" << std::endl;
				return false;
			}
		}
	}

	return true;
}

bool MCPClientValidator::verifyErrorResponse(Json::Value& response)
{
	if (!response.isMember("error") || !response["error"].isObject()) {
		std::cerr << "Missing or invalid error object" << std::endl;
		return false;
	}

	Json::Value& error = response["error"];

	// Error code validation
	if (!error.isMember("code") || !error["code"].isInt()) {
		std::cerr << "Missing or invalid error code" << std::endl;
		return false;
	}

	int code = error["code"].asInt();
	if (!MCPValidator::isValidErrorCode(code)) {
		std::cerr << "Error code out of valid range: " << code << std::endl;
		return false;
	}

	// Error message validation
	if (!error.isMember("message") || !error["message"].isString()) {
		std::cerr << "Missing or invalid error message" << std::endl;
		return false;
	}

	// Diagnostic data validation
	if (error.isMember("data") && !error["data"].isObject()) {
		std::cerr << "Invalid error data format" << std::endl;
		return false;
	}

	if (error.isMember("data") && error["data"].isObject()) {
		Json::Value& data = error["data"];
		if (data.isMember("retryable") && !data["retryable"].isBool()) {
			std::cerr << "Invalid retryable flag format" << std::endl;
			return false;
		}
	}

	return true;
}

bool MCPClientValidator::verifySendRequest(Json::Value& sendRequest)
{
	// Error response validation
	if (sendRequest.isMember("error")) {
		return verifyErrorResponse(sendRequest);
	}

	// General request validation
	if (!sendRequest.isMember("method") || !sendRequest["method"].isString()) {
		std::cerr << "Missing or invalid method" << std::endl;
		return false;
	}

	std::string method = sendRequest["method"].asString();

	if (method == "initialize") {
		return verifyInitializeRequest(sendRequest);
	} else if (method == "callTool") {
		return verifyCallToolRequest(sendRequest);
	} else if (method == "getResource") {
		return verifyGetResourceRequest(sendRequest);
	} else if (method == "generate") {
		return verifyGenerateRequest(sendRequest);
	} else if (method == "createStream") {
		return verifyCreateStreamRequest(sendRequest);
	} else {
		std::cerr << "Unsupported method: " << method << std::endl;
		return false;
	}
}
