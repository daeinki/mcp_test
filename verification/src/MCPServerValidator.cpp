#include "MCPServerValidator.h"

MCPServerValidator::MCPServerValidator()
{
	supportedVersions = {"1.2.0"};

	implementedTools = {
		"geo_locator", "code_review", "data_analyzer"
	};

	allowedClients = {
		"Claude", "GPT", "Gemini"
	};

	allowedEnvironments = {
		"prod", "staging", "dev"
	};

	allowedIpRanges = {
		{"192.168.0.0", "192.168.255.255"},
		{"10.0.0.0", "10.255.255.255"}
	};

	maxPayloadSize = 1048576; // 1MB

	serverToolSupport = {"async", "sync", "batch"};

	modelTokenLimits = {
		{"gpt-4", 8192},
		{"claude-2", 100000},
		{"default", 4096}
	};
}

bool MCPServerValidator::resourceExists(const std::string& uri)
{
	// In actual implementation, check the database or file system
	std::unordered_set<std::string> existingResources = {
		"postgres:///sales", "mysql:///users", "file:///data/report.csv"
	};

	return existingResources.find(uri) != existingResources.end();
}

bool MCPServerValidator::isIpInAllowedRange(const std::string& ip)
{
	// For simplicity, only perform string comparison
	for (const auto& range : allowedIpRanges) {
		if (ip >= range.first && ip <= range.second) {
			return true;
		}
	}
	return false;
}

bool MCPServerValidator::hasRolePermission(const std::string& role, const std::string& resource)
{
	// Resource access permissions by role
	std::unordered_map<std::string, std::unordered_set<std::string>> rolePermissions = {
		{"admin", {"postgres:///sales", "mysql:///users", "file:///data/report.csv"}},
		{"analyst", {"postgres:///sales", "file:///data/report.csv"}},
		{"user", {"file:///data/report.csv"}}
	};

	if (rolePermissions.find(role) == rolePermissions.end()) {
		return false;
	}

	return rolePermissions[role].find(resource) != rolePermissions[role].end();
}

bool MCPServerValidator::isValidAuthToken(const std::string& token)
{
	// In actual implementation, perform JWT validation etc.
	std::unordered_set<std::string> validTokens = {
		"xyz123", "abc456", "def789"
	};

	return validTokens.find(token) != validTokens.end();
}

bool MCPServerValidator::isCompatibleTemplateVersion(const std::string& templateName)
{
	// In actual implementation, integrate with template version management system
	std::unordered_map<std::string, std::string> templateVersions = {
		{"code_review", "2.0"},
		{"data_analysis", "1.5"},
		{"summary", "3.0"}
	};

	return templateVersions.find(templateName) != templateVersions.end();
}

bool MCPServerValidator::isValidSession(const std::string& sessionId)
{
	// In actual implementation, connect to session store
	std::unordered_set<std::string> activeSessions = {
		"stream_123", "12345678-1234-1234-1234-123456789012"
	};

	return activeSessions.find(sessionId) != activeSessions.end();
}

bool MCPServerValidator::checkRateLimit(const std::string& clientId, int limit)
{
	std::lock_guard<std::mutex> lock(rateLimitMutex);

	auto now = std::chrono::steady_clock::now();

	if (rateLimits.find(clientId) == rateLimits.end()) {
		// First request
		rateLimits[clientId] = {1, now};
		return true;
	}

	auto& [count, timestamp] = rateLimits[clientId];
	auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - timestamp).count();

	if (elapsed >= 1) {
		// More than 1 second elapsed, reset counter
		count = 1;
		timestamp = now;
		return true;
	} else if (count < limit) {
		// Within 1 second but below the limit
		count++;
		return true;
	} else {
		// Rate limit exceeded
		return false;
	}
}

bool MCPServerValidator::verifyInitializeRequest(Json::Value* request)
{
	if (!request->isMember("params") || !(*request)["params"].isObject()) {
		std::cerr << "Missing or invalid params" << std::endl;
		return false;
	}

	Json::Value& params = (*request)["params"];

	// Verify protocol version (exact match)
	if (!params.isMember("protocolVersion") || !params["protocolVersion"].isString()) {
		std::cerr << "Missing or invalid protocolVersion" << std::endl;
		return false;
	}

	std::string version = params["protocolVersion"].asString();
	if (supportedVersions.find(version) == supportedVersions.end()) {
		std::cerr << "Unsupported protocol version: " << version << std::endl;
		return false;
	}

	// Verify client information
	if (!params.isMember("clientInfo") || !params["clientInfo"].isObject()) {
		std::cerr << "Missing or invalid clientInfo" << std::endl;
		return false;
	}

	Json::Value& clientInfo = params["clientInfo"];

	// Verify client name whitelist
	if (!clientInfo.isMember("name") || !clientInfo["name"].isString()) {
		std::cerr << "Missing or invalid client name" << std::endl;
		return false;
	}

	std::string clientName = clientInfo["name"].asString();
	if (allowedClients.find(clientName) == allowedClients.end()) {
		std::cerr << "Unauthorized client: " << clientName << std::endl;
		return false;
	}

	// Verify environment
	if (clientInfo.isMember("environment") && clientInfo["environment"].isString()) {
		std::string environment = clientInfo["environment"].asString();
		if (allowedEnvironments.find(environment) == allowedEnvironments.end()) {
			std::cerr << "Unauthorized environment: " << environment << std::endl;
			return false;
		}
	}

	// Verify capability compatibility
	if (params.isMember("capabilities") && params["capabilities"].isObject()) {
		Json::Value& capabilities = params["capabilities"];
		
		// Verify tool support
		if (capabilities.isMember("toolSupport") && capabilities["toolSupport"].isArray()) {
			bool hasCompatibleTool = false;
			for (const auto& tool : capabilities["toolSupport"]) {
				if (tool.isString() && serverToolSupport.find(tool.asString()) != serverToolSupport.end()) {
					hasCompatibleTool = true;
					break;
				}
			}
			
			if (!hasCompatibleTool) {
				std::cerr << "No compatible tool support found" << std::endl;
				return false;
			}
		}
		
		// Verify maximum payload size
		if (capabilities.isMember("maxPayloadSize") && capabilities["maxPayloadSize"].isInt()) {
			int clientMaxPayload = capabilities["maxPayloadSize"].asInt();
			if (clientMaxPayload > maxPayloadSize) {
				std::cerr << "Client payload size exceeds server limit" << std::endl;
				return false;
			}
		}
	}

	return true;
}

bool MCPServerValidator::verifyCallToolRequest(Json::Value* request)
{
	if (!request->isMember("params") || !(*request)["params"].isObject()) {
		std::cerr << "Missing or invalid params" << std::endl;
		return false;
	}

	// Verify security token
	if (request->isMember("_security") && (*request)["_security"].isObject()) {
		Json::Value& security = (*request)["_security"];
		
		// Verify authentication token
		if (security.isMember("auth_token") && security["auth_token"].isString()) {
			std::string token = security["auth_token"].asString();
			if (!isValidAuthToken(token)) {
				std::cerr << "Invalid authentication token" << std::endl;
				return false;
			}
		} else {
			std::cerr << "Missing authentication token" << std::endl;
			return false;
		}
		
		// Verify rate limit
		if (security.isMember("rate_limit") && security["rate_limit"].isInt()) {
			int limit = security["rate_limit"].asInt();
			std::string clientId = (*request)["id"].asString();
			
			if (!checkRateLimit(clientId, limit)) {
				std::cerr << "Rate limit exceeded for client: " << clientId << std::endl;
				return false;
			}
		}
	} else {
		std::cerr << "Missing security information" << std::endl;
		return false;
	}

	// Verify IP
	if (request->isMember("arguments") && (*request)["arguments"].isObject()) {
		Json::Value& args = (*request)["arguments"];
		
		if (args.isMember("ip") && args["ip"].isString()) {
			std::string ip = args["ip"].asString();
			if (!isIpInAllowedRange(ip)) {
				std::cerr << "IP not in allowed range: " << ip << std::endl;
				return false;
			}
		}
	}

	return true;
}

bool MCPServerValidator::verifyGetResourceRequest(Json::Value* request)
{
	if (!request->isMember("params") || !(*request)["params"].isObject()) {
		std::cerr << "Missing or invalid params" << std::endl;
		return false;
	}

	Json::Value& params = (*request)["params"];

	// Verify URI existence
	if (!params.isMember("uri") || !params["uri"].isString()) {
		std::cerr << "Missing or invalid URI" << std::endl;
		return false;
	}

	std::string uri = params["uri"].asString();
	if (!resourceExists(uri)) {
		std::cerr << "Resource does not exist: " << uri << std::endl;
		return false;
	}

	// Role-based access control
	if (params.isMember("_context") && params["_context"].isObject()) {
		Json::Value& context = params["_context"];
		
		if (context.isMember("user_role") && context["user_role"].isString()) {
			std::string role = context["user_role"].asString();
			
			if (!hasRolePermission(role, uri)) {
				std::cerr << "Role " << role << " does not have permission to access " << uri << std::endl;
				return false;
			}
		} else {
			std::cerr << "Missing or invalid user role" << std::endl;
			return false;
		}
	} else {
		std::cerr << "Missing context information" << std::endl;
		return false;
	}

	return true;
}

bool MCPServerValidator::verifyGenerateRequest(Json::Value* request)
{
	if (!request->isMember("params") || !(*request)["params"].isObject()) {
		std::cerr << "Missing or invalid params" << std::endl;
		return false;
	}

	Json::Value& params = (*request)["params"];

	// Verify template version compatibility
	if (!params.isMember("template") || !params["template"].isString()) {
		std::cerr << "Missing or invalid template" << std::endl;
		return false;
	}

	std::string templateName = params["template"].asString();
	if (!isCompatibleTemplateVersion(templateName)) {
		std::cerr << "Incompatible template version: " << templateName << std::endl;
		return false;
	}

	// Verify compliance with variable policies
	if (params.isMember("variables") && params["variables"].isObject()) {
		Json::Value& vars = params["variables"];
		
		if (templateName == "code_review" && vars.isMember("complexity") && vars["complexity"].isInt()) {
			int complexity = vars["complexity"].asInt();
			if (complexity > 4) { // Organization policy: maximum 4
				std::cerr << "Complexity exceeds organization policy limit" << std::endl;
				return false;
			}
		}
	}

	// Verify model constraints
	if (params.isMember("_model") && params["_model"].isObject()) {
		Json::Value& model = params["_model"];
		
		if (model.isMember("max_tokens") && model["max_tokens"].isInt()) {
			int requestedTokens = model["max_tokens"].asInt();
			
			// Use default model allocation
			int tokenLimit = modelTokenLimits["default"];
			
			// If a specific model is specified
			if (model.isMember("name") && model["name"].isString()) {
				std::string modelName = model["name"].asString();
				if (modelTokenLimits.find(modelName) != modelTokenLimits.end()) {
					tokenLimit = modelTokenLimits[modelName];
				}
			}
			
			if (requestedTokens > tokenLimit) {
				std::cerr << "Requested tokens exceed model limit: " << requestedTokens << " > " << tokenLimit << std::endl;
				return false;
			}
		}
	}

	return true;
}

bool MCPServerValidator::verifyCreateStreamRequest(Json::Value* request)
{
	if (!request->isMember("params") || !(*request)["params"].isObject()) {
		std::cerr << "Missing or invalid params" << std::endl;
		return false;
	}

	Json::Value& params = (*request)["params"];

	// Verify session ID validity
	if (!params.isMember("session_id") || !params["session_id"].isString()) {
		std::cerr << "Missing or invalid session_id" << std::endl;
		return false;
	}

	std::string sessionId = params["session_id"].asString();
	if (!isValidSession(sessionId)) {
		std::cerr << "Invalid session: " << sessionId << std::endl;
		return false;
	}

	// Verify QoS
	if (params.isMember("qos") && params["qos"].isObject()) {
		Json::Value& qos = params["qos"];
		
		if (qos.isMember("bandwidth") && qos["bandwidth"].isInt()) {
			int bandwidth = qos["bandwidth"].asInt();
			// Check server capacity limit (e.g., maximum 100Mbps)
			if (bandwidth > 100000000) {
				std::cerr << "Requested bandwidth exceeds server capacity" << std::endl;
				return false;
			}
		}
	}

	// Handle according to SLA grade
	if (params.isMember("_priority") && params["_priority"].isString()) {
		std::string priority = params["_priority"].asString();
		// Here you can implement additional verification logic according to SLA grade.
		// For example, special handling for priority "high".
	}

	return true;
}

bool MCPServerValidator::verifyErrorResponse(Json::Value* response)
{
	if (!response->isMember("error") || !(*response)["error"].isObject()) {
		std::cerr << "Missing or invalid error object" << std::endl;
		return false;
	}

	Json::Value& error = (*response)["error"];

	// Verify error code
	if (!error.isMember("code") || !error["code"].isInt()) {
		std::cerr << "Missing or invalid error code" << std::endl;
		return false;
	}

	int code = error["code"].asInt();
	if (!MCPValidator::isValidErrorCode(code)) {
		std::cerr << "Error code out of valid range: " << code << std::endl;
		return false;
	}

	// Verify internal error classification mapping
	// In actual implementation, verify mapping with server's internal error codes.

	// Verify retryable status
	if (error.isMember("data") && error["data"].isObject()) {
		Json::Value& data = error["data"];
		if (data.isMember("retryable") && data["retryable"].isBool()) {
			bool retryable = data["retryable"].asBool();
			// Here you can verify if retry is actually possible based on the server's current state.
		}
	}

	// Check for sensitive information leakage
	if (error.isMember("_security") && error["_security"].isObject()) {
		Json::Value& security = error["_security"];
		if (security.isMember("stack_trace")) {
			// In production environment, stack trace should be removed.
			std::cerr << "Stack trace should not be included in production environment" << std::endl;
			return false;
		}
	}

	return true;
}

bool MCPServerValidator::verifyReceiveRequest(Json::Value* receiveRequest)
{
	// Verify error response
	if (receiveRequest->isMember("error")) {
		return verifyErrorResponse(receiveRequest);
	}

	// Verify general request
	if (!receiveRequest->isMember("method") || !(*receiveRequest)["method"].isString()) {
		std::cerr << "Missing or invalid method" << std::endl;
		return false;
	}

	std::string method = (*receiveRequest)["method"].asString();

	if (method == "initialize") {
		return verifyInitializeRequest(receiveRequest);
	} else if (method == "callTool") {
		return verifyCallToolRequest(receiveRequest);
	} else if (method == "getResource") {
		return verifyGetResourceRequest(receiveRequest);
	} else if (method == "generate") {
		return verifyGenerateRequest(receiveRequest);
	} else if (method == "createStream") {
		return verifyCreateStreamRequest(receiveRequest);
	} else {
		std::cerr << "Unsupported method: " << method << std::endl;
		return false;
	}
}
