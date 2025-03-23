#ifndef MCP_CLIENT_VALIDATOR_H
#define MCP_CLIENT_VALIDATOR_H

#include <json/json.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include "MCPValidator.h"

class MCPClientValidator {
private:
	// Supported protocol version range
	std::string supportedVersionPattern;

	// List of tools registered locally
	std::unordered_set<std::string> registeredTools;

	// Allowed URI schemas
	std::unordered_set<std::string> allowedUriSchemas;

	// Registered templates
	std::unordered_set<std::string> registeredTemplates;

	// SQL injection pattern check
	bool containsSqlInjection(const std::string& query);

	// URI schema validation
	bool isValidUriSchema(const std::string& uri);

	// Initialize request validation
	bool verifyInitializeRequest(Json::Value& request);

	// Tool execution request validation
	bool verifyCallToolRequest(Json::Value& request);

	// Resource access request validation
	bool verifyGetResourceRequest(Json::Value& request);

	// Prompt generation request validation
	bool verifyGenerateRequest(Json::Value& request);

	// Streaming request validation
	bool verifyCreateStreamRequest(Json::Value& request);

public:
	MCPClientValidator();

	// Error response validation
	bool verifyErrorResponse(Json::Value& response);

	// Client-side request validation function
	bool verifySendRequest(Json::Value& sendRequest);
};

#endif // MCP_CLIENT_VALIDATOR_H
