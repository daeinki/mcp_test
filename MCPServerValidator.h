#ifndef MCP_SERVER_VALIDATOR_H
#define MCP_SERVER_VALIDATOR_H

#include <json/json.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <chrono>
#include <mutex>
#include "MCPValidator.h"

class MCPServerValidator {
private:
	// Exact supported protocol versions
	std::unordered_set<std::string> supportedVersions;

	// List of tools implemented on the server
	std::unordered_set<std::string> implementedTools;

	// List of allowed clients
	std::unordered_set<std::string> allowedClients;

	// List of allowed environments
	std::unordered_set<std::string> allowedEnvironments;

	// Allowed IP ranges
	std::vector<std::pair<std::string, std::string>> allowedIpRanges;

	// Server maximum payload size
	int maxPayloadSize;

	// Server tool support list
	std::unordered_set<std::string> serverToolSupport;

	// Maximum token allocations per model
	std::unordered_map<std::string, int> modelTokenLimits;

	// Check if resource exists
	bool resourceExists(const std::string& uri);

	// Check if IP is within allowed range
	bool isIpInAllowedRange(const std::string& ip);

	// Role-based access control
	bool hasRolePermission(const std::string& role, const std::string& resource);

	// Token validation
	bool isValidAuthToken(const std::string& token);

	// Server template version compatibility validation
	bool isCompatibleTemplateVersion(const std::string& templateName);

	// Session validation
	bool isValidSession(const std::string& sessionId);

	// Initialize request validation
	bool verifyInitializeRequest(Json::Value* request);

	// Tool execution request validation
	bool verifyCallToolRequest(Json::Value* request);

	// Resource access request validation
	bool verifyGetResourceRequest(Json::Value* request);

	// Prompt generation request validation
	bool verifyGenerateRequest(Json::Value* request);

	// Streaming request validation
	bool verifyCreateStreamRequest(Json::Value* request);

	// Request rate limit validation
	bool checkRateLimit(const std::string& clientId, int limit);

	// Current request rate storage
	std::unordered_map<std::string, std::pair<int, std::chrono::time_point<std::chrono::steady_clock>>> rateLimits;
	std::mutex rateLimitMutex;

public:
	MCPServerValidator();

	// Error response validation
	bool verifyErrorResponse(Json::Value* response);

	// Server-side request validation function
	bool verifyReceiveRequest(Json::Value* receiveRequest);
};

#endif // MCP_SERVER_VALIDATOR_H
