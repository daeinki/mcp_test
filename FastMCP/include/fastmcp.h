// include/fastmcp.h
#ifndef FASTMCP_H
#define FASTMCP_H

#include <string>
#include <functional>
#include <map>
#include <vector>
#include <json/json.h>

namespace fastmcp {

// Tool function type
using ToolFunction = std::function<Json::Value(const Json::Value&)>;

// Resource function type
using ResourceFunction = std::function<Json::Value(const std::map<std::string, std::string>&)>;

// MCP message types
enum class MessageType {
	HELLO,
	READY,
	TOOL_CALL,
	TOOL_RESULT,
	RESOURCE_REQUEST,
	RESOURCE_RESPONSE,
	ERROR
};

// Tool definition
struct Tool {
	std::string name;
	std::string description;
	std::vector<std::string> parameter_names;
	std::vector<std::string> parameter_types;
	std::string return_type;
	ToolFunction function;
};

// Resource definition
struct Resource {
	std::string pattern;
	ResourceFunction function;
};

class FastMCP {
public:
	FastMCP(const std::string& name);
	~FastMCP();

	// Add a tool
	void add_tool(const std::string& name, 
					const std::string& description,
					const std::vector<std::string>& parameter_names,
					const std::vector<std::string>& parameter_types,
					const std::string& return_type,
					ToolFunction function);

	// Add a resource
	void add_resource(const std::string& pattern, ResourceFunction function);

	// Run the server
	void run(const std::string& transport = "stdio");

	// Process a message (public for testing)
	Json::Value process_message(const Json::Value& message);

private:
	std::string name_;
	std::map<std::string, Tool> tools_;
	std::vector<Resource> resources_;

	// Handle different message types
	Json::Value handle_hello();
	Json::Value handle_tool_call(const Json::Value& message);
	Json::Value handle_resource_request(const Json::Value& message);

	// Match a resource pattern
	bool match_resource_pattern(const std::string& pattern, const std::string& uri, 
								std::map<std::string, std::string>& params);

	// Helper functions for transport
	void run_stdio();
};

} // namespace fastmcp

#endif // FASTMCP_H
