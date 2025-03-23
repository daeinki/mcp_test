// src/fastmcp.cpp
#include "fastmcp.h"
#include <iostream>
#include <sstream>
#include <regex>

namespace fastmcp {

FastMCP::FastMCP(const std::string& name) : name_(name) {}

FastMCP::~FastMCP() {}

void FastMCP::add_tool(const std::string& name, 
						const std::string& description,
						const std::vector<std::string>& parameter_names,
						const std::vector<std::string>& parameter_types,
						const std::string& return_type,
						ToolFunction function)
{
	Tool tool;
	tool.name = name;
	tool.description = description;
	tool.parameter_names = parameter_names;
	tool.parameter_types = parameter_types;
	tool.return_type = return_type;
	tool.function = function;

	tools_[name] = tool;
}

void FastMCP::add_resource(const std::string& pattern, ResourceFunction function)
{
	Resource resource;
	resource.pattern = pattern;
	resource.function = function;

	resources_.push_back(resource);
}

void FastMCP::run(const std::string& transport)
{
	if (transport == "stdio") {
		run_stdio();
	} else {
		std::cerr << "Unsupported transport: " << transport << std::endl;
	}
}

Json::Value FastMCP::process_message(const Json::Value& message)
{
	std::string type = message["type"].asString();

	if (type == "hello") {
		return handle_hello();
	} else if (type == "tool_call") {
		return handle_tool_call(message);
	} else if (type == "resource_request") {
		return handle_resource_request(message);
	} else {
		Json::Value error;
		error["type"] = "error";
		error["error"] = "Unknown message type: " + type;
		return error;
	}
}

Json::Value FastMCP::handle_hello()
{
	Json::Value response;
	response["type"] = "ready";

	// Add tools
	Json::Value toolsJson(Json::arrayValue);
	for (const auto& pair : tools_) {
		const Tool& tool = pair.second;
		
		Json::Value toolJson;
		toolJson["name"] = tool.name;
		toolJson["description"] = tool.description;
		
		Json::Value paramsJson(Json::arrayValue);
		for (size_t i = 0; i < tool.parameter_names.size(); i++) {
			Json::Value paramJson;
			paramJson["name"] = tool.parameter_names[i];
			paramJson["type"] = tool.parameter_types[i];
			paramsJson.append(paramJson);
		}
		
		toolJson["parameters"] = paramsJson;
		toolJson["return_type"] = tool.return_type;
		
		toolsJson.append(toolJson);
	}
	response["tools"] = toolsJson;

	// Add resources
	Json::Value resourcesJson(Json::arrayValue);
	for (const Resource& resource : resources_) {
		Json::Value resourceJson;
		resourceJson["pattern"] = resource.pattern;
		resourcesJson.append(resourceJson);
	}
	response["resources"] = resourcesJson;

	return response;
}

Json::Value FastMCP::handle_tool_call(const Json::Value& message)
{
	std::string tool_name = message["tool"].asString();

	// Check if tool exists
	if (tools_.find(tool_name) == tools_.end()) {
		Json::Value error;
		error["type"] = "error";
		error["error"] = "Tool not found: " + tool_name;
		return error;
	}

	// Get parameters
	const Json::Value& params = message["parameters"];

	// Call tool function
	try {
		Json::Value result = tools_[tool_name].function(params);
		
		Json::Value response;
		response["type"] = "tool_result";
		response["result"] = result;
		
		return response;
	} catch (const std::exception& e) {
		Json::Value error;
		error["type"] = "error";
		error["error"] = "Tool execution error: " + std::string(e.what());
		return error;
	}
}

Json::Value FastMCP::handle_resource_request(const Json::Value& message)
{
	std::string uri = message["uri"].asString();

	// Find matching resource
	for (const Resource& resource : resources_) {
		std::map<std::string, std::string> params;
		if (match_resource_pattern(resource.pattern, uri, params)) {
			try {
				Json::Value result = resource.function(params);
				
				Json::Value response;
				response["type"] = "resource_response";
				response["data"] = result;
				
				return response;
			} catch (const std::exception& e) {
				Json::Value error;
				error["type"] = "error";
				error["error"] = "Resource execution error: " + std::string(e.what());
				return error;
			}
		}
	}

	// No matching resource found
	Json::Value error;
	error["type"] = "error";
	error["error"] = "Resource not found: " + uri;
	return error;
}

bool FastMCP::match_resource_pattern(const std::string& pattern, const std::string& uri,
									std::map<std::string, std::string>& params)
{
	// Convert pattern to regex
	std::string regex_pattern = pattern;
	std::regex param_regex("\\{([^\\}]+)\\}");
	std::string replaced_pattern = std::regex_replace(regex_pattern, param_regex, "([^/]+)");

	// Add start and end anchors
	replaced_pattern = "^" + replaced_pattern + "$";

	// Extract parameter names
	std::vector<std::string> param_names;
	auto param_begin = std::sregex_iterator(pattern.begin(), pattern.end(), param_regex);
	auto param_end = std::sregex_iterator();

	for (auto it = param_begin; it != param_end; ++it) {
		std::smatch match = *it;
		param_names.push_back(match[1].str());
	}

	// Match URI against pattern
	std::regex uri_regex(replaced_pattern);
	std::smatch uri_match;

	if (std::regex_match(uri, uri_match, uri_regex)) {
		// Extract parameter values
		for (size_t i = 0; i < param_names.size(); i++) {
			params[param_names[i]] = uri_match[i + 1].str();
		}
		return true;
	}

	return false;
}

void FastMCP::run_stdio()
{
	std::string line;
	Json::CharReaderBuilder reader;
	Json::StreamWriterBuilder writer;

	while (std::getline(std::cin, line)) {
		if (line.empty()) {
			continue;
		}
		
		// Parse JSON message
		Json::Value message;
		std::string errors;
		std::istringstream input(line);
		
		if (!Json::parseFromStream(reader, input, &message, &errors)) {
			std::cerr << "Error parsing JSON: " << errors << std::endl;
			continue;
		}
		
		// Process message
		Json::Value response = process_message(message);
		
		// Write response
		std::string output = Json::writeString(writer, response);
		std::cout << output << std::endl;
	}
}

} // namespace fastmcp
