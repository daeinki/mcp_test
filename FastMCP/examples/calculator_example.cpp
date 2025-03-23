// examples/calculator_example.cpp
#include "fastmcp.h"
#include <cmath>

int main()
{
	// Create an MCP server
	fastmcp::FastMCP mcp("Calculator Example");

	// Add tools
	mcp.add_tool(
		"add", 
		"Add two numbers",
		{"a", "b"},
		{"number", "number"},
		"number",
		[](const Json::Value& params) -> Json::Value {
			double a = params["a"].asDouble();
			double b = params["b"].asDouble();
			return a + b;
		}
	);

	mcp.add_tool(
		"subtract", 
		"Subtract two numbers",
		{"a", "b"},
		{"number", "number"},
		"number",
		[](const Json::Value& params) -> Json::Value {
			double a = params["a"].asDouble();
			double b = params["b"].asDouble();
			return a - b;
		}
	);

	mcp.add_tool(
		"multiply", 
		"Multiply two numbers",
		{"a", "b"},
		{"number", "number"},
		"number",
		[](const Json::Value& params) -> Json::Value {
			double a = params["a"].asDouble();
			double b = params["b"].asDouble();
			return a * b;
		}
	);

	mcp.add_tool(
		"divide", 
		"Divide two numbers",
		{"a", "b"},
		{"number", "number"},
		"number",
		[](const Json::Value& params) -> Json::Value {
			double a = params["a"].asDouble();
			double b = params["b"].asDouble();
			if (b == 0) {
				throw std::runtime_error("Division by zero");
			}
			return a / b;
		}
	);

	mcp.add_tool(
		"sqrt", 
		"Square root of a number",
		{"a"},
		{"number"},
		"number",
		[](const Json::Value& params) -> Json::Value {
			double a = params["a"].asDouble();
			if (a < 0) {
				throw std::runtime_error("Cannot take square root of negative number");
			}
			return std::sqrt(a);
		}
	);

	// Add a resource
	mcp.add_resource(
		"greeting://{name}",
		[](const std::map<std::string, std::string>& params) -> Json::Value {
			std::string name = params.at("name");
			return "Hello, " + name + "!";
		}
	);

	// Run the server
	mcp.run();

	return 0;
}
