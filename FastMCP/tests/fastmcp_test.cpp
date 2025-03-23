// tests/fastmcp_test.cpp
#include "fastmcp.h"
#include <gtest/gtest.h>
#include <sstream>

class FastMCPTest : public ::testing::Test {
protected:
	void SetUp() override
	{
		mcp = std::make_unique<fastmcp::FastMCP>("Test Server");
		
		// Add a simple tool
		mcp->add_tool(
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
		
		// Add a resource
		mcp->add_resource(
			"greeting://{name}",
			[](const std::map<std::string, std::string>& params) -> Json::Value {
				std::string name = params.at("name");
				return "Hello, " + name + "!";
			}
		);
	}

	std::unique_ptr<fastmcp::FastMCP> mcp;
};

// Test handling hello message
TEST_F(FastMCPTest, HandleHello)
{
	Json::Value message;
	message["type"] = "hello";

	Json::Value response = mcp->process_message(message);

	EXPECT_EQ(response["type"].asString(), "ready");
	EXPECT_EQ(response["tools"].size(), 1);
	EXPECT_EQ(response["tools"][0]["name"].asString(), "add");
	EXPECT_EQ(response["resources"].size(), 1);
	EXPECT_EQ(response["resources"][0]["pattern"].asString(), "greeting://{name}");
}

// Test tool execution
TEST_F(FastMCPTest, HandleToolCall)
{
	Json::Value message;
	message["type"] = "tool_call";
	message["tool"] = "add";

	Json::Value params;
	params["a"] = 2;
	params["b"] = 3;
	message["parameters"] = params;

	Json::Value response = mcp->process_message(message);

	EXPECT_EQ(response["type"].asString(), "tool_result");
	EXPECT_EQ(response["result"].asDouble(), 5.0);
}

// Test resource request
TEST_F(FastMCPTest, HandleResourceRequest)
{
	Json::Value message;
	message["type"] = "resource_request";
	message["uri"] = "greeting://World";

	Json::Value response = mcp->process_message(message);

	EXPECT_EQ(response["type"].asString(), "resource_response");
	EXPECT_EQ(response["data"].asString(), "Hello, World!");
}

// Test error handling for non-existent tool
TEST_F(FastMCPTest, HandleNonExistentTool)
{
	Json::Value message;
	message["type"] = "tool_call";
	message["tool"] = "non_existent_tool";

	Json::Value response = mcp->process_message(message);

	EXPECT_EQ(response["type"].asString(), "error");
	EXPECT_TRUE(response["error"].asString().find("Tool not found") != std::string::npos);
}

// Test error handling for non-existent resource
TEST_F(FastMCPTest, HandleNonExistentResource)
{
	Json::Value message;
	message["type"] = "resource_request";
	message["uri"] = "non_existent://resource";

	Json::Value response = mcp->process_message(message);

	EXPECT_EQ(response["type"].asString(), "error");
	EXPECT_TRUE(response["error"].asString().find("Resource not found") != std::string::npos);
}

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
