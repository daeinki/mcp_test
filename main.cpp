#include <iostream>
#include <json/json.h>
#include <cassert>
#include "MCPClientValidator.h"
#include "MCPServerValidator.h"

// Testing Initialize Request
void testInitializeRequest()
{
	std::cout << "Testing Initialize Request..." << std::endl;

	// Creating client-side request
	Json::Value request;
	request["jsonrpc"] = "2.0";
	request["id"] = "init_123";
	request["method"] = "initialize";
	request["params"]["protocolVersion"] = "1.2.0";
	request["params"]["clientInfo"]["name"] = "Claude";
	request["params"]["clientInfo"]["version"] = "2.1";

	// Client-side validation
	MCPClientValidator clientValidator;
	bool clientResult = clientValidator.verifySendRequest(request);
	assert(clientResult);

	// Server-side request preparation (including additional fields)
	request["params"]["clientInfo"]["environment"] = "prod";
	request["params"]["capabilities"]["toolSupport"] = Json::arrayValue;
	request["params"]["capabilities"]["toolSupport"].append("async");
	request["params"]["capabilities"]["maxPayloadSize"] = 1048576;

	// Server-side validation
	MCPServerValidator serverValidator;
	bool serverResult = serverValidator.verifyReceiveRequest(&request);
	assert(serverResult);

	std::cout << "Initialize request test passed." << std::endl;
}

// Testing Call Tool Request
void testCallToolRequest()
{
	std::cout << "Testing Call Tool Request..." << std::endl;

	// Creating client-side request
	Json::Value request;
	request["jsonrpc"] = "2.0";
	request["id"] = "call_123";
	request["method"] = "callTool";
	request["params"]["name"] = "geo_locator";
	request["params"]["arguments"]["ip"] = "192.168.0.1";

	// Client-side validation
	MCPClientValidator clientValidator;
	bool clientResult = clientValidator.verifySendRequest(request);
	assert(clientResult);

	// Server-side request preparation (adding security fields)
	request["_security"]["auth_token"] = "xyz123";
	request["_security"]["rate_limit"] = 50;

	// Server-side validation
	MCPServerValidator serverValidator;
	bool serverResult = serverValidator.verifyReceiveRequest(&request);
	assert(serverResult);

	std::cout << "Call tool request test passed." << std::endl;
}

// Testing Get Resource Request
void testGetResourceRequest()
{
	std::cout << "Testing Get Resource Request..." << std::endl;

	// Creating client-side request
	Json::Value request;
	request["jsonrpc"] = "2.0";
	request["id"] = "resource_123";
	request["method"] = "getResource";
	request["params"]["uri"] = "postgres:///sales";
	request["params"]["query"] = "SELECT * FROM sales WHERE date > '2023-01-01'";

	// Client-side validation
	MCPClientValidator clientValidator;
	bool clientResult = clientValidator.verifySendRequest(request);
	assert(clientResult);

	// Server-side request preparation (adding context fields)
	request["params"]["_context"]["user_role"] = "analyst";

	// Server-side validation
	MCPServerValidator serverValidator;
	bool serverResult = serverValidator.verifyReceiveRequest(&request);
	assert(serverResult);

	std::cout << "Get resource request test passed." << std::endl;
}

// Testing Generate Request
void testGenerateRequest()
{
	std::cout << "Testing Generate Request..." << std::endl;

	// Creating client-side request
	Json::Value request;
	request["jsonrpc"] = "2.0";
	request["id"] = "generate_123";
	request["method"] = "generate";
	request["params"]["template"] = "code_review";
	request["params"]["variables"]["language"] = "python";
	request["params"]["variables"]["complexity"] = 3;

	// Client-side validation
	MCPClientValidator clientValidator;
	bool clientResult = clientValidator.verifySendRequest(request);
	assert(clientResult);

	// Server-side request preparation (adding model constraints)
	request["params"]["_model"]["max_tokens"] = 4096;

	// Server-side validation
	MCPServerValidator serverValidator;
	bool serverResult = serverValidator.verifyReceiveRequest(&request);
	assert(serverResult);

	std::cout << "Generate request test passed." << std::endl;
}

// Testing Stream Request
void testCreateStreamRequest()
{
	std::cout << "Testing Create Stream Request..." << std::endl;

	// Creating client-side request
	Json::Value request;
	request["jsonrpc"] = "2.0";
	request["id"] = "stream_123";
	request["method"] = "createStream";
	request["params"]["session_id"] = "12345678-1234-1234-1234-123456789012";
	request["params"]["qos"]["bandwidth"] = 1000000;

	// Client-side validation
	MCPClientValidator clientValidator;
	bool clientResult = clientValidator.verifySendRequest(request);
	assert(clientResult);

	// Server-side request preparation (adding priority field)
	request["params"]["_priority"] = "high";

	// Server-side validation
	MCPServerValidator serverValidator;
	bool serverResult = serverValidator.verifyReceiveRequest(&request);
	assert(serverResult);

	std::cout << "Create stream request test passed." << std::endl;
}

// Testing Error Response
void testErrorResponse()
{
	std::cout << "Testing Error Response..." << std::endl;

	// Server-side error response creation
	Json::Value serverResponse;
	serverResponse["jsonrpc"] = "2.0";
	serverResponse["id"] = "error_123";
	serverResponse["error"]["code"] = -32603;
	serverResponse["error"]["message"] = "DB Connection Failed";
	serverResponse["error"]["data"]["retryable"] = true;
	serverResponse["error"]["_security"]["stack_trace"] = "at line 42 in db_connect.cpp...";

	// Server-side validation of outgoing response
	MCPServerValidator serverValidator;
	bool serverResult = serverValidator.verifyErrorResponse(&serverResponse);
	assert(!serverResult); // Should fail because of stack trace in production

	// Remove sensitive information before sending to client
	serverResponse["error"]["_security"].removeMember("stack_trace");
	serverResult = serverValidator.verifyErrorResponse(&serverResponse);
	assert(serverResult); // Should pass after removing stack trace

	// Client-side validation of received response
	MCPClientValidator clientValidator;
	bool clientResult = clientValidator.verifyErrorResponse(serverResponse);
	assert(clientResult);

	std::cout << "Error response test passed." << std::endl;
}
// Testing Invalid Requests
void testInvalidRequests()
{
	std::cout << "Testing Invalid Requests..." << std::endl;

	MCPClientValidator clientValidator;

	// 1. Invalid JSON-RPC version
	Json::Value request1;
	request1["jsonrpc"] = "1.0"; // Not 2.0
	request1["id"] = "invalid_1";
	request1["method"] = "initialize";
	request1["params"]["protocolVersion"] = "1.2.0";
	assert(!clientValidator.verifySendRequest(request1));

	// 2. Unsupported method
	Json::Value request2;
	request2["jsonrpc"] = "2.0";
	request2["id"] = "invalid_2";
	request2["method"] = "unsupportedMethod";
	request2["params"]["someParam"] = "value";
	assert(!clientValidator.verifySendRequest(request2));

	// 3. Invalid IP format
	Json::Value request3;
	request3["jsonrpc"] = "2.0";
	request3["id"] = "invalid_3";
	request3["method"] = "callTool";
	request3["params"]["name"] = "geo_locator";
	request3["params"]["arguments"]["ip"] = "999.999.999.999"; // Invalid IP
	assert(!clientValidator.verifySendRequest(request3));

	// 4. SQL Injection attempt
	Json::Value request4;
	request4["jsonrpc"] = "2.0";
	request4["id"] = "invalid_4";
	request4["method"] = "getResource";
	request4["params"]["uri"] = "postgres:///sales";
	request4["params"]["query"] = "SELECT * FROM users; DROP TABLE users;"; // SQL Injection
	assert(!clientValidator.verifySendRequest(request4));

	std::cout << "Invalid requests test passed." << std::endl;
}

int main()
{
	try {
		testInitializeRequest();
		testCallToolRequest();
		testGetResourceRequest();
		testGenerateRequest();
		testCreateStreamRequest();
		testErrorResponse();
		testInvalidRequests();
		
		std::cout << "\nAll tests passed successfully!" << std::endl;
	} catch (const std::exception& e) {
		std::cerr << "Test failed with exception: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}
