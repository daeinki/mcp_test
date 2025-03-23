#include <iostream>
#include <string>
#include <json/json.h>

// MCP Server (Brave Search) Class
class MCPServer {
public:
    std::string name = "brave-search";
    std::string version = "0.6.2";

    // Method to process JSON-RPC messages and generate responses
    Json::Value processMessage(const Json::Value& message) {
        std::string method = message["method"].asString();

        // Handle initialize request
        if (method == "initialize") {
            Json::Value response;
            response["jsonrpc"] = "2.0";
            response["id"] = message["id"];
            Json::Value result;
            result["protocolVersion"] = "2024-11-05";
            Json::Value serverInfo;
            serverInfo["name"] = name;
            serverInfo["version"] = version;
            result["serverInfo"] = serverInfo;
            // Set capabilities (example)
            Json::Value capabilities;
            capabilities["tools"] = Json::arrayValue;
            Json::Value resources;
            resources["subscribe"] = true;
            capabilities["resources"] = resources;
            capabilities["prompts"] = Json::objectValue;
            capabilities["logging"] = Json::objectValue;
            result["capabilities"] = capabilities;
            response["result"] = result;
            return response;
        }
        // Handle listTools request
        else if (method == "listTools") {
            Json::Value response;
            response["jsonrpc"] = "2.0";
            response["id"] = message["id"];
            Json::Value result;
            Json::Value tools(Json::arrayValue);

            // Tool 1: brave_web_search
            Json::Value tool1;
            tool1["name"] = "brave_web_search";
            tool1["description"] = "Performs a web search using the Brave Search API, ideal for general queries, news, articles, and online content.";
            Json::Value inputSchema;
            inputSchema["type"] = "object";
            Json::Value properties;
            Json::Value queryProp;
            queryProp["type"] = "string";
            queryProp["description"] = "Search query (max 400 chars, 50 words)";
            properties["query"] = queryProp;
            Json::Value countProp;
            countProp["type"] = "number";
            countProp["description"] = "Number of results (1-20, default 10)";
            countProp["default"] = 10;
            properties["count"] = countProp;
            Json::Value offsetProp;
            offsetProp["type"] = "number";
            offsetProp["description"] = "Pagination offset (max 9, default 0)";
            offsetProp["default"] = 0;
            properties["offset"] = offsetProp;
            inputSchema["properties"] = properties;
            Json::Value required(Json::arrayValue);
            required.append("query");
            inputSchema["required"] = required;
            tool1["inputSchema"] = inputSchema;
            tools.append(tool1);

            // Tool 2: brave_local_search (brief information)
            Json::Value tool2;
            tool2["name"] = "brave_local_search";
            tool2["description"] = "Searches for local businesses and locations...";
            tool2["inputSchema"] = Json::objectValue; // Simplified
            tools.append(tool2);

            result["tools"] = tools;
            response["result"] = result;
            return response;
        }
        // Handle callTool request
        else if (method == "callTool") {
            Json::Value params = message["params"];
            std::string toolName = params["name"].asString();
            Json::Value arguments = params["arguments"];
            Json::Value response;
            response["jsonrpc"] = "2.0";
            response["id"] = message["id"];

            if (toolName == "brave_web_search") {
                // Validate the presence of the required argument 'query'
                if (!arguments.isMember("query") || !arguments["query"].isString()) {
                    Json::Value error;
                    error["code"] = -32602;
                    error["message"] = "Invalid arguments for brave_web_search";
                    Json::Value data;
                    data["isError"] = true;
                    Json::Value content(Json::arrayValue);
                    Json::Value errorMsg;
                    errorMsg["type"] = "text";
                    errorMsg["text"] = "Error: Invalid arguments for brave_web_search";
                    content.append(errorMsg);
                    data["content"] = content;
                    error["data"] = data;
                    response["error"] = error;
                    return response;
                }
                std::string query = arguments["query"].asString();
                int count = arguments.isMember("count") ? arguments["count"].asInt() : 10;

                // (Simulate actual API call or rate limit check)
                std::string resultText = "Search Results for: " + query + "\n\n";
                for (int i = 1; i <= count; i++) {
                    resultText += std::to_string(i) + ". [Result " + std::to_string(i) +
                                  "] - Description of search result " + std::to_string(i) + "\n";
                }
                Json::Value result;
                Json::Value content(Json::arrayValue);
                Json::Value textContent;
                textContent["type"] = "text";
                textContent["text"] = resultText;
                content.append(textContent);
                result["content"] = content;
                result["isError"] = false;
                response["result"] = result;
                return response;
            }
            else {
                // Handle undefined tool call
                Json::Value error;
                error["code"] = -32601;
                error["message"] = "Method not found";
                response["error"] = error;
                return response;
            }
        }
        // Handle shutdown request
        else if (method == "shutdown") {
            Json::Value response;
            response["jsonrpc"] = "2.0";
            response["id"] = message["id"];
            response["result"] = Json::nullValue;
            return response;
        }
        // Handle exit and initialized notifications (no response)
        else if (method == "exit") {
            std::cout << "Server received exit notification.\n";
            return Json::Value();
        }
        else if (method == "initialized") {
            std::cout << "Server received initialized notification.\n";
            return Json::Value();
        }
        else {
            // Handle unknown method
            Json::Value response;
            response["jsonrpc"] = "2.0";
            response["id"] = message["id"];
            Json::Value error;
            error["code"] = -32601;
            error["message"] = "Method not found";
            response["error"] = error;
            return response;
        }
    }
};

// MCP Client (Claude) Class
class MCPClient {
public:
    std::string name = "Claude-Desktop";
    std::string version = "1.0.0";
    MCPServer* server; // Connection to the server (simulation)

    MCPClient(MCPServer* srv) : server(srv) {}

    // Send request and receive response (JSON-RPC format)
    Json::Value sendRequest(const Json::Value& request) {
        std::cout << "Client sending: " << request.toStyledString() << std::endl;
        Json::Value response = server->processMessage(request);
        if (!response.isNull()) {
            if (response.isMember("result"))
                std::cout << "Client received response: " << response.toStyledString() << std::endl;
            else if (response.isMember("error"))
                std::cout << "Client received error: " << response.toStyledString() << std::endl;
        }
        return response;
    }

    // Send notification without expecting a response
    void sendNotification(const Json::Value& notification) {
        std::cout << "Client sending notification: " << notification.toStyledString() << std::endl;
        server->processMessage(notification);
    }

    // Simulate connection and handshake
    void connect() {
        // Initialize request
        Json::Value initRequest;
        initRequest["jsonrpc"] = "2.0";
        initRequest["id"] = 1;
        initRequest["method"] = "initialize";
        Json::Value params;
        params["protocolVersion"] = "2024-11-05";
        Json::Value clientInfo;
        clientInfo["name"] = name;
        clientInfo["version"] = version;
        params["clientInfo"] = clientInfo;
        params["capabilities"] = Json::objectValue; // Simplified
        initRequest["params"] = params;
        sendRequest(initRequest);

        // Send initialized notification
        Json::Value initNotification;
        initNotification["jsonrpc"] = "2.0";
        initNotification["method"] = "initialized";
        initNotification["params"] = Json::objectValue;
        sendNotification(initNotification);
    }

    // Request tool list
    void listTools() {
        Json::Value request;
        request["jsonrpc"] = "2.0";
        request["id"] = 2;
        request["method"] = "listTools";
        request["params"] = Json::objectValue;
        sendRequest(request);
    }

    // Call tool (e.g., brave_web_search)
    void callTool(const std::string& toolName, const Json::Value& arguments) {
        Json::Value request;
        request["jsonrpc"] = "2.0";
        request["id"] = 3;
        request["method"] = "callTool";
        Json::Value params;
        params["name"] = toolName;
        params["arguments"] = arguments;
        request["params"] = params;
        sendRequest(request);
    }

    // Termination process: shutdown request followed by exit notification
    void shutdown() {
        Json::Value shutdownRequest;
        shutdownRequest["jsonrpc"] = "2.0";
        shutdownRequest["id"] = 4;
        shutdownRequest["method"] = "shutdown";
        shutdownRequest["params"] = Json::objectValue;
        sendRequest(shutdownRequest);

        Json::Value exitNotification;
        exitNotification["jsonrpc"] = "2.0";
        exitNotification["method"] = "exit";
        exitNotification["params"] = Json::objectValue;
        sendNotification(exitNotification);
    }
};

int main() {
    // Create server instance
    MCPServer server;

    // Create client instance that connects to the server
    MCPClient client(&server);

    // Perform connection and handshake
    client.connect();

    // Request tool list
    client.listTools();

    // Call brave_web_search tool (e.g., "Latest AI Development Trends", 5 results)
    Json::Value arguments;
    arguments["query"] = "Latest AI Development Trends";
    arguments["count"] = 5;
    client.callTool("brave_web_search", arguments);

    // Normal termination: shutdown and exit
    client.shutdown();

    return 0;
}
