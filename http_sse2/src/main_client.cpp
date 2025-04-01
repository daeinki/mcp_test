#include "HttpTransportClient.h"
#include <iostream>
#include <json/json.h>

int main()
{
	std::string serverUrl = "http://localhost:8080";
	HttpTransportClient client(serverUrl);

	Json::Value request;
	request["method"] = "initialize";
	request["params"] = Json::Value();

	Json::StreamWriterBuilder writer;
	std::string jsonRequest = Json::writeString(writer, request);

	std::cout << "Sending initialize request: " << jsonRequest << std::endl;
	std::string response = client.send(jsonRequest);

	std::cout << "Received response: " << response << std::endl;

	return 0;
}
