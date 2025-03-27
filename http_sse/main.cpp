// main.cpp
#include "McpTransport.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <json/json.h>

// 요청 핸들러 구현
class TestRequestHandler : public IMcpRequestHandler {
public:
	std::string handleRequest(const std::string &requestContext) override {
		std::cout << "Server received request: " << requestContext << std::endl;
		
		Json::Value root;
		Json::Reader reader;
		
		if (reader.parse(requestContext, root)) {
			std::string method = root.get("method", "").asString();
			
			Json::Value responseRoot;
			
			if (method == "initialize") {
				responseRoot["result"] = "success";
				responseRoot["message"] = "Server initialized successfully";
			} else {
				responseRoot["error"] = "Unknown method";
			}
			
			Json::FastWriter writer;
			return writer.write(responseRoot);
		}
		
		return "{}";
	}
};

// 이벤트 리스너 구현
class TestEventListener : public IMcpEventListener {
public:
	void onEvent(const std::string &eventName, const std::string &eventData) override {
		std::cout << "Client received event: " << eventName << " with data: " << eventData << std::endl;
	}
};

int main() {
	// 서버 생성 및 시작
	TestRequestHandler handler;
	McpTransportServer server(8080, &handler);
	server.run();

	// 서버가 안정적으로 시작할 때까지 잠시 대기
	std::this_thread::sleep_for(std::chrono::seconds(1));

	// 클라이언트 생성
	McpTransportClient client("http://localhost:8080");
	TestEventListener listener;
	client.subscribe(&listener);

	// initialize 메서드 호출
	Json::Value initRequest;
	initRequest["method"] = "initialize";
	initRequest["params"]["clientName"] = "TestClient";
	initRequest["params"]["version"] = "1.0";

	Json::FastWriter writer;
	std::string requestStr = writer.write(initRequest);

	std::cout << "Sending initialize request: " << requestStr << std::endl;
	std::string response = client.send(requestStr);
	std::cout << "Received response: " << response << std::endl;

	// 이벤트 브로드캐스트 테스트
	std::this_thread::sleep_for(std::chrono::seconds(1));
	Json::Value eventData;
	eventData["notification"] = "This is a test notification";
	eventData["timestamp"] = static_cast<Json::UInt64>(time(nullptr));

	server.broadcastEvent("notification", writer.write(eventData));

	// 잠시 대기 후 종료
	std::cout << "Press Enter to exit..." << std::endl;
	std::cin.get();

	// 서버 중지
	server.stop();

	return 0;
}
