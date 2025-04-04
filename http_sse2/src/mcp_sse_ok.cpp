#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <json/json.h> // jsoncpp 헤더 포함
#include <thread>
#include <chrono>

#define LOG(msg)	std::cout << __LINE__ << " " << msg << std::endl

// HTTP 응답 생성 함수 (일반적인 HTTP 요청용)
std::string createHttpResponse(int statusCode, const std::string& body = "") {
    std::string statusText;
    switch (statusCode) {
        case 200: statusText = "OK"; break;
        case 400: statusText = "Bad Request"; break;
        case 404: statusText = "Not Found"; break;
        case 500: statusText = "Internal Server Error"; break;
        default: statusText = "Unknown"; break;
    }

    std::stringstream ss;
    ss << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    ss << "Content-Type: application/json\r\n";
    ss << "Content-Length: " << body.length() << "\r\n";
    ss << "\r\n";
    ss << body;
    return ss.str();
}

// SSE 연결 처리 함수
void handleSSEConnection(int clientSocket) {
	// 1. SSE 헤더 전송
	std::string sseHeader =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/event-stream\r\n"
		"Cache-Control: no-cache\r\n"
		"Connection: keep-alive\r\n"
		"Access-Control-Allow-Origin: *\r\n"  // CORS 허용
		"\r\n";
	if (send(clientSocket, sseHeader.c_str(), sseHeader.length(), 0) < 0) {
		perror("Error sending SSE headers");
		close(clientSocket);
		return;
	}
	std::cout << "SSE headers sent." << std::endl;

	// 2. "endpoint" 이벤트 전송 (클라이언트가 POST 대상 URL로 사용)
	std::string endpointEvent =
		"event: endpoint\r\n"
		"data: http://localhost:8080/mcp\r\n"
		"\r\n";
	if (send(clientSocket, endpointEvent.c_str(), endpointEvent.length(), 0) < 0) {
		perror("Error sending endpoint event");
		close(clientSocket);
		return;
	}
	std::cout << "Endpoint event sent." << std::endl;

	// 3. 주기적으로 SSE 이벤트 전송 (예시: 2초 간격)
	int counter = 0;
	while (true) {
		std::ostringstream oss;
		oss << "data: {\"jsonrpc\":\"2.0\", \"method\":\"notify\", \"params\":\"Message " << counter++ << "\"}\r\n\r\n";
		std::string eventMessage = oss.str();

		if (send(clientSocket, eventMessage.c_str(), eventMessage.length(), 0) < 0) {
			perror("Error sending message event");
			break;
		}
		std::cout << "Sent event: " << counter << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(2));
	}

	close(clientSocket);
	std::cout << "Client connection closed." << std::endl;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int port = 8080; // 서버 포트

    // 1. 소켓 생성
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return 1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // 2. 소켓 바인딩
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return 1;
    }

    // 3. 연결 대기
    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        close(server_fd);
        return 1;
    }

    std::cout << "MCP Server listening on port " << port << std::endl;

    while (true) {
        std::cout << "Waiting for connection..." << std::endl;
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
            continue;
        }

        char buffer[4096] = {0};
        ssize_t bytes_received = recv(new_socket, buffer, 4095, 0);
        if (bytes_received < 0) {
            perror("recv failed");
            close(new_socket);
            continue;
        } else if (bytes_received == 0) {
            std::cout << "Client disconnected." << std::endl;
            close(new_socket);
            continue;
        }

        std::string request(buffer, bytes_received);
        std::cout << "Received request:\n" << request << std::endl;

        // 기본적인 HTTP 요청 파싱 (간단하게 처리)
        std::istringstream iss(request);
        std::string method, path, protocol;
        iss >> method >> path >> protocol;

        if (method == "GET" && path == "/mcp") {
            // SSE 연결 처리
            std::thread sse_thread(handleSSEConnection, new_socket);
            sse_thread.detach(); // 메인 스레드와 분리하여 실행
        } else if (method == "POST" && path == "/mcp") {
            // 이전의 HTTP POST 요청 처리 (선택 사항)
            std::string response_body;
            int response_code = 404;
            try {
                size_t body_start = request.find("\r\n\r\n");
                if (body_start != std::string::npos) {
                    std::string json_str = request.substr(body_start + 4);
                    Json::Value root;
                    Json::Reader reader;
                    if (reader.parse(json_str, root)) {
                        std::cout << "Parsed JSON request body (HTTP):" << root.toStyledString() << std::endl;
                        Json::Value response_json;
                        response_json["status"] = "success";
                        response_json["message"] = "HTTP MCP request received.";
                        Json::FastWriter writer;
                        response_body = writer.write(response_json);
                        response_code = 200;
                    } else {
                        response_body = R"({"status": "error", "message": "Invalid JSON format"})";
                        response_code = 400;
                    }
                } else {
                    response_body = R"({"status": "error", "message": "No request body found"})";
                    response_code = 400;
                }
            } catch (const std::exception& e) {
                response_body = R"({"status": "error", "message": "Error processing JSON"})";
                response_code = 500;
            }
            std::string http_response = createHttpResponse(response_code, response_body);
            send(new_socket, http_response.c_str(), http_response.length(), 0);
            close(new_socket);
        } else {
            // 그 외 요청은 404 처리
            std::string response_body = R"({"status": "error", "message": "Not Found"})";
            std::string http_response = createHttpResponse(404, response_body);
            send(new_socket, http_response.c_str(), http_response.length(), 0);
            close(new_socket);
        }
    }

    close(server_fd);
    return 0;
}