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

// SSE 응답 전송 함수
void sendSSEEvent(int client_socket, const std::string& event, const std::string& data) {
    std::stringstream ss;
    ss << "event: " << event << "\n";
    ss << "data: " << data << "\n\n";
    std::string sse_message = ss.str();
    send(client_socket, sse_message.c_str(), sse_message.length(), 0);
}

// SSE 연결 처리 함수
void handleSSEConnection(int client_socket) {
    std::cout << "Client connected for SSE." << std::endl;

    // SSE 헤더 전송
    std::string sse_header = "HTTP/1.1 200 OK\r\n";
    sse_header += "Content-Type: text/event-stream\r\n";
    sse_header += "Cache-Control: no-cache\r\n";
    sse_header += "Connection: keep-alive\r\n";
    sse_header += "\r\n";

	LOG("send");
    send(client_socket, sse_header.c_str(), sse_header.length(), 0);
	LOG("sent");

    char buffer[4096] = {0};
    while (true) {
		LOG("waiting");
        ssize_t bytes_received = recv(client_socket, buffer, 4095, 0);
		LOG("recv");
        if (bytes_received > 0) {
            std::string received_data(buffer, bytes_received);
            std::cout << "Received from SSE client: " << received_data << std::endl;

            Json::Value root;
            Json::Reader reader;
            if (reader.parse(received_data, root)) {
                std::string command = root.get("command", "").asString();

                if (command == "initialize") {
                    std::cout << "Received initialize command." << std::endl;
                    Json::Value response;
                    response["tools"] = Json::arrayValue;
                    Json::Value tool1;
                    tool1["name"] = "sampleTool";
                    tool1["description"] = "A sample tool for testing.";
                    response["tools"].append(tool1);

                    response["resources"] = Json::arrayValue;
                    Json::Value resource1;
                    resource1["name"] = "sampleResource";
                    resource1["type"] = "text";
                    response["resources"].append(resource1);

                    Json::FastWriter writer;
                    std::string response_str = writer.write(response);
                    sendSSEEvent(client_socket, "mcp_response", response_str);
                } else {
                    std::cerr << "Unknown command received: " << command << std::endl;
                    Json::Value error_response;
                    error_response["error"] = "Unknown command";
                    Json::FastWriter writer;
                    sendSSEEvent(client_socket, "error", writer.write(error_response));
                }
            } else {
                std::cerr << "Error parsing JSON from SSE client: " << reader.getFormattedErrorMessages() << std::endl;
                Json::Value error_response;
                error_response["error"] = "Invalid JSON";
                Json::FastWriter writer;
                sendSSEEvent(client_socket, "error", writer.write(error_response));
            }
        } else if (bytes_received == 0) {
            std::cout << "SSE client disconnected." << std::endl;
            break;
        } else {
            perror("recv (SSE) failed");
            break;
        }
        memset(buffer, 0, sizeof(buffer)); // 버퍼 초기화
    }
    close(client_socket);
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