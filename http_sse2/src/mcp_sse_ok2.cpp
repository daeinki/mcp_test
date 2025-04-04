#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <mutex>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <json/json.h>
#include <thread>
#include <chrono>
#include <algorithm>

#define LOG(msg) std::cout << __LINE__ << " " << msg << std::endl

// 세션 관리를 위한 구조
std::map<std::string, int> sse_connections; // sessionId -> socket_fd
std::mutex sse_mutex;

// URL에서 쿼리 파라미터 추출 함수
std::string extractQueryParam(const std::string& url, const std::string& param)
{
    size_t pos = url.find(param + "=");
    if (pos == std::string::npos) return "";
    
    std::string value = url.substr(pos + param.length() + 1);
    size_t end_pos = value.find("&");
    if (end_pos != std::string::npos) {
        value = value.substr(0, end_pos);
    }
    return value;
}

// HTTP 요청 파싱 (메서드, 경로, 헤더, 본문 추출)
void parseHttpRequest(const std::string& request, std::string& method, std::string& path, std::map<std::string, std::string>& headers, std::string& body)
{
	// Clear output parameters
	method.clear();
	path.clear();
	headers.clear();
	body.clear();
	
	// Find the position of the first header (after the request line)
	size_t pos = request.find("\r\n");
	if (pos == std::string::npos) return; // Invalid request
	
	// Parse request line
	std::string request_line = request.substr(0, pos);
	std::istringstream request_line_stream(request_line);
	std::string http_version;
	request_line_stream >> method >> path >> http_version;
	
	// Move past request line
	pos += 2; // Skip \r\n
	
	// Find the end of headers
	size_t headers_end = request.find("\r\n\r\n", pos);
	if (headers_end == std::string::npos) {
		headers_end = request.length();
	} else {
		// Extract body
		body = request.substr(headers_end + 4); // Skip \r\n\r\n
	}
	
	// Parse headers
	size_t line_start = pos;
	while (line_start < headers_end) {
		size_t line_end = request.find("\r\n", line_start);
		if (line_end == std::string::npos || line_end > headers_end) {
			break;
		}
		
		std::string line = request.substr(line_start, line_end - line_start);
		size_t colon_pos = line.find(": ");
		if (colon_pos != std::string::npos) {
			std::string key = line.substr(0, colon_pos);
			std::string value = line.substr(colon_pos + 2);
			headers[key] = value;
		}
		
		line_start = line_end + 2; // Skip \r\n
	}
}

// SSE 메시지 전송 함수
void sendSSEMessage(int socket_fd, const std::string& event, const std::string& data)
{
    std::string message = "event: " + event + "\ndata: " + data + "\n\n";
    send(socket_fd, message.c_str(), message.length(), 0);
    LOG("Sent SSE message: " << message);
}

// SSE 연결 처리 함수
void handleSSEConnection(int client_socket, const std::string& sessionId)
{
    LOG("Client connected for SSE with sessionId: " << sessionId);
    
    // 세션 등록
    {
        std::lock_guard<std::mutex> lock(sse_mutex);
        sse_connections[sessionId] = client_socket;
    }
    
    // SSE 헤더 전송
    std::string sse_header = "HTTP/1.1 200 OK\r\n";
    sse_header += "Content-Type: text/event-stream\r\n";
    sse_header += "Cache-Control: no-cache\r\n";
    sse_header += "Connection: keep-alive\r\n";
    sse_header += "Access-Control-Allow-Origin: *\r\n";
    sse_header += "\r\n"; // 헤더 종료
    
    if (send(client_socket, sse_header.c_str(), sse_header.length(), 0) < 0) {
        perror("Error sending SSE headers");
        close(client_socket);
        return;
    }
    LOG("SSE headers sent");
    
    // endpoint 이벤트 전송
    std::string endpointUrl = "http://localhost:8080/mcp?sessionId=" + sessionId;
    sendSSEMessage(client_socket, "endpoint", endpointUrl);
    
    // 하트비트 전송
    int counter = 0;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(25));
        
        // 연결 확인
        Json::Value heartbeat;
        heartbeat["type"] = "heartbeat";
        heartbeat["count"] = counter++;
        
        Json::FastWriter writer;
        std::string heartbeatStr = writer.write(heartbeat);
        heartbeatStr.erase(std::remove(heartbeatStr.begin(), heartbeatStr.end(), '\n'), heartbeatStr.end());
        
        if (send(client_socket, ("event: heartbeat\ndata: " + heartbeatStr + "\n\n").c_str(), 
                 ("event: heartbeat\ndata: " + heartbeatStr + "\n\n").length(), 0) < 0) {
            LOG("Heartbeat failed, client disconnected");
            break;
        }
        LOG("Sent heartbeat: " << counter);
    }
    
    // 연결 종료 시 세션 제거
    {
        std::lock_guard<std::mutex> lock(sse_mutex);
        sse_connections.erase(sessionId);
    }
    close(client_socket);
    LOG("SSE connection closed for sessionId: " << sessionId);
}

// HTTP 응답 생성 함수
std::string createHttpResponse(int status_code, const std::string& body, 
                              const std::string& content_type = "application/json")
{
    std::string status_text;
    switch(status_code) {
        case 200: status_text = "OK"; break;
        case 202: status_text = "Accepted"; break;
        case 400: status_text = "Bad Request"; break;
        case 404: status_text = "Not Found"; break;
        case 500: status_text = "Internal Server Error"; break;
        default: status_text = "Unknown"; break;
    }
    
    std::stringstream ss;
    ss << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";
    ss << "Content-Type: " << content_type << "\r\n";
    ss << "Content-Length: " << body.length() << "\r\n";
    ss << "Access-Control-Allow-Origin: *\r\n";
    ss << "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n";
    ss << "Access-Control-Allow-Headers: Content-Type\r\n";
    ss << "\r\n";
    ss << body;
    
    return ss.str();
}

// 메인 함수
int main()
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int port = 8080;
    
    // 소켓 설정
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return 1;
    }
    
    // SO_REUSEADDR 설정
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        return 1;
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return 1;
    }
    
    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        close(server_fd);
        return 1;
    }
    
    LOG("MCP Server listening on port " << port);
    
    while (true) {
        LOG("Waiting for connection...");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
            continue;
        }
        
        // 요청 읽기
        char buffer[8192] = {0};
        ssize_t bytes_received = recv(new_socket, buffer, 8191, 0);
        if (bytes_received <= 0) {
            if (bytes_received < 0) perror("recv failed");
            close(new_socket);
            continue;
        }
        
        std::string request(buffer, bytes_received);
        LOG("Received request length: " << bytes_received);

		LOG("Received request: " << request);
        
        // 요청 파싱
        std::string method, path;
        std::map<std::string, std::string> headers;
        std::string body;
        parseHttpRequest(request, method, path, headers, body);
        
        LOG("Method: " << method << ", Path: " << path);
        
        // OPTIONS 요청 처리 (CORS)
        if (method == "OPTIONS") {
            std::string options_response = "HTTP/1.1 200 OK\r\n";
            options_response += "Access-Control-Allow-Origin: *\r\n";
            options_response += "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n";
            options_response += "Access-Control-Allow-Headers: Content-Type\r\n";
            options_response += "Content-Length: 0\r\n";
            options_response += "\r\n";
            
            send(new_socket, options_response.c_str(), options_response.length(), 0);
            close(new_socket);
            continue;
        }
        
        // SSE 요청 처리
        if (method == "GET" && path.find("/sse") == 0) {
            std::string sessionId = extractQueryParam(path, "sessionId");
            if (sessionId.empty()) {
                // 세션 ID 없으면 생성
                sessionId = "session-" + std::to_string(time(nullptr));
            }
            
            LOG("Starting SSE connection with sessionId: " << sessionId);
            std::thread sse_thread(handleSSEConnection, new_socket, sessionId);
            sse_thread.detach();
            continue;
        }
        
        // MCP 요청 처리
        if (method == "POST" && path.find("/mcp") == 0) {
            std::string sessionId = extractQueryParam(path, "sessionId");
            LOG("Received MCP request for sessionId: " << sessionId);
            
            int status_code = 200;
            std::string response_body;
            
            try {
                Json::Value request_json;
                Json::Reader reader;
               
                if (reader.parse(body, request_json)) {
                    LOG("Parsed JSON: " << body);
                    
                    std::string method = request_json.get("method", "").asString();
                    int id = request_json.get("id", 0).asInt();
                    
                    Json::Value response;
                    response["jsonrpc"] = "2.0";
                    response["id"] = id;
                    
                    if (method == "initialize") {
                        LOG("Handling initialize request");
                        
                        Json::Value result;
                        result["protocolVersion"] = "2024-11-05";
                        
                        Json::Value capabilities;
                        capabilities["experimental"] = Json::objectValue;
                        
                        Json::Value tools;
                        tools["listChanged"] = true;
                        capabilities["tools"] = tools;
                        
                        Json::Value serverInfo;
                        serverInfo["name"] = "C++ MCP Server";
                        serverInfo["version"] = "1.0.0";
                        
                        result["capabilities"] = capabilities;
                        result["serverInfo"] = serverInfo;
                        
                        response["result"] = result;
                    } else {
                        LOG("Unknown method: " << method);
                        Json::Value error;
                        error["code"] = -32601;
                        error["message"] = "Method not found: " + method;
                        response["error"] = error;
                    }
                    
                    Json::FastWriter writer;
                    response_body = writer.write(response);
                    // 줄바꿈 제거
                    response_body.erase(std::remove(response_body.begin(), response_body.end(), '\n'), response_body.end());
                } else {
                    LOG("Failed to parse JSON request");
                    status_code = 400;
                    response_body = "{\"error\":\"Invalid JSON\"}";
                }
            } catch (const std::exception& e) {
                LOG("Exception: " << e.what());
                status_code = 500;
                response_body = "{\"error\":\"" + std::string(e.what()) + "\"}";
            }
            
            // HTTP 응답 보내기
            std::string http_response = createHttpResponse(status_code, response_body);
            send(new_socket, http_response.c_str(), http_response.length(), 0);
            close(new_socket);
            
            // 동일한 세션 ID의 SSE 연결로 메시지 보내기
            if (!sessionId.empty()) {
                std::lock_guard<std::mutex> lock(sse_mutex);
                auto it = sse_connections.find(sessionId);
                if (it != sse_connections.end()) {
                    int sse_socket = it->second;
                    sendSSEMessage(sse_socket, "mcp", response_body);
                    LOG("Sent MCP response to SSE channel for sessionId: " << sessionId);
                } else {
                    LOG("No active SSE connection for sessionId: " << sessionId);
                }
            } else {
                LOG("No sessionId provided in MCP request");
            }
            
            continue;
        }
        
        // 지원하지 않는 요청
        std::string not_found = "{\"error\":\"Not found\"}";
        std::string response = createHttpResponse(404, not_found);
        send(new_socket, response.c_str(), response.length(), 0);
        close(new_socket);
    }
    
    close(server_fd);
    return 0;
}