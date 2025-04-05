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
#include <random>
#include <ctime>
#include <functional>
#include <uuid/uuid.h>
#include <atomic>
#include <cstring>

// 디버그 로그 매크로
#define LOG_ERROR(msg) std::cerr << "\033[1;31m[ERROR] " << msg << "\033[0m" << std::endl
#define LOG_INFO(msg) std::cout << "\033[1;32m[INFO] " << msg << "\033[0m" << std::endl
#define LOG_DEBUG(msg) std::cout << "\033[1;34m[DEBUG] " << msg << "\033[0m" << std::endl

// 포트 설정
const int PORT = 8080;

// 세션 정보 구조체
struct SessionInfo {
	int socket_fd;
	bool initialized;
	std::chrono::system_clock::time_point lastActivity;

	SessionInfo() : socket_fd(-1), initialized(false) {}

	SessionInfo(int fd) : socket_fd(fd), initialized(false) {
		lastActivity = std::chrono::system_clock::now();
	}
};

// 전역 세션 관리
std::map<std::string, SessionInfo> sessions;
std::mutex sessions_mutex;
std::atomic<bool> server_running(true);

// UUID 생성 함수
std::string generateUUID()
{
	uuid_t uuid;
	char uuid_str[37];

	uuid_generate(uuid);
	uuid_unparse_lower(uuid, uuid_str);

	return std::string(uuid_str);
}

// 현재 시간을 밀리초로 반환
long long getCurrentTimeMillis()
{
	return std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::system_clock::now().time_since_epoch()
	).count();
}

// 현재 시간을 문자열로 반환
std::string getCurrentTimeStr()
{
	auto now = std::chrono::system_clock::now();
	std::time_t now_time = std::chrono::system_clock::to_time_t(now);
	char buffer[26];
	struct tm tm_info;

	localtime_r(&now_time, &tm_info);
	strftime(buffer, 26, "%Y-%m-%dT%H:%M:%S", &tm_info);

	return std::string(buffer);
}

// URL에서 쿼리 파라미터 추출
std::string extractQueryParam(const std::string& url, const std::string& param)
{
	std::string paramPrefix = param + "=";
	size_t pos = url.find(paramPrefix);

	if (pos == std::string::npos) {
		return "";
	}

	std::string value = url.substr(pos + paramPrefix.length());
	size_t endPos = value.find('&');

	if (endPos != std::string::npos) {
		value = value.substr(0, endPos);
	}

	return value;
}

// HTTP 요청 파싱
bool parseHttpRequest(const std::string& request, std::string& method, std::string& path, 
                      std::map<std::string, std::string>& headers, std::string& body)
{
	method.clear();
	path.clear();
	headers.clear();
	body.clear();

	try {
		// 헤더와 바디의 경계 찾기
		size_t header_end = request.find("\r\n\r\n");
		if (header_end == std::string::npos) {
			LOG_ERROR("Invalid HTTP request format - missing header boundary");
			return false;
		}
		
		// 헤더 부분 추출
		std::string header_part = request.substr(0, header_end);
		
		// 요청 라인 추출
		size_t first_line_end = header_part.find("\r\n");
		if (first_line_end == std::string::npos) {
			LOG_ERROR("Invalid HTTP request format - missing first line");
			return false;
		}
		
		std::string first_line = header_part.substr(0, first_line_end);
		std::istringstream first_line_stream(first_line);
		std::string http_version;
		if (!(first_line_stream >> method >> path >> http_version)) {
			LOG_ERROR("Invalid HTTP request line: " << first_line);
			return false;
		}
		
		// 헤더 파싱
		std::istringstream header_stream(header_part.substr(first_line_end + 2)); // +2 to skip \r\n
		std::string header_line;
		while (std::getline(header_stream, header_line)) {
			if (header_line.empty() || header_line == "\r") {
				continue;
			}
			
			// 개행 문자 제거
			if (!header_line.empty() && header_line.back() == '\r') {
				header_line.pop_back();
			}
			
			size_t colon_pos = header_line.find(": ");
			if (colon_pos != std::string::npos) {
				std::string key = header_line.substr(0, colon_pos);
				std::string value = header_line.substr(colon_pos + 2);
				headers[key] = value;
			}
		}
		
		// 바디 추출
		if (header_end + 4 < request.size()) {
			body = request.substr(header_end + 4);
			
			// Content-Length 확인
			auto content_length_it = headers.find("Content-Length");
			if (content_length_it != headers.end()) {
				size_t content_length = std::stoul(content_length_it->second);
				LOG_DEBUG("Content-Length: " << content_length << ", actual body size: " << body.size());
				
				// 지정된 Content-Length만큼만 사용
				if (body.size() > content_length) {
					body = body.substr(0, content_length);
				}
				// 본문이 충분히 수신되지 않았다면 로그 출력
				else if (body.size() < content_length) {
					LOG_DEBUG("Received body size");
				}
			}
		}
		
		LOG_DEBUG("Parsed HTTP request: " << method << " " << path);
		LOG_DEBUG("Headers count: " << headers.size());
		LOG_DEBUG("Body size: " << body.size() << " bytes");
		LOG_DEBUG("Body content: " << body);
		
		return true;
	}
	catch (const std::exception& e) {
		LOG_ERROR("Exception during HTTP parsing: " << e.what());
		return false;
	}
}

// JSON을 문자열로 변환
std::string jsonToString(const Json::Value& json)
{
	Json::StreamWriterBuilder builder;
	builder["indentation"] = "";  // 공백 없이

	return Json::writeString(builder, json);
}

// SSE 메시지 전송
bool sendSSEMessage(int socket_fd, const std::string& event, const std::string& data)
{
	std::string message = "event: " + event + "\ndata: " + data + "\n\n";

	LOG_DEBUG("Sending SSE: event=" << event);

	size_t total_sent = 0;
	size_t length = message.length();

	while (total_sent < length) {
		ssize_t sent = send(socket_fd, message.c_str() + total_sent, length - total_sent, 0);
		
		if (sent <= 0) {
			LOG_ERROR("Failed to send SSE message: " << strerror(errno));
			return false;
		}
		
		total_sent += sent;
	}

	return true;
}

// 특정 시간 후에 작업을 실행하는 타이머 함수
void scheduleTask(std::function<void()> task, std::chrono::milliseconds delay)
{
	std::thread([task, delay]() {
		std::this_thread::sleep_for(delay);
		task();
	}).detach();
}

// HTTP 응답 생성
std::string createHttpResponse(int status_code, const std::string& body, 
                               const std::string& content_type = "application/json")
{
	std::string status_text;

	switch(status_code) {
		case 200: status_text = "OK"; break;
		case 400: status_text = "Bad Request"; break;
		case 404: status_text = "Not Found"; break;
		case 500: status_text = "Internal Server Error"; break;
		default: status_text = "Unknown"; break;
	}

	std::ostringstream response;

	response << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";
	response << "Content-Type: " << content_type << "\r\n";
	response << "Content-Length: " << body.length() << "\r\n";
	response << "Access-Control-Allow-Origin: *\r\n";
	response << "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n";
	response << "Access-Control-Allow-Headers: Content-Type\r\n";
	response << "\r\n";
	response << body;

	return response.str();
}

// 전체 HTTP 요청 읽기 함수
std::string readFullHttpRequest(int client_socket)
{
	const int BUFFER_SIZE = 4096;
	char buffer[BUFFER_SIZE];
	std::string request;

	// 초기 데이터 읽기
	ssize_t bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
	if (bytes_read <= 0) {
		return "";
	}

	buffer[bytes_read] = '\0';
	request.append(buffer, bytes_read);

	// Content-Length 헤더 찾기
	size_t header_end = request.find("\r\n\r\n");
	if (header_end == std::string::npos) {
		// 헤더가 완전히 수신되지 않음
		LOG_ERROR("Incomplete HTTP headers received");
		return request;
	}

	// Content-Length 추출
	size_t content_length = 0;
	size_t content_pos = request.find("Content-Length: ");
	if (content_pos != std::string::npos) {
		size_t value_start = content_pos + 16; // "Content-Length: " 길이
		size_t value_end = request.find("\r\n", value_start);
		if (value_end != std::string::npos) {
			std::string length_str = request.substr(value_start, value_end - value_start);
			content_length = std::stoul(length_str);
		}
	}

	// 현재 본문 크기 계산
	size_t body_start = header_end + 4; // \r\n\r\n 건너뛰기
	size_t current_body_size = 0;
	if (body_start < request.size()) {
		current_body_size = request.size() - body_start;
	}

	// 필요한 경우 더 읽기
	while (content_length > 0 && current_body_size < content_length) {
		bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
		if (bytes_read <= 0) {
			break;
		}
		
		buffer[bytes_read] = '\0';
		request.append(buffer, bytes_read);
		current_body_size += bytes_read;
	}

	return request;
}

// SSE 연결 처리 함수 (/sse)
void handleSSEConnection(int client_socket)
{
	LOG_INFO("SSE => /sse connected");

	// 세션 ID 생성
	std::string sessionId = generateUUID();

	// 세션 등록
	{
		std::lock_guard<std::mutex> lock(sessions_mutex);
		sessions[sessionId] = SessionInfo(client_socket);
	}

	LOG_INFO("Created sessionId: " << sessionId);

	// SSE 헤더 전송
	std::string sse_headers = 
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/event-stream\r\n"
		"Cache-Control: no-cache\r\n"
		"Connection: keep-alive\r\n"
		"Access-Control-Allow-Origin: *\r\n"
		"Access-Control-Allow-Methods: GET, OPTIONS\r\n"
		"Access-Control-Allow-Headers: Content-Type\r\n"
		"\r\n";

	ssize_t header_sent = send(client_socket, sse_headers.c_str(), sse_headers.length(), 0);
	if (header_sent < 0) {
		LOG_ERROR("Failed to send SSE headers: " << strerror(errno));
		close(client_socket);
		
		std::lock_guard<std::mutex> lock(sessions_mutex);
		sessions.erase(sessionId);
		return;
	}

	// endpoint 이벤트 전송
	std::string endpointUrl = "/message?sessionId=" + sessionId;
	if (!sendSSEMessage(client_socket, "endpoint", endpointUrl)) {
		LOG_ERROR("Failed to send endpoint event");
		close(client_socket);
		
		std::lock_guard<std::mutex> lock(sessions_mutex);
		sessions.erase(sessionId);
		return;
	}

	// 하트비트 루프
	while (server_running) {
		std::this_thread::sleep_for(std::chrono::seconds(3));
		
		// 세션 유효성 확인
		bool session_valid = false;
		{
			std::lock_guard<std::mutex> lock(sessions_mutex);
			auto it = sessions.find(sessionId);
			if (it != sessions.end() && it->second.socket_fd == client_socket) {
				session_valid = true;
			}
		}
		
		if (!session_valid) {
			LOG_INFO("Session no longer valid, stopping heartbeat: " << sessionId);
			break;
		}
		
		// 하트비트 전송
		std::string heartbeat_data = std::to_string(getCurrentTimeMillis());
		if (!sendSSEMessage(client_socket, "heartbeat", heartbeat_data)) {
			LOG_ERROR("Failed to send heartbeat, connection probably closed");
			break;
		}
	}

	// 연결 종료
	LOG_INFO("SSE connection closing for sessionId: " << sessionId);
	close(client_socket);

	// 세션 제거
	{
		std::lock_guard<std::mutex> lock(sessions_mutex);
		sessions.erase(sessionId);
	}
}

// JSON-RPC 메시지 처리 함수 (/message)
void handleMessageRequest(int client_socket, const std::string& request)
{
	std::string method, path, body;
	std::map<std::string, std::string> headers;

	if (!parseHttpRequest(request, method, path, headers, body)) {
		LOG_ERROR("Failed to parse HTTP request");
		std::string error_response = createHttpResponse(400, "{\"error\":\"Invalid HTTP request\"}");
		send(client_socket, error_response.c_str(), error_response.length(), 0);
		close(client_socket);
		return;
	}

	// sessionId 추출
	std::string sessionId = extractQueryParam(path, "sessionId");
	if (sessionId.empty()) {
		LOG_ERROR("Missing sessionId");
		std::string error_response = createHttpResponse(400, "{\"error\":\"Missing sessionId in ?sessionId=...\"}");
		send(client_socket, error_response.c_str(), error_response.length(), 0);
		close(client_socket);
		return;
	}

	LOG_INFO("Received message for sessionId " << sessionId);

	// 세션 찾기
	int sse_socket;
	bool session_found = false;

	{
		std::lock_guard<std::mutex> lock(sessions_mutex);
		auto it = sessions.find(sessionId);
		if (it != sessions.end()) {
			sse_socket = it->second.socket_fd;
			session_found = true;
		}
	}

	if (!session_found) {
		LOG_ERROR("No SSE session with sessionId: " << sessionId);
		std::string error_response = createHttpResponse(404, "{\"error\":\"No SSE session with that sessionId\"}");
		send(client_socket, error_response.c_str(), error_response.length(), 0);
		close(client_socket);
		return;
	}

	// JSON-RPC 파싱
	Json::Value rpc;
	Json::CharReaderBuilder reader;
	std::string errors;
	std::istringstream body_stream(body);

	if (!Json::parseFromStream(reader, body_stream, &rpc, &errors)) {
		LOG_ERROR("Failed to parse JSON-RPC: " << errors);
		LOG_ERROR("Raw body content: '" << body << "'");
		std::string error_response = createHttpResponse(400, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}");
		send(client_socket, error_response.c_str(), error_response.length(), 0);
		close(client_socket);
		return;
	}

	// JSON-RPC 형식 검증
	if (!rpc.isMember("jsonrpc") || rpc["jsonrpc"].asString() != "2.0" || !rpc.isMember("method")) {
		LOG_ERROR("Invalid JSON-RPC format");
		Json::Value error_response;
		error_response["jsonrpc"] = "2.0";
		error_response["id"] = rpc.isMember("id") ? rpc["id"] : Json::nullValue;
		error_response["error"]["code"] = -32600;
		error_response["error"]["message"] = "Invalid JSON-RPC request";
		
		std::string response_str = createHttpResponse(400, jsonToString(error_response));
		send(client_socket, response_str.c_str(), response_str.length(), 0);
		close(client_socket);
		return;
	}

	// 요청 로깅
	LOG_INFO("Received " << rpc["method"].asString() << " request for sessionId: " << sessionId);

	// 최소 HTTP 응답 생성
	Json::Value ack_response;
	ack_response["jsonrpc"] = "2.0";
	ack_response["id"] = rpc.isMember("id") ? rpc["id"] : Json::nullValue;
	ack_response["result"]["ack"] = "Received " + rpc["method"].asString();

	std::string response_str = createHttpResponse(200, jsonToString(ack_response));
	send(client_socket, response_str.c_str(), response_str.length(), 0);
	close(client_socket);

	LOG_INFO("Sent acknowledgment response for " << ack_response["result"]["ack"].asString());

	// 메소드별 처리 및 SSE 응답
	std::string method_name = rpc["method"].asString();

	if (method_name == "initialize") {
		// 세션 초기화 상태 업데이트
		{
			std::lock_guard<std::mutex> lock(sessions_mutex);
			auto it = sessions.find(sessionId);
			if (it != sessions.end()) {
				it->second.initialized = true;
			}
		}
		
		// 초기화 응답 (capabilities) 생성 및 전송
		Json::Value init_response;
		init_response["jsonrpc"] = "2.0";
		init_response["id"] = rpc.isMember("id") ? rpc["id"] : Json::nullValue;
		
		Json::Value& result = init_response["result"];
		result["protocolVersion"] = "2024-11-05";
		
		Json::Value& capabilities = result["capabilities"];
		capabilities["tools"]["listChanged"] = true;
		capabilities["resources"]["subscribe"] = true;
		capabilities["resources"]["listChanged"] = true;
		capabilities["prompts"]["listChanged"] = true;
		capabilities["logging"] = Json::objectValue;
		
		Json::Value& server_info = result["serverInfo"];
		server_info["name"] = "cpp-capabilities-server";
		server_info["version"] = "1.0.0";
		
		std::string init_str = jsonToString(init_response);
		sendSSEMessage(sse_socket, "message", init_str);
		LOG_INFO("Sent initialize capabilities response");
	}
	else if (method_name == "tools/list") {
		// 도구 목록 응답 생성 및 전송
		Json::Value tools_response;
		tools_response["jsonrpc"] = "2.0";
		tools_response["id"] = rpc.isMember("id") ? rpc["id"] : Json::nullValue;
		
		Json::Value& result = tools_response["result"];
		
		Json::Value tools(Json::arrayValue);
		Json::Value add_tool;
		add_tool["name"] = "addNumbersTool";
		add_tool["description"] = "Adds two numbers 'a' and 'b' and returns their sum.";
		
		Json::Value& input_schema = add_tool["inputSchema"];
		input_schema["type"] = "object";
		
		Json::Value& properties = input_schema["properties"];
		properties["a"]["type"] = "number";
		properties["b"]["type"] = "number";
		
		Json::Value required(Json::arrayValue);
		required.append("a");
		required.append("b");
		input_schema["required"] = required;
		
		tools.append(add_tool);
		result["tools"] = tools;
		result["count"] = 1;
		
		std::string tools_str = jsonToString(tools_response);
		sendSSEMessage(sse_socket, "message", tools_str);
		LOG_INFO("Sent tools/list response");
	}
	else if (method_name == "tools/call") {
		// 도구 호출 처리
		std::string tool_name = rpc["params"]["name"].asString();
		LOG_INFO("Tool call: " << tool_name);
		
		if (tool_name == "addNumbersTool") {
			// 계산 수행
			int a = rpc["params"]["arguments"]["a"].asInt();
			int b = rpc["params"]["arguments"]["b"].asInt();
			int sum = a + b;
			
			// 결과 응답 생성 및 전송
			Json::Value call_response;
			call_response["jsonrpc"] = "2.0";
			call_response["id"] = rpc.isMember("id") ? rpc["id"] : Json::nullValue;
			
			Json::Value& result = call_response["result"];
			
			Json::Value content(Json::arrayValue);
			Json::Value text_content;
			text_content["type"] = "text";
			text_content["text"] = "Sum of " + std::to_string(a) + " + " + std::to_string(b) + " = " + std::to_string(sum);
			content.append(text_content);
			
			result["content"] = content;
			
			std::string call_str = jsonToString(call_response);
			sendSSEMessage(sse_socket, "message", call_str);
			LOG_INFO("Sent tools/call response with sum: " << sum);
		}
		else {
			// 알 수 없는 도구 오류
			Json::Value error_response;
			error_response["jsonrpc"] = "2.0";
			error_response["id"] = rpc.isMember("id") ? rpc["id"] : Json::nullValue;
			error_response["error"]["code"] = -32601;
			error_response["error"]["message"] = "No such tool '" + tool_name + "'";
			
			std::string error_str = jsonToString(error_response);
			sendSSEMessage(sse_socket, "message", error_str);
			LOG_INFO("Sent error response for unknown tool: " << tool_name);
		}
	}
	else if (method_name == "notifications/initialized") {
		LOG_INFO("Received notifications/initialized, no SSE response needed");
	}
	else {
		// 알 수 없는 메소드 오류
		Json::Value error_response;
		error_response["jsonrpc"] = "2.0";
		error_response["id"] = rpc.isMember("id") ? rpc["id"] : Json::nullValue;
		error_response["error"]["code"] = -32601;
		error_response["error"]["message"] = "Method '" + method_name + "' not recognized";
		
		std::string error_str = jsonToString(error_response);
		sendSSEMessage(sse_socket, "message", error_str);
		LOG_INFO("Sent error response for unknown method: " << method_name);
	}
}

int main()
{
	int server_fd;
	struct sockaddr_in address;

	// 소켓 생성
	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		LOG_ERROR("Socket creation failed: " << strerror(errno));
		return 1;
	}

	// SO_REUSEADDR 설정
	int opt = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
		LOG_ERROR("setsockopt failed: " << strerror(errno));
		return 1;
	}

	// 주소 구성
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);

	// 바인드
	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		LOG_ERROR("Bind failed: " << strerror(errno));
		return 1;
	}

	// 리슨
	if (listen(server_fd, 10) < 0) {
		LOG_ERROR("Listen failed: " << strerror(errno));
		return 1;
	}

	LOG_INFO("[MCP] C++ server with tools/call at http://localhost:" << PORT);
	LOG_INFO("GET  /sse => SSE => endpoint => /message?sessionId=...");
	LOG_INFO("POST /message?sessionId=... => initialize => SSE => capabilities, tools/list => SSE => Tools, tools/call => SSE => sum, etc.");

	// 세션 청소 스레드
	std::thread([&]() {
		while (server_running) {
			std::this_thread::sleep_for(std::chrono::minutes(5));
			auto now = std::chrono::system_clock::now();
			
			std::lock_guard<std::mutex> lock(sessions_mutex);
			for (auto it = sessions.begin(); it != sessions.end();) {
				auto diff = std::chrono::duration_cast<std::chrono::minutes>(now - it->second.lastActivity).count();
				if (diff > 30) { // 30분 이상 활동 없음
					LOG_INFO("Removing inactive session: " << it->first);
					close(it->second.socket_fd);
					it = sessions.erase(it);
				} else {
					++it;
				}
			}
		}
	}).detach();

	// 메인 서버 루프
	while (server_running) {
		int new_socket;
		struct sockaddr_in client_addr;
		socklen_t addrlen = sizeof(client_addr);
		
		LOG_DEBUG("Waiting for connection...");
		if ((new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen)) < 0) {
			LOG_ERROR("Accept failed: " << strerror(errno));
			continue;
		}
		
		// 클라이언트 정보
		char client_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
		int client_port = ntohs(client_addr.sin_port);
		LOG_INFO("Client connected: " << client_ip << ":" << client_port);
		
		// 전체 HTTP 요청 읽기
		std::string request = readFullHttpRequest(new_socket);
		if (request.empty()) {
			LOG_ERROR("Failed to receive data from client");
			close(new_socket);
			continue;
		}
		
		// 요청 종류 확인
		if (request.find("GET /sse") == 0) {
			// SSE 연결 처리
			std::thread sse_thread(handleSSEConnection, new_socket);
			sse_thread.detach();
		}
		else if (request.find("POST /message") == 0) {
			// JSON-RPC 메시지 처리
			std::thread message_thread(handleMessageRequest, new_socket, request);
			message_thread.detach();
		}
		else if (request.find("OPTIONS") == 0) {
			// CORS 옵션 요청 처리
			std::string options_response = 
				"HTTP/1.1 200 OK\r\n"
				"Access-Control-Allow-Origin: *\r\n"
				"Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n"
				"Access-Control-Allow-Headers: Content-Type\r\n"
				"Content-Length: 0\r\n"
				"\r\n";
			
			send(new_socket, options_response.c_str(), options_response.length(), 0);
			close(new_socket);
		}
		else {
			// 지원하지 않는 요청
			std::string not_found = "{\"error\":\"Not found\"}";
			std::string response = createHttpResponse(404, not_found);
			send(new_socket, response.c_str(), response.length(), 0);
			close(new_socket);
		}
	}

	// 서버 종료
	close(server_fd);
	return 0;
}