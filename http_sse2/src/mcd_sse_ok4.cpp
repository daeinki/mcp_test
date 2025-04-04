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
#include <random>
#include <uuid/uuid.h>
#include <atomic>
#include <functional>
#include <ctime>

// 디버그 로그 매크로
#define LOG_ERROR(msg) std::cerr << "\033[1;31m[ERROR][" << __LINE__ << "] " << msg << "\033[0m" << std::endl
#define LOG_INFO(msg) std::cout << "\033[1;32m[INFO][" << __LINE__ << "] " << msg << "\033[0m" << std::endl
#define LOG_DEBUG(msg) std::cout << "\033[1;34m[DEBUG][" << __LINE__ << "] " << msg << "\033[0m" << std::endl
#define LOG_WARN(msg) std::cout << "\033[1;33m[WARN][" << __LINE__ << "] " << msg << "\033[0m" << std::endl

// 프로토콜 버전 - MCP Inspector가 기대하는 버전으로 설정
const std::string PROTOCOL_VERSION = "2023-03-20";

// 세션 관리를 위한 구조
struct SessionInfo {
    int socket_fd;
    bool initialized;
    std::string clientName;
    std::chrono::system_clock::time_point lastActivity;
    int nextMessageId;
    bool connectionCompleteSent;
    
    SessionInfo() : socket_fd(-1), initialized(false), clientName(""), 
                    nextMessageId(1), connectionCompleteSent(false) {}
    
    SessionInfo(int fd) : socket_fd(fd), initialized(false), clientName(""), 
                          nextMessageId(1), connectionCompleteSent(false) {
        lastActivity = std::chrono::system_clock::now();
    }
    
    // 다음 메시지 ID 생성
    int getNextMessageId() {
        return nextMessageId++;
    }
};

// 전역 변수
std::map<std::string, SessionInfo> sessions;
std::mutex sessions_mutex;
std::atomic<bool> server_running(true);

// UUID 생성 함수
std::string generateUUID() {
    uuid_t uuid;
    uuid_generate(uuid);
    char uuid_str[37];
    uuid_unparse_lower(uuid, uuid_str);
    return std::string(uuid_str);
}

// 현재 시간을 포맷팅된 문자열로 반환
std::string getCurrentTimeStr() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    char buffer[26];
    struct tm tm_info;
    localtime_r(&now_time, &tm_info);
    strftime(buffer, 26, "%Y-%m-%dT%H:%M:%S", &tm_info);
    return std::string(buffer);
}

// URL에서 쿼리 파라미터 추출 함수
std::string extractQueryParam(const std::string& url, const std::string& param) {
    size_t pos = url.find(param + "=");
    if (pos == std::string::npos) return "";
    
    std::string value = url.substr(pos + param.length() + 1);
    size_t end_pos = value.find("&");
    if (end_pos != std::string::npos) {
        value = value.substr(0, end_pos);
    }
    return value;
}

// HTTP 요청 파싱
bool parseHttpRequest(const std::string& request, std::string& method, std::string& path, 
                     std::map<std::string, std::string>& headers, std::string& body) {
    method.clear();
    path.clear();
    headers.clear();
    body.clear();
    
    // 최소 요청 길이 체크
    if (request.length() < 16) {
        LOG_ERROR("Request too short: " << request.length() << " bytes");
        return false;
    }
    
    try {
        // 요청 라인 찾기
        size_t req_line_end = request.find("\r\n");
        if (req_line_end == std::string::npos) {
            LOG_ERROR("Invalid request format - no request line end");
            return false;
        }
        
        // 요청 라인 파싱
        std::string req_line = request.substr(0, req_line_end);
        std::istringstream iss(req_line);
        std::string http_version;
        if (!(iss >> method >> path >> http_version)) {
            LOG_ERROR("Failed to parse request line: " << req_line);
            return false;
        }
        
        // 헤더 영역의 끝 찾기
        size_t headers_end = request.find("\r\n\r\n");
        if (headers_end == std::string::npos) {
            LOG_ERROR("Invalid request format - no headers end");
            return false;
        }
        
        // 헤더 파싱
        size_t header_start = req_line_end + 2; // \r\n 이후
        std::string header_block = request.substr(header_start, headers_end - header_start);
        std::istringstream header_stream(header_block);
        std::string header_line;
        
        while (std::getline(header_stream, header_line)) {
            // 줄바꿈 문자 제거
            if (!header_line.empty() && header_line.back() == '\r') {
                header_line.pop_back();
            }
            
            if (header_line.empty()) continue;
            
            size_t colon_pos = header_line.find(": ");
            if (colon_pos != std::string::npos) {
                std::string key = header_line.substr(0, colon_pos);
                std::string value = header_line.substr(colon_pos + 2);
                headers[key] = value;
            }
        }
        
        // 본문 추출
        if (headers_end + 4 < request.length()) {
            body = request.substr(headers_end + 4);
            
            // Content-Length 확인
            if (headers.find("Content-Length") != headers.end()) {
                size_t expected_length = std::stoull(headers["Content-Length"]);
                if (body.length() != expected_length) {
                    LOG_WARN("Body length mismatch: expected " << expected_length 
                             << ", got " << body.length());
                }
            }
        }
        
        return true;
    }
    catch (const std::exception& e) {
        LOG_ERROR("Exception during HTTP parsing: " << e.what());
        return false;
    }
}

// 소켓 에러 점검 함수
bool checkSocketError(int socket_fd) {
    int error = 0;
    socklen_t len = sizeof(error);
    int retval = getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &error, &len);
    
    if (retval != 0) {
        LOG_ERROR("Failed to get socket error status: " << strerror(errno));
        return true;
    }
    
    if (error != 0) {
        LOG_ERROR("Socket error detected: " << strerror(error));
        return true;
    }
    
    return false; // 에러 없음
}

// JSON을 문자열로 변환
std::string jsonToString(const Json::Value& json) {
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";  // 공백 없이
    return Json::writeString(builder, json);
}

// SSE 메시지 전송 함수 - MCP Inspector 호환
bool sendSSEMessage(int socket_fd, const std::string& event, const std::string& data) {
    if (socket_fd < 0) {
        LOG_ERROR("Invalid socket descriptor: " << socket_fd);
        return false;
    }
    
    if (checkSocketError(socket_fd)) {
        LOG_ERROR("Socket error detected before sending message");
        return false;
    }
    
    // SSE 메시지 형식: 명확히 필드를 구분하고 올바른 줄바꿈 문자 사용
    std::string message = "event: " + event + "\ndata: " + data + "\n\n";
    
    LOG_DEBUG("Sending SSE message - Event: " << event);
    LOG_DEBUG("Data: " << data);
    
    size_t total_sent = 0;
    size_t message_len = message.length();
    
    // 메시지 전체가 전송될 때까지 시도
    while (total_sent < message_len) {
        ssize_t result = send(socket_fd, message.c_str() + total_sent, message_len - total_sent, 0);
        
        if (result > 0) {
            total_sent += result;
        }
        else if (result == 0) {
            LOG_ERROR("Connection closed during send");
            return false;
        }
        else { // result < 0
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            } else {
                LOG_ERROR("Send failed: " << strerror(errno));
                return false;
            }
        }
    }
    
    LOG_INFO("✓ SSE message sent successfully - Event: " << event);
    return true;
}

// 특정 시간 후에 작업을 실행하는 타이머 함수
void scheduleTask(std::function<void()> task, std::chrono::milliseconds delay) {
    std::thread([task, delay]() {
        std::this_thread::sleep_for(delay);
        task();
    }).detach();
}

// tools/list 알림 메시지 생성
Json::Value createToolsListNotification() {
    Json::Value notification;
    notification["jsonrpc"] = "2.0";
    notification["method"] = "tools/list";
    
    Json::Value params;
    Json::Value tools(Json::arrayValue);
    
    // 도구 1 - 계산기
    Json::Value calculator;
    calculator["name"] = "calculator";
    calculator["description"] = "A simple calculator tool";
    
    Json::Value calcParams;
    calcParams["type"] = "object";
    
    Json::Value calcProperties;
    Json::Value expressionProp;
    expressionProp["type"] = "string";
    expressionProp["description"] = "Math expression to evaluate";
    calcProperties["expression"] = expressionProp;
    
    calcParams["properties"] = calcProperties;
    
    Json::Value calcRequired(Json::arrayValue);
    calcRequired.append("expression");
    calcParams["required"] = calcRequired;
    
    calculator["parameters"] = calcParams;
    tools.append(calculator);
    
    // 도구 2 - 날씨
    Json::Value weather;
    weather["name"] = "weather";
    weather["description"] = "Get current weather for a location";
    
    Json::Value weatherParams;
    weatherParams["type"] = "object";
    
    Json::Value weatherProperties;
    Json::Value locationProp;
    locationProp["type"] = "string";
    locationProp["description"] = "City name or zip code";
    weatherProperties["location"] = locationProp;
    
    weatherParams["properties"] = weatherProperties;
    
    Json::Value weatherRequired(Json::arrayValue);
    weatherRequired.append("location");
    weatherParams["required"] = weatherRequired;
    
    weather["parameters"] = weatherParams;
    tools.append(weather);
    
    params["tools"] = tools;
    notification["params"] = params;
    
    return notification;
}

// resources/list 알림 메시지 생성
Json::Value createResourcesListNotification() {
    Json::Value notification;
    notification["jsonrpc"] = "2.0";
    notification["method"] = "resources/list";
    
    Json::Value params;
    Json::Value resources(Json::arrayValue);
    
    // 리소스 1 - 텍스트 문서
    Json::Value textDoc;
    textDoc["id"] = generateUUID();
    textDoc["name"] = "Sample Text Document";
    textDoc["type"] = "text";
    
    Json::Value textMeta;
    textMeta["size"] = 1024;
    textMeta["lastModified"] = getCurrentTimeStr();
    textDoc["metadata"] = textMeta;
    
    resources.append(textDoc);
    
    // 리소스 2 - 이미지
    Json::Value image;
    image["id"] = generateUUID();
    image["name"] = "Sample Image";
    image["type"] = "image";
    
    Json::Value imgMeta;
    imgMeta["width"] = 800;
    imgMeta["height"] = 600;
    imgMeta["format"] = "jpeg";
    image["metadata"] = imgMeta;
    
    resources.append(image);
    
    params["resources"] = resources;
    notification["params"] = params;
    
    return notification;
}

// connection/complete 알림 메시지 생성
Json::Value createConnectionCompleteNotification() {
    Json::Value notification;
    notification["jsonrpc"] = "2.0";
    notification["method"] = "connection/complete";
    
    Json::Value params;
    params["status"] = "ready";
    notification["params"] = params;
    
    return notification;
}

// notification/initialized 알림 메시지 생성
Json::Value createInitializedNotification() {
    Json::Value notification;
    notification["jsonrpc"] = "2.0";
    notification["method"] = "notification/initialized";
    
    Json::Value params;
    params["timestamp"] = getCurrentTimeStr();
    notification["params"] = params;
    
    return notification;
}

// tools/list 알림 전송
bool sendToolsListNotification(int socket_fd, const std::string& sessionId) {
    LOG_INFO("Sending tools/list notification to session: " << sessionId);
    
    // 메시지 생성
    Json::Value toolsList = createToolsListNotification();
    std::string toolsListStr = jsonToString(toolsList);
    
    // 메시지 전송
    return sendSSEMessage(socket_fd, "message", toolsListStr);
}

// resources/list 알림 전송
bool sendResourcesListNotification(int socket_fd, const std::string& sessionId) {
    LOG_INFO("Sending resources/list notification to session: " << sessionId);
    
    // 메시지 생성
    Json::Value resourcesList = createResourcesListNotification();
    std::string resourcesListStr = jsonToString(resourcesList);
    
    // 메시지 전송
    return sendSSEMessage(socket_fd, "message", resourcesListStr);
}

// connection/complete 알림 전송
bool sendConnectionCompleteNotification(int socket_fd, const std::string& sessionId) {
    LOG_INFO("Sending connection/complete notification to session: " << sessionId);
    
    // 세션 상태 확인
    {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        auto it = sessions.find(sessionId);
        if (it != sessions.end() && it->second.connectionCompleteSent) {
            LOG_INFO("Connection complete already sent for session: " << sessionId);
            return true;
        }
    }
    
    // 메시지 생성
    Json::Value connectionComplete = createConnectionCompleteNotification();
    std::string connectionCompleteStr = jsonToString(connectionComplete);
    
    // 메시지 전송
    bool success = sendSSEMessage(socket_fd, "message", connectionCompleteStr);
    
    if (success) {
        // 전송 성공 시 세션 상태 업데이트
        std::lock_guard<std::mutex> lock(sessions_mutex);
        auto it = sessions.find(sessionId);
        if (it != sessions.end()) {
            it->second.connectionCompleteSent = true;
            LOG_INFO("✓ Connection complete notification sent successfully");
        }
    }
    
    return success;
}

// notification/initialized 알림 전송
bool sendInitializedNotification(int socket_fd, const std::string& sessionId) {
    LOG_INFO("Sending initialized notification to session: " << sessionId);
    
    // 메시지 생성
    Json::Value initialized = createInitializedNotification();
    std::string initializedStr = jsonToString(initialized);
    
    // 메시지 전송
    return sendSSEMessage(socket_fd, "message", initializedStr);
}

// 알림 시퀀스 시작 함수
void startNotificationSequence(int socket_fd, const std::string& sessionId) {
    LOG_INFO("Starting notification sequence for session: " << sessionId);
    
    // 1. 초기화 알림 전송
    scheduleTask([socket_fd, sessionId]() {
        bool initializedSuccess = sendInitializedNotification(socket_fd, sessionId);
        
        if (initializedSuccess) {
            // 2. tools/list 전송
            scheduleTask([socket_fd, sessionId]() {
                bool toolsSuccess = sendToolsListNotification(socket_fd, sessionId);
                
                if (toolsSuccess) {
                    // 3. resources/list 전송
                    scheduleTask([socket_fd, sessionId]() {
                        bool resourcesSuccess = sendResourcesListNotification(socket_fd, sessionId);
                        
                        if (resourcesSuccess) {
                            // 4. connection/complete 전송
                            scheduleTask([socket_fd, sessionId]() {
                                sendConnectionCompleteNotification(socket_fd, sessionId);
                            }, std::chrono::milliseconds(1000));
                        }
                    }, std::chrono::milliseconds(1000));
                }
            }, std::chrono::milliseconds(1000));
        }
    }, std::chrono::milliseconds(500));
}

// initialize 후속 처리 함수
void handlePostInitialize(int socket_fd, const std::string& sessionId) {
    LOG_INFO("Starting post-initialize handling for session: " << sessionId);
    
    // 세션 상태 업데이트
    {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        auto it = sessions.find(sessionId);
        if (it != sessions.end()) {
            it->second.initialized = true;
        }
    }
    
    // 알림 시퀀스 시작
    startNotificationSequence(socket_fd, sessionId);
}

// SSE 연결 처리 함수
void handleSSEConnection(int client_socket, const std::string& sessionId) {
    LOG_INFO("Client connected for SSE with sessionId: " << sessionId);
    
    // 세션 등록
    {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        sessions[sessionId] = SessionInfo(client_socket);
    }
    
    // SSE 헤더 전송 - 정확한 헤더 형식 준수
    std::string sse_headers = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "\r\n"; // 헤더 종료
    
    ssize_t header_sent = send(client_socket, sse_headers.c_str(), sse_headers.length(), 0);
    if (header_sent < 0) {
        LOG_ERROR("Failed to send SSE headers: " << strerror(errno));
        close(client_socket);
        
        std::lock_guard<std::mutex> lock(sessions_mutex);
        sessions.erase(sessionId);
        return;
    }
    LOG_INFO("SSE headers sent successfully");
    
    // 잠시 대기하여 클라이언트가 연결을 준비할 시간을 줌
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // endpoint 이벤트 전송 - MCP Inspector가 이 URL로 MCP 요청을 보냄
    std::string endpointUrl = "http://localhost:8080/mcp?sessionId=" + sessionId;
    if (!sendSSEMessage(client_socket, "endpoint", endpointUrl)) {
        LOG_ERROR("Failed to send endpoint event, closing connection");
        close(client_socket);
        
        std::lock_guard<std::mutex> lock(sessions_mutex);
        sessions.erase(sessionId);
        return;
    }
    
    LOG_INFO("Endpoint event sent successfully, SSE connection established");
    
    // 하트비트를 위한 루프
    int counter = 0;
    while (server_running) {
        std::this_thread::sleep_for(std::chrono::seconds(20));
        
        // 세션 상태 확인
        bool session_valid = false;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex);
            auto it = sessions.find(sessionId);
            if (it != sessions.end() && it->second.socket_fd == client_socket) {
                session_valid = true;
                it->second.lastActivity = std::chrono::system_clock::now();
            }
        }
        
        if (!session_valid) {
            LOG_INFO("Session no longer valid, stopping heartbeat: " << sessionId);
            break;
        }
        
        // 하트비트 전송
        Json::Value heartbeat;
        heartbeat["type"] = "heartbeat";
        heartbeat["count"] = ++counter;
        heartbeat["time"] = getCurrentTimeStr();
        
        std::string heartbeatStr = jsonToString(heartbeat);
        
        if (!sendSSEMessage(client_socket, "heartbeat", heartbeatStr)) {
            LOG_ERROR("Heartbeat failed, connection probably closed");
            break;
        }
    }
    
    // 연결 종료 처리
    LOG_INFO("SSE connection closing for sessionId: " << sessionId);
    close(client_socket);
    
    std::lock_guard<std::mutex> lock(sessions_mutex);
    sessions.erase(sessionId);
}

// HTTP 응답 생성 함수
std::string createHttpResponse(int status_code, const std::string& body, 
                              const std::string& content_type = "application/json") {
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
int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    int port = 8080;
    
    // 소켓 설정
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
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        LOG_ERROR("Bind failed: " << strerror(errno));
        close(server_fd);
        return 1;
    }
    
    if (listen(server_fd, 10) < 0) {
        LOG_ERROR("Listen failed: " << strerror(errno));
        close(server_fd);
        return 1;
    }
    
    LOG_INFO("MCP Server listening on port " << port);
    
    // 세션 청소를 위한 백그라운드 스레드
    std::thread([&]() {
        while (server_running) {
            std::this_thread::sleep_for(std::chrono::minutes(5));
            auto now = std::chrono::system_clock::now();
            
            std::lock_guard<std::mutex> lock(sessions_mutex);
            for (auto it = sessions.begin(); it != sessions.end();) {
                auto diff = std::chrono::duration_cast<std::chrono::minutes>(now - it->second.lastActivity).count();
                if (diff > 30) { // 30분 이상 활동이 없으면 세션 제거
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
        LOG_INFO("Waiting for connection...");
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            LOG_ERROR("Accept failed: " << strerror(errno));
            continue;
        }
        
        // 클라이언트 정보 로깅
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(address.sin_port);
        LOG_INFO("Client connected: " << client_ip << ":" << client_port);
        
        // 요청 읽기
        char buffer[8192] = {0};
        ssize_t bytes_received = recv(new_socket, buffer, 8191, 0);
        if (bytes_received <= 0) {
            if (bytes_received < 0) LOG_ERROR("Receive failed: " << strerror(errno));
            else LOG_ERROR("Client disconnected before sending data");
            close(new_socket);
            continue;
        }
        
        std::string request(buffer, bytes_received);
        LOG_DEBUG("Received request of " << bytes_received << " bytes");
        
        // 요청 파싱
        std::string method, path;
        std::map<std::string, std::string> headers;
        std::string body;
        
        if (!parseHttpRequest(request, method, path, headers, body)) {
            LOG_ERROR("Failed to parse HTTP request");
            close(new_socket);
            continue;
        }
        
        LOG_INFO("Request: " << method << " " << path);
        
        // OPTIONS 요청 처리 (CORS)
        if (method == "OPTIONS") {
            std::string options_response = 
                "HTTP/1.1 200 OK\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type\r\n"
                "Content-Length: 0\r\n"
                "\r\n";
            
            send(new_socket, options_response.c_str(), options_response.length(), 0);
            close(new_socket);
            continue;
        }
        
        // SSE 요청 처리
        if (method == "GET" && path.find("/sse") == 0) {
            std::string sessionId = extractQueryParam(path, "sessionId");
            if (sessionId.empty()) {
                // 세션 ID 없으면 생성
                sessionId = "session-" + generateUUID();
                LOG_INFO("Generated new sessionId: " << sessionId);
            }
            
            LOG_INFO("Starting SSE connection with sessionId: " << sessionId);
            std::thread sse_thread(handleSSEConnection, new_socket, sessionId);
            sse_thread.detach();
            continue;
        }
        
        // MCP 요청 처리
        if (method == "POST" && path.find("/mcp") == 0) {
            std::string sessionId = extractQueryParam(path, "sessionId");
            LOG_INFO("Received MCP request for sessionId: " << sessionId);
            
            int status_code = 200;
            std::string response_body;
            bool isInitializeRequest = false;
            
            try {
                Json::Value request_json;
                Json::CharReaderBuilder readerBuilder;
                std::string errors;
                std::stringstream stream(body);
                
                if (Json::parseFromStream(readerBuilder, stream, &request_json, &errors)) {
                    LOG_DEBUG("Parsed JSON request: " << body);
                    
                    std::string rpc_method = request_json.get("method", "").asString();
                    bool hasId = request_json.isMember("id");
                    int id = hasId ? request_json.get("id", 0).asInt() : -1;
                    
                    // JSON-RPC 응답 구성
                    Json::Value response;
                    response["jsonrpc"] = "2.0";
                    if (hasId) {
                        response["id"] = id;
                    }
                    
                    LOG_INFO("Processing RPC method: " << rpc_method);
                    
                    if (rpc_method == "initialize") {
                        LOG_INFO("Handling initialize request");
                        isInitializeRequest = true;
                        
                        // 클라이언트 정보 저장
                        if (request_json.isMember("params") && request_json["params"].isMember("clientInfo")) {
                            std::lock_guard<std::mutex> lock(sessions_mutex);
                            auto it = sessions.find(sessionId);
                            if (it != sessions.end()) {
                                it->second.clientName = request_json["params"]["clientInfo"].get("name", "Unknown Client").asString();
                                LOG_INFO("Client name: " << it->second.clientName);
                            }
                        }
                        
                        // initialize 응답 구성
                        Json::Value result;
                        result["protocolVersion"] = PROTOCOL_VERSION;
                        
                        Json::Value capabilities;
                        capabilities["experimental"] = Json::objectValue;
                        
                        // Tools 기능 지원 표시
                        Json::Value tools;
                        tools["listChanged"] = true;
                        capabilities["tools"] = tools;
                        
                        // Resources 기능 지원 표시
                        Json::Value resources;
                        resources["listChanged"] = true;
                        capabilities["resources"] = resources;
                        
                        // 서버 정보
                        Json::Value serverInfo;
                        serverInfo["name"] = "C++ MCP Server";
                        serverInfo["version"] = "1.0.0";
                        
                        result["capabilities"] = capabilities;
                        result["serverInfo"] = serverInfo;
                        
                        response["result"] = result;
                    } else if (rpc_method == "tools/invoke") {
                        LOG_INFO("Handling tool invocation");
                        
                        // 도구 호출 처리
                        std::string toolName = request_json["params"]["name"].asString();
                        LOG_INFO("Tool name: " << toolName);
                        
                        if (toolName == "calculator") {
                            std::string expression = request_json["params"]["parameters"]["expression"].asString();
                            LOG_INFO("Calculator expression: " << expression);
                            
                            // 매우 단순한 계산기 예제
                            int result = 0;
                            try {
                                if (expression.find("+") != std::string::npos) {
                                    size_t pos = expression.find("+");
                                    int a = std::stoi(expression.substr(0, pos));
                                    int b = std::stoi(expression.substr(pos + 1));
                                    result = a + b;
                                } else if (expression.find("-") != std::string::npos) {
                                    size_t pos = expression.find("-");
                                    int a = std::stoi(expression.substr(0, pos));
                                    int b = std::stoi(expression.substr(pos + 1));
                                    result = a - b;
                                }
                                
                                Json::Value resultObj;
                                resultObj["result"] = result;
                                response["result"] = resultObj;
                            } catch (...) {
                                Json::Value error;
                                error["code"] = -32603;
                                error["message"] = "Invalid expression";
                                response["error"] = error;
                            }
                        } else if (toolName == "weather") {
                            std::string location = request_json["params"]["parameters"]["location"].asString();
                            LOG_INFO("Weather location: " << location);
                            
                            // 날씨 정보 시뮬레이션
                            std::random_device rd;
                            std::mt19937 gen(rd());
                            std::uniform_int_distribution<> temp_dist(10, 30);
                            std::uniform_int_distribution<> humid_dist(30, 90);
                            
                            int temperature = temp_dist(gen);
                            int humidity = humid_dist(gen);
                            
                            Json::Value resultObj;
                            resultObj["location"] = location;
                            resultObj["temperature"] = temperature;
                            resultObj["unit"] = "Celsius";
                            resultObj["humidity"] = humidity;
                            resultObj["description"] = temperature > 25 ? "Sunny" : "Cloudy";
                            
                            response["result"] = resultObj;
                        } else {
                            Json::Value error;
                            error["code"] = -32601;
                            error["message"] = "Tool not found: " + toolName;
                            response["error"] = error;
                        }
                    } else if (rpc_method == "resources/get") {
                        LOG_INFO("Handling resource request");
                        
                        std::string resourceId = request_json["params"]["id"].asString();
                        LOG_INFO("Resource ID: " << resourceId);
                        
                        // 리소스 내용 반환
                        Json::Value resultObj;
                        resultObj["id"] = resourceId;
                        resultObj["content"] = "This is the content of resource " + resourceId;
                        resultObj["type"] = "text";
                        
                        response["result"] = resultObj;
                    } else if (rpc_method == "tools/list" || rpc_method == "resources/list") {
                        LOG_INFO("Handling direct " << rpc_method << " request");
                        
                        // 직접 요청에 대해 빈 목록 반환 (알림으로 이미 전송함)
                        Json::Value resultObj;
                        if (rpc_method == "tools/list") {
                            resultObj["tools"] = Json::Value(Json::arrayValue);
                        } else {
                            resultObj["resources"] = Json::Value(Json::arrayValue);
                        }
                        
                        response["result"] = resultObj;
                    } else {
                        LOG_ERROR("Unknown method: " << rpc_method);
                        Json::Value error;
                        error["code"] = -32601;
                        error["message"] = "Method not found: " + rpc_method;
                        response["error"] = error;
                    }
                    
                    // JSON 응답 문자열로 변환
                    response_body = jsonToString(response);
                } else {
                    LOG_ERROR("Failed to parse JSON request: " << errors);
                    status_code = 400;
                    response_body = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}";
                }
            } catch (const std::exception& e) {
                LOG_ERROR("Exception: " << e.what());
                status_code = 500;
                response_body = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Internal error: " + std::string(e.what()) + "\"}}";
            }
            
            // HTTP 응답 보내기
            std::string http_response = createHttpResponse(status_code, response_body);
            send(new_socket, http_response.c_str(), http_response.length(), 0);
            
            // initialize 요청이었다면 별도 스레드에서 후속 처리 시작
            if (isInitializeRequest && !sessionId.empty()) {
                int socket_fd;
                {
                    std::lock_guard<std::mutex> lock(sessions_mutex);
                    auto it = sessions.find(sessionId);
                    if (it != sessions.end()) {
                        socket_fd = it->second.socket_fd;
                        LOG_INFO("Starting post-initialize process for session: " << sessionId);
                        std::thread([socket_fd, sessionId]() {
                            handlePostInitialize(socket_fd, sessionId);
                        }).detach();
                    }
                }
            }
            
            // 응답 후 소켓 닫기
            close(new_socket);
            continue;
        }
        
        // 지원하지 않는 요청
        LOG_ERROR("Unsupported request: " << method << " " << path);
        std::string not_found = "{\"error\":\"Not found\"}";
        std::string response = createHttpResponse(404, not_found);
        send(new_socket, response.c_str(), response.length(), 0);
        close(new_socket);
    }
    
    // 서버 종료 처리
    LOG_INFO("Server shutting down");
    close(server_fd);
    return 0;
}