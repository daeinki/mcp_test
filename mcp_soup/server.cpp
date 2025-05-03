// server.cpp
#include <libsoup/soup.h>
#include <json/json.h>
#include <glib.h>

#include <iostream>
#include <string>
#include <unordered_map>
#include <mutex>
#include <queue>
#include <thread>
#include <chrono>
#include <random>
#include <sstream>

// ———— 로깅 매크로 ————
#define LOG_INFO(msg)   std::cout << "[INFO] "  << msg << std::endl
#define LOG_DEBUG(msg)  std::cout << "[DEBUG] " << msg << std::endl
#define LOG_ERROR(msg)  std::cerr << "[ERROR] " << msg << std::endl

// ———— 클라이언트 세션 정보 ————
class ClientSession {
public:
  ClientSession() : serverMessage(nullptr), initialized(false), connected(false) {}
  
  // 복사 및 이동 생성자/연산자 삭제
  ClientSession(const ClientSession&) = delete;
  ClientSession& operator=(const ClientSession&) = delete;
  ClientSession(ClientSession&&) = delete;
  ClientSession& operator=(ClientSession&&) = delete;

  SoupServerMessage* serverMessage;
  bool initialized;
  bool connected;
  std::mutex mutex;
  std::queue<std::string> messageQueue;
};

// ———— 서버 관리 클래스 ————
class StreamingServer {
public:
  StreamingServer();
  ~StreamingServer();
  
  // 서버 실행
  bool start(uint16_t port);
  void runMainLoop();
  
private:
  // UUID 생성기
  static std::string generateUUID();
  
  // URI 쿼리 파라미터 추출
  static std::string extractQueryParam(const std::string& uri, const std::string& key);
  
  // 현재 시간(밀리초) 가져오기
  static uint64_t getCurrentTimeMillis();
  
  // SSE 이벤트 전송 기능
  void sendEventMessage(const std::string& sessionId, const std::string& eventType, const std::string& messageData);
  void sendJsonMessage(const std::string& sessionId, const std::string& eventType, const Json::Value& data);
  void sendHeartbeat(const std::string& sessionId, SoupServerMessage* serverMessage);
  
  // 오류 응답 생성 및 전송
  void sendErrorResponse(SoupServerMessage* message, int statusCode, const std::string& errorMessage);
  void sendJsonRpcErrorResponse(const std::string& sessionId, const Json::Value& request, int errorCode, const std::string& errorMessage);
  
  // 요청 처리 핸들러
  static void handleSseRequest(SoupServer* server, SoupServerMessage* message, 
                       const char* path, GHashTable* query, gpointer userData);
  static void handleJsonRpcRequest(SoupServer* server, SoupServerMessage* message, 
                           const char* path, GHashTable* query, gpointer userData);
  
  // 세션 관리
  std::string createSession(SoupServerMessage* message);
  bool resumeSession(const std::string& sessionId, SoupServerMessage* message);
  void removeSession(const std::string& sessionId);
  std::shared_ptr<ClientSession> getSession(const std::string& sessionId);
  static void onSessionClosed(SoupServerMessage* message, gpointer userData);
  
  // JSON-RPC 메소드 핸들러
  void handleInitializeMethod(const std::string& sessionId, const Json::Value& request);
  void handleToolsListMethod(const std::string& sessionId, const Json::Value& request);
  void handleToolsCallMethod(const std::string& sessionId, const Json::Value& request);
  
  // 하트비트 스레드
  void startHeartbeatThread();
  void heartbeatLoop();
  
  // 서버 객체 및 관련 자원
  SoupServer* server;
  std::unordered_map<std::string, std::shared_ptr<ClientSession>> sessions;
  std::mutex sessionsMutex;
  std::thread heartbeatThread;
  bool isRunning;

  // 싱글톤 인스턴스 (핸들러에서 this 포인터 접근용)
  static StreamingServer* instance;
};

// 정적 인스턴스 초기화
StreamingServer* StreamingServer::instance = nullptr;

// ———— 서버 클래스 구현 ————
StreamingServer::StreamingServer() : server(nullptr), isRunning(false) {
  instance = this;
}

StreamingServer::~StreamingServer() {
  isRunning = false;
  if (heartbeatThread.joinable()) {
    heartbeatThread.join();
  }
  if (server) {
    g_object_unref(server);
  }
}

bool StreamingServer::start(uint16_t port) {
  GError* error = nullptr;
  
  // 서버 생성 - NULL 종료 인자 형식 맞추기
  server = soup_server_new(nullptr, nullptr);
  if (!server) {
    LOG_ERROR("Failed to create server instance");
    return false;
  }
  
  // 요청 핸들러 등록
  soup_server_add_handler(server, "/sse", handleSseRequest, this, NULL);
  soup_server_add_handler(server, "/message", handleJsonRpcRequest, this, NULL);

  // 서버 시작
  soup_server_listen_all(server, port, (SoupServerListenOptions)0, &error);
  if (error) {
    LOG_ERROR("Listen error: " << error->message);
    g_error_free(error);
    return false;
  }
  
  LOG_INFO("Server listening on port " << port);
  isRunning = true;
  
  // 하트비트 스레드 시작
  startHeartbeatThread();
  
  return true;
}

void StreamingServer::runMainLoop() {
  // GLib 메인 루프 실행
  GMainLoop* loop = g_main_loop_new(NULL, FALSE);
  g_main_loop_run(loop);
  g_main_loop_unref(loop);
}

std::string StreamingServer::generateUUID() {
  static const char* hexChars = "0123456789abcdef";
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 15);
  std::string uuid = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
  
  for (char &c : uuid) {
    if (c == 'x' || c == 'y') {
      int r = dis(gen);
      if (c == 'y') r = (r & 0x3) | 0x8;  // RFC 4122 variant
      c = hexChars[r];
    }
  }
  
  return uuid;
}

std::string StreamingServer::extractQueryParam(const std::string& uri, const std::string& key) {
  auto queryPos = uri.find('?');
  if (queryPos == std::string::npos) return "";
  
  std::string query = uri.substr(queryPos + 1);
  std::string prefix = key + "=";
  auto paramPos = query.find(prefix);
  
  if (paramPos == std::string::npos) return "";
  
  auto valueStart = paramPos + prefix.size();
  auto valueEnd = query.find('&', valueStart);
  
  return query.substr(valueStart, valueEnd == std::string::npos ? 
                     query.size() - valueStart : valueEnd - valueStart);
}

uint64_t StreamingServer::getCurrentTimeMillis() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()
  ).count();
}

void StreamingServer::sendEventMessage(const std::string& sessionId, const std::string& eventType, const std::string& messageData) {
  // SSE 포맷 구성
  std::ostringstream oss;
  oss << "event: " << eventType << "\n"
      << "data: "  << messageData   << "\n\n";  // 매개변수 이름 변경됨
  std::string eventData = oss.str();
  
  LOG_DEBUG("Event data: " << eventData << " Sending event: " << eventType << " to " << sessionId);
  
  std::lock_guard<std::mutex> lock(sessionsMutex);
  auto it = sessions.find(sessionId);
  if (it == sessions.end() || !it->second->connected) {
    LOG_DEBUG("Drop event: session not found or disconnected: " << sessionId);
    return;
  }
  
  // 변수 이름을 serverMessage로 변경하여 매개변수 이름 충돌 방지
  SoupServerMessage* serverMessage = it->second->serverMessage;
  SoupMessageBody* body = soup_server_message_get_response_body(serverMessage);
  
  // 메시지 바디에 추가하고 전송
  GBytes* bytes = g_bytes_new(eventData.c_str(), eventData.size());
  soup_message_body_append_bytes(body, bytes);
  g_bytes_unref(bytes);
  
  soup_server_unpause_message(server, serverMessage);
}

void StreamingServer::sendJsonMessage(const std::string& sessionId, const std::string& eventType, const Json::Value& data) {
  // JSON -> 문자열 변환
  std::string jsonStr = Json::FastWriter().write(data);
  if (!jsonStr.empty() && jsonStr.back() == '\n') {
    jsonStr.pop_back();  // 불필요한 줄바꿈 제거
  }
  sendEventMessage(sessionId, eventType, jsonStr);
}

void StreamingServer::sendHeartbeat(const std::string& sessionId, SoupServerMessage* serverMessage) {
  std::string heartbeatData = std::to_string(getCurrentTimeMillis());

  // SSE 포맷 구성
  std::ostringstream oss;
  oss << "event: heartbeat" << "\n"
      << "data: "  << heartbeatData   << "\n\n";  // 매개변수 이름 변경됨
  std::string eventData = oss.str();
  
  LOG_DEBUG("Event data: " << eventData << " Sending event to " << sessionId);
  
  SoupMessageBody* body = soup_server_message_get_response_body(serverMessage);
  
  // 메시지 바디에 추가하고 전송
  GBytes* bytes = g_bytes_new(eventData.c_str(), eventData.size());
  soup_message_body_append_bytes(body, bytes);
  g_bytes_unref(bytes);
  
  soup_server_unpause_message(server, serverMessage);

}

void StreamingServer::sendErrorResponse(SoupServerMessage* message, int statusCode, const std::string& errorMessage) {
  soup_server_message_set_status(message, statusCode, nullptr);
  
  std::string errorJson = "{\"error\":\"" + errorMessage + "\"}";
  GBytes* error = g_bytes_new(errorJson.c_str(), errorJson.size());
  SoupMessageBody* body = soup_server_message_get_response_body(message);
  
  soup_message_body_append_bytes(body, error);
  g_bytes_unref(error);
  soup_message_body_complete(body);
}

void StreamingServer::sendJsonRpcErrorResponse(const std::string& sessionId, 
                                      const Json::Value& request, 
                                      int errorCode, 
                                      const std::string& errorMessage) {
  Json::Value response;
  response["jsonrpc"] = "2.0";
  response["id"] = request.isMember("id") ? request["id"] : Json::nullValue;
  response["error"]["code"] = errorCode;
  response["error"]["message"] = errorMessage;
  
  sendJsonMessage(sessionId, "message", response);
  LOG_INFO("Sent error response: " << errorMessage);
}

std::string StreamingServer::createSession(SoupServerMessage* message) {
  std::string sessionId = generateUUID();
  auto session = std::make_shared<ClientSession>();
  session->serverMessage = message;
  session->connected = true;
  
  {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    sessions[sessionId] = session;
  }
  
  // 연결 해제 시 세션 정리 콜백 등록
  g_signal_connect(message, "finished", G_CALLBACK(onSessionClosed), g_strdup(sessionId.c_str()));
  
  LOG_INFO("New session created: " << sessionId);
  return sessionId;
}

bool StreamingServer::resumeSession(const std::string& sessionId, SoupServerMessage* message) {
  std::lock_guard<std::mutex> lock(sessionsMutex);
  auto it = sessions.find(sessionId);
  if (it == sessions.end()) {
    return false;
  }
  
  it->second->serverMessage = message;
  it->second->connected = true;
  
  // 연결 해제 시 세션 정리 콜백 재등록
  g_signal_connect(message, "finished", G_CALLBACK(onSessionClosed), g_strdup(sessionId.c_str()));
  
  LOG_INFO("Resumed session: " << sessionId);
  return true;
}

void StreamingServer::removeSession(const std::string& sessionId) {
  std::lock_guard<std::mutex> lock(sessionsMutex);
  sessions.erase(sessionId);
  LOG_INFO("Session removed: " << sessionId);
}

std::shared_ptr<ClientSession> StreamingServer::getSession(const std::string& sessionId) {
  std::lock_guard<std::mutex> lock(sessionsMutex);
  auto it = sessions.find(sessionId);
  if (it != sessions.end()) {
    return it->second;
  }
  return nullptr;
}

void StreamingServer::onSessionClosed(SoupServerMessage* message, gpointer userData) {
  char* sessionId = static_cast<char*>(userData);
  if (instance) {
    instance->removeSession(sessionId);
  }
  g_free(sessionId);
}

void StreamingServer::handleSseRequest(SoupServer* server, SoupServerMessage* message,
                               const char* path, GHashTable* query, gpointer userData) {
  StreamingServer* self = static_cast<StreamingServer*>(userData);
  
  // URI에서 세션 ID 추출
  GUri* uri = soup_server_message_get_uri(message);
  char* uriStr = g_uri_to_string(uri);
  std::string fullUri(uriStr);
  g_free(uriStr);
  
  std::string sessionId = extractQueryParam(fullUri, "sessionId");
  bool isSessionResumed = false;
  
  // 세션 ID가 제공되었으면 세션 복구 시도
  if (!sessionId.empty()) {
    isSessionResumed = self->resumeSession(sessionId, message);
  }
  
  // 새 세션 또는 복구 실패 시, 새 세션 생성
  if (!isSessionResumed) {
    // SSE 헤더 설정
    soup_message_headers_append(
      soup_server_message_get_response_headers(message),
      "Content-Type", "text/event-stream");
    soup_message_headers_append(
      soup_server_message_get_response_headers(message),
      "Cache-Control", "no-cache");
    soup_message_headers_append(
      soup_server_message_get_response_headers(message),
      "Connection", "keep-alive");
    soup_message_headers_append(
      soup_server_message_get_response_headers(message),
      "Access-Control-Allow-Origin", "*");
    soup_message_headers_append(
      soup_server_message_get_response_headers(message),
      "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    soup_message_headers_append(
      soup_server_message_get_response_headers(message),
      "Access-Control-Allow-Headers", "Content-Type");
    soup_message_headers_set_encoding(
      soup_server_message_get_response_headers(message),
      SOUP_ENCODING_CHUNKED);

    // 응답 상태 설정
    soup_server_message_set_status(message, SOUP_STATUS_OK, nullptr);
    
    // 새 세션 생성
    sessionId = self->createSession(message);
  }
  
  // 최초 엔드포인트 이벤트 전송
  std::string endpointMessage = "/message?sessionId=" + sessionId;
  self->sendEventMessage(sessionId, "endpoint", endpointMessage);
}

void StreamingServer::handleJsonRpcRequest(SoupServer* server, SoupServerMessage* message,
                                   const char* path, GHashTable* query, gpointer userData) {
  StreamingServer* self = static_cast<StreamingServer*>(userData);
  
  // CORS 프리플라이트 요청 처리
  if (soup_server_message_get_method(message) == SOUP_METHOD_OPTIONS) {
    soup_server_message_set_status(message, SOUP_STATUS_OK, nullptr);
    soup_message_headers_append(
      soup_server_message_get_response_headers(message),
      "Access-Control-Allow-Origin", "*");
    soup_message_headers_append(
      soup_server_message_get_response_headers(message),
      "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    soup_message_headers_append(
      soup_server_message_get_response_headers(message),
      "Access-Control-Allow-Headers", "Content-Type");
    
    SoupMessageBody* body = soup_server_message_get_response_body(message);
    soup_message_body_complete(body);
    return;
  }
  
  // POST 메소드가 아닌 경우 거부
  if (soup_server_message_get_method(message) != SOUP_METHOD_POST) {
    soup_server_message_set_status(message, SOUP_STATUS_NOT_IMPLEMENTED, nullptr);
    return;
  }
  
  // 세션 ID 추출
  GUri* uri = soup_server_message_get_uri(message);
  char* uriStr = g_uri_to_string(uri);
  std::string fullUri(uriStr);
  g_free(uriStr);
  
  std::string sessionId = extractQueryParam(fullUri, "sessionId");
  if (sessionId.empty()) {
    self->sendErrorResponse(message, SOUP_STATUS_BAD_REQUEST, "Missing sessionId");
    return;
  }
  
  // 세션 존재 확인
  auto session = self->getSession(sessionId);
  if (!session) {
    self->sendErrorResponse(message, SOUP_STATUS_NOT_FOUND, "Invalid sessionId");
    return;
  }
  
  // 요청 본문 파싱
  GBytes* requestBodyBytes = soup_message_body_flatten(
    soup_server_message_get_request_body(message));
  gsize bodySize;
  const char* bodyData = static_cast<const char*>(g_bytes_get_data(requestBodyBytes, &bodySize));
  
  Json::Value request;
  Json::CharReaderBuilder readerBuilder;
  std::string parseErrors;
  std::istringstream requestStream(std::string(bodyData, bodySize));
  g_bytes_unref(requestBodyBytes);
  
  // JSON 파싱
  if (!Json::parseFromStream(readerBuilder, requestStream, &request, &parseErrors)) {
    self->sendErrorResponse(message, SOUP_STATUS_BAD_REQUEST, "Invalid JSON");
    return;
  }
  
  // HTTP Ack 응답 생성 및 전송
  Json::Value ackResponse;
  ackResponse["jsonrpc"] = "2.0";
  if (request.isMember("id")) ackResponse["id"] = request["id"];
  
  std::string methodName = request.get("method", "").asString();
  ackResponse["result"]["ack"] = "Received " + methodName;
  
  std::string ackString = Json::FastWriter().write(ackResponse);
  
  soup_server_message_set_status(message, SOUP_STATUS_OK, nullptr);
  soup_message_headers_set_content_type(
    soup_server_message_get_response_headers(message),
    "application/json", nullptr);
  
  GBytes* response = g_bytes_new(ackString.c_str(), ackString.size());
  SoupMessageBody* body = soup_server_message_get_response_body(message);
  soup_message_body_append_bytes(body, response);
  g_bytes_unref(response);
  soup_message_body_complete(body);
  
  LOG_INFO("Ack sent for method: " << methodName);
  
  // 메소드별 처리
  if (methodName == "initialize") {
    self->handleInitializeMethod(sessionId, request);
  }
  else if (methodName == "tools/list") {
    self->handleToolsListMethod(sessionId, request);
  }
  else if (methodName == "tools/call") {
    self->handleToolsCallMethod(sessionId, request);
  }
  else if (methodName == "notifications/initialized") {
    LOG_INFO("Received notifications/initialized, no SSE response needed");
  }
  else {
    // 알 수 없는 메소드
    self->sendJsonRpcErrorResponse(
      sessionId, request, -32601, "Method '" + methodName + "' not recognized");
  }
}

void StreamingServer::handleInitializeMethod(const std::string& sessionId, const Json::Value& request) {
  // 세션 초기화
  {
    auto session = getSession(sessionId);
    if (session) {
      session->initialized = true;
    }
  }
  
  // 초기화 응답 생성
  Json::Value initResponse;
  initResponse["jsonrpc"] = "2.0";
  initResponse["id"] = request.isMember("id") ? request["id"] : Json::nullValue;
  
  Json::Value& result = initResponse["result"];
  result["protocolVersion"] = "2024-11-05";
  
  Json::Value& capabilities = result["capabilities"];
  capabilities["tools"]["listChanged"] = true;
  capabilities["resources"]["subscribe"] = true;
  capabilities["resources"]["listChanged"] = true;
  capabilities["prompts"]["listChanged"] = true;
  capabilities["logging"] = Json::objectValue;
  
  Json::Value& serverInfo = result["serverInfo"];
  serverInfo["name"] = "cpp-capabilities-server";
  serverInfo["version"] = "1.0.0";
  
  sendJsonMessage(sessionId, "message", initResponse);
  LOG_INFO("Sent initialize capabilities response");
}

void StreamingServer::handleToolsListMethod(const std::string& sessionId, const Json::Value& request) {
  // 도구 목록 응답 생성
  Json::Value toolsResponse;
  toolsResponse["jsonrpc"] = "2.0";
  toolsResponse["id"] = request.isMember("id") ? request["id"] : Json::nullValue;
  
  Json::Value& result = toolsResponse["result"];
  
  Json::Value tools(Json::arrayValue);
  Json::Value addTool;
  addTool["name"] = "addNumbersTool";
  addTool["description"] = "Adds two numbers 'a' and 'b' and returns their sum.";
  
  Json::Value& inputSchema = addTool["inputSchema"];
  inputSchema["type"] = "object";
  
  Json::Value& properties = inputSchema["properties"];
  properties["a"]["type"] = "number";
  properties["b"]["type"] = "number";
  
  Json::Value required(Json::arrayValue);
  required.append("a");
  required.append("b");
  inputSchema["required"] = required;
  
  tools.append(addTool);
  result["tools"] = tools;
  result["count"] = 1;
  
  sendJsonMessage(sessionId, "message", toolsResponse);
  LOG_INFO("Sent tools/list response");
}

void StreamingServer::handleToolsCallMethod(const std::string& sessionId, const Json::Value& request) {
  std::string toolName = request["params"]["name"].asString();
  LOG_INFO("Tool call: " << toolName);
  
  if (toolName == "addNumbersTool") {
    // 계산 수행
    int a = request["params"]["arguments"]["a"].asInt();
    int b = request["params"]["arguments"]["b"].asInt();
    int sum = a + b;
    
    // 결과 응답 생성
    Json::Value callResponse;
    callResponse["jsonrpc"] = "2.0";
    callResponse["id"] = request.isMember("id") ? request["id"] : Json::nullValue;
    
    Json::Value& result = callResponse["result"];
    
    Json::Value content(Json::arrayValue);
    Json::Value textContent;
    textContent["type"] = "text";
    textContent["text"] = "Sum of " + std::to_string(a) + " + " + std::to_string(b) +
                         " = " + std::to_string(sum);
    content.append(textContent);
    
    result["content"] = content;
    
    sendJsonMessage(sessionId, "message", callResponse);
    LOG_INFO("Sent tools/call response with sum: " << sum);
  }
  else {
    // 알 수 없는 도구
    sendJsonRpcErrorResponse(
      sessionId, request, -32601, "No such tool '" + toolName + "'");
  }
}

void StreamingServer::startHeartbeatThread() {
  heartbeatThread = std::thread(&StreamingServer::heartbeatLoop, this);
}

void StreamingServer::heartbeatLoop() {
  while (isRunning) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    std::lock_guard<std::mutex> lock(sessionsMutex);
    for (const auto& [sessionId, session] : sessions) {
      if (session->connected && session->serverMessage) {
        sendHeartbeat(sessionId, session->serverMessage);
      }
    }
  }
}

// ———— 메인 함수 ————
int main() {
  StreamingServer server;

  if (!server.start(8000)) {
    LOG_ERROR("Failed to start server");
    return 1;
  }
  
  // 메인 루프 실행
  server.runMainLoop();
  
  return 0;
}
