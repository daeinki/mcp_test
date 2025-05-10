#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <chrono>
#include <random>
#include <ctime>
#include <functional>
#include <uuid/uuid.h> 
#include <atomic>
#include <queue>
#include <condition_variable>
#include <memory>

//#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <json/json.h>
#include "httplib.h"

// 로그 레벨과 로깅 매크로 정의
enum class LogLevel { ERROR, INFO, DEBUG };

class Logger {
public:
    static void log(LogLevel level, const std::string& message) {
        switch (level) {
            case LogLevel::ERROR:
                std::cerr << "[ERROR] " << message << std::endl;
                break;
            case LogLevel::INFO:
                std::cout << "[INFO] " << message << std::endl;
                break;
            case LogLevel::DEBUG:
                std::cout << "[DEBUG] " << message << std::endl;
                break;
        }
    }
};

#define LOG_ERROR(msg) do { std::ostringstream oss; oss << msg; Logger::log(LogLevel::ERROR, oss.str()); } while(0)
#define LOG_INFO(msg) do { std::ostringstream oss; oss << msg; Logger::log(LogLevel::INFO, oss.str()); } while(0)
#define LOG_DEBUG(msg) do { std::ostringstream oss; oss << msg; Logger::log(LogLevel::DEBUG, oss.str()); } while(0)

// 상수 정의
struct ServerConfig {
    static constexpr int DEFAULT_PORT = 8080;
    static constexpr int SSE_HEARTBEAT_INTERVAL_SECONDS = 15;
    static constexpr int SESSION_TIMEOUT_MINUTES = 30;
};

// SSE 메시지 구조체
struct SseMessage {
    std::string event;
    std::string data;
};

// 세션 정보 클래스
class Session {
public:
    explicit Session(const std::string& sessionId) : 
        id(sessionId),
        active(true),
        message_queue(std::make_shared<std::queue<SseMessage>>()),
        queue_mutex(std::make_shared<std::mutex>()),
        queue_cv(std::make_shared<std::condition_variable>()),
        lastActivity(std::chrono::system_clock::now()),
        initialized(false) {}

    void addMessage(const std::string& event, const std::string& data) {
        {
            std::lock_guard<std::mutex> lock(*queue_mutex);
            message_queue->push({event, data});
        }
        queue_cv->notify_one();
    }

    void stop() {
        active = false;
        queue_cv->notify_one();
    }

    void updateLastActivity() {
        lastActivity = std::chrono::system_clock::now();
    }

    // 세션 속성
    std::string id;
    std::atomic<bool> active;
    std::shared_ptr<std::queue<SseMessage>> message_queue;
    std::shared_ptr<std::mutex> queue_mutex;
    std::shared_ptr<std::condition_variable> queue_cv;
    std::chrono::system_clock::time_point lastActivity;
    bool initialized;
};

// 세션 관리자 클래스
class SessionManager {
public:
    SessionManager() : running(true) {}

    std::shared_ptr<Session> createSession() {
        std::string sessionId = generateUUID();
        auto session = std::make_shared<Session>(sessionId);
        {
            std::lock_guard<std::mutex> lock(sessions_mutex);
            sessions[sessionId] = session;
        }
        return session;
    }

    std::shared_ptr<Session> getSession(const std::string& sessionId) {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        auto it = sessions.find(sessionId);
        if (it != sessions.end() && it->second->active) {
            return it->second;
        }
        return nullptr;
    }

    void removeSession(const std::string& sessionId) {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        auto it = sessions.find(sessionId);
        if (it != sessions.end()) {
            it->second->stop();
            sessions.erase(it);
        }
    }

    void startCleanupThread() {
        cleanup_thread = std::thread(&SessionManager::cleanupSessions, this);
    }

    void stopCleanupThread() {
        running = false;
        if (cleanup_thread.joinable()) {
            cleanup_thread.join();
        }
    }

    void stopAllSessions() {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        for (auto& [id, session] : sessions) {
            session->stop();
        }
        sessions.clear();
    }

private:
    std::string generateUUID() {
        uuid_t uuid;
        char uuid_str[37];
        uuid_generate(uuid);
        uuid_unparse_lower(uuid, uuid_str);
        return std::string(uuid_str);
    }

    void cleanupSessions() {
        while (running) {
            std::this_thread::sleep_for(std::chrono::minutes(5));
            auto now = std::chrono::system_clock::now();
            int cleaned_count = 0;

            std::vector<std::string> sessions_to_remove;
            {
                std::lock_guard<std::mutex> lock(sessions_mutex);
                for (const auto& [id, session] : sessions) {
                    auto diff = std::chrono::duration_cast<std::chrono::minutes>(
                        now - session->lastActivity).count();
                    if (diff > ServerConfig::SESSION_TIMEOUT_MINUTES || !session->active) {
                        sessions_to_remove.push_back(id);
                    }
                }
            }

            if (!sessions_to_remove.empty()) {
                std::lock_guard<std::mutex> lock(sessions_mutex);
                for (const auto& id : sessions_to_remove) {
                    auto it = sessions.find(id);
                    if (it != sessions.end()) {
                        LOG_INFO("Removing inactive/stopped session: " << id);
                        it->second->stop();
                        sessions.erase(it);
                        cleaned_count++;
                    }
                }
                if (cleaned_count > 0) {
                    LOG_INFO("Cleaned up " << cleaned_count << " inactive sessions.");
                }
            }
        }
        LOG_INFO("Session cleanup thread finished.");
    }

    std::map<std::string, std::shared_ptr<Session>> sessions;
    std::mutex sessions_mutex;
    std::thread cleanup_thread;
    std::atomic<bool> running;
};

// JSON 유틸리티 클래스
class JsonUtils {
public:
    static std::string jsonToString(const Json::Value& json) {
        Json::StreamWriterBuilder builder;
        builder["indentation"] = "";
        return Json::writeString(builder, json);
    }

    static bool parseJson(const std::string& content, Json::Value& output) {
        Json::CharReaderBuilder reader_builder;
        std::unique_ptr<Json::CharReader> reader(reader_builder.newCharReader());
        std::string errors;
        return reader->parse(content.c_str(), content.c_str() + content.length(), &output, &errors);
    }
};

// SSE 유틸리티 클래스
class SseUtils {
public:
    static std::string formatSSEMessage(const std::string& event, const std::string& data) {
        std::ostringstream oss;
        oss << "event: " << event << "\n";
        std::string line;
        std::istringstream data_stream(data);
        while (std::getline(data_stream, line)) {
            oss << "data: " << line << "\n";
        }
        oss << "\n";
        return oss.str();
    }

    static long long getCurrentTimeMillis() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }
};

// MCP 도구 처리 클래스
class ToolHandler {
public:
    ToolHandler() {}

    Json::Value handleToolsList() {
        Json::Value response;
        response["tools"] = getAvailableTools();
        response["count"] = static_cast<int>(response["tools"].size());
        return response;
    }

    Json::Value handleToolCall(const std::string& tool_name, const Json::Value& arguments) {
        Json::Value result;
        Json::Value content(Json::arrayValue);
        Json::Value text_content;
        text_content["type"] = "text";

        if (tool_name == "addNumbersTool") {
            if (validateAddNumbersArguments(arguments)) {
                double a = arguments["a"].asDouble();
                double b = arguments["b"].asDouble();
                double sum = a + b;
                std::ostringstream sum_oss;
                sum_oss << "Sum of " << a << " + " << b << " = " << sum;
                text_content["text"] = sum_oss.str();
            } else {
                throw std::invalid_argument("Invalid arguments for addNumbersTool");
            }
        } else if (tool_name == "getCurrentTimeTool") {
            std::time_t now_c = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            std::string time_str = std::ctime(&now_c);
            if (!time_str.empty() && time_str.back() == '\n') {
                time_str.pop_back();
            }
            text_content["text"] = "Current server time is: " + time_str;
        } else {
            throw std::invalid_argument("Unknown tool: " + tool_name);
        }

        content.append(text_content);
        result["content"] = content;
        return result;
    }

private:
    bool validateAddNumbersArguments(const Json::Value& arguments) {
        return arguments.isMember("a") && arguments["a"].isNumeric() &&
               arguments.isMember("b") && arguments["b"].isNumeric();
    }

    Json::Value getAvailableTools() {
        Json::Value tools(Json::arrayValue);

        // 도구 1: addNumbersTool
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

        // 도구 2: getCurrentTimeTool
        Json::Value time_tool;
        time_tool["name"] = "getCurrentTimeTool";
        time_tool["description"] = "Returns the current server time.";
        time_tool["inputSchema"]["type"] = "object";
        time_tool["inputSchema"]["properties"] = Json::objectValue;
        tools.append(time_tool);

        return tools;
    }
};

// 요청과 응답을 위한 추상 인터페이스 정의
class IRequest {
public:
    virtual ~IRequest() = default;
    virtual bool hasParam(const std::string& name) const = 0;
    virtual std::string getParamValue(const std::string& name) const = 0;
    virtual std::string getBody() const = 0;
    virtual std::string getRemoteAddr() const = 0;
};

class IResponse {
public:
    virtual ~IResponse() = default;
    virtual void setStatus(int status_code) = 0;
    virtual void setContent(const std::string& content, const std::string& content_type) = 0;
};

// cpp-httplib 어댑터 구현
class HttplibRequestAdapter : public IRequest {
private:
    const httplib::Request& req;
public:
    explicit HttplibRequestAdapter(const httplib::Request& request) : req(request) {}
    
    bool hasParam(const std::string& name) const override {
        return req.has_param(name);
    }
    
    std::string getParamValue(const std::string& name) const override {
        return req.get_param_value(name);
    }
    
    std::string getBody() const override {
        return req.body;
    }
    
    std::string getRemoteAddr() const override {
        return req.remote_addr;
    }
};

class HttplibResponseAdapter : public IResponse {
private:
    httplib::Response& res;
public:
    explicit HttplibResponseAdapter(httplib::Response& response) : res(response) {}
    
    void setStatus(int status_code) override {
        res.status = status_code;
    }
    
    void setContent(const std::string& content, const std::string& content_type) override {
        res.set_content(content, content_type);
    }
};

// MCP 핸들러 클래스
class MCPHandler {
public:
    MCPHandler(SessionManager& sessionManager) : session_manager(sessionManager), tool_handler() {}

    void handleRequest(const IRequest& req, IResponse& res) {
        std::string sessionId;
        if (req.hasParam("sessionId")) {
            sessionId = req.getParamValue("sessionId");
        } else {
            LOG_ERROR("Missing sessionId parameter in /message request from " << req.getRemoteAddr());
            sendErrorResponse(res, 400, "Missing sessionId parameter");
            return;
        }

        LOG_INFO("Received /message POST for sessionId: " << sessionId << " from " << req.getRemoteAddr());

        auto session = session_manager.getSession(sessionId);
        if (!session) {
            LOG_ERROR("No active SSE session found for sessionId: " << sessionId);
            sendErrorResponse(res, 404, "No active SSE session found for that sessionId");
            return;
        }
        session->updateLastActivity();

        Json::Value rpc;
        if (!parseAndValidateJsonRpc(req.getBody(), rpc)) {
            sendErrorResponse(res, 400, "Parse error", -32700);
            return;
        }

        std::string method_name = rpc["method"].asString();
        Json::Value rpc_id = rpc.isMember("id") ? rpc["id"] : Json::nullValue;

        LOG_INFO("Processing '" << method_name << "' request for session: " << sessionId);

        // HTTP 응답 즉시 전송
        sendAckResponse(res, method_name, rpc_id);

        // 비동기적으로 SSE 응답 처리
        try {
            processMethodAndSendSseResponse(method_name, rpc, rpc_id, session);
        } catch (const std::exception& e) {
            LOG_ERROR("Exception while processing method " << method_name << ": " << e.what());
            sendSseErrorResponse(session, rpc_id, "Internal server error", -32000);
        }
    }

private:
    bool parseAndValidateJsonRpc(const std::string& body, Json::Value& rpc) {
        if (!JsonUtils::parseJson(body, rpc)) {
            return false;
        }
        
        if (!rpc.isObject() || !rpc.isMember("jsonrpc") || rpc["jsonrpc"].asString() != "2.0" || 
            !rpc.isMember("method") || !rpc["method"].isString()) {
            return false;
        }
        
        return true;
    }

    void sendErrorResponse(IResponse& res, int status, const std::string& message, int code = 0) {
        Json::Value error;
        error["error"] = message;
        if (code != 0) {
            error["code"] = code;
            error["jsonrpc"] = "2.0";
            error["id"] = Json::nullValue;
            error["error"] = Json::Value();
            error["error"]["code"] = code;
            error["error"]["message"] = message;
        }
        res.setStatus(status);
        res.setContent(JsonUtils::jsonToString(error), "application/json");
    }

    void sendAckResponse(IResponse& res, const std::string& method_name, const Json::Value& rpc_id) {
        Json::Value ack;
        ack["jsonrpc"] = "2.0";
        ack["id"] = rpc_id;
        ack["result"]["ack"] = "Received " + method_name;
        res.setStatus(200);
        res.setContent(JsonUtils::jsonToString(ack), "application/json");
        LOG_DEBUG("Sent HTTP ACK for '" << method_name << "'");
    }

    void sendSseErrorResponse(std::shared_ptr<Session> session, const Json::Value& rpc_id, 
                             const std::string& message, int code) {
        Json::Value error_response;
        error_response["jsonrpc"] = "2.0";
        error_response["id"] = rpc_id;
        error_response["error"]["code"] = code;
        error_response["error"]["message"] = message;
        
        session->addMessage("message", JsonUtils::jsonToString(error_response));
    }

    void processMethodAndSendSseResponse(const std::string& method_name, const Json::Value& rpc, 
                                        const Json::Value& rpc_id, std::shared_ptr<Session> session) {
        Json::Value response;
        response["jsonrpc"] = "2.0";
        response["id"] = rpc_id;

        if (method_name == "initialize") {
            handleInitialize(session, rpc_id, response);
        } else if (method_name == "tools/list") {
            handleToolsList(session, rpc_id, response);
        } else if (method_name == "tools/call") {
            handleToolsCall(session, rpc, rpc_id);
            return; // handleToolsCall sends its own response
        } else if (method_name == "notifications/initialized") {
            LOG_INFO("Received 'notifications/initialized'. No action needed.");
            return; // 알림에는 응답 필요 없음
        } else {
            sendSseErrorResponse(session, rpc_id, "Method not found: '" + method_name + "'", -32601);
            return;
        }

        session->addMessage("message", JsonUtils::jsonToString(response));
        LOG_INFO("Queued '" << method_name << "' response for SSE session: " << session->id);
    }

    void handleInitialize(std::shared_ptr<Session> session, const Json::Value& rpc_id, Json::Value& response) {
        session->initialized = true;

        Json::Value& result = response["result"];
        result["protocolVersion"] = "2024-11-05";

        Json::Value& capabilities = result["capabilities"];
        capabilities["tools"]["listChanged"] = true;
        capabilities["resources"]["subscribe"] = true;
        capabilities["resources"]["listChanged"] = true;
        capabilities["prompts"]["listChanged"] = true;
        capabilities["logging"] = Json::objectValue;

        Json::Value& server_info = result["serverInfo"];
        server_info["name"] = "cpp-httplib-mcp-server";
        server_info["version"] = "1.1.0";
    }

    void handleToolsList(std::shared_ptr<Session> session, const Json::Value& rpc_id, Json::Value& response) {
        response["result"] = tool_handler.handleToolsList();
    }

    void handleToolsCall(std::shared_ptr<Session> session, const Json::Value& rpc, const Json::Value& rpc_id) {
        Json::Value call_response;
        call_response["jsonrpc"] = "2.0";
        call_response["id"] = rpc_id;

        if (!rpc.isMember("params") || !rpc["params"].isObject() ||
            !rpc["params"].isMember("name") || !rpc["params"]["name"].isString() ||
            !rpc["params"].isMember("arguments") || !rpc["params"]["arguments"].isObject()) {
                
            sendSseErrorResponse(session, rpc_id, "Invalid parameters for tools/call", -32602);
            return;
        }

        std::string tool_name = rpc["params"]["name"].asString();
        Json::Value arguments = rpc["params"]["arguments"];
        
        try {
            Json::Value result = tool_handler.handleToolCall(tool_name, arguments);
            call_response["result"] = result;
            LOG_INFO("Processed tool call for '" << tool_name << "' successfully");
        } catch (const std::exception& e) {
            LOG_ERROR("Error processing tool '" << tool_name << "': " << e.what());
            call_response["error"]["code"] = -32602;
            call_response["error"]["message"] = std::string("Tool error: ") + e.what();
        }

        session->addMessage("message", JsonUtils::jsonToString(call_response));
    }

    SessionManager& session_manager;
    ToolHandler tool_handler;
};

// MCP 서버 클래스
class MCPServer {
public:
    explicit MCPServer(int port = ServerConfig::DEFAULT_PORT) : 
        port(port), 
        session_manager(), 
        mcp_handler(session_manager) {
    }

    void start() {
        // CORS 헤더 설정
        svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
            res.set_header("Access-Control-Allow-Origin", "*");
            res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");

            if (req.method == "OPTIONS") {
                res.status = 204;
                return httplib::Server::HandlerResponse::Handled;
            }
            return httplib::Server::HandlerResponse::Unhandled;
        });

        // SSE 엔드포인트 설정
        setupSseEndpoint();

        // 메시지 엔드포인트 설정
        setupMessageEndpoint();

        // 세션 정리 스레드 시작
        session_manager.startCleanupThread();

        // 서버 시작 로그
        LOG_INFO("[MCP] C++ cpp-httplib server starting on port " << port);
        LOG_INFO("SSE endpoint: GET /sse");
        LOG_INFO("Message endpoint: POST /message?sessionId=...");
        LOG_INFO("Server listening on http://localhost:" << port);

        // 서버 시작 (블로킹 호출)
        svr.listen("0.0.0.0", port);
    }

    void stop() {
        LOG_INFO("Server shutting down...");
        session_manager.stopAllSessions();
        session_manager.stopCleanupThread();
        LOG_INFO("Server stopped.");
    }

private:
    void setupSseEndpoint() {
        svr.Get("/sse", [this](const httplib::Request& req, httplib::Response& res) {
            LOG_INFO("SSE Connection request received from " << req.remote_addr);
            
            auto session = session_manager.createSession();
            LOG_INFO("Created sessionId: " << session->id << " for " << req.remote_addr);
            
            // SSE 응답 설정
            res.set_header("Content-Type", "text/event-stream");
            res.set_header("Cache-Control", "no-cache");
            res.set_header("Connection", "keep-alive");
            res.status = 200;
            
            // 청크 콘텐츠 제공자 설정
            res.set_chunked_content_provider(
                "text/event-stream",
                [this, session](size_t offset, httplib::DataSink& sink) {
                    return handleSseStream(session, offset, sink);
                },
                [this, session](bool success) {
                    handleSseConnectionClose(session, success);
                }
            );
        });
    }
    
    void setupMessageEndpoint() {
        svr.Post("/message", [this](const httplib::Request& req, httplib::Response& res) {
            HttplibRequestAdapter req_adapter(req);
            HttplibResponseAdapter res_adapter(res);
            mcp_handler.handleRequest(req_adapter, res_adapter);
        });
    }

    bool handleSseStream(std::shared_ptr<Session> session, size_t offset, httplib::DataSink& sink) {
        // 첫 연결 시 endpoint 이벤트 전송
        if (offset == 0) {
            LOG_DEBUG("Sending endpoint event for session: " << session->id);
            std::string endpointUrl = "/message?sessionId=" + session->id;
            std::string initial_message = SseUtils::formatSSEMessage("endpoint", endpointUrl);
            if (!sink.write(initial_message.c_str(), initial_message.length())) {
                LOG_ERROR("Failed to send initial endpoint message");
                session->active = false;
                return false;
            }
            LOG_DEBUG("Endpoint event sent successfully.");
        }

        while (session->active) {
            std::unique_lock<std::mutex> lock(*session->queue_mutex);
            if (session->message_queue->empty() && session->active) {
                auto wait_status = session->queue_cv->wait_for(
                    lock, 
                    std::chrono::seconds(ServerConfig::SSE_HEARTBEAT_INTERVAL_SECONDS)
                );
                
                if (wait_status == std::cv_status::timeout) {
                    lock.unlock();
                    if (!sendHeartbeat(session, sink)) {
                        return false;
                    }
                    continue;
                }
            }

            if (!session->active) {
                lock.unlock();
                break;
            }

            if (!session->message_queue->empty()) {
                SseMessage msg = session->message_queue->front();
                session->message_queue->pop();
                lock.unlock();

                if (!sendSseMessage(session, msg, sink)) {
                    return false;
                }
            } else {
                lock.unlock();
            }
        }

        LOG_INFO("SSE stream ending for session: " << session->id);
        sink.done();
        return false;
    }

    bool sendHeartbeat(std::shared_ptr<Session> session, httplib::DataSink& sink) {
        std::string heartbeat_data = std::to_string(SseUtils::getCurrentTimeMillis());
        std::string heartbeat_message = SseUtils::formatSSEMessage("heartbeat", heartbeat_data);
        LOG_DEBUG("Sending heartbeat for session: " << session->id);
        
        if (!sink.write(heartbeat_message.c_str(), heartbeat_message.length())) {
            LOG_ERROR("Failed to send heartbeat. Closing connection.");
            session->active = false;
            return false;
        }
        
        session->updateLastActivity();
        return true;
    }

    bool sendSseMessage(std::shared_ptr<Session> session, const SseMessage& msg, httplib::DataSink& sink) {
        std::string sse_formatted_msg = SseUtils::formatSSEMessage(msg.event, msg.data);
        LOG_DEBUG("Sending message event '" << msg.event << "' for session: " << session->id);
        
        if (!sink.write(sse_formatted_msg.c_str(), sse_formatted_msg.length())) {
            LOG_ERROR("Failed to send message. Closing connection.");
            session->active = false;
            return false;
        }
        
        session->updateLastActivity();
        return true;
    }

    void handleSseConnectionClose(std::shared_ptr<Session> session, bool success) {
        LOG_INFO("SSE connection closed for session: " << session->id 
                 << (success ? " successfully." : " with error."));
        session->active = false;
        session->queue_cv->notify_all();
    }

    int port;
    httplib::Server svr;
    SessionManager session_manager;
    MCPHandler mcp_handler;
};

int main(int argc, char* argv[]) {
    int port = ServerConfig::DEFAULT_PORT;

    // 명령줄 인자에서 포트 번호 파싱
    if (argc > 1) {
        try {
            port = std::stoi(argv[1]);
            if (port <= 0 || port > 65535) {
                LOG_ERROR("Invalid port number. Using default port: " << ServerConfig::DEFAULT_PORT);
                port = ServerConfig::DEFAULT_PORT;
            } else {
                LOG_INFO("Using port: " << port);
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Invalid port number format. Using default port: " << ServerConfig::DEFAULT_PORT);
            port = ServerConfig::DEFAULT_PORT;
        }
    } else {
        LOG_INFO("No port specified. Using default port: " << ServerConfig::DEFAULT_PORT);
    }

    MCPServer server(port);   
    
    try {
        server.start();
    } catch (const std::exception& e) {
        LOG_ERROR("Exception occurred: " << e.what());;
        return 1;
    }
    
    server.stop();
    return 0;
}