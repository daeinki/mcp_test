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
#include <uuid/uuid.h> // Ubuntu/Debian: sudo apt-get install uuid-dev
#include <atomic>
#include <queue>
#include <condition_variable>
#include <memory> // For std::shared_ptr

//#define CPPHTTPLIB_OPENSSL_SUPPORT // HTTPS 지원이 필요하다면 주석 해제 (sudo apt-get install libssl-dev)
#include <json/json.h> // jsoncpp 헤더 (sudo apt-get install libjsoncpp-dev)
#include "httplib.h" // cpp-httplib 헤더 (https://github.com/yhirose/cpp-httplib)

// 디버그 로그 매크로
#define LOG_ERROR(msg) std::cerr << "\033[1;31m[ERROR] " << msg << "\033[0m" << std::endl
#define LOG_INFO(msg) std::cout << "\033[1;32m[INFO] " << msg << "\033[0m" << std::endl
#define LOG_DEBUG(msg) std::cout << "\033[1;34m[DEBUG] " << msg << "\033[0m" << std::endl

// 포트 설정
const int PORT = 8080;
const int SSE_HEARTBEAT_INTERVAL_SECONDS = 15;
const int SESSION_TIMEOUT_MINUTES = 30;

// SSE 메시지 큐를 위한 구조체
struct SseMessage {
	std::string event;
	std::string data;
};

// 세션 정보 구조체 (cpp-httplib 용으로 수정)
struct SessionInfo {
	std::string id;
	std::atomic<bool> active; // SSE 루프 제어
	std::shared_ptr<std::queue<SseMessage>> message_queue;
	std::shared_ptr<std::mutex> queue_mutex;
	std::shared_ptr<std::condition_variable> queue_cv;
	std::chrono::system_clock::time_point lastActivity;
	bool initialized; // MCP initialize 메소드 수신 여부

	SessionInfo(std::string session_id) :
		id(session_id),
		active(true),
		message_queue(std::make_shared<std::queue<SseMessage>>()),
		queue_mutex(std::make_shared<std::mutex>()),
		queue_cv(std::make_shared<std::condition_variable>()),
		lastActivity(std::chrono::system_clock::now()),
		initialized(false) {}

	// 세션에 메시지 추가 (스레드 안전)
	void addMessage(const std::string& event, const std::string& data) {
		{
			std::lock_guard<std::mutex> lock(*queue_mutex);
			message_queue->push({event, data});
		}
		queue_cv->notify_one(); // SSE 루프에 신호 보내기
	}

	// 세션 종료 신호 보내기
	void stop() {
		active = false;
		queue_cv->notify_one(); // 대기 중인 SSE 루프 즉시 깨우기
	}

	// 마지막 활동 시간 업데이트
	void updateLastActivity() {
		lastActivity = std::chrono::system_clock::now();
	}
};

// 전역 세션 관리
std::map<std::string, std::shared_ptr<SessionInfo>> sessions;
std::mutex sessions_mutex;
std::atomic<bool> server_running(true); // 서버 종료 플래그

// UUID 생성 함수
std::string generateUUID() {
	uuid_t uuid;
	char uuid_str[37];
	uuid_generate(uuid);
	uuid_unparse_lower(uuid, uuid_str);
	return std::string(uuid_str);
}

// 현재 시간을 밀리초로 반환
long long getCurrentTimeMillis() {
	return std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::system_clock::now().time_since_epoch()
	).count();
}

// JSON을 문자열로 변환
std::string jsonToString(const Json::Value& json) {
	Json::StreamWriterBuilder builder;
	builder["indentation"] = ""; // 공백 없이
	return Json::writeString(builder, json);
}

// 세션 정리 함수 (비활성 세션 제거)
void cleanupInactiveSessions() {
	while (server_running) {
		std::this_thread::sleep_for(std::chrono::minutes(5)); // 5분마다 체크
		auto now = std::chrono::system_clock::now();
		int cleaned_count = 0;

		std::vector<std::string> sessions_to_remove;
		{
			std::lock_guard<std::mutex> lock(sessions_mutex);
			for (auto const& [id, session_ptr] : sessions) {
				auto diff = std::chrono::duration_cast<std::chrono::minutes>(now - session_ptr->lastActivity).count();
				if (diff > SESSION_TIMEOUT_MINUTES || !session_ptr->active) { // 비활성 또는 비활성화된 세션
					sessions_to_remove.push_back(id);
				}
			}
		} // Lock 해제

		if (!sessions_to_remove.empty()) {
			std::lock_guard<std::mutex> lock(sessions_mutex);
			for (const auto& id : sessions_to_remove) {
				auto it = sessions.find(id);
				if (it != sessions.end()) {
					LOG_INFO("Removing inactive/stopped session: " << id);
					it->second->stop(); // SSE 루프 확실히 종료
					sessions.erase(it);
					cleaned_count++;
				}
			}
		}
		if (cleaned_count > 0) {
			LOG_INFO("Cleaned up " << cleaned_count << " inactive sessions.");
		}
	}
	LOG_INFO("Session cleanup thread finished.");
}

// SSE 메시지 형식화
std::string formatSSEMessage(const std::string& event, const std::string& data) {
	std::ostringstream oss;
	oss << "event: " << event << "\n";
	// 데이터에 개행 문자가 포함된 경우 각 줄 앞에 "data: "를 붙여야 함
	std::string line;
	std::istringstream data_stream(data);
	while (std::getline(data_stream, line)) {
		oss << "data: " << line << "\n";
	}
	oss << "\n"; // 메시지 종료
	return oss.str();
}

int main() {
	// cpp-httplib 서버 인스턴스 생성
	httplib::Server svr;

	// CORS 헤더 설정을 위한 후크 (모든 응답에 적용)
    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization"); // 필요에 따라 헤더 추가

        // OPTIONS 요청 사전 처리 (Preflight)
        if (req.method == "OPTIONS") {
            res.status = 204; // No Content
            return httplib::Server::HandlerResponse::Handled; // 요청 처리 완료
        }
        return httplib::Server::HandlerResponse::Unhandled; // 다음 핸들러로 계속 진행
    });


	// === SSE 엔드포인트 (/sse) ===
	svr.Get("/sse", [&](const httplib::Request& req, httplib::Response& res) {
		LOG_INFO("SSE Connection request received from " << req.remote_addr);

		// 세션 ID 생성 및 세션 정보 객체 생성
		std::string sessionId = generateUUID();
		auto session_ptr = std::make_shared<SessionInfo>(sessionId);

		// 전역 세션 맵에 등록
		{
			std::lock_guard<std::mutex> lock(sessions_mutex);
			sessions[sessionId] = session_ptr;
		}
		LOG_INFO("Created sessionId: " << sessionId << " for " << req.remote_addr);

		// SSE 응답 설정 (Chunked Transfer Encoding 사용)
		res.set_header("Content-Type", "text/event-stream");
		res.set_header("Cache-Control", "no-cache");
		res.set_header("Connection", "keep-alive");
		// CORS 헤더는 pre_routing_handler에서 이미 설정됨

        res.status = 200;

		// 청크 컨텐츠 제공자 설정 (SSE 메시지 스트리밍)
		res.set_chunked_content_provider(
			"text/event-stream",  // Content type should be the first parameter
			// on_content 제공자 람다
			[session_ptr](size_t offset, httplib::DataSink& sink) {
				// 첫 연결 시 endpoint 이벤트 전송
				if (offset == 0) {
                    LOG_DEBUG("Sending endpoint event for session: " << session_ptr->id);
					std::string endpointUrl = "/message?sessionId=" + session_ptr->id;
					std::string initial_message = formatSSEMessage("endpoint", endpointUrl);
					if (!sink.write(initial_message.c_str(), initial_message.length())) {
						LOG_ERROR("Failed to send initial endpoint message for session: " << session_ptr->id);
                        session_ptr->active = false; // sink 실패 시 active 플래그 내림
						return false; // 연결 종료 신호
					}
                    LOG_DEBUG("Endpoint event sent successfully.");
				}

				while (session_ptr->active) {
					std::unique_lock<std::mutex> lock(*session_ptr->queue_mutex);
					// 메시지 큐가 비어있고 세션이 활성 상태이면 대기 (하트비트 간격만큼 타임아웃)
					if (session_ptr->message_queue->empty() && session_ptr->active) {
						if (session_ptr->queue_cv->wait_for(lock, std::chrono::seconds(SSE_HEARTBEAT_INTERVAL_SECONDS)) == std::cv_status::timeout) {
							// 타임아웃 발생 -> 하트비트 전송
							lock.unlock(); // 뮤텍스 해제 후 전송
							std::string heartbeat_data = std::to_string(getCurrentTimeMillis());
							std::string heartbeat_message = formatSSEMessage("heartbeat", heartbeat_data);
							LOG_DEBUG("Sending heartbeat for session: " << session_ptr->id);
							if (!sink.write(heartbeat_message.c_str(), heartbeat_message.length())) {
								LOG_ERROR("Failed to send heartbeat for session: " << session_ptr->id << ". Closing connection.");
                                session_ptr->active = false; // sink 실패 시 active 플래그 내림
								return false; // 연결 종료
							}
							session_ptr->updateLastActivity(); // 하트비트 성공 시 활동 시간 갱신
							continue; // 다시 큐 확인 루프로
						}
					}

                    // 루프 재진입 시 세션 비활성 상태 체크
                    if (!session_ptr->active) {
                         LOG_INFO("SSE loop detected inactive session, exiting: " << session_ptr->id);
                         break;
                    }


					// 큐에 메시지가 있거나 세션이 비활성화됨
					if (!session_ptr->message_queue->empty()) {
						SseMessage msg = session_ptr->message_queue->front();
						session_ptr->message_queue->pop();
						lock.unlock(); // 뮤텍스 해제 후 전송

						std::string sse_formatted_msg = formatSSEMessage(msg.event, msg.data);
                        LOG_DEBUG("Sending message event '" << msg.event << "' for session: " << session_ptr->id);
						if (!sink.write(sse_formatted_msg.c_str(), sse_formatted_msg.length())) {
							LOG_ERROR("Failed to send message event '" << msg.event << "' for session: " << session_ptr->id << ". Closing connection.");
                            session_ptr->active = false; // sink 실패 시 active 플래그 내림
							return false; // 연결 종료
						}
						session_ptr->updateLastActivity(); // 메시지 성공 시 활동 시간 갱신
					} else {
                        // 큐는 비었지만 active 플래그가 false가 되어 루프 종료 조건 충족
                         lock.unlock();
                         break; // while 루프 탈출
                    }
				} // end while(session_ptr->active)

				// 루프 종료 시 (active가 false가 되었거나 sink.write 실패)
				LOG_INFO("SSE stream ending for session: " << session_ptr->id);
                sink.done(); // 스트림 종료 알림
				return false; // 연결 종료
			},
			// on_connection_close 콜백 (선택 사항)
			[session_ptr, sessionId](bool success) {
                 LOG_INFO("SSE connection closed for session: " << sessionId << (success ? " successfully." : " with error."));
				 session_ptr->active = false; // SSE 루프 확실히 종료
                 session_ptr->queue_cv->notify_all(); // 대기 중인 스레드 깨우기 (혹시 있다면)

				// 전역 세션 맵에서 즉시 제거 (선택적, cleanup 스레드가 처리할 수도 있음)
                 // std::lock_guard<std::mutex> lock(sessions_mutex);
                 // sessions.erase(sessionId);
			}
		);
	});

	// === 메시지 엔드포인트 (/message) ===
	svr.Post("/message", [&](const httplib::Request& req, httplib::Response& res) {
		// sessionId 추출
		std::string sessionId;
		if (req.has_param("sessionId")) {
			sessionId = req.get_param_value("sessionId");
		} else {
			LOG_ERROR("Missing sessionId parameter in /message request from " << req.remote_addr);
			res.status = 400;
			res.set_content("{\"error\":\"Missing sessionId parameter\"}", "application/json");
			return;
		}

		LOG_INFO("Received /message POST for sessionId: " << sessionId << " from " << req.remote_addr);

		// 세션 찾기
		std::shared_ptr<SessionInfo> session_ptr;
		{
			std::lock_guard<std::mutex> lock(sessions_mutex);
			auto it = sessions.find(sessionId);
			if (it != sessions.end() && it->second->active) {
				session_ptr = it->second;
                session_ptr->updateLastActivity(); // 메시지 수신 시 활동 시간 갱신
			}
		}

		if (!session_ptr) {
			LOG_ERROR("No active SSE session found for sessionId: " << sessionId);
			res.status = 404; // Not Found
			res.set_content("{\"error\":\"No active SSE session found for that sessionId\"}", "application/json");
			return;
		}

		// JSON-RPC 파싱
		Json::Value rpc;
		Json::CharReaderBuilder reader_builder;
		std::unique_ptr<Json::CharReader> const reader(reader_builder.newCharReader());
		std::string errors;

		if (!reader->parse(req.body.c_str(), req.body.c_str() + req.body.length(), &rpc, &errors)) {
			LOG_ERROR("Failed to parse JSON-RPC body for session " << sessionId << ": " << errors);
			LOG_ERROR("Raw body: " << req.body);
			res.status = 400; // Bad Request
			res.set_content("{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}", "application/json");
			return;
		}

		// JSON-RPC 형식 검증
		if (!rpc.isObject() || !rpc.isMember("jsonrpc") || rpc["jsonrpc"].asString() != "2.0" || !rpc.isMember("method") || !rpc["method"].isString()) {
			LOG_ERROR("Invalid JSON-RPC format for session " << sessionId);
			res.status = 400; // Bad Request
            Json::Value error_response;
            error_response["jsonrpc"] = "2.0";
            error_response["id"] = rpc.isMember("id") ? rpc["id"] : Json::nullValue;
            error_response["error"]["code"] = -32600;
            error_response["error"]["message"] = "Invalid Request";
			res.set_content(jsonToString(error_response), "application/json");
			return;
		}

		std::string method_name = rpc["method"].asString();
		Json::Value rpc_id = rpc.isMember("id") ? rpc["id"] : Json::nullValue; // ID 추출

		LOG_INFO("Processing '" << method_name << "' request (ID: " << (rpc_id.isNull() ? "null" : rpc_id.toStyledString()) <<") for session: " << sessionId);

		// --- 즉시 HTTP ACK 응답 전송 ---
		Json::Value ack_response;
		ack_response["jsonrpc"] = "2.0";
		ack_response["id"] = rpc_id;
		ack_response["result"]["ack"] = "Received " + method_name;
		res.status = 200; // OK
		res.set_content(jsonToString(ack_response), "application/json");
		LOG_DEBUG("Sent HTTP ACK for '" << method_name << "' for session: " << sessionId);
		// --- HTTP 응답 전송 완료 ---


		// --- 실제 처리 및 SSE 응답 준비 (비동기적 전송) ---
        // 중요: HTTP 응답은 위에서 이미 전송되었으므로, 여기서부턴 SSE 채널로 응답/결과를 보냄

		try {
			if (method_name == "initialize") {
				// 세션 초기화 상태 업데이트
				session_ptr->initialized = true;

				// capabilities 응답 생성
				Json::Value init_response;
				init_response["jsonrpc"] = "2.0";
				init_response["id"] = rpc_id;

				Json::Value& result = init_response["result"];
				result["protocolVersion"] = "2024-11-05"; // 예시 버전

				Json::Value& capabilities = result["capabilities"];
				capabilities["tools"]["listChanged"] = true;
				capabilities["resources"]["subscribe"] = true;
				capabilities["resources"]["listChanged"] = true;
				capabilities["prompts"]["listChanged"] = true;
				capabilities["logging"] = Json::objectValue; // 빈 객체

				Json::Value& server_info = result["serverInfo"];
				server_info["name"] = "cpp-httplib-mcp-server";
				server_info["version"] = "1.1.0";

				// SSE 큐에 추가
				session_ptr->addMessage("message", jsonToString(init_response));
				LOG_INFO("Queued 'initialize' capabilities response for SSE session: " << sessionId);

			} else if (method_name == "tools/list") {
				// 도구 목록 응답 생성
				Json::Value tools_response;
				tools_response["jsonrpc"] = "2.0";
				tools_response["id"] = rpc_id;

				Json::Value& result = tools_response["result"];
				Json::Value tools(Json::arrayValue);

				// 예시 도구: addNumbersTool
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

                // 예시 도구 2: getCurrentTimeTool
                Json::Value time_tool;
                time_tool["name"] = "getCurrentTimeTool";
                time_tool["description"] = "Returns the current server time.";
                time_tool["inputSchema"]["type"] = "object"; // 입력 없음
                time_tool["inputSchema"]["properties"] = Json::objectValue;
                tools.append(time_tool);


				result["tools"] = tools;
				result["count"] = static_cast<int>(tools.size());

				// SSE 큐에 추가
				session_ptr->addMessage("message", jsonToString(tools_response));
				LOG_INFO("Queued 'tools/list' response for SSE session: " << sessionId);

			} else if (method_name == "tools/call") {
                if (!rpc.isMember("params") || !rpc["params"].isObject() ||
                    !rpc["params"].isMember("name") || !rpc["params"]["name"].isString() ||
                    !rpc["params"].isMember("arguments") || !rpc["params"]["arguments"].isObject()) {
                     LOG_ERROR("Invalid 'tools/call' params for session: " << sessionId);
                     // 오류 응답 SSE로 전송
                    Json::Value error_response;
                    error_response["jsonrpc"] = "2.0";
                    error_response["id"] = rpc_id;
                    error_response["error"]["code"] = -32602; // Invalid params
                    error_response["error"]["message"] = "Invalid parameters for tools/call";
                    session_ptr->addMessage("message", jsonToString(error_response));
                    return; // 함수 종료
                }

				std::string tool_name = rpc["params"]["name"].asString();
                Json::Value arguments = rpc["params"]["arguments"]; // 인자 객체 복사
				LOG_INFO("Processing 'tools/call' for tool '" << tool_name << "' for session: " << sessionId);


                Json::Value call_response; // 결과 또는 오류 담을 JSON
                call_response["jsonrpc"] = "2.0";
                call_response["id"] = rpc_id;

				if (tool_name == "addNumbersTool") {
                    if (!arguments.isMember("a") || !arguments["a"].isNumeric() ||
                        !arguments.isMember("b") || !arguments["b"].isNumeric()) {
                        LOG_ERROR("Invalid arguments for addNumbersTool in session: " << sessionId);
                        call_response["error"]["code"] = -32602;
                        call_response["error"]["message"] = "Invalid arguments for addNumbersTool: 'a' and 'b' (numbers) are required.";
                    } else {
                        double a = arguments["a"].asDouble(); // double로 처리
                        double b = arguments["b"].asDouble();
                        double sum = a + b;

                        // 결과 응답 생성
                        Json::Value& result = call_response["result"];
                        Json::Value content(Json::arrayValue);
                        Json::Value text_content;
                        text_content["type"] = "text";
                         // 결과 포맷팅 (소수점 포함 가능하도록)
                        std::ostringstream sum_oss;
                        sum_oss << "Sum of " << a << " + " << b << " = " << sum;
                        text_content["text"] = sum_oss.str();
                        content.append(text_content);
                        result["content"] = content;
                        LOG_INFO("Calculated sum " << sum << " for addNumbersTool call for session: " << sessionId);
                    }

				} else if (tool_name == "getCurrentTimeTool") {
                    // getCurrentTimeTool 처리
                    std::time_t now_c = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                    std::string time_str = std::ctime(&now_c);
                    time_str.pop_back(); // 마지막 개행 문자 제거

                    Json::Value& result = call_response["result"];
                    Json::Value content(Json::arrayValue);
                    Json::Value text_content;
                    text_content["type"] = "text";
                    text_content["text"] = "Current server time is: " + time_str;
                    content.append(text_content);
                    result["content"] = content;
                    LOG_INFO("Provided current time for getCurrentTimeTool call for session: " << sessionId);

                } else {
					// 알 수 없는 도구 오류
                    LOG_ERROR("Unknown tool requested: '" << tool_name << "' for session: " << sessionId);
					call_response["error"]["code"] = -32601; // Method not found (여기선 Tool not found 의미로 사용)
					call_response["error"]["message"] = "Tool not found: '" + tool_name + "'";
				}

                // 결과 또는 오류를 SSE 큐에 추가
                session_ptr->addMessage("message", jsonToString(call_response));
                LOG_INFO("Queued 'tools/call' " << (call_response.isMember("result") ? "result" : "error") << " for SSE session: " << sessionId);

			} else if (method_name == "notifications/initialized") {
				// 클라이언트가 초기화 완료 알림. 보통 서버는 특별히 할 일 없음.
				LOG_INFO("Received 'notifications/initialized' from session: " << sessionId << ". No action needed.");
                // 이 알림에 대한 응답은 JSON-RPC 스펙상 필요 없음 (HTTP ACK만 보냄)
			}
			else {
				// 알 수 없는 메소드 오류
                LOG_ERROR("Unknown method '" << method_name << "' requested for session: " << sessionId);
				Json::Value error_response;
				error_response["jsonrpc"] = "2.0";
				error_response["id"] = rpc_id;
				error_response["error"]["code"] = -32601; // Method not found
				error_response["error"]["message"] = "Method not found: '" + method_name + "'";

                // 오류 응답을 SSE 큐에 추가
				session_ptr->addMessage("message", jsonToString(error_response));
                LOG_INFO("Queued MethodNotFound error for SSE session: " << sessionId);
			}
		} catch (const std::exception& e) {
            LOG_ERROR("Exception occurred while processing '" << method_name << "' for session " << sessionId << ": " << e.what());
             // 일반적인 서버 오류 응답 SSE로 전송
            Json::Value error_response;
            error_response["jsonrpc"] = "2.0";
            error_response["id"] = rpc_id;
            error_response["error"]["code"] = -32000; // Server error
            error_response["error"]["message"] = "Internal server error processing request.";
            session_ptr->addMessage("message", jsonToString(error_response));
        }
	});

	// 서버 시작 전 로그
	LOG_INFO("[MCP] C++ cpp-httplib server starting on port " << PORT);
	LOG_INFO("SSE endpoint: GET /sse");
	LOG_INFO("Message endpoint: POST /message?sessionId=...");

	// 비활성 세션 정리 스레드 시작
	std::thread cleanup_thread(cleanupInactiveSessions);

	// 서버 리슨 시작 (블로킹 호출)
    LOG_INFO("Server listening on http://localhost:" << PORT);
	svr.listen("0.0.0.0", PORT); // 모든 인터페이스에서 리슨

	// 서버 종료 처리 (svr.listen()이 반환된 후)
	LOG_INFO("Server shutting down...");
	server_running = false; // 정리 스레드 종료 신호
    {
        // 모든 활성 세션에게 종료 신호 보내기
        std::lock_guard<std::mutex> lock(sessions_mutex);
        for (auto const& [id, session_ptr] : sessions) {
            session_ptr->stop();
        }
        sessions.clear(); // 세션 맵 비우기
    }
	if (cleanup_thread.joinable()) {
		cleanup_thread.join(); // 정리 스레드 완료 대기
	}

	LOG_INFO("Server stopped.");
	return 0;
}