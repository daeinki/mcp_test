// McpTransport.h
#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <map>
#include <curl/curl.h>
#include <json/json.h>

// 클라이언트 인터페이스 (주어진 인터페이스)
class ITransportClient {
public:
	virtual std::string send(const std::string &requestContext) = 0;
	virtual ~ITransportClient() = default;
};

// 서버 인터페이스 (주어진 인터페이스)
class ITransportServer {
public:
	virtual void run() = 0;
	virtual void stop() = 0;
	virtual ~ITransportServer() = default;
};

// 추가된 이벤트 리스너 인터페이스
class IMcpEventListener {
public:
	virtual void onEvent(const std::string &eventName, const std::string &eventData) = 0;
	virtual ~IMcpEventListener() = default;
};

// 추가된 요청 핸들러 인터페이스
class IMcpRequestHandler {
public:
	virtual std::string handleRequest(const std::string &requestContext) = 0;
	virtual ~IMcpRequestHandler() = default;
};

// SSE 클라이언트 구현
class SseClient {
public:
	SseClient(const std::string &url, IMcpEventListener *listener);
	~SseClient();

	void start();
	void stop();

private:
	static size_t writeCallback(char *ptr, size_t size, size_t nmemb, void *userdata);
	void processEventData(const std::string &data);

	std::string url_;
	IMcpEventListener *listener_;
	CURL *curl_;
	std::thread worker_;
	std::atomic<bool> running_;
	std::string buffer_;
};

// HTTP 클라이언트 구현
class HttpClient {
public:
	HttpClient();
	~HttpClient();
    
	std::string post(const std::string &url, const std::string &data);
    
private:
	static size_t writeCallback(char *ptr, size_t size, size_t nmemb, void *userdata);

	CURL *curl_;
	std::string response_;
};

// MCP 클라이언트 구현
class McpTransportClient : public ITransportClient {
public:
	McpTransportClient(const std::string &serverUrl);
	~McpTransportClient();

	std::string send(const std::string &requestContext) override;
	void subscribe(IMcpEventListener *listener);
    
private:
	std::string serverUrl_;
	HttpClient httpClient_;
	std::unique_ptr<SseClient> sseClient_;
};

// SSE 이벤트 관리자
class SseEventManager {
public:
	struct Client {
		int id;
		std::function<void(const std::string &)> sendEvent;
	};

	SseEventManager();
	~SseEventManager();

	int addClient(std::function<void(const std::string &)> sendEvent);
	void removeClient(int clientId);
	void broadcastEvent(const std::string &eventName, const std::string &eventData);

private:
	std::mutex mutex_;
	std::map<int, Client> clients_;
	int nextClientId_;
};

// MCP 서버 구현
class McpTransportServer : public ITransportServer {
public:
	McpTransportServer(int port, IMcpRequestHandler *handler);
	~McpTransportServer();

	void run() override;
	void stop() override;
	void broadcastEvent(const std::string &eventName, const std::string &eventData);

private:
	void workerThread();
	void handleConnection(int clientSocket);
	std::string handleHttpRequest(const std::string &request);

	int port_;
	IMcpRequestHandler *handler_;
	SseEventManager eventManager_;
	std::atomic<bool> running_;
	int serverSocket_;
	std::thread worker_;
};
