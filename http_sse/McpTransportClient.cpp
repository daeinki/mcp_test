// McpTransportClient.cpp
#include "McpTransport.h"
#include <sstream>
#include <iostream>

// SseClient 구현
SseClient::SseClient(const std::string &url, IMcpEventListener *listener)
	: url_(url), listener_(listener), running_(false) {
	curl_global_init(CURL_GLOBAL_ALL);
	curl_ = curl_easy_init();
}

SseClient::~SseClient() {
	stop();
	curl_easy_cleanup(curl_);
	curl_global_cleanup();
}

void SseClient::start() {
	if (!running_.exchange(true)) {
		worker_ = std::thread([this]() {
			if (curl_) {
				curl_easy_setopt(curl_, CURLOPT_URL, url_.c_str());
				curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, SseClient::writeCallback);
				curl_easy_setopt(curl_, CURLOPT_WRITEDATA, this);
				
				struct curl_slist *headers = nullptr;
				headers = curl_slist_append(headers, "Accept: text/event-stream");
				headers = curl_slist_append(headers, "Cache-Control: no-cache");
				headers = curl_slist_append(headers, "Connection: keep-alive");
				curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
				
				CURLcode res = curl_easy_perform(curl_);
				curl_slist_free_all(headers);
				
				if (res != CURLE_OK) {
					std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
				}
			}
		});
	}
}

void SseClient::stop() {
	if (running_.exchange(false)) {
		curl_easy_setopt(curl_, CURLOPT_TIMEOUT_MS, 100);
		if (worker_.joinable()) {
			worker_.join();
		}
	}
}

size_t SseClient::writeCallback(char *ptr, size_t size, size_t nmemb, void *userdata) {
	size_t realSize = size * nmemb;
	SseClient *self = static_cast<SseClient*>(userdata);

	if (self->running_) {
		self->buffer_.append(ptr, realSize);
		
		size_t pos;
		while ((pos = self->buffer_.find("\n\n")) != std::string::npos) {
			std::string event = self->buffer_.substr(0, pos);
			self->buffer_.erase(0, pos + 2);
			self->processEventData(event);
		}
	}

	return realSize;
}

void SseClient::processEventData(const std::string &data) {
	std::string eventName;
	std::string eventData;

	std::istringstream iss(data);
	std::string line;

	while (std::getline(iss, line)) {
		if (line.empty()) continue;
		
		size_t colonPos = line.find(':');
		if (colonPos != std::string::npos) {
			std::string field = line.substr(0, colonPos);
			std::string value = line.substr(colonPos + 1);
			
			// 선행 공백 제거
			if (!value.empty() && value[0] == ' ') {
				value.erase(0, 1);
			}
			
			if (field == "event") {
				eventName = value;
			} else if (field == "data") {
				eventData = value;
			}
		}
	}

	if (!eventName.empty() && !eventData.empty() && listener_) {
		listener_->onEvent(eventName, eventData);
	}
}

// HttpClient 구현
HttpClient::HttpClient() {
	curl_global_init(CURL_GLOBAL_ALL);
	curl_ = curl_easy_init();
}

HttpClient::~HttpClient() {
	curl_easy_cleanup(curl_);
	curl_global_cleanup();
}

std::string HttpClient::post(const std::string &url, const std::string &data) {
	response_.clear();

	if (curl_) {
		// 이전 설정을 초기화하여 깨끗한 상태에서 시작
		curl_easy_reset(curl_);

		struct curl_slist *headers = nullptr;
		headers = curl_slist_append(headers, "Content-Type: application/json");
		
		curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, data.c_str());
		curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, HttpClient::writeCallback);
		curl_easy_setopt(curl_, CURLOPT_WRITEDATA, this);
		
		// 타임아웃 설정 추가
		curl_easy_setopt(curl_, CURLOPT_CONNECTTIMEOUT, 10L); // 연결 타임아웃 10초
		curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 30L);        // 전체 작업 타임아웃 30초
		
		// 리다이렉트 처리 설정
		curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt(curl_, CURLOPT_MAXREDIRS, 3L);
		
		// SSL 인증서 검증 비활성화 (테스트 환경에서만 사용)
		curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl_, CURLOPT_SSL_VERIFYHOST, 0L);

		CURLcode res = curl_easy_perform(curl_);

		curl_slist_free_all(headers);

		if (res != CURLE_OK) {
			std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
			
			// 추가 오류 정보 로깅
			long http_code = 0;
			curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);
			std::cerr << "HTTP response code: " << http_code << std::endl;
		}
	}

	return response_;
}

size_t HttpClient::writeCallback(char *ptr, size_t size, size_t nmemb, void *userdata) {
	size_t realSize = size * nmemb;
	HttpClient *self = static_cast<HttpClient*>(userdata);
	self->response_.append(ptr, realSize);
	return realSize;
}

// McpTransportClient 구현
McpTransportClient::McpTransportClient(const std::string &serverUrl)
	: serverUrl_(serverUrl) {
}

McpTransportClient::~McpTransportClient() {
}

std::string McpTransportClient::send(const std::string &requestContext) {
	return httpClient_.post(serverUrl_ + "/api", requestContext);
}

void McpTransportClient::subscribe(IMcpEventListener *listener) {
	sseClient_ = std::make_unique<SseClient>(serverUrl_ + "/events", listener);
	sseClient_->start();
}
