// McpTransportServer.cpp
#include "McpTransport.h"
#include <sstream>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

// SseEventManager 구현
SseEventManager::SseEventManager() : nextClientId_(1)
{
}

SseEventManager::~SseEventManager()
{
}

int SseEventManager::addClient(std::function<void(const std::string &)> sendEvent)
{
	std::lock_guard<std::mutex> lock(mutex_);
	int clientId = nextClientId_++;
	clients_[clientId] = {clientId, sendEvent};
	return clientId;
}

void SseEventManager::removeClient(int clientId)
{
	std::lock_guard<std::mutex> lock(mutex_);
	clients_.erase(clientId);
}

void SseEventManager::broadcastEvent(const std::string &eventName, const std::string &eventData)
{
	std::lock_guard<std::mutex> lock(mutex_);

	// SSE 포맷으로 이벤트 구성
	std::stringstream ss;
	ss << "event: " << eventName << "\n";
	ss << "data: " << eventData << "\n\n";
	std::string eventMessage = ss.str();

	for (auto &pair : clients_)
	{
		try
		{
			pair.second.sendEvent(eventMessage);
		}
		catch (const std::exception &e)
		{
			std::cerr << "Error sending event to client " << pair.first << ": " << e.what() << std::endl;
		}
	}
}

// McpTransportServer 구현
McpTransportServer::McpTransportServer(int port, IMcpRequestHandler *handler)
	: port_(port), handler_(handler), running_(false), serverSocket_(-1)
{
}

McpTransportServer::~McpTransportServer()
{
	stop();
}

void McpTransportServer::run()
{
	if (!running_.exchange(true))
	{
		worker_ = std::thread(&McpTransportServer::workerThread, this);
	}
}

void McpTransportServer::stop()
{
	if (running_.exchange(false))
	{
		if (serverSocket_ >= 0)
		{
			close(serverSocket_);
			serverSocket_ = -1;
		}

		if (worker_.joinable())
		{
			worker_.join();
		}
	}
}

void McpTransportServer::broadcastEvent(const std::string &eventName, const std::string &eventData)
{
	eventManager_.broadcastEvent(eventName, eventData);
}

void McpTransportServer::workerThread()
{
	// 서버 소켓 생성
	serverSocket_ = socket(AF_INET, SOCK_STREAM, 0);
	if (serverSocket_ < 0)
	{
		std::cerr << "Error creating server socket" << std::endl;
		return;
	}

	// 소켓 옵션 설정
	int opt = 1;
	if (setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
	{
		std::cerr << "Error setting socket options" << std::endl;
		close(serverSocket_);
		return;
	}

	// 논블로킹 모드 설정
	int flags = fcntl(serverSocket_, F_GETFL, 0);
	fcntl(serverSocket_, F_SETFL, flags | O_NONBLOCK);

	// 주소 바인딩
	sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(port_);

	if (bind(serverSocket_, (struct sockaddr *)&address, sizeof(address)) < 0)
	{
		std::cerr << "Error binding socket to port " << port_ << std::endl;
		close(serverSocket_);
		return;
	}

	// 연결 대기
	if (listen(serverSocket_, 5) < 0)
	{
		std::cerr << "Error listening on socket" << std::endl;
		close(serverSocket_);
		return;
	}

	std::cout << "Server started on port " << port_ << std::endl;

	// 클라이언트 연결 수락
	while (running_)
	{
		fd_set readSet;
		FD_ZERO(&readSet);
		FD_SET(serverSocket_, &readSet);

		struct timeval timeout;
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		int result = select(serverSocket_ + 1, &readSet, nullptr, nullptr, &timeout);

		if (result < 0)
		{
			if (errno != EINTR)
			{
				std::cerr << "Error in select(): " << strerror(errno) << std::endl;
				break;
			}
		}
		else if (result == 0)
		{
			// 타임아웃, 계속 진행
			continue;
		}

		if (FD_ISSET(serverSocket_, &readSet))
		{
			sockaddr_in clientAddr;
			socklen_t clientAddrLen = sizeof(clientAddr);

			int clientSocket = accept(serverSocket_, (struct sockaddr *)&clientAddr, &clientAddrLen);
			if (clientSocket < 0)
			{
				if (errno != EAGAIN && errno != EWOULDBLOCK)
				{
					std::cerr << "Error accepting client connection: " << strerror(errno) << std::endl;
				}
				continue;
			}

			// 새 스레드에서 클라이언트 연결 처리
			std::thread clientThread(&McpTransportServer::handleConnection, this, clientSocket);
			clientThread.detach();
		}
	}

	close(serverSocket_);
	serverSocket_ = -1;
}

void McpTransportServer::handleConnection(int clientSocket)
{
	const int bufferSize = 4096;
	char buffer[bufferSize];
	std::string request;

	// 요청 읽기
	ssize_t bytesRead;
	while ((bytesRead = read(clientSocket, buffer, bufferSize - 1)) > 0)
	{
		buffer[bytesRead] = '\0';
		request.append(buffer, bytesRead);

		// HTTP 요청의 끝 검사 (빈 줄)
		if (request.find("\r\n\r\n") != std::string::npos)
		{
			break;
		}
	}

	if (bytesRead < 0 && (errno != EAGAIN && errno != EWOULDBLOCK))
	{
		std::cerr << "Error reading from client socket: " << strerror(errno) << std::endl;
		close(clientSocket);
		return;
	}

	// HTTP 요청 처리
	std::string response = handleHttpRequest(request);

	// 응답 전송
	if (request.find("Accept: text/event-stream") != std::string::npos)
	{
		// SSE 클라이언트 처리
		send(clientSocket, response.c_str(), response.length(), 0);

		// SSE 클라이언트 등록
		auto sendEvent = [clientSocket](const std::string &event)
		{
			send(clientSocket, event.c_str(), event.length(), 0);
		};

		int clientId = eventManager_.addClient(sendEvent);

		// 초기 이벤트 전송
		std::string initEvent = "event: connect\ndata: Connected to event stream\n\n";
		sendEvent(initEvent);

		// 클라이언트가 연결을 종료할 때까지 대기
		char keepAliveBuffer[1];
		while (running_ && read(clientSocket, keepAliveBuffer, 1) >= 0)
		{
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}

		// 클라이언트 등록 해제
		eventManager_.removeClient(clientId);	
	}
	else
	{
		// 일반 HTTP 요청 처리
		send(clientSocket, response.c_str(), response.length(), 0);
	}

	close(clientSocket);
}

std::string McpTransportServer::handleHttpRequest(const std::string &request)
{
	// HTTP 요청 파싱
	std::istringstream iss(request);
	std::string requestLine;
	std::getline(iss, requestLine);

	std::istringstream rls(requestLine);
	std::string method, path, httpVersion;
	rls >> method >> path >> httpVersion;

	// 요청 헤더 파싱
	std::map<std::string, std::string> headers;
	std::string headerLine;
	while (std::getline(iss, headerLine) && headerLine != "\r")
	{
		size_t colonPos = headerLine.find(':');
		if (colonPos != std::string::npos)
		{
			std::string name = headerLine.substr(0, colonPos);
			std::string value = headerLine.substr(colonPos + 1);

			// 공백 제거
			while (!value.empty() && (value[0] == ' ' || value[0] == '\t'))
			{
				value.erase(0, 1);
			}
			while (!value.empty() && (value[value.length() - 1] == '\r'))
			{
				value.erase(value.length() - 1);
			}

			headers[name] = value;
		}
	}

	// 요청 본문 파싱
	std::string body;
	if (method == "POST")
	{
		// 헤더에서 Content-Length 검사
		auto it = headers.find("Content-Length");
		if (it != headers.end())
		{
			int contentLength = std::stoi(it->second);

			// 이미 본문의 일부가 읽혔을 수 있음
			size_t headerEnd = request.find("\r\n\r\n");
			if (headerEnd != std::string::npos)
			{
				headerEnd += 4; // "\r\n\r\n" 건너뛰기
				body = request.substr(headerEnd);
			}
		}
	}

	std::string responseBody;
	std::string contentType = "text/plain";
	int statusCode = 200;

	// 경로 기반 요청 처리
	if (path == "/api" && method == "POST")
	{
		if (handler_)
		{
			responseBody = handler_->handleRequest(body);
			contentType = "application/json";
		}
		else
		{
			statusCode = 500;
			responseBody = "No request handler registered";
		}
	}
	else if (path == "/events" && method == "GET")
	{
		// SSE 연결 처리
		return "HTTP/1.1 200 OK\r\n"
			   "Content-Type: text/event-stream\r\n"
			   "Cache-Control: no-cache\r\n"
			   "Connection: keep-alive\r\n"
			   "Transfer-Encoding: chunked\r\n"
			   "\r\n";
	}
	else
	{
		statusCode = 404;
		responseBody = "Not Found";
	}

	// HTTP 응답 구성
	std::stringstream response;
	response << "HTTP/1.1 " << statusCode << (statusCode == 200 ? " OK" : statusCode == 404 ? " Not Found"
																							: " Internal Server Error")
			 << "\r\n";
	response << "Content-Type: " << contentType << "\r\n";
	response << "Content-Length: " << responseBody.length() << "\r\n";
	response << "Connection: close\r\n";
	response << "\r\n";
	response << responseBody;

	return response.str();
}
