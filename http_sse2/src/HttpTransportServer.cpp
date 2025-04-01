#include "HttpTransportServer.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

HttpTransportServer::HttpTransportServer(int port)
	: m_port(port), m_running(false)
{
}

HttpTransportServer::~HttpTransportServer()
{
	stop();
}

void HttpTransportServer::run()
{
	m_running = true;
	m_thread = std::thread(&HttpTransportServer::serverLoop, this);
}

void HttpTransportServer::stop()
{
	m_running = false;
	if(m_thread.joinable()) {
		m_thread.join();
	}
}

void HttpTransportServer::serverLoop()
{
	int server_fd, new_socket;
	struct sockaddr_in address;
	int opt = 1;
	int addrlen = sizeof(address);

	if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
		std::cerr << "Socket creation error" << std::endl;
		return;
	}

	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
					&opt, sizeof(opt)) < 0) {
		std::cerr << "setsockopt error" << std::endl;
		close(server_fd);
		return;
	}

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(m_port);

	if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		std::cerr << "Bind failed" << std::endl;
		close(server_fd);
		return;
	}

	if (listen(server_fd, 3) < 0) {
		std::cerr << "Listen failed" << std::endl;
		close(server_fd);
		return;
	}

	std::cout << "Server listening on port " << m_port << std::endl;

	while(m_running) {
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(server_fd, &readfds);
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		int activity = select(server_fd + 1, &readfds, NULL, NULL, &tv);
		if ((activity < 0) && (errno != EINTR)) {
			std::cerr << "select error" << std::endl;
		}

		if (FD_ISSET(server_fd, &readfds)) {
			if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
										(socklen_t*)&addrlen)) < 0) {
				std::cerr << "accept error" << std::endl;
				continue;
			}

			// Read request
			char buffer[30000] = {0};
			int valread = read(new_socket, buffer, sizeof(buffer));
			std::cout << "Received request: " << buffer << std::endl;

			// Prepare for the HTTP/1.1 and SSE header
			std::stringstream response;
			response << "HTTP/1.1 200 OK\r\n";
			response << "Content-Type: text/event-stream\r\n";
			response << "Cache-Control: no-cache\r\n";
			response << "Connection: keep-alive\r\n\r\n";

			if (strstr(buffer, "initialize") != nullptr) {
				response << "data: {\"status\":\"initialized\"}\n\n";
			} else {
				response << "data: {\"status\":\"unknown request\"}\n\n";
			}

			std::string responseStr = response.str();
			send(new_socket, responseStr.c_str(), responseStr.size(), 0);
			close(new_socket);
		}
	}
	close(server_fd);
}
