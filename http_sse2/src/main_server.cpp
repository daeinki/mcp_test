#include "HttpTransportServer.h"
#include <iostream>
#include <csignal>
#include <chrono>
#include <thread>

HttpTransportServer* server = nullptr;

void signalHandler(int signum) {
	if(server) {
		server->stop();
	}
	exit(signum);
}

int main()
{
	signal(SIGINT, signalHandler);

	int port = 8080;
	HttpTransportServer httpServer(port);
	server = &httpServer;
	httpServer.run();

	std::cout << "Server running. Press Ctrl+C to stop." << std::endl;

	while (true) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	return 0;
}
