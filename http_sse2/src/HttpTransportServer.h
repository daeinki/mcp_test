#ifndef HTTPTRANSPORTSERVER_H
#define HTTPTRANSPORTSERVER_H

#include "ITransport.h"
#include <atomic>
#include <thread>

class HttpTransportServer : public ITransportServer {
public:
	explicit HttpTransportServer(int port);
	virtual ~HttpTransportServer();

	void run() override;
	void stop() override;
private:
	void serverLoop();
	int m_port;
	std::atomic<bool> m_running;
	std::thread m_thread;
};

#endif // HTTPTRANSPORTSERVER_H
