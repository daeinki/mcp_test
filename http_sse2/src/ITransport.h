#ifndef ITRANSPORT_H
#define ITRANSPORT_H

#include <string>

class ITransportClient {
public:
	virtual ~ITransportClient() {}
	virtual std::string send(const std::string &requestContext) = 0;
};

class ITransportServer {
public:
	virtual ~ITransportServer() {}
	virtual void run() = 0;
	virtual void stop() = 0;
};

#endif // ITRANSPORT_H
