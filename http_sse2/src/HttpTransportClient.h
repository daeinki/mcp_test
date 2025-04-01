#ifndef HTTPTRANSPORTCLIENT_H
#define HTTPTRANSPORTCLIENT_H

#include "ITransport.h"
#include <string>

class HttpTransportClient : public ITransportClient {
public:
	explicit HttpTransportClient(const std::string& serverUrl);
	virtual ~HttpTransportClient();
	std::string send(const std::string &requestContext) override;
private:
	std::string m_serverUrl;
};

#endif // HTTPTRANSPORTCLIENT_H
