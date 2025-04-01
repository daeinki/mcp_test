#include "HttpTransportClient.h"
#include <curl/curl.h>
#include <sstream>
#include <iostream>

// Callback to write received data into a std::string
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

HttpTransportClient::HttpTransportClient(const std::string& serverUrl)
	: m_serverUrl(serverUrl)
{
}

HttpTransportClient::~HttpTransportClient() {}

std::string HttpTransportClient::send(const std::string &requestContext)
{
	CURL *curl;
	CURLcode res;
	std::string readBuffer;

	curl = curl_easy_init();
	if(curl) {
		// Setting HTTP POST transport
		curl_easy_setopt(curl, CURLOPT_URL, m_serverUrl.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestContext.c_str());
		// Setting a callback for reading response data
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

		res = curl_easy_perform(curl);
		if(res != CURLE_OK) {
			std::cerr << "curl_easy_perform() failed: "
						<< curl_easy_strerror(res) << std::endl;
		}
		curl_easy_cleanup(curl);
	}
	return readBuffer;
}
