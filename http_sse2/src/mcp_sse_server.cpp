#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <thread> // For basic delay
#include <chrono> // For basic delay
#include <algorithm> // For std::transform

// --- Platform Specific Socket Includes ---
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> // For close()
#include <cstring> // For memset, strerror
#include <cerrno>  // For errno
using socket_t = int;
#define INVALID_SOCKET -1
#define SOCKET_ERROR   -1
#define close_socket(s) close(s)
// --- End Platform Specific ---

const int PORT = 8080; // Port the server will listen on
const int BUFFER_SIZE = 4096;
const std::string MCP_SSE_ENDPOINT = "/mcp"; // Endpoint for SSE connection

// --- Helper Functions ---

// Prints error messages (platform-aware)
void print_socket_error(const std::string& message) {
    std::cerr << message << ": " << strerror(errno) << std::endl;
}

// Sends data over a socket
bool send_data(socket_t client_socket, const std::string& data) {
    if (send(client_socket, data.c_str(), data.length(), 0) == SOCKET_ERROR) {
        print_socket_error("Send failed");
        return false;
    }
    return true;
}

// Formats and sends an SSE event
bool send_sse_event(socket_t client_socket, const std::string& event_name, const std::string& json_data) {
    std::ostringstream oss;
    oss << "event: " << event_name << "\n";
    // Handle multi-line JSON data - prefix each line with "data: "
    std::istringstream json_stream(json_data);
    std::string line;
    while (std::getline(json_stream, line)) {
        oss << "data: " << line << "\n";
    }
    oss << "\n"; // End of event marker

    std::cout << "Sending SSE Event:\n" << oss.str() << std::endl; // Log outgoing event
    return send_data(client_socket, oss.str());
}

// Handles a single client connection
void handle_client(socket_t client_socket) {
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    // 1. Read the HTTP request from the client
    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received == SOCKET_ERROR) {
        print_socket_error("Receive failed");
        close_socket(client_socket);
        return;
    }
    if (bytes_received == 0) {
        std::cout << "Client disconnected prematurely." << std::endl;
        close_socket(client_socket);
        return;
    }

    std::string request_str(buffer);
    std::cout << "Received Request:\n" << request_str << std::endl;

    // 2. Basic HTTP Request Parsing (Very Simple)
    // We expect something like: GET /mcp HTTP/1.1
    // And headers like: Accept: text/event-stream
    std::istringstream request_stream(request_str);
    std::string method, path, http_version;
    request_stream >> method >> path >> http_version;

	std::cout << request_stream.str() << std::endl;
	std::cout << "Parsed Request: " << method << " " << path << " " << http_version << std::endl;

std::cout << __LINE__ << std::endl;

    bool is_sse_request = false;
    if (method == "GET" && path == MCP_SSE_ENDPOINT) {
        std::string line;
		// Create a fresh stream to read headers from the beginning
		std::istringstream fresh_stream(request_str);
		std::string request_line;
		std::getline(fresh_stream, request_line); // Skip the first line (already parsed)

		while (std::getline(fresh_stream, line)) {
			// Remove carriage return if present
			if (!line.empty() && line.back() == '\r') {
			line.pop_back();
			}
			
			// Empty line marks end of headers
			if (line.empty()) {
				break;
			}
			
			size_t colon_pos = line.find(':');
			if (colon_pos != std::string::npos) {
				std::string header_name = line.substr(0, colon_pos);
				std::string header_value = line.substr(colon_pos + 1);
				// Trim leading whitespace
				header_value.erase(0, header_value.find_first_not_of(" \t"));
				
				// Convert to lowercase for case-insensitive comparison
				std::transform(header_name.begin(), header_name.end(), header_name.begin(), ::tolower);
				
				if (header_name == "accept" && header_value.find("text/event-stream") != std::string::npos) {
					is_sse_request = true;
				}
			}
		}
	}

    // 3. Handle Request
    if (is_sse_request) {
        std::cout << "SSE connection requested for " << path << std::endl;

        // Send SSE HTTP Headers
        std::string sse_headers =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/event-stream\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: keep-alive\r\n"
            "Access-Control-Allow-Origin: *\r\n" // Optional: Allow cross-origin requests if Inspector runs from a different origin
            "\r\n"; // End of headers

        if (!send_data(client_socket, sse_headers)) {
            close_socket(client_socket);
            return;
        }
        std::cout << "Sent SSE headers." << std::endl;

        // --- MCP Initialization ---
        // Wait a tiny bit before sending the first event (optional)
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        // Construct the MCP initialize request (Server -> Client)
        // Using manual JSON string creation for simplicity. Use a library for complex JSON.
        std::string mcp_initialize_payload = R"({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "mcpVersion": "1.0",
                "capabilities": {
                    "exampleCapability": true
                }
            }
        })";

        // Send the MCP initialize event via SSE
        if (!send_sse_event(client_socket, "mcp", mcp_initialize_payload)) {
            std::cerr << "Failed to send MCP initialize event." << std::endl;
            // Connection might be closed by client or error occurred
        } else {
             std::cout << "Sent MCP initialize event. Waiting for client interaction (or disconnect)." << std::endl;
             // In a full implementation, you would now wait for client messages (often via HTTP POST)
             // or continue sending other SSE events if needed.
             // For this basic test, we just keep the connection open until the client closes it
             // or an error occurs. You could add a loop here to keep sending heartbeat pings if needed.

             // Keep the connection open - read periodically to detect disconnect
            char temp_buffer[10];
            while (true) {
                int check_recv = recv(client_socket, temp_buffer, sizeof(temp_buffer), MSG_PEEK); // Peek, don't consume
                if (check_recv == 0) {
                    std::cout << "Client disconnected." << std::endl;
                    break;
                } else if (check_recv == SOCKET_ERROR) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                             print_socket_error("Socket error during keep-alive check");
                             break;
                        }
                     // No data pending, connection likely still alive
                } else {
                     // Data is available, but we are not processing client->server SSE messages in this example.
                     // A full server might read and process it here or handle it via separate POST requests.
                    // std::cout << "Data received from client (not processed in this example)." << std::endl;
                    // You might want to actually recv() here if you expect client data over SSE
                    // int actual_recv = recv(client_socket, temp_buffer, sizeof(temp_buffer), 0);
                    // std::cout << "Received " << actual_recv << " bytes." << std::endl;
                }
                // Prevent busy-waiting
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            }
        }

    } else {
        // Send a basic HTTP 404 Not Found for other requests
        std::cout << "Unsupported request: " << method << " " << path << std::endl;
        std::string response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send_data(client_socket, response);
    }

    // 4. Close Client Socket
    std::cout << "Closing client socket." << std::endl;
    close_socket(client_socket);
}

int main() {
    // 1. Create Socket
    socket_t server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        print_socket_error("Socket creation failed");
        return 1;
    }
    std::cout << "Server socket created." << std::endl;

     // Optional: Allow address reuse immediately after server stops
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        print_socket_error("setsockopt(SO_REUSEADDR) failed");
    }

    // 2. Bind Socket
    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
    server_addr.sin_port = htons(PORT);      // Convert port to network byte order

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        print_socket_error("Bind failed");
        close_socket(server_socket);
        return 1;
    }
    std::cout << "Socket bound to port " << PORT << "." << std::endl;

    // 3. Listen for Connections
    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) { // SOMAXCONN is a common backlog size
        print_socket_error("Listen failed");
        close_socket(server_socket);
        return 1;
    }
    std::cout << "Server listening on port " << PORT << "..." << std::endl;

    // 4. Accept Connections Loop
    while (true) {
        sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        socket_t client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);

        if (client_socket == INVALID_SOCKET) {
            print_socket_error("Accept failed");
            // Decide if the error is critical; maybe continue for non-critical errors
            // For simplicity, we continue here, but a production server might need better error handling.
            continue;
        }

        // Optional: Print client connection info
		char* client_ip = inet_ntoa(client_addr.sin_addr); // Simpler for example
		std::cout << "Accepted connection from " << client_ip << ":" << ntohs(client_addr.sin_port) << std::endl;


        // Handle the client in a separate function (or thread for concurrency)
        // For simplicity, this server handles one client at a time sequentially.
        handle_client(client_socket);
    }

    // 5. Close Server Socket (Technically unreachable in this simple loop)
    close_socket(server_socket);

    return 0;
}