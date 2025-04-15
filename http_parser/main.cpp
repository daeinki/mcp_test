#include <iostream>
#include <sstream>
#include <string>
#include <algorithm>
#include <cctype>
#include <json/json.h>

// 입력 문자열의 모든 문자를 소문자로 변환하는 헬퍼 함수
std::string toLower(const std::string &s) {
    std::string ret = s;
    std::transform(ret.begin(), ret.end(), ret.begin(), ::tolower);
    return ret;
}

// jsoncpp의 Json::Value 내부의 key들을 재귀적으로 소문자로 변환하는 함수
Json::Value convertKeysToLower(const Json::Value &value) {
    if (value.isObject()) {
        Json::Value newObj(Json::objectValue);
        for (const auto& key : value.getMemberNames()) {
            newObj[toLower(key)] = convertKeysToLower(value[key]);
        }
        return newObj;
    } else if (value.isArray()) {
        Json::Value newArr(Json::arrayValue);
        for (const auto& item : value) {
            newArr.append(convertKeysToLower(item));
        }
        return newArr;
    }
    // 숫자, 문자열 등 객체나 배열이 아니면 그대로 반환
    return value;
}

int main() {
    // HTTP 메시지 전체 (요청 라인, 헤더, 그리고 JSON body)
    std::string input =
        "POST /initialize HTTP/1.1\n"
        "Host: example.com\n"
        "Content-Type: application/json\n"
        "Authorization: Bearer <your_token>\n"
        "User-Agent: CustomClient/1.0\n"
        "Accept: application/json\n"
        "Content-Length: <length_of_body>\n"
        "\n"
        "{\n"
        "  \"method\": \"initialize\",\n"
        "  \"params\": {\n"
        "    \"sessionId\": \"<session_id>\",\n"
        "    \"capabilities\": [\"tool1\", \"tool2\"]\n"
        "  }\n"
        "}\n";

    // HTTP 메시지를 헤더 부분과 body 부분으로 분리 (\n\n을 구분자로 사용)
    size_t pos = input.find("\n\n");
    if (pos == std::string::npos)
        pos = input.find("\r\n\r\n");
    if (pos == std::string::npos) {
        std::cerr << "유효하지 않은 HTTP 메시지 형식입니다." << std::endl;
        return 1;
    }
    std::string headerPart = input.substr(0, pos);
    std::string bodyPart = input.substr(pos + 2); // 간단히 \n\n 이후로 처리

    // 헤더 부분 파싱: 첫번째 줄은 요청 라인이고 이후 줄은 "Key: Value" 형식임
    std::istringstream headerStream(headerPart);
    std::string line;
    std::getline(headerStream, line); // 요청 라인 읽기
    std::string requestLine = line; // 요청 라인을 그대로 저장

    // 헤더들을 저장할 JSON 객체
    Json::Value headerJson(Json::objectValue);
    while (std::getline(headerStream, line)) {
        if (line.empty()) continue;
        size_t colonPos = line.find(':');
        if (colonPos != std::string::npos) {
            std::string key = line.substr(0, colonPos);
            std::string value = line.substr(colonPos + 1);
            // value의 앞뒤 공백 제거
            value.erase(value.begin(), std::find_if(value.begin(), value.end(), [](unsigned char ch) {
                return !std::isspace(ch);
            }));
            value.erase(std::find_if(value.rbegin(), value.rend(), [](unsigned char ch) {
                return !std::isspace(ch);
            }).base(), value.end());
            headerJson[toLower(key)] = value;
        }
    }

    // jsoncpp를 이용하여 JSON body 파싱
    Json::CharReaderBuilder builder;
    Json::Value bodyJson;
    std::string errs;
    std::istringstream bodyStream(bodyPart);
    if (!Json::parseFromStream(builder, bodyStream, &bodyJson, &errs)) {
        std::cerr << "JSON body 파싱 실패: " << errs << std::endl;
        return 1;
    }

    // JSON body 내부의 key들을 재귀적으로 소문자로 변환
    Json::Value lowerBodyJson = convertKeysToLower(bodyJson);

    // 최종 결과를 요청 라인, 헤더, 그리고 변환된 JSON body로 구성
    Json::Value outputJson(Json::objectValue);
    outputJson["request_line"] = requestLine;
    outputJson["headers"] = headerJson;
    outputJson["body"] = lowerBodyJson;

    // jsoncpp의 StreamWriter를 사용하여 JSON 출력
    Json::StreamWriterBuilder writer;
    std::cout << Json::writeString(writer, outputJson) << std::endl;

    return 0;
}
