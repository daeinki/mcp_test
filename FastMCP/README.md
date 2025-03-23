### Tool 테스트용 JSON 데이터

1. 덧셈 (add) 테스트:
```json
{"type": "tool_call", "tool": "add", "parameters": {"a": 5, "b": 3}}
```

2. 뺄셈 (subtract) 테스트:
```json
{"type": "tool_call", "tool": "subtract", "parameters": {"a": 10, "b": 4}}
```

3. 곱셈 (multiply) 테스트:
```json
{"type": "tool_call", "tool": "multiply", "parameters": {"a": 6, "b": 7}}
```

4. 나눗셈 (divide) 테스트:
```json
{"type": "tool_call", "tool": "divide", "parameters": {"a": 20, "b": 5}}
```

5. 제곱근 (sqrt) 테스트:
```json
{"type": "tool_call", "tool": "sqrt", "parameters": {"a": 16}}
```

6. 나눗셈 에러 테스트 (0으로 나누기):
```json
{"type": "tool_call", "tool": "divide", "parameters": {"a": 10, "b": 0}}
```

7. 제곱근 에러 테스트 (음수):
```json
{"type": "tool_call", "tool": "sqrt", "parameters": {"a": -4}}
```

8. 리소스 요청 테스트:
```json
{"type": "resource_request", "uri": "greeting://World"}
```

9. 존재하지 않는 도구 테스트:
```json
{"type": "tool_call", "tool": "non_existent_tool", "parameters": {}}
```

10. 존재하지 않는 리소스 테스트:
```json
{"type": "resource_request", "uri": "non_existent://resource"}
```

이 JSON 데이터들을 사용하여 calculator_example을 테스트할 수 있습니다. 각 JSON 문자열을 한 줄씩 프로그램의 표준 입력으로 전달하면 됩니다. 예를 들어, 터미널에서 다음과 같이 실행할 수 있습니다:

```bash
echo '{"type": "tool_call", "tool": "add", "parameters": {"a": 5, "b": 3}}' | ./calculator_example
```

### Resource 테스트용 JSON 데이터

1. 기본 인사말 리소스 요청:
```json
{"type": "resource_request", "uri": "greeting://World"}
```
예상 응답: `{"type": "resource_response", "data": "Hello, World!"}`

2. 다른 이름으로 인사말 리소스 요청:
```json
{"type": "resource_request", "uri": "greeting://Alice"}
```
예상 응답: `{"type": "resource_response", "data": "Hello, Alice!"}`

3. 한글 이름으로 인사말 리소스 요청:
```json
{"type": "resource_request", "uri": "greeting://홍길동"}
```
예상 응답: `{"type": "resource_response", "data": "Hello, 홍길동!"}`

4. 특수 문자가 포함된 이름으로 인사말 리소스 요청:
```json
{"type": "resource_request", "uri": "greeting://John_Doe"}
```
예상 응답: `{"type": "resource_response", "data": "Hello, John_Doe!"}`

5. 공백이 포함된 이름으로 인사말 리소스 요청 (URL 인코딩 사용):
```json
{"type": "resource_request", "uri": "greeting://John%20Doe"}
```
예상 응답: `{"type": "resource_response", "data": "Hello, John%20Doe!"}`

6. 잘못된 패턴의 리소스 요청:
```json
{"type": "resource_request", "uri": "greeting:///invalid"}
```
예상 응답: 에러 메시지 (패턴이 일치하지 않음)

7. 존재하지 않는 리소스 패턴 요청:
```json
{"type": "resource_request", "uri": "unknown://resource"}
```
예상 응답: `{"type": "error", "error": "Resource not found: unknown://resource"}`

8. 빈 이름으로 인사말 리소스 요청:
```json
{"type": "resource_request", "uri": "greeting://"}
```
예상 응답: `{"type": "resource_response", "data": "Hello, !"}`

이러한 JSON 데이터를 사용하여 calculator_example의 리소스 처리 기능을 테스트할 수 있습니다. 각 JSON 문자열을 프로그램의 표준 입력으로 전달하면 된다.
예를 들어:

```bash
echo '{"type": "resource_request", "uri": "greeting://Alice"}' | ./calculator_example
```

또는 여러 테스트를 한 번에 실행하려면 파일로 저장한 후 입력으로 전달할 수도 있다.

```bash
cat resource_tests.json | ./calculator_example
```

여기서 resource_tests.json 파일에는 위의 JSON 데이터가 각 줄에 하나씩 포함되어 있어야 한다.
