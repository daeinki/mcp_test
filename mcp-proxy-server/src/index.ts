import express from 'express';
import { exec } from 'child_process';
import bodyParser from 'body-parser';

const app = express();
const PORT = 3000; // Proxy 서버가 사용할 포트
const MCP_SERVER_URL = 'http://localhost:8080'; // 실제 MCP server 주소

// JSON 및 URL-encoded 형태의 요청 본문 파싱
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 모든 요청을 처리하는 핸들러
app.all('*', (req, res) => {
  // 원본 요청 URL을 MCP 서버 주소와 결합
  const targetUrl = `${MCP_SERVER_URL}${req.originalUrl}`;
  const method = req.method.toUpperCase();

  // 기본 curl 명령어 구성 (-s: silent 모드)
  let curlCommand = `curl -s -X ${method} "${targetUrl}"`;

  // Content-Type 헤더 전달 (필요에 따라 다른 헤더 추가 가능)
  if (req.headers['content-type']) {
    curlCommand += ` -H "Content-Type: ${req.headers['content-type']}"`;
  }

  // POST, PUT, PATCH 요청 등의 경우 본문 데이터 전달
  if (['POST', 'PUT', 'PATCH'].includes(method)) {
    const requestBody = JSON.stringify(req.body);
    curlCommand += ` --data '${requestBody}'`;
  }

  console.log(`Forwarding request with command: ${curlCommand}`);

  // curl 명령어 실행
  exec(curlCommand, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error while executing curl: ${error.message}`);
      return res.status(500).send(stderr || 'Internal Server Error');
    }
    // MCP server의 응답을 그대로 반환
    res.send(stdout);
  });
});

// Proxy 서버 시작
app.listen(PORT, () => {
  console.log(`MCP Proxy Server is running on port ${PORT}`);
});

