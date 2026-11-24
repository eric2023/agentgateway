#!/usr/bin/env python3
"""
AgentGateway test client — simulates AI agent requests through the proxy.

The gateway AUDITS and FORWARDS AI requests (does not block). Tests verify:
1. AI chat/completions request → AUDIT (forwarded, X-AgentGateway-Decision: AUDIT)
2. AI Anthropic /v1/messages request → AUDIT
3. AI embeddings request → AUDIT
4. Streaming AI request → AUDIT
5. Non-AI request → FORWARD (no AI decision header)
6. Qwen dashscope request → AUDIT

Run with the gateway already started: python3 gateway/agentgatewayd.py
"""

import os
import ssl
import json
import time
import socket

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8443
CA_CERT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "certs", "ca-cert.pem")


def setup_proxy_env():
    """Set proxy environment variables for HTTP clients."""
    os.environ["HTTPS_PROXY"] = f"http://{GATEWAY_HOST}:{GATEWAY_PORT}"
    os.environ["HTTP_PROXY"] = f"http://{GATEWAY_HOST}:{GATEWAY_PORT}"
    os.environ["SSL_CERT_FILE"] = CA_CERT
    os.environ["REQUESTS_CA_BUNDLE"] = CA_CERT
    os.environ["NODE_EXTRA_CA_CERTS"] = CA_CERT
    os.environ["PYTHONHTTPSVERIFY"] = "0"


def test_ai_chat_completions():
    """Test 1: Standard OpenAI-style chat completions request → AUDIT."""
    print("\n" + "=" * 60)
    print("TEST 1: AI chat/completions → expect AUDIT")
    print("=" * 60)

    body = json.dumps({
        "model": "gpt-4",
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "What is the capital of France?"}
        ],
        "temperature": 0.7,
        "max_tokens": 100,
        "stream": False,
    })

    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer sk-test-key-1234567890",
        "Host": "api.openai.com",
    }

    result = send_https_request(
        "api.openai.com", 443, "POST", "/v1/chat/completions",
        headers, body
    )
    print_result("AUDIT", result)
    return result


def test_ai_anthropic():
    """Test 2: Anthropic-style request → AUDIT."""
    print("\n" + "=" * 60)
    print("TEST 2: Anthropic /v1/messages → expect AUDIT")
    print("=" * 60)

    body = json.dumps({
        "model": "claude-3-opus-20240229",
        "messages": [
            {"role": "user", "content": "Write a haiku about debugging."}
        ],
        "max_tokens": 50,
    })

    headers = {
        "Content-Type": "application/json",
        "x-api-key": "sk-ant-test123456",
        "anthropic-version": "2023-06-01",
        "Host": "api.anthropic.com",
    }

    result = send_https_request(
        "api.anthropic.com", 443, "POST", "/v1/messages",
        headers, body
    )
    print_result("AUDIT", result)
    return result


def test_ai_embeddings():
    """Test 3: Embeddings request → AUDIT."""
    print("\n" + "=" * 60)
    print("TEST 3: /v1/embeddings → expect AUDIT")
    print("=" * 60)

    body = json.dumps({
        "model": "text-embedding-ada-002",
        "input": "The food was delicious and the waiter was friendly.",
    })

    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer sk-embed-test-key",
        "Host": "api.openai.com",
    }

    result = send_https_request(
        "api.openai.com", 443, "POST", "/v1/embeddings",
        headers, body
    )
    print_result("AUDIT", result)
    return result


def test_ai_streaming():
    """Test 4: Streaming AI request → AUDIT."""
    print("\n" + "=" * 60)
    print("TEST 4: Streaming chat/completions (stream=true) → expect AUDIT")
    print("=" * 60)

    body = json.dumps({
        "model": "deepseek-chat",
        "messages": [
            {"role": "user", "content": "Count from 1 to 10."}
        ],
        "stream": True,
        "max_tokens": 200,
    })

    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer sk-deepseek-test",
        "Host": "api.deepseek.com",
    }

    result = send_https_request(
        "api.deepseek.com", 443, "POST", "/v1/chat/completions",
        headers, body
    )
    print_result("AUDIT", result)
    return result


def test_non_ai_request():
    """Test 5: Non-AI request → FORWARD (not audited)."""
    print("\n" + "=" * 60)
    print("TEST 5: Non-AI request (example.com) → expect FORWARD")
    print("=" * 60)

    headers = {
        "Host": "example.com",
        "User-Agent": "AgentGateway-Test-Client/1.0",
        "Accept": "text/html",
    }

    result = send_https_request(
        "example.com", 443, "GET", "/",
        headers, None
    )
    print_result("FORWARD", result)
    return result


def test_qwen_style():
    """Test 6: Qwen/dashscope style request → AUDIT."""
    print("\n" + "=" * 60)
    print("TEST 6: Qwen dashscope /api/v1/services/aigc/text-generation → expect AUDIT")
    print("=" * 60)

    body = json.dumps({
        "model": "qwen-turbo",
        "input": {
            "messages": [
                {"role": "user", "content": "Hello, who are you?"}
            ]
        },
        "parameters": {
            "temperature": 0.8,
            "max_tokens": 100,
        }
    })

    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer sk-qwen-test-key",
        "Host": "dashscope.aliyuncs.com",
    }

    result = send_https_request(
        "dashscope.aliyuncs.com", 443, "POST",
        "/api/v1/services/aigc/text-generation/generation",
        headers, body
    )
    print_result("AUDIT", result)
    return result


def send_https_request(host, port, method, path, headers, body):
    """Send an HTTPS request through the proxy using CONNECT tunneling."""
    result = {
        "test": f"{method} {host}{path}",
        "expected": "",
        "actual": "",
        "status": None,
        "body_preview": "",
        "audited": False,
        "passed": False,
    }

    try:
        proxy_sock = socket.create_connection((GATEWAY_HOST, GATEWAY_PORT), timeout=10)

        connect_req = (
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"\r\n"
        ).encode()
        proxy_sock.sendall(connect_req)

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = proxy_sock.recv(4096)
            if not chunk:
                break
            resp += chunk

        connect_status = resp.split(b"\r\n")[0].decode()
        if "200" not in connect_status:
            result["actual"] = f"CONNECT failed: {connect_status}"
            result["status"] = "CONNECT_FAIL"
            proxy_sock.close()
            return result

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(CA_CERT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        tls_sock = ctx.wrap_socket(proxy_sock, server_hostname=host)

        req_line = f"{method} {path} HTTP/1.1\r\n"
        req = req_line.encode()
        for k, v in headers.items():
            req += f"{k}: {v}\r\n".encode()
        if body:
            req += f"Content-Length: {len(body)}\r\n".encode()
        req += b"Connection: close\r\n\r\n"
        if body:
            req += body.encode() if isinstance(body, str) else body

        tls_sock.sendall(req)

        tls_sock.settimeout(8)
        resp_data = b""
        while True:
            try:
                chunk = tls_sock.recv(65536)
                if not chunk:
                    break
                resp_data += chunk
                if b"\r\n\r\n" in resp_data:
                    header_end = resp_data.find(b"\r\n\r\n")
                    header_block = resp_data[:header_end]
                    for line in header_block.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            cl = int(line.split(b":")[1].strip())
                            body_start = header_end + 4
                            if len(resp_data) >= body_start + cl:
                                break
                    else:
                        continue
                    break
            except socket.timeout:
                break
            except ssl.SSLError:
                break

        try:
            tls_sock.close()
        except Exception:
            pass

        if resp_data:
            header_end = resp_data.find(b"\r\n\r\n")
            if header_end != -1:
                header_block = resp_data[:header_end].decode("utf-8", errors="replace")
                resp_body = resp_data[header_end + 4:]
                status_line = header_block.split("\r\n")[0]
                try:
                    result["status"] = int(status_line.split(" ")[1])
                except (IndexError, ValueError):
                    result["status"] = 0

                # Gateway marks audited AI requests with this header.
                if "X-AgentGateway-Decision: AUDIT" in header_block:
                    result["audited"] = True
                    result["actual"] = f"AUDITED ({result['status']})"
                else:
                    result["actual"] = f"FORWARDED ({result['status']})"

                result["body_preview"] = resp_body[:300].decode("utf-8", errors="replace")
            else:
                result["actual"] = "Malformed response"
        else:
            result["actual"] = "No response"

    except ConnectionRefusedError:
        result["actual"] = "Gateway not running"
        result["status"] = "CONN_REFUSED"
    except Exception as e:
        result["actual"] = f"Error: {e}"
        result["status"] = "ERROR"

    return result


def print_result(expected, result):
    """Print test result and determine pass/fail.

    AUDIT: request was identified as AI and forwarded (any upstream status).
    FORWARD: request was forwarded without the AI decision header. Non-AI hosts
             are blind-tunneled (no MITM), so the client connects directly to the
             real server — a TLS error from the real server's certificate is
             expected and still counts as a pass (the gateway did not audit it).
    """
    actual = result["actual"]
    if expected == "AUDIT":
        result["passed"] = result["audited"]
    else:  # FORWARD
        result["passed"] = not result["audited"]

    status_icon = "✅" if result["passed"] else "❌"
    print(f"  {status_icon} Expected: {expected} | Actual: {actual} | Status: {result['status']}")
    if result["body_preview"]:
        preview = result["body_preview"][:200].replace("\n", " ")
        print(f"  Body: {preview}")
    result["expected"] = expected


def main():
    print("=" * 60)
    print("AgentGateway Test Suite")
    print("=" * 60)
    print(f"Gateway: {GATEWAY_HOST}:{GATEWAY_PORT}")
    print(f"CA cert: {CA_CERT}")

    setup_proxy_env()

    print("\nWaiting for gateway...", end=" ")
    for _ in range(10):
        try:
            s = socket.create_connection((GATEWAY_HOST, GATEWAY_PORT), timeout=1)
            s.close()
            print("OK")
            break
        except ConnectionRefusedError:
            time.sleep(0.5)
    else:
        print("FAILED - Gateway not running!")
        print("Start it first: python3 gateway/agentgatewayd.py")
        return

    results = []
    results.append(test_ai_chat_completions())
    results.append(test_ai_anthropic())
    results.append(test_ai_embeddings())
    results.append(test_ai_streaming())
    results.append(test_qwen_style())
    results.append(test_non_ai_request())

    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    for r in results:
        icon = "✅" if r["passed"] else "❌"
        print(f"  {icon} {r['test']:52s} expected={r['expected']:8s} actual={r['actual']}")
    print(f"\n  {passed}/{total} tests passed")
    print("=" * 60)

    return results


if __name__ == "__main__":
    main()
