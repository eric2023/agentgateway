// SPDX-License-Identifier: Apache-2.0
// AI request detection — ported from agentgatewayd.py detect_ai_request().

use serde_json::Value;

/// AI API path patterns. If any appears in the request path, it's likely an AI call.
const AI_API_PATHS: &[&str] = &[
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/responses",
    "/v1/messages",       // Anthropic
    "/v1/embeddings",
    "/chat/completions",
    "/api/v1/chat",
    "/api/chat",
    "/v1/models",
];

/// AI authentication headers.
const AI_AUTH_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "anthropic-version",
    "x-goog-api-key",
];

/// Hosts that may carry AI API calls and should be MITM'd for inspection.
const AI_HOST_PATTERNS: &[&str] = &[
    "openai.com",
    "anthropic.com",
    "api.deepseek.com",
    "dashscope.aliyuncs.com",
    "moonshot.cn",
    "bigmodel.cn",
    "ai.uniontech.com",
    "uosai.uniontech.com",
    "xiaou.uniontech.com",
    "agent-dev.uniontech.com",
    "agentapi-dev.uniontech.com",
    "immersivetranslate.com",
    "copilot.tencent.com",
    "codebuddy.cn",
    "githubcopilot.com",
    "generativelanguage.googleapis.com",
    "aip.baidubce.com",
    "minimaxi.com",
    "spark-api.xf-yun.com",
];

/// Detect if an HTTP request is an AI model API call.
/// Returns (is_ai, confidence, signals, detail_json).
pub fn detect_ai_request(
    _method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> (bool, i32, Vec<String>, Value) {
    let mut signals: Vec<String> = Vec::new();
    let mut detail = serde_json::Map::new();
    let mut confidence: i32 = 0;

    // Signal 1: AI API path
    let path_lower = path.to_lowercase();
    for ai_path in AI_API_PATHS {
        if path_lower.contains(ai_path) {
            signals.push(format!("path_match:{}", ai_path));
            confidence += 2;
            break;
        }
    }

    // Signal 2: AI auth headers
    for hdr_name in AI_AUTH_HEADERS {
        for (k, v) in headers {
            if k.to_lowercase() == *hdr_name {
                signals.push(format!("auth_header:{}", k));
                confidence += 1;
                if v.to_lowercase().contains("bearer") {
                    detail.insert("auth_type".to_string(), Value::String("bearer".to_string()));
                }
                break;
            }
        }
    }

    // Signal 3: Request body JSON structure
    if !body.is_empty() {
        if let Ok(body_json) = serde_json::from_slice::<Value>(body) {
            if let Some(obj) = body_json.as_object() {
                // Model
                if let Some(model) = obj.get("model").and_then(|m| m.as_str()) {
                    detail.insert("model".to_string(), Value::String(model.to_string()));
                }

                // Messages
                if obj.contains_key("messages") {
                    signals.push("body:messages[]".to_string());
                    confidence += 2;
                    if let Some(msgs) = obj.get("messages").and_then(|m| m.as_array()) {
                        detail.insert("message_count".to_string(), Value::Number(msgs.len().into()));
                        // Extract prompt preview from last message
                        if let Some(last_msg) = msgs.last() {
                            if let Some(content) = last_msg.get("content") {
                                if let Some(s) = content.as_str() {
                                    detail.insert("preview".to_string(),
                                        Value::String(s.chars().take(200).collect()));
                                } else if let Some(arr) = content.as_array() {
                                    for part in arr {
                                        if part.get("type").and_then(|t| t.as_str()) == Some("text") {
                                            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                                                detail.insert("preview".to_string(),
                                                    Value::String(text.chars().take(200).collect()));
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    detail.insert("prompt_len".to_string(),
                        Value::Number(body.len().into()));
                }

                // Prompt (non-chat APIs)
                if obj.contains_key("prompt") {
                    signals.push("body:prompt".to_string());
                    confidence += 2;
                    if let Some(p) = obj.get("prompt") {
                        detail.insert("preview".to_string(),
                            Value::String(p.to_string().chars().take(200).collect()));
                    }
                    detail.insert("prompt_len".to_string(),
                        Value::Number(body.len().into()));
                }

                // Body signal fields
                for sig in &["max_tokens", "temperature", "top_p", "stream"] {
                    if obj.contains_key(*sig) {
                        signals.push(format!("body:{}", sig));
                        confidence += 1;
                    }
                }

                // Model field in body
                if obj.contains_key("model") {
                    signals.push("body:model".to_string());
                    confidence += 1;
                }

                // Stream mode
                if obj.get("stream").and_then(|s| s.as_bool()) == Some(true) {
                    detail.insert("stream_mode".to_string(), Value::Bool(true));
                }
            }
        }
    }

    // Decision: 2+ signals or confidence >= 3
    let is_ai = confidence >= 3 || signals.len() >= 2;
    (is_ai, confidence, signals, Value::Object(detail))
}

/// Check if a host should be MITM'd (might carry AI API calls).
pub fn should_mitm_host(host: &str) -> bool {
    let host_lower = host.to_lowercase();
    for pattern in AI_HOST_PATTERNS {
        if host_lower == *pattern || host_lower.ends_with(&format!(".{}", pattern)) {
            return true;
        }
    }
    false
}
