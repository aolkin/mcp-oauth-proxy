use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;

/// Proxy an SSE connection to a downstream MCP server using raw byte passthrough.
///
/// Opens a streaming GET to `downstream_url` with the given auth header and
/// `Accept: text/event-stream`. Returns the raw byte stream as an SSE response,
/// preserving the exact framing from downstream.
pub async fn proxy_sse(
    downstream_url: &str,
    auth_header_name: &str,
    auth_header_value: &str,
    client: &reqwest::Client,
) -> Result<Response, StatusCode> {
    let resp = client
        .get(downstream_url)
        .header(auth_header_name, auth_header_value)
        .header("Accept", "text/event-stream")
        .send()
        .await
        .map_err(|e| {
            tracing::error!(url = %downstream_url, error = %e, "Failed to connect to downstream");
            StatusCode::BAD_GATEWAY
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        tracing::error!(url = %downstream_url, status = %status, body = %body, "Downstream returned error");
        return Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "text/plain")
            .body(Body::from(format!("Downstream returned {status}")))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }

    let stream = resp.bytes_stream();
    Response::builder()
        .status(200)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-cache")
        .header("Connection", "keep-alive")
        .body(Body::from_stream(stream))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Forward a POST request body to a downstream MCP server and return the response.
pub async fn proxy_post(
    downstream_url: &str,
    auth_header_name: &str,
    auth_header_value: &str,
    body: axum::body::Bytes,
    client: &reqwest::Client,
) -> Result<Response, StatusCode> {
    let resp = client
        .post(downstream_url)
        .header(auth_header_name, auth_header_value)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(url = %downstream_url, error = %e, "Failed to connect to downstream");
            StatusCode::BAD_GATEWAY
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let headers = resp.headers().clone();
        let body_bytes = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
        tracing::error!(url = %downstream_url, status = %status, "Downstream returned error");

        let mut builder = Response::builder().status(StatusCode::BAD_GATEWAY);
        if let Some(ct) = headers.get("content-type") {
            builder = builder.header("Content-Type", ct);
        }
        return builder
            .body(Body::from(body_bytes))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);
    }

    let status = resp.status();
    let headers = resp.headers().clone();
    let body_bytes = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut builder = Response::builder().status(status.as_u16());
    if let Some(ct) = headers.get("content-type") {
        builder = builder.header("Content-Type", ct);
    }
    builder
        .body(Body::from(body_bytes))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
