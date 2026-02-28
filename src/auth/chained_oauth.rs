use crate::config::DownstreamConfig;

pub async fn post_downstream_token(
    client: &reqwest::Client,
    ds: &DownstreamConfig,
    form_params: &[(&str, &str)],
) -> Result<serde_json::Value, String> {
    let resp = client
        .post(&ds.oauth_token_url)
        .header("Accept", &ds.oauth_token_accept)
        .form(form_params)
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Failed to parse token response: {e}"))?;

    if !status.is_success() {
        let err_desc = body["error_description"]
            .as_str()
            .or_else(|| body["error"].as_str())
            .unwrap_or("unknown error");
        return Err(format!(
            "Downstream token endpoint returned {status}: {err_desc}"
        ));
    }

    Ok(body)
}
