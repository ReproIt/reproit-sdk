use std::{
    env, fs,
    io::{Read as _, Write as _},
    sync::Arc,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::DefaultBodyLimit,
    http::{Request, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use reproit_core::{
    Error, ErrorCode, canonical,
    model::{
        ExceptionCategory, ExceptionFailureIdentity, FailureFrame, FailureIdentity, OperationKind,
    },
};
use reproit_sdk_rust::{
    AutomaticManagedEngine, AutomaticManagedRustOperationFactory, ExactResponseFailureClassifier,
    ManagedProjectToken, OfficialManagedProject, package_running_rust_subject,
};
use reproit_sdk_rust_axum::{AxumRequestCapture, capture_axum_request};
use serde::{Deserialize, Serialize};
use tower::ServiceExt as _;

const OVERFLOW: &str = "Order total overflowed.\n";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Order {
    quantity: u16,
    unit_price_cents: u16,
}

#[derive(Serialize)]
struct Receipt {
    total_cents: u32,
}

fn total_cents(order: &Order) -> Option<u32> {
    u32::from(order.quantity).checked_mul(u32::from(order.unit_price_cents))
}

async fn checkout(Json(order): Json<Order>) -> Response {
    if order.quantity == 0 || order.quantity > 1_000 || order.unit_price_cents == 0 {
        return (
            StatusCode::BAD_REQUEST,
            "Use a quantity from 1 to 1000 and a positive price.\n",
        )
            .into_response();
    }
    match total_cents(&order) {
        Some(total_cents) => Json(Receipt { total_cents }).into_response(),
        None => (StatusCode::INTERNAL_SERVER_ERROR, OVERFLOW).into_response(),
    }
}

fn application() -> Router {
    Router::new()
        .route("/orders", post(checkout))
        .layer(DefaultBodyLimit::max(1_024))
}

fn capture() -> Result<AxumRequestCapture, Box<dyn std::error::Error>> {
    let project = OfficialManagedProject::from_build(
        &fs::read_to_string(".reproit/project.toml")?,
        &env::var("ORDERS_REPOSITORY_ID")?,
        &env::var("ORDERS_SOURCE_REVISION")?,
    )?;
    let engine = AutomaticManagedEngine::new(project, package_running_rust_subject()?);
    let factory = AutomaticManagedRustOperationFactory::new(engine, || {
        let token = env::var("REPROIT_MANAGED_PROJECT_TOKEN").map_err(|_| {
            Error::new(
                ErrorCode::AuthenticationRequired,
                "Set the managed project token.",
            )
        })?;
        ManagedProjectToken::new(token)
    });
    Ok(AxumRequestCapture::new(
        Arc::new(factory),
        "orders.checkout",
        Arc::new(ExactResponseFailureClassifier::new(
            500,
            OVERFLOW.as_bytes().to_vec(),
            failure_identity(),
        )),
    )?)
}

fn failure_identity() -> FailureIdentity {
    FailureIdentity::Exception(ExceptionFailureIdentity {
        category: ExceptionCategory::Exception,
        cause_types: Vec::new(),
        frames: vec![FailureFrame {
            function: "orders::total_cents".to_owned(),
            module: "orders".to_owned(),
            source: "crates/reproit-sdk-rust-axum/examples/orders.rs".to_owned(),
        }],
        operation_kind: OperationKind::RequestResponse,
        operation_name: "orders.checkout".to_owned(),
        runtime_family: "rust".to_owned(),
        schema: "reproit.failure.v1".to_owned(),
        stable_code: None,
        type_name: "OrderTotalOverflow".to_owned(),
    })
}

async fn replay(trigger: Vec<u8>) -> Result<(Vec<u8>, i32), Box<dyn std::error::Error>> {
    if trigger.is_empty() || trigger.len() > 1_024 {
        return Err("Use a nonempty order with at most 1024 bytes.".into());
    }
    let response = application()
        .oneshot(
            Request::post("/orders")
                .header("content-type", "application/json")
                .body(Body::from(trigger))?,
        )
        .await?;
    let status = response.status();
    let body = to_bytes(response.into_body(), 1_024).await?;
    if status == StatusCode::INTERNAL_SERVER_ERROR && body == OVERFLOW {
        return Ok((canonical::canonical_bytes(&failure_identity())?, 23));
    }
    if !status.is_success() {
        return Err("The captured order did not produce a valid response.".into());
    }
    Ok((br#"{"result":"PASS"}"#.to_vec(), 0))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("REPROIT_TRIGGER").as_deref() == Ok("stdin") {
        let mut trigger = Vec::new();
        std::io::stdin().take(1_025).read_to_end(&mut trigger)?;
        let (output, exit_code) = replay(trigger).await?;
        std::io::stdout().write_all(&output)?;
        std::process::exit(exit_code);
    }
    let application = application().route_layer(middleware::from_fn_with_state(
        capture()?,
        capture_axum_request,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    axum::serve(listener, application).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn replay_uses_the_checkout_route_and_rejects_invalid_input() {
        let mut trigger = br#"{"quantity":3,"unit_price_cents":30000}"#.to_vec();
        trigger.resize(1_024, b' ');
        assert_eq!(
            replay(trigger.clone()).await.expect("valid order"),
            (br#"{"result":"PASS"}"#.to_vec(), 0),
        );
        trigger.push(b' ');
        for invalid in [
            Vec::new(),
            trigger,
            b"{}".to_vec(),
            br#"{"quantity":0,"unit_price_cents":100}"#.to_vec(),
        ] {
            assert!(replay(invalid).await.is_err());
        }
    }

    #[tokio::test]
    async fn checkout_preserves_large_totals_and_rejects_invalid_orders() {
        for (body, status, expected) in [
            (
                r#"{"quantity":3,"unit_price_cents":30000}"#,
                StatusCode::OK,
                Some(r#"{"total_cents":90000}"#),
            ),
            (
                r#"{"quantity":1000,"unit_price_cents":65535}"#,
                StatusCode::OK,
                Some(r#"{"total_cents":65535000}"#),
            ),
            (
                r#"{"quantity":0,"unit_price_cents":100}"#,
                StatusCode::BAD_REQUEST,
                None,
            ),
            (
                r#"{"quantity":1001,"unit_price_cents":100}"#,
                StatusCode::BAD_REQUEST,
                None,
            ),
            (
                r#"{"quantity":1,"unit_price_cents":0}"#,
                StatusCode::BAD_REQUEST,
                None,
            ),
            (
                r#"{"quantity":1,"unit_price_cents":65536}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
                None,
            ),
        ] {
            let response = application()
                .oneshot(
                    Request::post("/orders")
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .expect("valid request"),
                )
                .await
                .expect("response");
            assert_eq!(response.status(), status, "{body}");
            if let Some(expected) = expected {
                assert_eq!(
                    to_bytes(response.into_body(), 1_024)
                        .await
                        .expect("bounded body"),
                    expected
                );
            }
        }
    }
}
