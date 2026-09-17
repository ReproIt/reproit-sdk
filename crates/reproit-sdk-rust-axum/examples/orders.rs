use std::{env, fs, sync::Arc};

use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::post,
};
use reproit_core::{
    Error, ErrorCode,
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
    let failure = FailureIdentity::Exception(ExceptionFailureIdentity {
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
    });
    Ok(AxumRequestCapture::new(
        Arc::new(factory),
        "orders.checkout",
        Arc::new(ExactResponseFailureClassifier::new(
            500,
            OVERFLOW.as_bytes().to_vec(),
            failure,
        )),
    )?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
