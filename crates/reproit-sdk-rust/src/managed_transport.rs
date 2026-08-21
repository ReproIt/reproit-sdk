use std::{
    fmt::Write as _,
    fs,
    io::{Read, Write as _},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use hickory_resolver::Resolver;
use reproit_cloud_api::{
    ManagedCandidateCommit, ManagedCandidateEncryptionGrantRequest,
    ManagedCandidateEncryptionResponse, ManagedCandidateStart, ManagedCandidateStatus,
    ManagedCandidateUploadRequest, UploadMissingPage, WorkloadKeyRegistration,
    WorkloadKeyRegistrationResult,
};
use reproit_core::{
    Error, ErrorCode, canonical,
    identity::{Digest, UploadId},
};
use rustls::pki_types::{CertificateDer, pem::PemObject as _};
use rustls_platform_verifier::BuilderVerifierExt as _;

use crate::{ManagedCandidateGrantDelivery, ManagedCandidateIngressDelivery};

const MAX_CA_BYTES: u64 = 1_048_576;
const MAX_CERTIFICATES: usize = 16;
const MAX_DNS_ADDRESSES: usize = 8;
const MAX_HEADER_BYTES: usize = 8_192;
const MAX_JSON_RESPONSE_BYTES: usize = 8_388_608;
const MAX_PROJECT_TOKEN_BYTES: usize = 1_024;
const MAX_REGISTRATION_BYTES: usize = 3_372_783;

/// A project token that authorizes one managed workload registration.
pub struct ManagedProjectToken(String);

impl ManagedProjectToken {
    pub fn new(value: String) -> Result<Self, Error> {
        if value.is_empty()
            || value.len() > MAX_PROJECT_TOKEN_BYTES
            || value.bytes().any(|byte| !byte.is_ascii_graphic())
        {
            return Err(Error::new(
                ErrorCode::SchemaInvalid,
                "The managed project token is invalid.",
            ));
        }
        Ok(Self(value))
    }

    fn into_authorization(self) -> String {
        format!("Bearer {}", self.0)
    }
}

#[derive(Clone)]
pub struct ManagedTlsEndpoint {
    destination: ManagedTlsDestination,
    authority: Arc<str>,
    client: Arc<rustls::ClientConfig>,
    origin: Arc<str>,
    server_name: rustls::pki_types::ServerName<'static>,
}

#[derive(Clone)]
enum ManagedTlsDestination {
    Address(SocketAddr),
    Dns(Arc<str>),
}

impl ManagedTlsEndpoint {
    pub fn new(
        address: &str,
        server_name: String,
        authority: String,
        ca_certificate_path: PathBuf,
    ) -> Result<Self, Error> {
        let address = address.parse().map_err(|_| endpoint_invalid())?;
        validate_authority(&authority)?;
        let metadata =
            fs::symlink_metadata(&ca_certificate_path).map_err(|_| endpoint_invalid())?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() == 0
            || metadata.len() > MAX_CA_BYTES
        {
            return Err(endpoint_invalid());
        }
        let bytes = fs::read(ca_certificate_path).map_err(|_| endpoint_invalid())?;
        let certificates = CertificateDer::pem_slice_iter(&bytes)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| endpoint_invalid())?;
        if certificates.is_empty() || certificates.len() > MAX_CERTIFICATES {
            return Err(endpoint_invalid());
        }
        let mut roots = rustls::RootCertStore::empty();
        let (accepted, rejected) = roots.add_parsable_certificates(certificates);
        if accepted == 0 || rejected != 0 {
            return Err(endpoint_invalid());
        }
        let client =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
        let server_name =
            rustls::pki_types::ServerName::try_from(server_name).map_err(|_| endpoint_invalid())?;
        Ok(Self {
            destination: ManagedTlsDestination::Address(address),
            origin: Arc::from(format!("https://{authority}")),
            authority: Arc::from(authority),
            client: Arc::new(client),
            server_name,
        })
    }

    fn official(origin: &str) -> Result<Self, Error> {
        let authority = official_authority(origin)?;
        let client =
            rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_platform_verifier()
                .map_err(|_| service_unavailable())?
                .with_no_client_auth();
        let server_name = rustls::pki_types::ServerName::try_from(authority.to_owned())
            .map_err(|_| endpoint_invalid())?;
        Ok(Self {
            destination: ManagedTlsDestination::Dns(Arc::from(format!("{authority}:443"))),
            authority: Arc::from(authority),
            client: Arc::new(client),
            origin: Arc::from(origin),
            server_name,
        })
    }

    fn request(
        &self,
        method: &str,
        target: &str,
        authorization: Option<&str>,
        content_type: Option<&str>,
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, Error> {
        validate_request_component(method)?;
        validate_target(target)?;
        if let Some(value) = authorization {
            validate_header_value(value)?;
        }
        if let Some(value) = content_type {
            validate_header_value(value)?;
        }
        let stream = self.connect(timeout)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|_| service_unavailable())?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|_| service_unavailable())?;
        let connection =
            rustls::ClientConnection::new(self.client.clone(), self.server_name.clone())
                .map_err(|_| endpoint_invalid())?;
        let mut stream = rustls::StreamOwned::new(connection, stream);
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|_| service_unavailable())?;
        let mut header = format!(
            "{method} {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.authority
        );
        if let Some(value) = authorization {
            header.push_str("Authorization: ");
            header.push_str(value);
            header.push_str("\r\n");
        }
        if let Some(value) = content_type {
            header.push_str("Content-Type: ");
            header.push_str(value);
            header.push_str("\r\n");
        }
        write!(header, "Content-Length: {}\r\n\r\n", body.len())
            .map_err(|_| service_unavailable())?;
        stream
            .write_all(header.as_bytes())
            .and_then(|()| stream.write_all(body))
            .map_err(|_| service_unavailable())?;
        read_response(&mut stream)
    }

    fn connect(&self, timeout: Duration) -> Result<TcpStream, Error> {
        match &self.destination {
            ManagedTlsDestination::Address(address) => {
                TcpStream::connect_timeout(address, timeout).map_err(|_| service_unavailable())
            }
            ManagedTlsDestination::Dns(destination) => connect_resolved(destination, timeout),
        }
    }

    fn upload_target<'a>(&self, upload_url: &'a str) -> Result<&'a str, Error> {
        let target = upload_url
            .strip_prefix(self.origin.as_ref())
            .ok_or_else(endpoint_invalid)?;
        validate_target(target)?;
        Ok(target)
    }
}

pub struct ManagedTlsClient {
    ingress: ManagedTlsEndpoint,
    key_service: ManagedTlsEndpoint,
}

impl ManagedTlsClient {
    #[must_use]
    pub fn new(key_service: ManagedTlsEndpoint, ingress: ManagedTlsEndpoint) -> Self {
        Self {
            ingress,
            key_service,
        }
    }

    pub(crate) fn official(origin: &str) -> Result<Self, Error> {
        let endpoint = ManagedTlsEndpoint::official(origin)?;
        Ok(Self::new(endpoint.clone(), endpoint))
    }

    pub fn register_workload_key(
        &self,
        project_token: ManagedProjectToken,
        request: &WorkloadKeyRegistration,
        timeout: Duration,
    ) -> Result<WorkloadKeyRegistrationResult, Error> {
        request.validate()?;
        let body = canonical::canonical_bytes(request)?;
        if body.len() > MAX_REGISTRATION_BYTES {
            return Err(Error::schema_invalid());
        }
        let authorization = project_token.into_authorization();
        let response = self.key_service.request(
            "POST",
            "/v1/workload-keys",
            Some(&authorization),
            Some("application/json"),
            &body,
            timeout,
        )?;
        let registration: WorkloadKeyRegistrationResult = response.decode_json(200)?;
        registration
            .validate_for_registration(request)
            .map_err(|_| response_invalid())?;
        Ok(registration)
    }
}

impl ManagedCandidateGrantDelivery for ManagedTlsClient {
    fn request_encryption_grant(
        &self,
        request: &ManagedCandidateEncryptionGrantRequest,
        timeout: Duration,
    ) -> Result<ManagedCandidateEncryptionResponse, Error> {
        request.validate()?;
        let body = canonical::canonical_bytes(request)?;
        let response = self.key_service.request(
            "POST",
            "/v1/managed-candidate-encryption-grants",
            None,
            Some("application/json"),
            &body,
            timeout,
        )?;
        let grant: ManagedCandidateEncryptionResponse = response.decode_json(200)?;
        grant.validate()?;
        Ok(grant)
    }
}

impl ManagedCandidateIngressDelivery for ManagedTlsClient {
    fn start(
        &self,
        request: &ManagedCandidateUploadRequest,
        timeout: Duration,
    ) -> Result<ManagedCandidateStart, Error> {
        request.validate()?;
        self.ingress
            .request(
                "POST",
                "/v1/managed-candidates",
                None,
                Some("application/json"),
                &canonical::canonical_bytes(request)?,
                timeout,
            )?
            .decode_json(200)
    }

    fn missing(
        &self,
        upload_id: UploadId,
        upload_token: &str,
        cursor: Option<&str>,
        timeout: Duration,
    ) -> Result<UploadMissingPage, Error> {
        validate_token(upload_token)?;
        if cursor.is_some_and(|value| {
            value.is_empty()
                || value.len() > 256
                || value
                    .bytes()
                    .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_'))
        }) {
            return Err(response_invalid());
        }
        let mut target = format!("/v1/managed-candidates/{upload_id}/missing?limit=100");
        if let Some(cursor) = cursor {
            target.push_str("&cursor=");
            target.push_str(cursor);
        }
        let authorization = format!("Bearer {upload_token}");
        self.ingress
            .request("GET", &target, Some(&authorization), None, &[], timeout)?
            .decode_json(200)
    }

    fn upload_object(
        &self,
        upload_url: &str,
        digest: Digest,
        bytes: &[u8],
        timeout: Duration,
    ) -> Result<(), Error> {
        if Digest::of(bytes) != digest {
            return Err(Error::object_digest_mismatch());
        }
        let target = self.ingress.upload_target(upload_url)?;
        let response = self.ingress.request(
            "PUT",
            target,
            None,
            Some("application/octet-stream"),
            bytes,
            timeout,
        )?;
        response.expect_empty(204)
    }

    fn commit(
        &self,
        upload_id: UploadId,
        upload_token: &str,
        timeout: Duration,
    ) -> Result<ManagedCandidateCommit, Error> {
        validate_token(upload_token)?;
        let target = format!("/v1/managed-candidates/{upload_id}/commit");
        let authorization = format!("Bearer {upload_token}");
        self.ingress
            .request("POST", &target, Some(&authorization), None, &[], timeout)?
            .decode_json(200)
    }

    fn cancel(
        &self,
        upload_id: UploadId,
        upload_token: &str,
        timeout: Duration,
    ) -> Result<ManagedCandidateStatus, Error> {
        validate_token(upload_token)?;
        let target = format!("/v1/managed-candidates/{upload_id}");
        let authorization = format!("Bearer {upload_token}");
        self.ingress
            .request("DELETE", &target, Some(&authorization), None, &[], timeout)?
            .decode_json(200)
    }
}

struct HttpResponse {
    body: Vec<u8>,
    status: u16,
}

impl HttpResponse {
    fn decode_json<T: serde::de::DeserializeOwned>(self, expected_status: u16) -> Result<T, Error> {
        if self.status != expected_status {
            return Err(decode_server_error(self.status, &self.body));
        }
        if self.body.is_empty() {
            return Err(response_invalid());
        }
        canonical::parse_strict(&self.body)
    }

    fn expect_empty(self, expected_status: u16) -> Result<(), Error> {
        if self.status != expected_status {
            return Err(decode_server_error(self.status, &self.body));
        }
        if !self.body.is_empty() {
            return Err(response_invalid());
        }
        Ok(())
    }
}

fn read_response(stream: &mut impl Read) -> Result<HttpResponse, Error> {
    let mut header = Vec::with_capacity(512);
    let mut byte = [0_u8; 1];
    while header.len() < MAX_HEADER_BYTES {
        if stream.read(&mut byte).map_err(|_| service_unavailable())? == 0 {
            return Err(response_invalid());
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !header.ends_with(b"\r\n\r\n") {
        return Err(response_invalid());
    }
    let text = std::str::from_utf8(&header).map_err(|_| response_invalid())?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(response_invalid)?;
    let mut content_length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(response_invalid)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(response_invalid());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(response_invalid());
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| response_invalid())?,
            );
        }
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_JSON_RESPONSE_BYTES {
        return Err(response_invalid());
    }
    let mut body = vec![0_u8; content_length];
    stream
        .read_exact(&mut body)
        .map_err(|_| service_unavailable())?;
    Ok(HttpResponse { body, status })
}

fn decode_server_error(status: u16, body: &[u8]) -> Error {
    if !body.is_empty()
        && let Ok(error) = canonical::parse_strict::<Error>(body)
    {
        return error;
    }
    if matches!(status, 429 | 502 | 503 | 504) {
        service_unavailable()
    } else {
        response_invalid()
    }
}

fn validate_authority(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 512
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'/' | b'?' | b'#' | b'@'))
    {
        return Err(endpoint_invalid());
    }
    Ok(())
}

fn official_authority(origin: &str) -> Result<&str, Error> {
    let authority = origin
        .strip_prefix("https://")
        .ok_or_else(endpoint_invalid)?;
    validate_authority(authority)?;
    if authority.len() > 253
        || authority.bytes().any(|byte| {
            !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && byte != b'-' && byte != b'.'
        })
        || !authority.contains('.')
        || authority.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        })
    {
        return Err(endpoint_invalid());
    }
    Ok(authority)
}

fn connect_resolved(destination: &str, timeout: Duration) -> Result<TcpStream, Error> {
    let host = destination
        .strip_suffix(":443")
        .ok_or_else(endpoint_invalid)?;
    let deadline = Instant::now() + timeout;
    let bounded = resolve_bounded(host, timeout)?;
    for ip_address in bounded {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let address = SocketAddr::new(ip_address, 443);
        if let Ok(stream) = TcpStream::connect_timeout(&address, deadline - now) {
            return Ok(stream);
        }
    }
    Err(service_unavailable())
}

fn resolve_bounded(host: &str, timeout: Duration) -> Result<Vec<std::net::IpAddr>, Error> {
    let host = host.to_owned();
    thread::Builder::new()
        .name("reproit-managed-dns".to_owned())
        .spawn(move || resolve_on_owned_runtime(&host, timeout))
        .map_err(|_| service_unavailable())?
        .join()
        .map_err(|_| service_unavailable())?
}

fn resolve_on_owned_runtime(host: &str, timeout: Duration) -> Result<Vec<std::net::IpAddr>, Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| service_unavailable())?;
    let mut builder = Resolver::builder_tokio().map_err(|_| service_unavailable())?;
    let options = builder.options_mut();
    options.attempts = 1;
    options.cache_size = 0;
    options.max_active_requests = 1;
    options.num_concurrent_reqs = 1;
    options.timeout = timeout;
    let resolver = builder.build().map_err(|_| service_unavailable())?;
    let lookup = runtime
        .block_on(tokio::time::timeout(timeout, resolver.lookup_ip(host)))
        .map_err(|_| service_unavailable())?
        .map_err(|_| service_unavailable())?;
    let addresses = collect_bounded_addresses(lookup.iter())?;
    drop(resolver);
    drop(runtime);
    Ok(addresses)
}

fn collect_bounded_addresses(
    addresses: impl IntoIterator<Item = std::net::IpAddr>,
) -> Result<Vec<std::net::IpAddr>, Error> {
    let addresses: Vec<_> = addresses.into_iter().take(MAX_DNS_ADDRESSES + 1).collect();
    if addresses.is_empty() || addresses.len() > MAX_DNS_ADDRESSES {
        return Err(service_unavailable());
    }
    Ok(addresses)
}

fn validate_request_component(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.len() > 16 || value.bytes().any(|byte| !byte.is_ascii_uppercase())
    {
        return Err(endpoint_invalid());
    }
    Ok(())
}

fn validate_target(value: &str) -> Result<(), Error> {
    if !value.starts_with('/')
        || value.len() > 4_096
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains('#')
    {
        return Err(endpoint_invalid());
    }
    Ok(())
}

fn validate_header_value(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 4_096
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() && byte != b' ')
    {
        return Err(endpoint_invalid());
    }
    Ok(())
}

fn validate_token(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_'))
    {
        return Err(response_invalid());
    }
    Ok(())
}

fn endpoint_invalid() -> Error {
    Error::new(
        ErrorCode::SchemaInvalid,
        "The managed TLS endpoint configuration is invalid.",
    )
}

fn response_invalid() -> Error {
    Error::new(
        ErrorCode::SchemaInvalid,
        "The managed service response is invalid.",
    )
}

fn service_unavailable() -> Error {
    Error::new(
        ErrorCode::ServiceUnavailable,
        "The managed capture service is unavailable.",
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn official_origin_accepts_one_canonical_https_origin() {
        assert_eq!(
            official_authority("https://cloud.reproit.com").unwrap(),
            "cloud.reproit.com"
        );
    }

    #[test]
    fn official_origin_rejects_noncanonical_and_non_origin_values() {
        for value in [
            "http://cloud.reproit.com",
            "https://cloud.reproit.com/",
            "https://user@example.com",
            "https://cloud.reproit.com/path",
            "https://cloud.reproit.com?query=yes",
            "https://cloud.reproit.com#fragment",
            "https://LOCAL.reproit.com",
            "https://localhost",
        ] {
            assert!(official_authority(value).is_err());
        }
    }

    #[test]
    fn resolved_address_count_has_an_exact_boundary() {
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            collect_bounded_addresses(std::iter::repeat_n(address, MAX_DNS_ADDRESSES))
                .unwrap()
                .len(),
            MAX_DNS_ADDRESSES
        );
        assert!(
            collect_bounded_addresses(std::iter::repeat_n(address, MAX_DNS_ADDRESSES + 1)).is_err()
        );
    }
}
