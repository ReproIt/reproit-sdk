use reproit_backend::config::{BackendSdk, ProjectConfig};
use reproit_core::{
    Error, ErrorCode, canonical,
    crypto::encode_base64url,
    identity::Digest,
    model::{Deployment, DeploymentFormat, ProcessingMode, Subject, SubjectFormat, Validate as _},
};
use serde::Serialize;

use crate::official_managed::official_managed_configuration;

const MAX_PROJECT_CONFIG_BYTES: usize = 65_536;
const PENDING_MANAGED_ORIGIN: &str = "pending-official-managed-origin";
const PENDING_SIGNER_ID: &str = "pending-managed-registration";
const PENDING_SUBJECT_URI: &str = "reproit-managed://pending-subject";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialManagedProject {
    project: ProjectConfig,
    source_revision: String,
}

impl OfficialManagedProject {
    pub fn from_build(
        project_toml: &str,
        build_repository_id: &str,
        source_revision: &str,
    ) -> Result<Self, Error> {
        Self::from_build_for_sdk(
            project_toml,
            build_repository_id,
            source_revision,
            BackendSdk::Rust,
        )
    }

    pub fn from_build_for_sdk(
        project_toml: &str,
        build_repository_id: &str,
        source_revision: &str,
        expected_sdk: BackendSdk,
    ) -> Result<Self, Error> {
        // Validate the installed release before the application captures any
        // customer state. An unbound package must fail without local capture.
        let _ = official_managed_configuration()?;
        if project_toml.is_empty() || project_toml.len() > MAX_PROJECT_CONFIG_BYTES {
            return Err(project_binding_invalid());
        }
        let project: ProjectConfig =
            toml::from_str(project_toml).map_err(|_| project_binding_invalid())?;
        project.validate().map_err(|_| project_binding_invalid())?;
        if project.processing_mode != ProcessingMode::Managed
            || project.sdk != expected_sdk
            || project.repository_id != build_repository_id
            || !valid_source_revision(source_revision)
        {
            return Err(project_binding_invalid());
        }
        Ok(Self {
            project,
            source_revision: source_revision.to_owned(),
        })
    }

    pub(crate) fn deployment(&self) -> Result<Deployment, Error> {
        self.deployment_for_subject_runtime(runtime_capability(self.project.sdk))
    }

    pub(crate) fn deployment_for_subject_runtime(
        &self,
        runtime_capability: &str,
    ) -> Result<Deployment, Error> {
        let pending_digest = Digest::of(b"pending managed subject");
        let deployment = Deployment {
            format: DeploymentFormat::V1,
            organization_id: self.project.organization_id,
            processing_mode: ProcessingMode::Managed,
            project_id: self.project.project_id,
            repository_id: self.project.repository_id.clone(),
            runtime_capabilities: vec![runtime_capability.to_owned()],
            runtime_endpoint: PENDING_MANAGED_ORIGIN.to_owned(),
            service_id: self.project.service_id,
            service_path: self.project.service_path.clone(),
            signature: encode_base64url(&[0_u8; 64]),
            signed_at: "1970-01-01T00:00:00.000Z".parse()?,
            signer_key_id: PENDING_SIGNER_ID.to_owned(),
            source_revision: self.source_revision.clone(),
            subject: Subject {
                architecture: "architecture.native".to_owned(),
                arguments: Vec::new(),
                artifact_digest: pending_digest,
                artifact_media_type: "application/vnd.reproit.subject-closure.v1+json".to_owned(),
                artifact_uri: PENDING_SUBJECT_URI.to_owned(),
                environment_names: Vec::new(),
                executable: "/reproit/subject/application/pending".to_owned(),
                format: SubjectFormat::V1,
                operating_system: "operating-system.linux".to_owned(),
                working_directory: "/reproit/subject/work".to_owned(),
            },
        };
        deployment.validate()?;
        Ok(deployment)
    }
}

fn runtime_capability(sdk: BackendSdk) -> &'static str {
    match sdk {
        BackendSdk::Dotnet => "runtime.dotnet-native",
        BackendSdk::Go => "runtime.go-native",
        BackendSdk::Nodejs => "runtime.node-native",
        BackendSdk::Python => "runtime.python-native",
        BackendSdk::Rust => "runtime.rust-native",
    }
}

#[derive(Serialize)]
struct StableManagedDeploymentBinding<'a> {
    format: DeploymentFormat,
    organization_id: reproit_core::identity::OrganizationId,
    processing_mode: ProcessingMode,
    project_id: reproit_core::identity::ProjectId,
    repository_id: &'a str,
    runtime_capabilities: &'a [String],
    runtime_endpoint: &'a str,
    service_id: reproit_core::identity::ServiceId,
    service_path: &'a str,
    source_revision: &'a str,
    subject: &'a Subject,
}

pub(crate) fn managed_deployment_binding_digest(deployment: &Deployment) -> Result<Digest, Error> {
    if deployment.processing_mode != ProcessingMode::Managed {
        return Err(project_binding_invalid());
    }
    canonical::digest(&StableManagedDeploymentBinding {
        format: deployment.format,
        organization_id: deployment.organization_id,
        processing_mode: deployment.processing_mode,
        project_id: deployment.project_id,
        repository_id: &deployment.repository_id,
        runtime_capabilities: &deployment.runtime_capabilities,
        runtime_endpoint: &deployment.runtime_endpoint,
        service_id: deployment.service_id,
        service_path: &deployment.service_path,
        source_revision: &deployment.source_revision,
        subject: &deployment.subject,
    })
}

fn valid_source_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn project_binding_invalid() -> Error {
    Error::new(
        ErrorCode::ConfigConflict,
        "The managed project build binding is invalid.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROJECT: &str = r#"
format = 1
organization_id = "org_01890f3e-7b1c-7cc0-8a1b-123456789abd"
profile = "backend"
profile_format = 1
processing_mode = "managed"
project_id = "prj_01890f3e-7b1c-7cc0-8a1b-123456789abe"
repository_id = "source.example/acme/commerce"
sdk = "rust"
service_id = "svc_01890f3e-7b1c-7cc0-8a1b-123456789abf"
service_path = "services/orders"

[run]
arguments = ["serve"]
program = "orders"
working_directory = "services/orders"

[source]
remote = "origin"
"#;

    #[test]
    fn project_binding_accepts_only_exact_managed_rust_scope() {
        if official_managed_configuration().is_err() {
            return;
        }
        let project = OfficialManagedProject::from_build(
            PROJECT,
            "source.example/acme/commerce",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .unwrap();
        let deployment = project.deployment().unwrap();
        assert_eq!(deployment.repository_id, "source.example/acme/commerce");
        assert_eq!(deployment.runtime_endpoint, PENDING_MANAGED_ORIGIN);
        assert!(
            OfficialManagedProject::from_build(
                PROJECT,
                "source.example/acme/commerce",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .is_ok()
        );

        assert!(
            OfficialManagedProject::from_build(
                PROJECT,
                "source.example/acme/other",
                "0123456789abcdef0123456789abcdef01234567",
            )
            .is_err()
        );
        for revision in [
            "0123456789abcdef0123456789abcdef0123456789",
            "0123456789abcdef0123456789abcdef0123456A",
        ] {
            assert!(
                OfficialManagedProject::from_build(
                    PROJECT,
                    "source.example/acme/commerce",
                    revision,
                )
                .is_err()
            );
        }
        assert!(
            OfficialManagedProject::from_build(
                PROJECT,
                "source.example/acme/commerce",
                "0123456789abcdef",
            )
            .is_err()
        );
    }

    #[test]
    fn project_binding_rejects_one_byte_beyond_the_bound() {
        let project = "a".repeat(MAX_PROJECT_CONFIG_BYTES + 1);
        assert!(
            OfficialManagedProject::from_build(
                &project,
                "source.example/acme/commerce",
                "0123456789abcdef0123456789abcdef01234567",
            )
            .is_err()
        );
    }

    #[test]
    fn deployment_binding_ignores_only_signing_state() {
        if official_managed_configuration().is_err() {
            return;
        }
        let project = OfficialManagedProject::from_build(
            PROJECT,
            "source.example/acme/commerce",
            "0123456789abcdef0123456789abcdef01234567",
        )
        .unwrap();
        let deployment = project.deployment().unwrap();
        let digest = managed_deployment_binding_digest(&deployment).unwrap();
        let mut changed = deployment.clone();
        changed.signed_at = "2026-01-01T00:00:00.000Z".parse().unwrap();
        changed.signer_key_id = "another-key".to_owned();
        changed.signature = encode_base64url(&[0x55; 64]);
        assert_eq!(managed_deployment_binding_digest(&changed).unwrap(), digest);
        changed.source_revision = "fedcba9876543210fedcba9876543210fedcba98".to_owned();
        assert_ne!(managed_deployment_binding_digest(&changed).unwrap(), digest);
    }
}
