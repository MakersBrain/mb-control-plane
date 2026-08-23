//! Dormant immutable full-fleet route-set publication substrate.
//!
//! This module is neutral between ordinary projection publication and recovery
//! maintenance/restore. The database owns authorization and transition state;
//! this module owns deterministic filesystem names, exact immutable evidence,
//! selector identity, and crash-safe local publication. It never reads or
//! clones route bytes from `current`.
//!
//! Active cutover is deliberately forbidden until every normal route writer is
//! copy-on-write. A future caller must also hold authenticated database
//! publication authority and the cross-process `SharedOdooHostGuard` across the
//! complete build/publication/reload observation. Registering this module does
//! not wire it into any writer.
#![allow(dead_code)]

use std::fs::File;
use std::io::{self, BufReader, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::gateway::{
    ROUTE_SET_GENERATION_FILE, RouteSetGenerationIdentity, RouteSetPublicationKind,
    parse_route_set_generation_config, route_set_generation_config,
};
use super::route_generation_fs::{
    CURRENT_SELECTOR, FILE_MODE, GENERATIONS_DIRECTORY, GENERATIONS_MODE, MAX_ROUTE_BYTES,
    PriorSelector, ROUTE_ROOT_MODE, SEALED_MODE, STAGING_MODE, create_at_file, cstring,
    digest_bytes, ensure_same_filesystem, invalid_input, invalid_state, mkdir_at,
    observe_current_selector, observe_generation_selector, observe_selector_from_handles,
    observe_selector_target, open_at_append_file, open_at_directory, open_at_file, open_directory,
    read_bounded, read_link_at, rename_exchange, symlink_at, unlink_at, validate_current_selector,
    validate_digest, validate_directory, validate_regular_file, validate_route_bytes,
    validate_selector_target, visit_generation_entries,
};

const INTENT_FILE: &str = ".route-set-intent-v1";
const EVIDENCE_FILE: &str = ".route-set-evidence-v1";
const PUBLICATION_MARKER_FILE: &str = ".route-set-publication-started-v1";
const RETENTION_MARKER_FILE: &str = ".route-set-retention-v1";
/// Exact route-only digest preimage: this domain, then for each strictly
/// UUID-ordered row its 16 UUID bytes, signed i64 generation in big-endian
/// order, followed by projection digest, disposition, applied-rendered digest,
/// and candidate rendered digest. Every text field is prefixed by its unsigned
/// big-endian u32 UTF-8 byte length.
const DIGEST_DOMAIN: &[u8] = b"mb-route-set-publication-v1\0";
pub(super) const MAX_ROUTES: usize = 500;
const MAX_EVIDENCE_LINE_BYTES: usize = 512;

fn selector_suffix(kind: RouteSetPublicationKind) -> &'static str {
    match kind {
        RouteSetPublicationKind::Projection => "projection",
        RouteSetPublicationKind::RecoveryMaintenance => "recovery-maintenance",
        RouteSetPublicationKind::RecoveryRestore => "recovery-restore",
        RouteSetPublicationKind::Startup => "startup",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct RouteSetGenerationName(String);

impl RouteSetGenerationName {
    pub(super) fn new(publication_id: Uuid, kind: RouteSetPublicationKind) -> Self {
        Self(format!(
            "route-{}-{}",
            publication_id.simple(),
            selector_suffix(kind)
        ))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn selector_target(&self) -> String {
        format!("{GENERATIONS_DIRECTORY}/{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RouteSetGenerationIntent {
    protocol_version: u8,
    pub publication_id: Uuid,
    pub publication_kind: RouteSetPublicationKind,
    pub global_fence_token: i64,
    scope: RouteSetGenerationIntentScope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RouteSetGenerationIntentScope {
    Fleet {
        startup_effect_run_id: Uuid,
    },
    Workshop {
        target_workshop_id: Uuid,
        target_route_fence_token: i64,
    },
}

impl RouteSetGenerationIntent {
    pub(super) fn new(
        publication_id: Uuid,
        publication_kind: RouteSetPublicationKind,
        global_fence_token: i64,
        target_workshop_id: Uuid,
        target_route_fence_token: i64,
    ) -> io::Result<Self> {
        let intent = Self {
            protocol_version: 1,
            publication_id,
            publication_kind,
            global_fence_token,
            scope: RouteSetGenerationIntentScope::Workshop {
                target_workshop_id,
                target_route_fence_token,
            },
        };
        intent.validate()?;
        Ok(intent)
    }

    pub(super) fn new_startup(
        publication_id: Uuid,
        startup_effect_run_id: Uuid,
        global_fence_token: i64,
    ) -> io::Result<Self> {
        let intent = Self {
            protocol_version: 1,
            publication_id,
            publication_kind: RouteSetPublicationKind::Startup,
            global_fence_token,
            scope: RouteSetGenerationIntentScope::Fleet {
                startup_effect_run_id,
            },
        };
        intent.validate()?;
        Ok(intent)
    }

    fn validate(&self) -> io::Result<()> {
        let scope_valid = match (self.publication_kind, &self.scope) {
            (
                RouteSetPublicationKind::Startup,
                RouteSetGenerationIntentScope::Fleet {
                    startup_effect_run_id,
                },
            ) => !startup_effect_run_id.is_nil(),
            (
                RouteSetPublicationKind::Projection
                | RouteSetPublicationKind::RecoveryMaintenance
                | RouteSetPublicationKind::RecoveryRestore,
                RouteSetGenerationIntentScope::Workshop {
                    target_workshop_id,
                    target_route_fence_token,
                },
            ) => !target_workshop_id.is_nil() && *target_route_fence_token > 0,
            _ => false,
        };
        if self.protocol_version != 1
            || self.publication_id.is_nil()
            || self.global_fence_token <= 0
            || !scope_valid
        {
            return Err(invalid_input("route-set generation intent is invalid"));
        }
        Ok(())
    }

    fn name(&self) -> RouteSetGenerationName {
        RouteSetGenerationName::new(self.publication_id, self.publication_kind)
    }

    fn identity(&self, route_set_digest: String) -> io::Result<RouteSetGenerationIdentity> {
        match &self.scope {
            RouteSetGenerationIntentScope::Fleet {
                startup_effect_run_id,
            } => RouteSetGenerationIdentity::new_startup(
                self.publication_id,
                *startup_effect_run_id,
                self.global_fence_token,
                route_set_digest,
            ),
            RouteSetGenerationIntentScope::Workshop {
                target_workshop_id,
                target_route_fence_token,
            } => RouteSetGenerationIdentity::new(
                self.publication_id,
                self.publication_kind,
                self.global_fence_token,
                *target_workshop_id,
                *target_route_fence_token,
                route_set_digest,
            ),
        }
        .map_err(|error| io::Error::other(error.1))
    }

    const fn startup_effect_run_id(&self) -> Option<Uuid> {
        match &self.scope {
            RouteSetGenerationIntentScope::Fleet {
                startup_effect_run_id,
            } => Some(*startup_effect_run_id),
            RouteSetGenerationIntentScope::Workshop { .. } => None,
        }
    }

    const fn target_scope(&self) -> Option<(Uuid, i64)> {
        match &self.scope {
            RouteSetGenerationIntentScope::Fleet { .. } => None,
            RouteSetGenerationIntentScope::Workshop {
                target_workshop_id,
                target_route_fence_token,
            } => Some((*target_workshop_id, *target_route_fence_token)),
        }
    }

    fn canonical_bytes(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        bytes.push(b'\n');
        if bytes.len() > 1024 {
            return Err(invalid_input("route-set intent exceeds its bound"));
        }
        Ok(bytes)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StartupRouteSetGenerationIntentWire {
    protocol_version: u8,
    publication_id: Uuid,
    publication_kind: RouteSetPublicationKind,
    startup_effect_run_id: Uuid,
    global_fence_token: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkshopRouteSetGenerationIntentWire {
    protocol_version: u8,
    publication_id: Uuid,
    publication_kind: RouteSetPublicationKind,
    global_fence_token: i64,
    target_workshop_id: Uuid,
    target_route_fence_token: i64,
}

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum RouteSetGenerationIntentWire {
    Startup(StartupRouteSetGenerationIntentWire),
    Workshop(WorkshopRouteSetGenerationIntentWire),
}

impl Serialize for RouteSetGenerationIntent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.scope {
            RouteSetGenerationIntentScope::Fleet {
                startup_effect_run_id,
            } => StartupRouteSetGenerationIntentWire {
                protocol_version: self.protocol_version,
                publication_id: self.publication_id,
                publication_kind: self.publication_kind,
                startup_effect_run_id: *startup_effect_run_id,
                global_fence_token: self.global_fence_token,
            }
            .serialize(serializer),
            RouteSetGenerationIntentScope::Workshop {
                target_workshop_id,
                target_route_fence_token,
            } => WorkshopRouteSetGenerationIntentWire {
                protocol_version: self.protocol_version,
                publication_id: self.publication_id,
                publication_kind: self.publication_kind,
                global_fence_token: self.global_fence_token,
                target_workshop_id: *target_workshop_id,
                target_route_fence_token: *target_route_fence_token,
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for RouteSetGenerationIntent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let intent = match RouteSetGenerationIntentWire::deserialize(deserializer)? {
            RouteSetGenerationIntentWire::Startup(wire) => Self {
                protocol_version: wire.protocol_version,
                publication_id: wire.publication_id,
                publication_kind: wire.publication_kind,
                global_fence_token: wire.global_fence_token,
                scope: RouteSetGenerationIntentScope::Fleet {
                    startup_effect_run_id: wire.startup_effect_run_id,
                },
            },
            RouteSetGenerationIntentWire::Workshop(wire) => Self {
                protocol_version: wire.protocol_version,
                publication_id: wire.publication_id,
                publication_kind: wire.publication_kind,
                global_fence_token: wire.global_fence_token,
                scope: RouteSetGenerationIntentScope::Workshop {
                    target_workshop_id: wire.target_workshop_id,
                    target_route_fence_token: wire.target_route_fence_token,
                },
            },
        };
        intent.validate().map_err(serde::de::Error::custom)?;
        Ok(intent)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum RouteDisposition {
    Present,
    Absent,
}

impl RouteDisposition {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct RouteSetSealEvidence {
    pub workshop_id: Uuid,
    pub projection_generation: i64,
    pub projection_digest: String,
    pub disposition: RouteDisposition,
    pub applied_rendered_digest: Option<String>,
    pub rendered_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GenerationPhase {
    Staging,
    Sealed,
    Published,
}

#[derive(Clone, Debug)]
pub(super) struct SealedRouteSetGeneration {
    pub name: RouteSetGenerationName,
    pub identity: RouteSetGenerationIdentity,
    pub route_count: usize,
    pub present_route_count: usize,
    pub selector: PriorSelector,
}

pub(super) struct RouteSetGenerationSealer<'a> {
    generation: &'a mut RouteSetGenerationDirectory,
    hasher: Sha256,
    previous_workshop: Option<Uuid>,
    route_count: usize,
    present_route_count: usize,
    manifest_reader: BufReader<File>,
    manifest_append: File,
    existing_manifest_exhausted: bool,
}

#[derive(Debug)]
pub(super) struct RouteSetGenerationDirectory {
    root_path: PathBuf,
    root: File,
    generations: File,
    directory: File,
    directory_dev: u64,
    directory_ino: u64,
    intent: RouteSetGenerationIntent,
    name: RouteSetGenerationName,
    phase: GenerationPhase,
    sealed: Option<SealedRouteSetGeneration>,
}

impl RouteSetGenerationDirectory {
    pub(super) fn create_or_open(
        route_root: &Path,
        intent: RouteSetGenerationIntent,
    ) -> io::Result<Self> {
        intent.validate()?;
        let root = open_directory(route_root)?;
        validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
        let generations_name = cstring(GENERATIONS_DIRECTORY)?;
        let generations_created = match mkdir_at(&root, &generations_name, GENERATIONS_MODE) {
            Ok(()) => {
                root.sync_all()?;
                true
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error),
        };
        let generations = open_at_directory(&root, &generations_name)?;
        if generations_created {
            generations.set_permissions(std::fs::Permissions::from_mode(GENERATIONS_MODE))?;
            generations.sync_all()?;
        }
        validate_directory(
            &generations,
            GENERATIONS_MODE,
            "route generations directory",
        )?;
        ensure_same_filesystem(&root, &generations)?;

        let name = intent.name();
        let generation_name = cstring(name.as_str())?;
        let created = match mkdir_at(&generations, &generation_name, STAGING_MODE) {
            Ok(()) => {
                generations.sync_all()?;
                true
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error),
        };
        let directory = open_at_directory(&generations, &generation_name)?;
        validate_directory(&directory, STAGING_MODE, "route-set staging directory")?;
        ensure_same_filesystem(&generations, &directory)?;
        let metadata = directory.metadata()?;
        let generation = Self {
            root_path: route_root.to_owned(),
            root,
            generations,
            directory,
            directory_dev: metadata.dev(),
            directory_ino: metadata.ino(),
            intent,
            name,
            phase: GenerationPhase::Staging,
            sealed: None,
        };
        generation.validate_named_directory(STAGING_MODE)?;
        generation.refuse_if_selected()?;
        if created {
            generation.write_intent()?;
        } else {
            let entries = inspect_entries(&generation.directory, true, true, false)?;
            if entries.intent_present {
                generation.verify_intent()?;
                if entries.identity_present {
                    ensure_identity_matches_intent(
                        &read_identity(&generation.directory)?,
                        &generation.intent,
                    )?;
                }
            } else if entries.total_route_count == 0
                && !entries.evidence_present
                && !entries.identity_present
                && !entries.publication_marker_present
            {
                generation.write_intent()?;
            } else {
                return Err(invalid_state(
                    "preexisting route-set generation has no exact intent",
                ));
            }
        }
        Ok(generation)
    }

    pub(super) fn open_existing_sealed(
        route_root: &Path,
        intent: RouteSetGenerationIntent,
        route_set_digest: &str,
        route_count: usize,
        present_route_count: usize,
    ) -> io::Result<Self> {
        Self::open_existing(
            route_root,
            intent,
            route_set_digest,
            route_count,
            present_route_count,
            GenerationPhase::Sealed,
        )
    }

    pub(super) fn open_existing_published(
        route_root: &Path,
        intent: RouteSetGenerationIntent,
        route_set_digest: &str,
        route_count: usize,
        present_route_count: usize,
    ) -> io::Result<Self> {
        Self::open_existing(
            route_root,
            intent,
            route_set_digest,
            route_count,
            present_route_count,
            GenerationPhase::Published,
        )
    }

    fn open_existing(
        route_root: &Path,
        intent: RouteSetGenerationIntent,
        route_set_digest: &str,
        route_count: usize,
        present_route_count: usize,
        phase: GenerationPhase,
    ) -> io::Result<Self> {
        intent.validate()?;
        validate_digest(route_set_digest, "route-set digest")?;
        validate_counts(route_count, present_route_count)?;
        let root = open_directory(route_root)?;
        validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
        let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
        validate_directory(
            &generations,
            GENERATIONS_MODE,
            "route generations directory",
        )?;
        ensure_same_filesystem(&root, &generations)?;
        let name = intent.name();
        let directory = open_at_directory(&generations, &cstring(name.as_str())?)?;
        validate_directory(&directory, SEALED_MODE, "sealed route-set generation")?;
        ensure_same_filesystem(&generations, &directory)?;
        let metadata = directory.metadata()?;
        let identity = intent.identity(route_set_digest.to_owned())?;
        let selector =
            PriorSelector::from_recorded(name.selector_target(), metadata.dev(), metadata.ino())?;
        let generation = Self {
            root_path: route_root.to_owned(),
            root,
            generations,
            directory,
            directory_dev: metadata.dev(),
            directory_ino: metadata.ino(),
            intent,
            name: name.clone(),
            phase,
            sealed: Some(SealedRouteSetGeneration {
                name,
                identity,
                route_count,
                present_route_count,
                selector,
            }),
        };
        generation.validate_named_directory(SEALED_MODE)?;
        generation.verify_sealed_bytes()?;
        generation.validate_named_directory(SEALED_MODE)?;
        Ok(generation)
    }

    #[cfg(test)]
    fn path(&self) -> PathBuf {
        self.root_path
            .join(GENERATIONS_DIRECTORY)
            .join(self.name.as_str())
    }

    pub(super) fn begin_seal(&mut self) -> io::Result<RouteSetGenerationSealer<'_>> {
        if self.phase != GenerationPhase::Staging {
            return Err(invalid_state("route-set generation is not staging"));
        }
        self.validate_named_directory(STAGING_MODE)?;
        self.verify_intent()?;
        let manifest_name = cstring(EVIDENCE_FILE)?;
        match create_at_file(&self.directory, &manifest_name, FILE_MODE) {
            Ok(file) => {
                file.sync_all()?;
                file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
                validate_regular_file(&file, FILE_MODE, "route-set evidence manifest")?;
                self.directory.sync_all()?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let manifest_read = open_at_file(&self.directory, &manifest_name)?;
        validate_regular_file(&manifest_read, FILE_MODE, "route-set evidence manifest")?;
        let manifest_append = open_at_append_file(&self.directory, &manifest_name)?;
        validate_regular_file(&manifest_append, FILE_MODE, "route-set evidence manifest")?;
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        Ok(RouteSetGenerationSealer {
            generation: self,
            hasher,
            previous_workshop: None,
            route_count: 0,
            present_route_count: 0,
            manifest_reader: BufReader::new(manifest_read),
            manifest_append,
            existing_manifest_exhausted: false,
        })
    }

    fn finish_seal(
        &mut self,
        hasher: Sha256,
        route_count: usize,
        present_route_count: usize,
    ) -> io::Result<&SealedRouteSetGeneration> {
        validate_counts(route_count, present_route_count)?;
        let entries = inspect_entries(&self.directory, true, true, false)?;
        if entries.total_route_count != present_route_count
            || !entries.intent_present
            || !entries.evidence_present
            || entries.publication_marker_present
        {
            return Err(invalid_state(
                "route-set staging membership differs from evidence",
            ));
        }
        let route_set_digest = format!("sha256:{:x}", hasher.finalize());
        let identity = self.intent.identity(route_set_digest)?;
        let config =
            route_set_generation_config(&identity).map_err(|error| io::Error::other(error.1))?;
        write_create_only_or_verify(
            &self.directory,
            ROUTE_SET_GENERATION_FILE,
            config.as_bytes(),
            "route-set generation identity",
        )?;
        let entries = inspect_entries(&self.directory, true, true, false)?;
        if entries.total_route_count != present_route_count
            || !entries.intent_present
            || !entries.evidence_present
            || !entries.identity_present
            || entries.publication_marker_present
        {
            return Err(invalid_state("route-set generation changed while sealing"));
        }
        self.directory
            .set_permissions(std::fs::Permissions::from_mode(SEALED_MODE))?;
        self.directory.sync_all()?;
        self.generations.sync_all()?;
        self.validate_named_directory(SEALED_MODE)?;
        let selector = PriorSelector::from_recorded(
            self.name.selector_target(),
            self.directory_dev,
            self.directory_ino,
        )?;
        self.phase = GenerationPhase::Sealed;
        self.sealed = Some(SealedRouteSetGeneration {
            name: self.name.clone(),
            identity,
            route_count,
            present_route_count,
            selector,
        });
        self.verify_sealed_bytes()?;
        self.validate_named_directory(SEALED_MODE)?;
        Ok(self.sealed.as_ref().expect("route-set seal was assigned"))
    }

    pub(super) fn publish(&mut self, expected_prior: &PriorSelector) -> io::Result<PriorSelector> {
        self.publish_with_hooks(expected_prior, || Ok(()), || Ok(()))
    }

    fn publish_with_hooks(
        &mut self,
        expected_prior: &PriorSelector,
        before_exchange: impl FnOnce() -> io::Result<()>,
        after_exchange: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<PriorSelector> {
        if self.phase != GenerationPhase::Sealed {
            return Err(invalid_state("only a sealed route-set may be published"));
        }
        self.validate_named_directory(SEALED_MODE)?;
        self.verify_sealed_bytes()?;
        if &observe_selector_from_handles(&self.root, &self.generations)? != expected_prior {
            return Err(invalid_state(
                "current selector differs from recorded prior",
            ));
        }
        self.install_publication_marker()?;
        self.phase = GenerationPhase::Published;
        self.exchange_to_candidate(expected_prior, before_exchange, after_exchange)
    }

    fn exchange_to_candidate(
        &mut self,
        expected_prior: &PriorSelector,
        before_exchange: impl FnOnce() -> io::Result<()>,
        after_exchange: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<PriorSelector> {
        if self.phase != GenerationPhase::Published {
            return Err(invalid_state("route-set publication marker is absent"));
        }
        self.validate_named_directory(SEALED_MODE)?;
        self.verify_sealed_bytes()?;
        let candidate_target = self.name.selector_target();
        before_exchange()?;
        let artifact = cstring(exchange_artifact_name(
            &self.intent,
            SelectorExchange::Publish,
        ))?;
        let current = cstring(CURRENT_SELECTOR)?;
        symlink_at(&cstring(&candidate_target)?, &self.root, &artifact)?;
        if let Err(error) = self.root.sync_all() {
            let _ = unlink_at(&self.root, &artifact, false);
            return Err(error);
        }
        let pre_exchange = (|| {
            if &observe_selector_from_handles(&self.root, &self.generations)? != expected_prior {
                return Err(invalid_state(
                    "current selector changed immediately before route-set exchange",
                ));
            }
            self.validate_named_directory(SEALED_MODE)?;
            self.verify_sealed_bytes()?;
            let sealed = self
                .sealed
                .as_ref()
                .ok_or_else(|| invalid_state("route-set has no seal"))?;
            if observe_selector_target(&self.generations, candidate_target.clone())?
                != sealed.selector
            {
                return Err(invalid_state(
                    "route-set candidate identity changed before exchange",
                ));
            }
            Ok(())
        })();
        if let Err(error) = pre_exchange {
            let _ = unlink_at(&self.root, &artifact, false);
            let _ = self.root.sync_all();
            return Err(error);
        }
        if let Err(error) = rename_exchange(&self.root, &artifact, &current) {
            let _ = unlink_at(&self.root, &artifact, false);
            return Err(error);
        }
        self.root.sync_all()?;
        let captured =
            observe_selector_target(&self.generations, read_link_at(&self.root, &artifact)?)?;
        if &captured != expected_prior {
            return Err(invalid_state(
                "selector changed before route-set publication",
            ));
        }
        self.observe_selected()?;
        after_exchange()?;
        unlink_at(&self.root, &artifact, false)?;
        self.root.sync_all()?;
        Ok(captured)
    }

    fn resume_published_from_prior(
        &mut self,
        expected_prior: &PriorSelector,
    ) -> io::Result<PriorSelector> {
        self.exchange_to_candidate(expected_prior, || Ok(()), || Ok(()))
    }

    pub(super) fn observe_selected(&self) -> io::Result<&SealedRouteSetGeneration> {
        if self.phase != GenerationPhase::Published {
            return Err(invalid_state("route-set publication has not started"));
        }
        let expected = self.name.selector_target();
        validate_current_selector(&self.root, &expected)?;
        self.validate_named_directory(SEALED_MODE)?;
        self.verify_sealed_bytes()?;
        validate_current_selector(&self.root, &expected)?;
        Ok(self
            .sealed
            .as_ref()
            .expect("published route-set has a seal"))
    }

    fn restore_prior(&mut self, prior: &PriorSelector) -> io::Result<()> {
        if self.phase != GenerationPhase::Published {
            return Err(invalid_state(
                "only a published route-set may restore prior",
            ));
        }
        self.observe_selected()?;
        if &observe_selector_target(&self.generations, prior.target().to_owned())? != prior {
            return Err(invalid_state("recorded prior selector identity changed"));
        }
        let artifact = cstring(exchange_artifact_name(
            &self.intent,
            SelectorExchange::Restore,
        ))?;
        let current = cstring(CURRENT_SELECTOR)?;
        symlink_at(&cstring(prior.target())?, &self.root, &artifact)?;
        if let Err(error) = self.root.sync_all() {
            let _ = unlink_at(&self.root, &artifact, false);
            return Err(error);
        }
        if let Err(error) = rename_exchange(&self.root, &artifact, &current) {
            let _ = unlink_at(&self.root, &artifact, false);
            return Err(error);
        }
        self.root.sync_all()?;
        if read_link_at(&self.root, &artifact)? != self.name.selector_target()
            || &observe_selector_from_handles(&self.root, &self.generations)? != prior
        {
            return Err(invalid_state("prior selector restoration differs"));
        }
        unlink_at(&self.root, &artifact, false)?;
        self.root.sync_all()
    }

    pub(super) fn dispose(mut self) -> io::Result<()> {
        if self.phase == GenerationPhase::Published {
            return Err(invalid_state("published route-set cannot be disposed"));
        }
        self.refuse_if_selected()?;
        let mode = if self.phase == GenerationPhase::Staging {
            STAGING_MODE
        } else {
            SEALED_MODE
        };
        self.validate_named_directory(mode)?;
        let entries = inspect_entries(
            &self.directory,
            true,
            self.phase == GenerationPhase::Sealed,
            false,
        )?;
        if !entries.intent_present {
            return Err(invalid_state("route-set has no exact intent"));
        }
        dispose_entries(&self.directory, self.phase == GenerationPhase::Sealed)?;
        self.directory.sync_all()?;
        self.validate_named_directory(mode)?;
        unlink_at(&self.generations, &cstring(self.name.as_str())?, true)?;
        self.generations.sync_all()?;
        self.phase = GenerationPhase::Published;
        Ok(())
    }

    fn write_intent(&self) -> io::Result<()> {
        write_create_only_or_verify(
            &self.directory,
            INTENT_FILE,
            &self.intent.canonical_bytes()?,
            "route-set intent",
        )
    }

    fn verify_intent(&self) -> io::Result<()> {
        verify_intent_file(&self.directory, &self.intent)
    }

    fn install_publication_marker(&self) -> io::Result<()> {
        let identity = &self
            .sealed
            .as_ref()
            .ok_or_else(|| invalid_state("route-set has no seal"))?
            .identity;
        write_create_only_or_verify(
            &self.directory,
            PUBLICATION_MARKER_FILE,
            &identity_line(identity)?,
            "route-set publication marker",
        )
    }

    fn verify_sealed_bytes(&self) -> io::Result<()> {
        self.verify_intent()?;
        let sealed = self
            .sealed
            .as_ref()
            .ok_or_else(|| invalid_state("route-set has no seal"))?;
        let identity = read_identity(&self.directory)?;
        if identity != sealed.identity {
            return Err(invalid_state("route-set identity changed"));
        }
        verify_evidence_manifest(
            &self.directory,
            sealed.route_count,
            sealed.present_route_count,
            &identity.route_set_digest,
        )?;
        let published = self.phase == GenerationPhase::Published;
        let entries = inspect_entries(&self.directory, true, true, published)?;
        if entries.total_route_count != sealed.present_route_count
            || !entries.intent_present
            || !entries.evidence_present
            || !entries.identity_present
            || entries.publication_marker_present != published
        {
            return Err(invalid_state("sealed route-set membership changed"));
        }
        if published {
            verify_marker_identity(&self.directory, &identity)?;
        }
        Ok(())
    }

    fn validate_named_directory(&self, mode: u32) -> io::Result<()> {
        validate_named_identity(
            &self.generations,
            &self.directory,
            self.name.as_str(),
            mode,
            self.directory_dev,
            self.directory_ino,
        )
    }

    fn refuse_if_selected(&self) -> io::Result<()> {
        match read_link_at(&self.root, &cstring(CURRENT_SELECTOR)?) {
            Ok(target) if target == self.name.selector_target() => {
                Err(invalid_state("selected route-set is not disposable"))
            }
            Ok(target) => validate_selector_target(&target),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl<'a> RouteSetGenerationSealer<'a> {
    pub(super) const fn publication_kind(&self) -> RouteSetPublicationKind {
        self.generation.intent.publication_kind
    }

    pub(super) const fn target_workshop_id(&self) -> Option<Uuid> {
        match self.generation.intent.target_scope() {
            Some((workshop_id, _)) => Some(workshop_id),
            None => None,
        }
    }

    pub(super) fn stage_present(
        &mut self,
        workshop_id: Uuid,
        projection_generation: i64,
        projection_digest: &str,
        applied_rendered_digest: &str,
        contents: &[u8],
    ) -> io::Result<RouteSetSealEvidence> {
        self.stage_present_with_baseline(
            workshop_id,
            projection_generation,
            projection_digest,
            Some(applied_rendered_digest),
            contents,
        )
    }

    pub(super) fn stage_startup_present(
        &mut self,
        workshop_id: Uuid,
        projection_generation: i64,
        projection_digest: &str,
        applied_rendered_digest: Option<&str>,
        contents: &[u8],
    ) -> io::Result<RouteSetSealEvidence> {
        if self.publication_kind() != RouteSetPublicationKind::Startup {
            return Err(invalid_input("nullable baseline is startup-only"));
        }
        self.stage_present_with_baseline(
            workshop_id,
            projection_generation,
            projection_digest,
            applied_rendered_digest,
            contents,
        )
    }

    fn stage_present_with_baseline(
        &mut self,
        workshop_id: Uuid,
        projection_generation: i64,
        projection_digest: &str,
        applied_rendered_digest: Option<&str>,
        contents: &[u8],
    ) -> io::Result<RouteSetSealEvidence> {
        self.validate_next(workshop_id)?;
        self.validate_capacity()?;
        validate_projection(projection_generation, projection_digest)?;
        if let Some(digest) = applied_rendered_digest {
            validate_digest(digest, "applied rendered digest")?;
        }
        validate_route_bytes(contents)?;
        write_create_only_or_verify(
            &self.generation.directory,
            &format!("{workshop_id}.conf"),
            contents,
            "route-set route",
        )?;
        let evidence = RouteSetSealEvidence {
            workshop_id,
            projection_generation,
            projection_digest: projection_digest.to_owned(),
            disposition: RouteDisposition::Present,
            applied_rendered_digest: applied_rendered_digest.map(str::to_owned),
            rendered_digest: digest_bytes(contents),
        };
        self.record(&evidence)?;
        Ok(evidence)
    }

    pub(super) fn stage_absent(
        &mut self,
        workshop_id: Uuid,
        projection_generation: i64,
        projection_digest: &str,
        applied_rendered_digest: &str,
    ) -> io::Result<RouteSetSealEvidence> {
        self.stage_absent_with_baseline(
            workshop_id,
            projection_generation,
            projection_digest,
            Some(applied_rendered_digest),
        )
    }

    pub(super) fn stage_startup_absent(
        &mut self,
        workshop_id: Uuid,
        projection_generation: i64,
        projection_digest: &str,
        applied_rendered_digest: Option<&str>,
    ) -> io::Result<RouteSetSealEvidence> {
        if self.publication_kind() != RouteSetPublicationKind::Startup {
            return Err(invalid_input("nullable baseline is startup-only"));
        }
        self.stage_absent_with_baseline(
            workshop_id,
            projection_generation,
            projection_digest,
            applied_rendered_digest,
        )
    }

    fn stage_absent_with_baseline(
        &mut self,
        workshop_id: Uuid,
        projection_generation: i64,
        projection_digest: &str,
        applied_rendered_digest: Option<&str>,
    ) -> io::Result<RouteSetSealEvidence> {
        self.validate_next(workshop_id)?;
        self.validate_capacity()?;
        validate_projection(projection_generation, projection_digest)?;
        if let Some(digest) = applied_rendered_digest {
            validate_digest(digest, "applied rendered digest")?;
        }
        let evidence = RouteSetSealEvidence {
            workshop_id,
            projection_generation,
            projection_digest: projection_digest.to_owned(),
            disposition: RouteDisposition::Absent,
            applied_rendered_digest: applied_rendered_digest.map(str::to_owned),
            rendered_digest: digest_bytes(&[]),
        };
        self.record(&evidence)?;
        Ok(evidence)
    }

    fn record(&mut self, evidence: &RouteSetSealEvidence) -> io::Result<()> {
        self.validate_next(evidence.workshop_id)?;
        self.validate_capacity()?;
        validate_evidence(evidence)?;
        let route_name = cstring(format!("{}.conf", evidence.workshop_id))?;
        match evidence.disposition {
            RouteDisposition::Present => {
                let route = open_at_file(&self.generation.directory, &route_name)?;
                validate_regular_file(&route, FILE_MODE, "route-set route")?;
                let bytes = read_bounded(route, MAX_ROUTE_BYTES)?;
                validate_route_bytes(&bytes)?;
                if digest_bytes(&bytes) != evidence.rendered_digest {
                    return Err(invalid_state("route-set route differs from evidence"));
                }
            }
            RouteDisposition::Absent => match open_at_file(&self.generation.directory, &route_name)
            {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => return Err(invalid_state("absent route has staged bytes")),
                Err(error) => return Err(error),
            },
        }
        let line = evidence_line(evidence)?;
        if !self.existing_manifest_exhausted {
            match read_evidence_line(&mut self.manifest_reader)? {
                Some(existing) if existing == line => {}
                Some(_) => return Err(invalid_state("preexisting route-set evidence differs")),
                None => {
                    self.existing_manifest_exhausted = true;
                    self.manifest_append.write_all(&line)?;
                    self.manifest_append.sync_all()?;
                    self.generation.directory.sync_all()?;
                }
            }
        } else {
            self.manifest_append.write_all(&line)?;
            self.manifest_append.sync_all()?;
            self.generation.directory.sync_all()?;
        }
        fold_evidence(&mut self.hasher, evidence)?;
        self.previous_workshop = Some(evidence.workshop_id);
        self.route_count += 1;
        if evidence.disposition == RouteDisposition::Present {
            self.present_route_count += 1;
        }
        Ok(())
    }

    fn validate_next(&self, workshop_id: Uuid) -> io::Result<()> {
        if workshop_id.is_nil()
            || self
                .previous_workshop
                .is_some_and(|previous| previous >= workshop_id)
        {
            return Err(invalid_input(
                "route-set evidence must be strictly non-nil workshop ordered",
            ));
        }
        Ok(())
    }

    fn validate_capacity(&self) -> io::Result<()> {
        if self.route_count >= MAX_ROUTES {
            return Err(invalid_input("route-set count exceeds its bound"));
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> io::Result<&'a SealedRouteSetGeneration> {
        if self.route_count == 0 && self.generation.intent.startup_effect_run_id().is_none() {
            return Err(invalid_input(
                "workshop-scoped route-set must contain at least one route",
            ));
        }
        if !self.existing_manifest_exhausted
            && read_evidence_line(&mut self.manifest_reader)?.is_some()
        {
            return Err(invalid_state("route-set manifest has unconsumed rows"));
        }
        self.manifest_append.sync_all()?;
        self.generation
            .finish_seal(self.hasher, self.route_count, self.present_route_count)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SelectorExchange {
    Publish,
    Restore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExchangeRecovery {
    AlreadyCleanPriorSelected,
    AlreadyCleanCandidateSelected,
    PreparedArtifactRemoved,
    ExchangedArtifactRemoved,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RouteSetRetentionDeletion {
    Deleted {
        directory_device: u64,
        directory_inode: u64,
    },
    AlreadyAbsent,
    ProtectedCurrent {
        directory_device: u64,
        directory_inode: u64,
    },
    IdentityMismatch {
        directory_device: u64,
        directory_inode: u64,
        mismatch: RouteSetRetentionMismatch,
        observed_identity: Option<RouteSetGenerationIdentity>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum RouteSetRetentionStep {
    InProgress,
    Complete(RouteSetRetentionDeletion),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RouteSetRetentionMismatch {
    DirectoryIdentity,
    ContentIdentity,
    ContentIntegrity,
}

#[derive(Serialize)]
struct RouteSetRetentionMarker<'a> {
    protocol_version: u8,
    directory_device: u64,
    directory_inode: u64,
    route_count: usize,
    present_route_count: usize,
    intent: &'a RouteSetGenerationIntent,
    identity: &'a RouteSetGenerationIdentity,
}

#[derive(Clone, Copy)]
pub(super) struct RouteSetPublicationEvidence<'a> {
    pub identity: &'a RouteSetGenerationIdentity,
    pub route_count: usize,
    pub present_route_count: usize,
    pub candidate: &'a PriorSelector,
}

pub(super) enum ExpectedPreStartState<'a> {
    Staging,
    Sealed(RouteSetPublicationEvidence<'a>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PreStartCandidateInspection {
    UnstartedAbsent,
    Pristine,
    StagedPartial {
        record_count: usize,
        present_count: usize,
    },
    SealedNotPublished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PostStartPublicationInspection {
    SealedBeforeMarker,
    MarkerBeforeExchange,
    PreparedExchange,
    ExchangeDone,
    CandidateSelected,
    ForeignOrInconclusive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ForwardPublicationResume {
    Resumed,
    AlreadySelected,
}

/// Proof that the original writer remains exclusively authorized to mutate
/// the selector after publication start. There is deliberately no production
/// constructor: an observe-only replacement/reconciliation claim (including
/// migration 0030) must never mint this capability. A future supervised
/// original-writer/host-guard protocol must add a separately reviewed minting
/// boundary before it can call the forward-resume primitive.
pub(super) struct ExclusiveOriginalWriterResumeAuthority {
    _private: (),
}

/// Inspect only a database-proven pre-start publication. This surface never
/// accepts a publication marker or selector-exchange artifact, so a caller
/// cannot use it to clean a generation after the filesystem start boundary.
pub(super) fn inspect_pre_start_candidate(
    route_root: &Path,
    intent: &RouteSetGenerationIntent,
    prior: &PriorSelector,
    expected: ExpectedPreStartState<'_>,
) -> io::Result<PreStartCandidateInspection> {
    intent.validate()?;
    if observe_current_selector(route_root)? != *prior {
        return Err(invalid_state(
            "pre-start selector differs from recorded prior",
        ));
    }
    let root = open_directory(route_root)?;
    validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
    for exchange in [SelectorExchange::Publish, SelectorExchange::Restore] {
        let artifact = cstring(exchange_artifact_name(intent, exchange))?;
        match read_link_at(&root, &artifact) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) | Err(_) => {
                return Err(invalid_state(
                    "pre-start route-set has a same-publication exchange artifact",
                ));
            }
        }
    }
    let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
    validate_directory(
        &generations,
        GENERATIONS_MODE,
        "route generations directory",
    )?;
    ensure_same_filesystem(&root, &generations)?;
    if observe_selector_target(&generations, prior.target().to_owned())? != *prior {
        return Err(invalid_state("pre-start prior directory identity changed"));
    }
    let directory = match open_at_directory(&generations, &cstring(intent.name().as_str())?) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return match expected {
                ExpectedPreStartState::Staging => Ok(PreStartCandidateInspection::UnstartedAbsent),
                ExpectedPreStartState::Sealed(_) => Err(invalid_state(
                    "sealed pre-start route-set generation is absent",
                )),
            };
        }
        Err(error) => return Err(error),
    };
    ensure_same_filesystem(&generations, &directory)?;
    let mode = directory.metadata()?.mode() & 0o7777;
    match expected {
        ExpectedPreStartState::Staging => {
            validate_directory(&directory, STAGING_MODE, "route-set staging directory")?;
            verify_intent_file(&directory, intent)?;
            let entries = inspect_entries(&directory, true, false, false)?;
            if !entries.intent_present
                || entries.identity_present
                || entries.publication_marker_present
            {
                return Err(invalid_state("pre-start staging membership is invalid"));
            }
            if !entries.evidence_present && entries.total_route_count == 0 {
                return Ok(PreStartCandidateInspection::Pristine);
            }
            let (record_count, present_count) = verify_partial_manifest(&directory)?;
            if entries.total_route_count != present_count {
                return Err(invalid_state("partial route-set membership differs"));
            }
            Ok(PreStartCandidateInspection::StagedPartial {
                record_count,
                present_count,
            })
        }
        ExpectedPreStartState::Sealed(evidence) => {
            if mode != SEALED_MODE {
                return Err(invalid_state("sealed pre-start route-set mode differs"));
            }
            if evidence.candidate.target() != intent.name().selector_target()
                || observe_candidate_selector(route_root, intent)? != *evidence.candidate
                || observe_generation_identity(
                    route_root,
                    intent,
                    evidence.route_count,
                    evidence.present_route_count,
                    false,
                )? != *evidence.identity
            {
                return Err(invalid_state("sealed pre-start route-set identity differs"));
            }
            Ok(PreStartCandidateInspection::SealedNotPublished)
        }
    }
}

pub(super) fn dispose_pre_start_candidate(
    route_root: &Path,
    intent: &RouteSetGenerationIntent,
    prior: &PriorSelector,
    expected: ExpectedPreStartState<'_>,
) -> io::Result<PreStartCandidateInspection> {
    let inspection = inspect_pre_start_candidate(route_root, intent, prior, expected)?;
    if inspection != PreStartCandidateInspection::UnstartedAbsent {
        dispose_exact_unpublished(route_root, intent)?;
    }
    Ok(inspection)
}

/// Remove only the startup candidate whose immutable on-disk intent binds it
/// to the supplied publication and effect. This recovery primitive does not
/// need a caller-provided fence (which is deliberately absent from the
/// recovery state envelope); the closed intent supplies and authenticates it.
pub(super) fn dispose_startup_recovery_candidate(
    route_root: &Path,
    publication_id: Uuid,
    startup_effect_run_id: Uuid,
) -> io::Result<bool> {
    if publication_id.is_nil() || startup_effect_run_id.is_nil() {
        return Err(invalid_input("startup recovery identity is invalid"));
    }
    let expected_name =
        RouteSetGenerationName::new(publication_id, RouteSetPublicationKind::Startup);
    let root = open_directory(route_root)?;
    validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
    let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
    validate_directory(
        &generations,
        GENERATIONS_MODE,
        "route generations directory",
    )?;
    ensure_same_filesystem(&root, &generations)?;
    let directory = match open_at_directory(&generations, &cstring(expected_name.as_str())?) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    ensure_same_filesystem(&generations, &directory)?;
    let mode = directory.metadata()?.mode() & 0o7777;
    if mode != STAGING_MODE && mode != SEALED_MODE {
        return Err(invalid_state("startup recovery candidate has unsafe mode"));
    }
    validate_directory(&directory, mode, "startup recovery candidate")?;
    let intent_file = open_at_file(&directory, &cstring(INTENT_FILE)?)?;
    validate_regular_file(&intent_file, FILE_MODE, "route-set intent")?;
    let intent: RouteSetGenerationIntent = serde_json::from_slice(
        read_bounded(intent_file, 1024)?
            .strip_suffix(b"\n")
            .ok_or_else(|| invalid_state("route-set intent is not canonical"))?,
    )
    .map_err(|_| invalid_state("route-set intent is malformed"))?;
    if intent.publication_id != publication_id
        || intent.publication_kind != RouteSetPublicationKind::Startup
        || intent.startup_effect_run_id() != Some(startup_effect_run_id)
        || intent.name() != expected_name
    {
        return Err(invalid_state("startup recovery intent differs"));
    }
    verify_intent_file(&directory, &intent)?;
    drop(directory);
    dispose_exact_unpublished(route_root, &intent)?;
    Ok(true)
}

/// Delete one database-authorized, no-longer-referenced published route-set
/// generation. A create-only marker makes deletion retry-safe after any
/// individual child unlink. The caller must hold the shared host guard.
pub(super) fn step_retained_route_set_generation_deletion(
    route_root: &Path,
    intent: &RouteSetGenerationIntent,
    identity: &RouteSetGenerationIdentity,
    expected_directory_device: u64,
    expected_directory_inode: u64,
    route_count: usize,
    present_route_count: usize,
) -> io::Result<RouteSetRetentionStep> {
    step_retained_route_set_generation_deletion_with_hook(
        route_root,
        intent,
        identity,
        expected_directory_device,
        expected_directory_inode,
        (route_count, present_route_count),
        || {},
    )
}

fn step_retained_route_set_generation_deletion_with_hook(
    route_root: &Path,
    intent: &RouteSetGenerationIntent,
    identity: &RouteSetGenerationIdentity,
    expected_directory_device: u64,
    expected_directory_inode: u64,
    counts: (usize, usize),
    before_marker_creation: impl FnOnce(),
) -> io::Result<RouteSetRetentionStep> {
    let (route_count, present_route_count) = counts;
    intent.validate()?;
    ensure_identity_matches_intent(identity, intent)?;
    validate_counts(route_count, present_route_count)?;
    if expected_directory_device == 0 || expected_directory_inode == 0 {
        return Err(invalid_input("retention directory identity is invalid"));
    }
    let name = intent.name();
    let target = name.selector_target();
    if target == "generations/boot-live" {
        return Err(invalid_input(
            "boot-live cannot be retained-generation deleted",
        ));
    }
    let selected = observe_current_selector(route_root)?;
    if selected.target() == target {
        return Ok(RouteSetRetentionStep::Complete(
            RouteSetRetentionDeletion::ProtectedCurrent {
                directory_device: selected.directory_device(),
                directory_inode: selected.directory_inode(),
            },
        ));
    }
    let root = open_directory(route_root)?;
    validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
    let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
    validate_directory(
        &generations,
        GENERATIONS_MODE,
        "route generations directory",
    )?;
    ensure_same_filesystem(&root, &generations)?;
    let directory = match open_at_directory(&generations, &cstring(name.as_str())?) {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(RouteSetRetentionStep::Complete(
                RouteSetRetentionDeletion::AlreadyAbsent,
            ));
        }
        Err(error) => return Err(error),
    };
    ensure_same_filesystem(&generations, &directory)?;
    let metadata = directory.metadata()?;
    if metadata.dev() != expected_directory_device || metadata.ino() != expected_directory_inode {
        return Ok(RouteSetRetentionStep::Complete(
            RouteSetRetentionDeletion::IdentityMismatch {
                directory_device: metadata.dev(),
                directory_inode: metadata.ino(),
                mismatch: RouteSetRetentionMismatch::DirectoryIdentity,
                observed_identity: None,
            },
        ));
    }
    validate_directory(&directory, SEALED_MODE, "retained route-set generation")?;
    let marker = RouteSetRetentionMarker {
        protocol_version: 1,
        directory_device: expected_directory_device,
        directory_inode: expected_directory_inode,
        route_count,
        present_route_count,
        intent,
        identity,
    };
    let marker_bytes = retention_marker_bytes(&marker)?;
    let names = retention_entry_names(&directory)?;
    if names.is_empty() {
        validate_named_identity(
            &generations,
            &directory,
            name.as_str(),
            SEALED_MODE,
            expected_directory_device,
            expected_directory_inode,
        )?;
        if observe_current_selector(route_root)? != selected {
            return Err(invalid_state(
                "route selector changed before retained directory unlink",
            ));
        }
        unlink_at(&generations, &cstring(name.as_str())?, true)?;
        generations.sync_all()?;
        return Ok(RouteSetRetentionStep::Complete(
            RouteSetRetentionDeletion::Deleted {
                directory_device: expected_directory_device,
                directory_inode: expected_directory_inode,
            },
        ));
    } else if names.iter().any(|entry| entry == RETENTION_MARKER_FILE) {
        verify_retention_marker(&directory, &marker_bytes)?;
    } else {
        verify_intent_file(&directory, intent)?;
        let observed_identity = read_identity(&directory)?;
        if observed_identity != *identity {
            return Ok(RouteSetRetentionStep::Complete(
                RouteSetRetentionDeletion::IdentityMismatch {
                    directory_device: metadata.dev(),
                    directory_inode: metadata.ino(),
                    mismatch: RouteSetRetentionMismatch::ContentIdentity,
                    observed_identity: Some(observed_identity),
                },
            ));
        }
        if verify_retention_generation(
            &generations,
            &directory,
            intent,
            identity,
            route_count,
            present_route_count,
            &metadata,
        )
        .is_err()
        {
            return Ok(RouteSetRetentionStep::Complete(
                RouteSetRetentionDeletion::IdentityMismatch {
                    directory_device: metadata.dev(),
                    directory_inode: metadata.ino(),
                    mismatch: RouteSetRetentionMismatch::ContentIntegrity,
                    observed_identity: Some(observed_identity),
                },
            ));
        }
        before_marker_creation();
        if observe_current_selector(route_root)? != selected {
            return Err(invalid_state(
                "route selector changed before retention marker creation",
            ));
        }
        write_create_only_or_verify(
            &directory,
            RETENTION_MARKER_FILE,
            &marker_bytes,
            "route-set retention marker",
        )?;
        return Ok(RouteSetRetentionStep::InProgress);
    }
    delete_one_retention_entry(route_root, &selected, &directory, &marker_bytes)?;
    Ok(RouteSetRetentionStep::InProgress)
}

#[cfg(test)]
fn delete_retained_route_set_generation(
    route_root: &Path,
    intent: &RouteSetGenerationIntent,
    identity: &RouteSetGenerationIdentity,
    expected_directory_device: u64,
    expected_directory_inode: u64,
    route_count: usize,
    present_route_count: usize,
) -> io::Result<RouteSetRetentionDeletion> {
    loop {
        match step_retained_route_set_generation_deletion(
            route_root,
            intent,
            identity,
            expected_directory_device,
            expected_directory_inode,
            route_count,
            present_route_count,
        )? {
            RouteSetRetentionStep::InProgress => {}
            RouteSetRetentionStep::Complete(outcome) => return Ok(outcome),
        }
    }
}

fn retention_marker_bytes(marker: &RouteSetRetentionMarker<'_>) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(marker).map_err(io::Error::other)?;
    bytes.push(b'\n');
    if bytes.len() > 4_096 {
        return Err(invalid_input(
            "route-set retention marker exceeds its bound",
        ));
    }
    Ok(bytes)
}

fn verify_retention_marker(directory: &File, expected: &[u8]) -> io::Result<()> {
    let file = open_at_file(directory, &cstring(RETENTION_MARKER_FILE)?)?;
    validate_regular_file(&file, FILE_MODE, "route-set retention marker")?;
    if read_bounded(file, 4_096)? != expected {
        return Err(invalid_state("route-set retention marker differs"));
    }
    Ok(())
}

fn verify_retention_generation(
    generations: &File,
    directory: &File,
    intent: &RouteSetGenerationIntent,
    identity: &RouteSetGenerationIdentity,
    route_count: usize,
    present_route_count: usize,
    metadata: &std::fs::Metadata,
) -> io::Result<()> {
    verify_evidence_manifest(
        directory,
        route_count,
        present_route_count,
        &identity.route_set_digest,
    )?;
    let entries = inspect_entries(directory, true, true, true)?;
    if entries.total_route_count != present_route_count
        || !entries.intent_present
        || !entries.evidence_present
        || !entries.identity_present
        || !entries.publication_marker_present
    {
        return Err(invalid_state("retained route-set membership differs"));
    }
    verify_marker_identity(directory, identity)?;
    validate_named_identity(
        generations,
        directory,
        intent.name().as_str(),
        SEALED_MODE,
        metadata.dev(),
        metadata.ino(),
    )
}

pub(super) fn validate_retention_generation_authority(
    intent: &RouteSetGenerationIntent,
    identity: &RouteSetGenerationIdentity,
) -> io::Result<()> {
    intent.validate()?;
    ensure_identity_matches_intent(identity, intent)
}

fn retention_entry_names(directory: &File) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    visit_generation_entries(directory, |name| {
        names.push(name.to_owned());
        if names.len() > MAX_ROUTES + 5 {
            return Err(invalid_state(
                "retained route-set membership exceeds its bound",
            ));
        }
        Ok(())
    })?;
    Ok(names)
}

fn delete_one_retention_entry(
    route_root: &Path,
    selected: &PriorSelector,
    directory: &File,
    marker_bytes: &[u8],
) -> io::Result<()> {
    let names = retention_entry_names(directory)?;
    if !names.iter().any(|entry| entry == RETENTION_MARKER_FILE) {
        if names.is_empty() {
            return Ok(());
        }
        return Err(invalid_state("route-set retention marker is absent"));
    }
    verify_retention_marker(directory, marker_bytes)?;
    let mut next = None;
    for name in &names {
        if name == RETENTION_MARKER_FILE {
            continue;
        }
        let valid = matches!(
            name.as_str(),
            INTENT_FILE | EVIDENCE_FILE | ROUTE_SET_GENERATION_FILE | PUBLICATION_MARKER_FILE
        ) || name
            .strip_suffix(".conf")
            .is_some_and(|stem| Uuid::parse_str(stem).is_ok());
        if !valid {
            return Err(invalid_state(
                "retained route-set contains an unowned entry",
            ));
        }
        let child = cstring(name)?;
        let file = open_at_file(directory, &child)?;
        validate_regular_file(&file, FILE_MODE, "retained route-set child")?;
        if next.is_none() {
            next = Some(child);
        }
    }
    let child = next.unwrap_or(cstring(RETENTION_MARKER_FILE)?);
    if observe_current_selector(route_root)? != *selected {
        return Err(invalid_state(
            "route selector changed before retained child unlink",
        ));
    }
    unlink_at(directory, &child, false)?;
    directory.sync_all()?;
    Ok(())
}

/// Classify an exact database-proven post-start publication without changing
/// the selector or removing an artifact. This is the only primitive suitable
/// for an observe-only replacement/reconciliation claim. Unknown selector or
/// artifact shapes are explicitly inconclusive and are never cleaned here.
pub(super) fn inspect_post_start_publication(
    route_root: &Path,
    intent: &RouteSetGenerationIntent,
    evidence: RouteSetPublicationEvidence<'_>,
    prior: &PriorSelector,
) -> io::Result<PostStartPublicationInspection> {
    intent.validate()?;
    ensure_identity_matches_intent(evidence.identity, intent)?;
    if evidence.candidate.target() != intent.name().selector_target() || evidence.candidate == prior
    {
        return Err(invalid_input("post-start selector identities are invalid"));
    }
    let root = open_directory(route_root)?;
    validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
    let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
    validate_directory(
        &generations,
        GENERATIONS_MODE,
        "route generations directory",
    )?;
    ensure_same_filesystem(&root, &generations)?;
    if observe_selector_target(&generations, evidence.candidate.target().to_owned())?
        != *evidence.candidate
        || observe_selector_target(&generations, prior.target().to_owned())? != *prior
    {
        return Err(invalid_state("post-start directory identity changed"));
    }
    let directory = open_at_directory(&generations, &cstring(intent.name().as_str())?)?;
    validate_directory(&directory, SEALED_MODE, "post-start route-set generation")?;
    let entries = inspect_entries(&directory, true, true, true)?;
    let marker = entries.publication_marker_present;
    if observe_generation_identity(
        route_root,
        intent,
        evidence.route_count,
        evidence.present_route_count,
        marker,
    )? != *evidence.identity
    {
        return Err(invalid_state("post-start loaded identity differs"));
    }
    let current = observe_selector_from_handles(&root, &generations)?;
    let restore_artifact = cstring(exchange_artifact_name(intent, SelectorExchange::Restore))?;
    match read_link_at(&root, &restore_artifact) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) | Err(_) => return Ok(PostStartPublicationInspection::ForeignOrInconclusive),
    }
    let artifact = cstring(exchange_artifact_name(intent, SelectorExchange::Publish))?;
    let artifact_target = match read_link_at(&root, &artifact) {
        Ok(target) => Some(target),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if !marker {
        return Ok(if artifact_target.is_none() && current == *prior {
            PostStartPublicationInspection::SealedBeforeMarker
        } else {
            PostStartPublicationInspection::ForeignOrInconclusive
        });
    }
    match (current, artifact_target.as_deref()) {
        (current, None) if current == *prior => {
            Ok(PostStartPublicationInspection::MarkerBeforeExchange)
        }
        (current, None) if current == *evidence.candidate => {
            Ok(PostStartPublicationInspection::CandidateSelected)
        }
        (current, Some(target)) if current == *prior && target == evidence.candidate.target() => {
            Ok(PostStartPublicationInspection::PreparedExchange)
        }
        (current, Some(target)) if current == *evidence.candidate && target == prior.target() => {
            Ok(PostStartPublicationInspection::ExchangeDone)
        }
        _ => Ok(PostStartPublicationInspection::ForeignOrInconclusive),
    }
}

/// Resume only in the forward direction after the database start boundary.
/// Exact exchange artifacts are cleaned by `recover_exchange_artifact`; no
/// restore exchange is exposed by this recovery surface.
pub(super) fn resume_post_start_publication_forward(
    _authority: ExclusiveOriginalWriterResumeAuthority,
    route_root: &Path,
    intent: &RouteSetGenerationIntent,
    evidence: RouteSetPublicationEvidence<'_>,
    prior: &PriorSelector,
) -> io::Result<ForwardPublicationResume> {
    let inspection = inspect_post_start_publication(route_root, intent, evidence, prior)?;
    match inspection {
        PostStartPublicationInspection::ForeignOrInconclusive => Err(invalid_state(
            "post-start route-set outcome is inconclusive",
        )),
        PostStartPublicationInspection::CandidateSelected => {
            observe_selected_identity(
                route_root,
                intent,
                evidence.identity,
                evidence.route_count,
                evidence.present_route_count,
            )?;
            Ok(ForwardPublicationResume::AlreadySelected)
        }
        PostStartPublicationInspection::ExchangeDone => {
            recover_exchange_artifact(
                route_root,
                intent,
                evidence,
                prior,
                SelectorExchange::Publish,
            )?;
            observe_selected_identity(
                route_root,
                intent,
                evidence.identity,
                evidence.route_count,
                evidence.present_route_count,
            )?;
            Ok(ForwardPublicationResume::Resumed)
        }
        PostStartPublicationInspection::SealedBeforeMarker => {
            let mut generation = RouteSetGenerationDirectory::open_existing_sealed(
                route_root,
                intent.clone(),
                &evidence.identity.route_set_digest,
                evidence.route_count,
                evidence.present_route_count,
            )?;
            generation.publish(prior)?;
            Ok(ForwardPublicationResume::Resumed)
        }
        PostStartPublicationInspection::MarkerBeforeExchange
        | PostStartPublicationInspection::PreparedExchange => {
            if inspection == PostStartPublicationInspection::PreparedExchange {
                recover_exchange_artifact(
                    route_root,
                    intent,
                    evidence,
                    prior,
                    SelectorExchange::Publish,
                )?;
            }
            let mut generation = RouteSetGenerationDirectory::open_existing_published(
                route_root,
                intent.clone(),
                &evidence.identity.route_set_digest,
                evidence.route_count,
                evidence.present_route_count,
            )?;
            generation.resume_published_from_prior(prior)?;
            Ok(ForwardPublicationResume::Resumed)
        }
    }
}

pub(super) fn observe_candidate_selector(
    route_root: &Path,
    intent: &RouteSetGenerationIntent,
) -> io::Result<PriorSelector> {
    intent.validate()?;
    observe_generation_selector(route_root, &intent.name().selector_target())
}

pub(super) fn observe_generation_identity(
    route_root: &Path,
    intent: &RouteSetGenerationIntent,
    expected_route_count: usize,
    expected_present_count: usize,
    publication_started: bool,
) -> io::Result<RouteSetGenerationIdentity> {
    intent.validate()?;
    validate_counts(expected_route_count, expected_present_count)?;
    let root = open_directory(route_root)?;
    validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
    let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
    validate_directory(
        &generations,
        GENERATIONS_MODE,
        "route generations directory",
    )?;
    ensure_same_filesystem(&root, &generations)?;
    let name = intent.name();
    let directory = open_at_directory(&generations, &cstring(name.as_str())?)?;
    validate_directory(&directory, SEALED_MODE, "route-set generation")?;
    ensure_same_filesystem(&generations, &directory)?;
    let metadata = directory.metadata()?;
    verify_intent_file(&directory, intent)?;
    let identity = read_identity(&directory)?;
    ensure_identity_matches_intent(&identity, intent)?;
    verify_evidence_manifest(
        &directory,
        expected_route_count,
        expected_present_count,
        &identity.route_set_digest,
    )?;
    let entries = inspect_entries(&directory, true, true, publication_started)?;
    if entries.total_route_count != expected_present_count
        || !entries.intent_present
        || !entries.evidence_present
        || !entries.identity_present
        || entries.publication_marker_present != publication_started
    {
        return Err(invalid_state("route-set observation membership differs"));
    }
    if publication_started {
        verify_marker_identity(&directory, &identity)?;
    }
    validate_named_identity(
        &generations,
        &directory,
        name.as_str(),
        SEALED_MODE,
        metadata.dev(),
        metadata.ino(),
    )?;
    Ok(identity)
}

pub(super) fn observe_selected_identity(
    route_root: &Path,
    intent: &RouteSetGenerationIntent,
    expected: &RouteSetGenerationIdentity,
    expected_route_count: usize,
    expected_present_count: usize,
) -> io::Result<PriorSelector> {
    ensure_identity_matches_intent(expected, intent)?;
    let first = observe_current_selector(route_root)?;
    if first.target() != intent.name().selector_target()
        || observe_generation_identity(
            route_root,
            intent,
            expected_route_count,
            expected_present_count,
            true,
        )? != *expected
    {
        return Err(invalid_state("selected route-set identity differs"));
    }
    let second = observe_current_selector(route_root)?;
    if second != first {
        return Err(invalid_state(
            "selector changed during route-set observation",
        ));
    }
    Ok(second)
}

pub(super) fn dispose_exact_unpublished(
    route_root: &Path,
    intent: &RouteSetGenerationIntent,
) -> io::Result<()> {
    intent.validate()?;
    let root = open_directory(route_root)?;
    validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
    let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
    validate_directory(
        &generations,
        GENERATIONS_MODE,
        "route generations directory",
    )?;
    ensure_same_filesystem(&root, &generations)?;
    let name = intent.name();
    let directory = open_at_directory(&generations, &cstring(name.as_str())?)?;
    ensure_same_filesystem(&generations, &directory)?;
    let metadata = directory.metadata()?;
    let mode = metadata.mode() & 0o7777;
    if mode != STAGING_MODE && mode != SEALED_MODE {
        return Err(invalid_state("route-set generation mode is unsafe"));
    }
    validate_directory(&directory, mode, "route-set generation")?;
    match read_link_at(&root, &cstring(CURRENT_SELECTOR)?) {
        Ok(target) if target == name.selector_target() => {
            return Err(invalid_state("selected route-set is not disposable"));
        }
        Ok(target) => validate_selector_target(&target)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    verify_intent_file(&directory, intent)?;
    let entries = inspect_entries(&directory, true, true, true)?;
    if entries.publication_marker_present {
        return Err(invalid_state(
            "publication-started route-set is not disposable",
        ));
    }
    if entries.identity_present {
        ensure_identity_matches_intent(&read_identity(&directory)?, intent)?;
    }
    dispose_entries(&directory, entries.identity_present)?;
    directory.sync_all()?;
    validate_named_identity(
        &generations,
        &directory,
        name.as_str(),
        mode,
        metadata.dev(),
        metadata.ino(),
    )?;
    unlink_at(&generations, &cstring(name.as_str())?, true)?;
    generations.sync_all()
}

fn exchange_artifact_name(intent: &RouteSetGenerationIntent, exchange: SelectorExchange) -> String {
    let suffix = match exchange {
        SelectorExchange::Publish => "publish",
        SelectorExchange::Restore => "restore",
    };
    format!(
        ".current-route-{suffix}-{}-{}",
        intent.publication_id.simple(),
        selector_suffix(intent.publication_kind)
    )
}

fn recover_exchange_artifact(
    route_root: &Path,
    intent: &RouteSetGenerationIntent,
    evidence: RouteSetPublicationEvidence<'_>,
    prior: &PriorSelector,
    exchange: SelectorExchange,
) -> io::Result<ExchangeRecovery> {
    ensure_identity_matches_intent(evidence.identity, intent)?;
    if evidence.candidate.target() != intent.name().selector_target() || evidence.candidate == prior
    {
        return Err(invalid_input(
            "route-set exchange selector identities are invalid",
        ));
    }
    if observe_generation_identity(
        route_root,
        intent,
        evidence.route_count,
        evidence.present_route_count,
        true,
    )? != *evidence.identity
    {
        return Err(invalid_state("route-set exchange identity differs"));
    }
    let root = open_directory(route_root)?;
    validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
    let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
    validate_directory(
        &generations,
        GENERATIONS_MODE,
        "route generations directory",
    )?;
    ensure_same_filesystem(&root, &generations)?;
    if &observe_selector_target(&generations, evidence.candidate.target().to_owned())?
        != evidence.candidate
        || &observe_selector_target(&generations, prior.target().to_owned())? != prior
    {
        return Err(invalid_state(
            "route-set exchange directory identity changed",
        ));
    }
    let artifact = cstring(exchange_artifact_name(intent, exchange))?;
    let artifact_target = match read_link_at(&root, &artifact) {
        Ok(target) => target,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let current = observe_selector_from_handles(&root, &generations)?;
            if current == *prior {
                return Ok(ExchangeRecovery::AlreadyCleanPriorSelected);
            }
            if current == *evidence.candidate {
                return Ok(ExchangeRecovery::AlreadyCleanCandidateSelected);
            }
            return Err(invalid_state("clean exchange has unknown current selector"));
        }
        Err(error) => return Err(error),
    };
    validate_selector_target(&artifact_target)?;
    let current = observe_selector_from_handles(&root, &generations)?;
    let outcome = match exchange {
        SelectorExchange::Publish
            if current == *prior && artifact_target == evidence.candidate.target() =>
        {
            ExchangeRecovery::PreparedArtifactRemoved
        }
        SelectorExchange::Publish
            if current == *evidence.candidate && artifact_target == prior.target() =>
        {
            ExchangeRecovery::ExchangedArtifactRemoved
        }
        SelectorExchange::Restore
            if current == *evidence.candidate && artifact_target == prior.target() =>
        {
            ExchangeRecovery::PreparedArtifactRemoved
        }
        SelectorExchange::Restore
            if current == *prior && artifact_target == evidence.candidate.target() =>
        {
            ExchangeRecovery::ExchangedArtifactRemoved
        }
        _ => {
            return Err(invalid_state(
                "route-set exchange artifact is not exact-owned",
            ));
        }
    };
    let expected_artifact = if artifact_target == evidence.candidate.target() {
        evidence.candidate
    } else {
        prior
    };
    if &observe_selector_target(&generations, artifact_target.clone())? != expected_artifact
        || read_link_at(&root, &artifact)? != artifact_target
        || observe_selector_from_handles(&root, &generations)? != current
    {
        return Err(invalid_state("route-set exchange changed during recovery"));
    }
    unlink_at(&root, &artifact, false)?;
    root.sync_all()?;
    if observe_selector_from_handles(&root, &generations)? != current {
        return Err(invalid_state("selector changed during exchange cleanup"));
    }
    match read_link_at(&root, &artifact) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(outcome),
        Ok(_) => Err(invalid_state("route-set exchange cleanup was incomplete")),
        Err(error) => Err(error),
    }
}

fn validate_projection(generation: i64, digest: &str) -> io::Result<()> {
    if generation <= 0 {
        return Err(invalid_input("projection generation must be positive"));
    }
    validate_digest(digest, "projection digest")
}

fn validate_evidence(evidence: &RouteSetSealEvidence) -> io::Result<()> {
    if evidence.workshop_id.is_nil() {
        return Err(invalid_input("route-set workshop is nil"));
    }
    validate_projection(evidence.projection_generation, &evidence.projection_digest)?;
    validate_digest(&evidence.rendered_digest, "rendered digest")?;
    if let Some(digest) = &evidence.applied_rendered_digest {
        validate_digest(digest, "applied rendered digest")?;
    }
    if evidence.disposition == RouteDisposition::Absent
        && evidence.rendered_digest != digest_bytes(&[])
    {
        return Err(invalid_input(
            "absent route must use canonical empty digest",
        ));
    }
    Ok(())
}

fn validate_counts(total: usize, present: usize) -> io::Result<()> {
    if total > MAX_ROUTES || present > total {
        return Err(invalid_input("route-set counts are outside their bounds"));
    }
    Ok(())
}

fn evidence_line(evidence: &RouteSetSealEvidence) -> io::Result<Vec<u8>> {
    validate_evidence(evidence)?;
    let mut line = serde_json::to_vec(evidence).map_err(io::Error::other)?;
    line.push(b'\n');
    if line.len() > MAX_EVIDENCE_LINE_BYTES {
        return Err(invalid_input("route-set evidence exceeds its bound"));
    }
    Ok(line)
}

fn read_evidence_line(reader: &mut BufReader<File>) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::with_capacity(MAX_EVIDENCE_LINE_BYTES);
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte)? {
            0 if line.is_empty() => return Ok(None),
            0 => return Err(invalid_state("route-set evidence is truncated")),
            _ => {
                line.push(byte[0]);
                if line.len() > MAX_EVIDENCE_LINE_BYTES {
                    return Err(invalid_state("route-set evidence exceeds its bound"));
                }
                if byte[0] == b'\n' {
                    return Ok(Some(line));
                }
            }
        }
    }
}

fn fold_evidence(hasher: &mut Sha256, evidence: &RouteSetSealEvidence) -> io::Result<()> {
    hasher.update(evidence.workshop_id.as_bytes());
    hasher.update(evidence.projection_generation.to_be_bytes());
    update_field(hasher, evidence.projection_digest.as_bytes())?;
    update_field(hasher, evidence.disposition.as_str().as_bytes())?;
    update_optional_field(hasher, evidence.applied_rendered_digest.as_deref())?;
    update_field(hasher, evidence.rendered_digest.as_bytes())
}

fn update_optional_field(hasher: &mut Sha256, value: Option<&str>) -> io::Result<()> {
    match value {
        Some(value) => update_field(hasher, value.as_bytes()),
        None => {
            hasher.update((-1_i32).to_be_bytes());
            Ok(())
        }
    }
}

fn update_field(hasher: &mut Sha256, value: &[u8]) -> io::Result<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| invalid_input("route-set digest field exceeds its bound"))?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn verify_evidence_manifest(
    directory: &File,
    expected_total: usize,
    expected_present: usize,
    expected_digest: &str,
) -> io::Result<()> {
    validate_counts(expected_total, expected_present)?;
    validate_digest(expected_digest, "route-set digest")?;
    let manifest = open_at_file(directory, &cstring(EVIDENCE_FILE)?)?;
    validate_regular_file(&manifest, FILE_MODE, "route-set evidence manifest")?;
    let mut reader = BufReader::new(manifest);
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    let mut previous = None;
    let mut total = 0_usize;
    let mut present = 0_usize;
    while let Some(line) = read_evidence_line(&mut reader)? {
        let json = line
            .strip_suffix(b"\n")
            .ok_or_else(|| invalid_state("route-set evidence is not canonical"))?;
        let evidence: RouteSetSealEvidence = serde_json::from_slice(json)
            .map_err(|_| invalid_state("route-set evidence is invalid"))?;
        if evidence_line(&evidence)? != line
            || previous.is_some_and(|prior| prior >= evidence.workshop_id)
        {
            return Err(invalid_state("route-set evidence is not canonical ordered"));
        }
        total += 1;
        if total > MAX_ROUTES {
            return Err(invalid_state("route-set evidence exceeds count bound"));
        }
        let route_name = cstring(format!("{}.conf", evidence.workshop_id))?;
        match evidence.disposition {
            RouteDisposition::Present => {
                let route = open_at_file(directory, &route_name)?;
                validate_regular_file(&route, FILE_MODE, "sealed route-set route")?;
                let bytes = read_bounded(route, MAX_ROUTE_BYTES)?;
                validate_route_bytes(&bytes)?;
                if digest_bytes(&bytes) != evidence.rendered_digest {
                    return Err(invalid_state("sealed route differs from evidence"));
                }
                present += 1;
            }
            RouteDisposition::Absent => match open_at_file(directory, &route_name) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => return Err(invalid_state("absent sealed route has bytes")),
                Err(error) => return Err(error),
            },
        }
        fold_evidence(&mut hasher, &evidence)?;
        previous = Some(evidence.workshop_id);
    }
    if total != expected_total || present != expected_present {
        return Err(invalid_state("route-set evidence cardinality differs"));
    }
    if format!("sha256:{:x}", hasher.finalize()) != expected_digest {
        return Err(invalid_state("route-set digest differs from evidence"));
    }
    Ok(())
}

fn identity_line(identity: &RouteSetGenerationIdentity) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(identity).map_err(io::Error::other)?;
    bytes.push(b'\n');
    if bytes.len() > 1024 {
        return Err(invalid_input("route-set identity exceeds its bound"));
    }
    Ok(bytes)
}

fn ensure_identity_matches_intent(
    identity: &RouteSetGenerationIdentity,
    intent: &RouteSetGenerationIntent,
) -> io::Result<()> {
    identity
        .validate()
        .map_err(|error| io::Error::other(error.1))?;
    if identity.publication_id != intent.publication_id
        || identity.publication_kind != intent.publication_kind
        || identity.global_fence_token != intent.global_fence_token
        || identity.startup_effect_run_id() != intent.startup_effect_run_id()
        || identity
            .target_workshop_id()
            .zip(identity.target_route_fence_token())
            != intent.target_scope()
    {
        return Err(invalid_state("route-set identity differs from intent"));
    }
    Ok(())
}

fn verify_intent_file(directory: &File, intent: &RouteSetGenerationIntent) -> io::Result<()> {
    let file = open_at_file(directory, &cstring(INTENT_FILE)?)?;
    validate_regular_file(&file, FILE_MODE, "route-set intent")?;
    if read_bounded(file, 1024)? != intent.canonical_bytes()? {
        return Err(invalid_state("route-set intent changed"));
    }
    Ok(())
}

fn read_identity(directory: &File) -> io::Result<RouteSetGenerationIdentity> {
    let file = open_at_file(directory, &cstring(ROUTE_SET_GENERATION_FILE)?)?;
    validate_regular_file(&file, FILE_MODE, "route-set identity")?;
    parse_route_set_generation_config(&read_bounded(file, MAX_ROUTE_BYTES)?)
        .map_err(|error| io::Error::other(error.1))
}

fn verify_marker_identity(
    directory: &File,
    identity: &RouteSetGenerationIdentity,
) -> io::Result<()> {
    let file = open_at_file(directory, &cstring(PUBLICATION_MARKER_FILE)?)?;
    validate_regular_file(&file, FILE_MODE, "route-set publication marker")?;
    if read_bounded(file, 1024)? != identity_line(identity)? {
        return Err(invalid_state("route-set publication marker changed"));
    }
    Ok(())
}

fn write_create_only_or_verify(
    directory: &File,
    name: &str,
    bytes: &[u8],
    description: &str,
) -> io::Result<()> {
    let name = cstring(name)?;
    match create_at_file(directory, &name, FILE_MODE) {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
            file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
            validate_regular_file(&file, FILE_MODE, description)?;
            directory.sync_all()
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let file = open_at_file(directory, &name)?;
            validate_regular_file(&file, FILE_MODE, description)?;
            if read_bounded(file, MAX_ROUTE_BYTES)? != bytes {
                return Err(invalid_state(format!("preexisting {description} differs")));
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[derive(Default)]
struct GenerationEntries {
    total_route_count: usize,
    intent_present: bool,
    evidence_present: bool,
    identity_present: bool,
    publication_marker_present: bool,
}

fn inspect_entries(
    directory: &File,
    intent_allowed: bool,
    identity_allowed: bool,
    marker_allowed: bool,
) -> io::Result<GenerationEntries> {
    let mut entries = GenerationEntries::default();
    visit_generation_entries(directory, |name| {
        let file = open_at_file(directory, &cstring(name)?)?;
        validate_regular_file(&file, FILE_MODE, "route-set child")?;
        match name {
            INTENT_FILE if intent_allowed && !entries.intent_present => {
                entries.intent_present = true
            }
            EVIDENCE_FILE if !entries.evidence_present => entries.evidence_present = true,
            ROUTE_SET_GENERATION_FILE if identity_allowed && !entries.identity_present => {
                entries.identity_present = true;
            }
            PUBLICATION_MARKER_FILE if marker_allowed && !entries.publication_marker_present => {
                entries.publication_marker_present = true;
            }
            _ if name
                .strip_suffix(".conf")
                .is_some_and(|stem| Uuid::parse_str(stem).is_ok()) =>
            {
                entries.total_route_count += 1;
                if entries.total_route_count > MAX_ROUTES {
                    return Err(invalid_state("route-set file count exceeds its bound"));
                }
            }
            _ => return Err(invalid_state("route-set contains an unexpected entry")),
        }
        Ok(())
    })?;
    Ok(entries)
}

fn verify_partial_manifest(directory: &File) -> io::Result<(usize, usize)> {
    let manifest = open_at_file(directory, &cstring(EVIDENCE_FILE)?)?;
    validate_regular_file(&manifest, FILE_MODE, "partial route-set evidence manifest")?;
    let mut reader = BufReader::new(manifest);
    let mut previous = None;
    let mut record_count = 0_usize;
    let mut present_count = 0_usize;
    while let Some(line) = read_evidence_line(&mut reader)? {
        let json = line
            .strip_suffix(b"\n")
            .ok_or_else(|| invalid_state("partial route-set evidence is not canonical"))?;
        let evidence: RouteSetSealEvidence = serde_json::from_slice(json)
            .map_err(|_| invalid_state("partial route-set evidence is invalid"))?;
        if evidence_line(&evidence)? != line
            || previous.is_some_and(|prior| prior >= evidence.workshop_id)
            || record_count >= MAX_ROUTES
        {
            return Err(invalid_state(
                "partial route-set evidence ordering is invalid",
            ));
        }
        let route_name = cstring(format!("{}.conf", evidence.workshop_id))?;
        match evidence.disposition {
            RouteDisposition::Present => {
                let route = open_at_file(directory, &route_name)?;
                validate_regular_file(&route, FILE_MODE, "partial route-set route")?;
                let bytes = read_bounded(route, MAX_ROUTE_BYTES)?;
                validate_route_bytes(&bytes)?;
                if digest_bytes(&bytes) != evidence.rendered_digest {
                    return Err(invalid_state("partial route differs from its evidence"));
                }
                present_count += 1;
            }
            RouteDisposition::Absent => match open_at_file(directory, &route_name) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => return Err(invalid_state("partial absent route has bytes")),
                Err(error) => return Err(error),
            },
        }
        previous = Some(evidence.workshop_id);
        record_count += 1;
    }
    Ok((record_count, present_count))
}

fn dispose_entries(directory: &File, identity_allowed: bool) -> io::Result<()> {
    visit_generation_entries(directory, |name| {
        let valid = name == INTENT_FILE
            || name == EVIDENCE_FILE
            || (identity_allowed && name == ROUTE_SET_GENERATION_FILE)
            || name
                .strip_suffix(".conf")
                .is_some_and(|stem| Uuid::parse_str(stem).is_ok());
        if !valid {
            return Err(invalid_state("route-set contains an unowned entry"));
        }
        let child = cstring(name)?;
        let file = open_at_file(directory, &child)?;
        validate_regular_file(&file, FILE_MODE, "route-set child")?;
        unlink_at(directory, &child, false)
    })
}

fn validate_named_identity(
    generations: &File,
    directory: &File,
    name: &str,
    mode: u32,
    expected_dev: u64,
    expected_ino: u64,
) -> io::Result<()> {
    validate_directory(directory, mode, "route-set generation")?;
    let named = open_at_directory(generations, &cstring(name)?)?;
    validate_directory(&named, mode, "named route-set generation")?;
    let metadata = named.metadata()?;
    if metadata.dev() != expected_dev || metadata.ino() != expected_ino {
        return Err(invalid_state("route-set path identity changed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{DirBuilder, hard_link};
    use std::os::unix::fs::{DirBuilderExt as _, symlink};

    use super::*;

    fn exclusive_original_writer_authority() -> ExclusiveOriginalWriterResumeAuthority {
        ExclusiveOriginalWriterResumeAuthority { _private: () }
    }

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("mb-route-set-{}", Uuid::new_v4()));
            DirBuilder::new()
                .mode(ROUTE_ROOT_MODE)
                .create(&path)
                .unwrap();
            Self(path)
        }

        fn install_current(&self, name: &str) {
            std::fs::create_dir_all(self.0.join(GENERATIONS_DIRECTORY).join(name)).unwrap();
            std::fs::set_permissions(
                self.0.join(GENERATIONS_DIRECTORY),
                std::fs::Permissions::from_mode(GENERATIONS_MODE),
            )
            .unwrap();
            std::fs::set_permissions(
                self.0.join(GENERATIONS_DIRECTORY).join(name),
                std::fs::Permissions::from_mode(SEALED_MODE),
            )
            .unwrap();
            symlink(
                format!("{GENERATIONS_DIRECTORY}/{name}"),
                self.0.join(CURRENT_SELECTOR),
            )
            .unwrap();
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn digest(marker: char) -> String {
        format!("sha256:{}", marker.to_string().repeat(64))
    }

    fn workshops() -> [Uuid; 2] {
        [
            Uuid::parse_str("10000000-0000-0000-0000-000000000001").unwrap(),
            Uuid::parse_str("20000000-0000-0000-0000-000000000002").unwrap(),
        ]
    }

    fn intent(kind: RouteSetPublicationKind) -> RouteSetGenerationIntent {
        RouteSetGenerationIntent::new(Uuid::new_v4(), kind, 41, workshops()[0], 73).unwrap()
    }

    fn seal_generation(generation: &mut RouteSetGenerationDirectory) -> SealedRouteSetGeneration {
        let mut sealer = generation.begin_seal().unwrap();
        sealer
            .stage_present(
                workshops()[0],
                4,
                &digest('a'),
                &digest('b'),
                b"server { return 204; }\n",
            )
            .unwrap();
        sealer
            .stage_absent(workshops()[1], 8, &digest('c'), &digest('d'))
            .unwrap();
        sealer.finish().unwrap().clone()
    }

    fn publication_evidence(sealed: &SealedRouteSetGeneration) -> RouteSetPublicationEvidence<'_> {
        RouteSetPublicationEvidence {
            identity: &sealed.identity,
            route_count: sealed.route_count,
            present_route_count: sealed.present_route_count,
            candidate: &sealed.selector,
        }
    }

    #[test]
    fn deterministic_names_are_closed_safe_and_kind_separated() {
        let publication = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(
            RouteSetGenerationName::new(publication, RouteSetPublicationKind::Projection).as_str(),
            "route-aaaaaaaabbbbccccddddeeeeeeeeeeee-projection"
        );
        assert_eq!(
            RouteSetGenerationName::new(publication, RouteSetPublicationKind::RecoveryMaintenance,)
                .selector_target(),
            "generations/route-aaaaaaaabbbbccccddddeeeeeeeeeeee-recovery-maintenance"
        );
        assert_eq!(
            RouteSetGenerationName::new(publication, RouteSetPublicationKind::RecoveryRestore)
                .as_str(),
            "route-aaaaaaaabbbbccccddddeeeeeeeeeeee-recovery-restore"
        );
        assert_eq!(
            RouteSetGenerationName::new(publication, RouteSetPublicationKind::Startup).as_str(),
            "route-aaaaaaaabbbbccccddddeeeeeeeeeeee-startup"
        );
        for kind in [
            RouteSetPublicationKind::Projection,
            RouteSetPublicationKind::RecoveryMaintenance,
            RouteSetPublicationKind::RecoveryRestore,
            RouteSetPublicationKind::Startup,
        ] {
            let name = RouteSetGenerationName::new(publication, kind);
            assert!(name.as_str().len() <= 64);
            validate_selector_target(&name.selector_target()).unwrap();
        }
    }

    #[test]
    fn fleet_scoped_startup_intent_and_empty_generation_are_exact() {
        let root = TestRoot::new();
        let publication_id = Uuid::new_v4();
        let effect_run_id = Uuid::new_v4();
        let intent =
            RouteSetGenerationIntent::new_startup(publication_id, effect_run_id, 41).unwrap();
        let intent_value = serde_json::to_value(&intent).unwrap();
        assert_eq!(intent_value.as_object().unwrap().len(), 5);
        assert_eq!(
            intent_value["startup_effect_run_id"],
            serde_json::json!(effect_run_id)
        );
        assert!(intent_value.get("target_workshop_id").is_none());
        let mut generation = RouteSetGenerationDirectory::create_or_open(&root.0, intent).unwrap();
        let sealed = generation.begin_seal().unwrap().finish().unwrap().clone();
        assert_eq!(sealed.route_count, 0);
        assert_eq!(sealed.present_route_count, 0);
        assert_eq!(sealed.identity.startup_effect_run_id(), Some(effect_run_id));
        assert_eq!(sealed.identity.target_workshop_id(), None);
    }

    #[test]
    fn startup_seals_uninitialized_present_and_absent_rows_with_null_marker() {
        let root = TestRoot::new();
        let intent =
            RouteSetGenerationIntent::new_startup(Uuid::new_v4(), Uuid::new_v4(), 41).unwrap();
        let mut generation = RouteSetGenerationDirectory::create_or_open(&root.0, intent).unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        let present = sealer
            .stage_startup_present(
                workshops()[0],
                1,
                &digest('a'),
                None,
                b"server { return 204; }\n",
            )
            .unwrap();
        let absent = sealer
            .stage_startup_absent(workshops()[1], 2, &digest('b'), None)
            .unwrap();
        assert_eq!(present.applied_rendered_digest, None);
        assert_eq!(absent.applied_rendered_digest, None);
        let sealed = sealer.finish().unwrap();
        assert_eq!(sealed.route_count, 2);
        assert_eq!(sealed.present_route_count, 1);
    }

    #[test]
    fn startup_recovery_disposes_only_the_exact_unpublished_effect_candidate() {
        let root = TestRoot::new();
        let publication_id = Uuid::new_v4();
        let effect_run_id = Uuid::new_v4();
        let intent =
            RouteSetGenerationIntent::new_startup(publication_id, effect_run_id, 41).unwrap();
        let generation = RouteSetGenerationDirectory::create_or_open(&root.0, intent).unwrap();
        let candidate = generation.path();
        assert!(candidate.exists());
        assert!(
            dispose_startup_recovery_candidate(&root.0, publication_id, Uuid::new_v4()).is_err()
        );
        assert!(candidate.exists());
        drop(generation);
        assert!(
            dispose_startup_recovery_candidate(&root.0, publication_id, effect_run_id).unwrap()
        );
        assert!(!candidate.exists());
        assert!(
            !dispose_startup_recovery_candidate(&root.0, publication_id, effect_run_id).unwrap()
        );
    }

    #[test]
    fn retained_published_generation_deletion_is_exact_current_safe_and_retryable() {
        let root = TestRoot::new();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let intent = intent(RouteSetPublicationKind::Projection);
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, intent.clone()).unwrap();
        let sealed = seal_generation(&mut generation);
        generation.publish(&prior).unwrap();
        assert!(matches!(
            delete_retained_route_set_generation(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
                sealed.present_route_count,
            )
            .unwrap(),
            RouteSetRetentionDeletion::ProtectedCurrent { .. }
        ));
        generation.restore_prior(&prior).unwrap();
        drop(generation);
        assert!(matches!(
            delete_retained_route_set_generation(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device() + 1,
                sealed.selector.directory_inode(),
                sealed.route_count,
                sealed.present_route_count,
            )
            .unwrap(),
            RouteSetRetentionDeletion::IdentityMismatch {
                mismatch: RouteSetRetentionMismatch::DirectoryIdentity,
                observed_identity: None,
                ..
            }
        ));
        assert!(matches!(
            delete_retained_route_set_generation(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
                sealed.present_route_count,
            )
            .unwrap(),
            RouteSetRetentionDeletion::Deleted { .. }
        ));
        assert!(matches!(
            delete_retained_route_set_generation(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
                sealed.present_route_count,
            )
            .unwrap(),
            RouteSetRetentionDeletion::AlreadyAbsent
        ));
    }

    #[test]
    fn retained_generation_partial_marker_resumes_without_retrusting_missing_bytes() {
        let root = TestRoot::new();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let intent = intent(RouteSetPublicationKind::Projection);
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, intent.clone()).unwrap();
        let sealed = seal_generation(&mut generation);
        generation.publish(&prior).unwrap();
        generation.restore_prior(&prior).unwrap();
        let directory = generation.path();
        let marker = RouteSetRetentionMarker {
            protocol_version: 1,
            directory_device: sealed.selector.directory_device(),
            directory_inode: sealed.selector.directory_inode(),
            route_count: sealed.route_count,
            present_route_count: sealed.present_route_count,
            intent: &intent,
            identity: &sealed.identity,
        };
        let marker_path = directory.join(RETENTION_MARKER_FILE);
        std::fs::write(&marker_path, retention_marker_bytes(&marker).unwrap()).unwrap();
        std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(FILE_MODE)).unwrap();
        std::fs::remove_file(directory.join(INTENT_FILE)).unwrap();
        drop(generation);
        assert!(matches!(
            delete_retained_route_set_generation(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
                sealed.present_route_count,
            )
            .unwrap(),
            RouteSetRetentionDeletion::Deleted { .. }
        ));
    }

    #[test]
    fn retained_generation_reports_only_valid_content_identity_as_typed_mismatch() {
        let root = TestRoot::new();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let intent = intent(RouteSetPublicationKind::Projection);
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, intent.clone()).unwrap();
        let sealed = seal_generation(&mut generation);
        generation.publish(&prior).unwrap();
        generation.restore_prior(&prior).unwrap();
        let observed = intent.identity(digest('f')).unwrap();
        let identity_path = generation.path().join(ROUTE_SET_GENERATION_FILE);
        std::fs::write(
            &identity_path,
            route_set_generation_config(&observed).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(FILE_MODE))
            .unwrap();
        drop(generation);
        assert!(matches!(
            delete_retained_route_set_generation(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
                sealed.present_route_count,
            )
            .unwrap(),
            RouteSetRetentionDeletion::IdentityMismatch {
                mismatch: RouteSetRetentionMismatch::ContentIdentity,
                observed_identity: Some(identity),
                ..
            } if identity == observed
        ));
    }

    #[test]
    fn retention_step_unlinks_at_most_one_entry_and_loss_stops_remaining_work() {
        let root = TestRoot::new();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let intent = intent(RouteSetPublicationKind::Projection);
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, intent.clone()).unwrap();
        let sealed = seal_generation(&mut generation);
        generation.publish(&prior).unwrap();
        generation.restore_prior(&prior).unwrap();
        let directory = generation.path();
        let before = std::fs::read_dir(&directory).unwrap().count();
        assert_eq!(
            step_retained_route_set_generation_deletion(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
                sealed.present_route_count,
            )
            .unwrap(),
            RouteSetRetentionStep::InProgress
        );
        let marked = std::fs::read_dir(&directory).unwrap().count();
        assert_eq!(marked, before + 1);
        assert_eq!(
            step_retained_route_set_generation_deletion(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
                sealed.present_route_count,
            )
            .unwrap(),
            RouteSetRetentionStep::InProgress
        );
        let after_one_unlink = std::fs::read_dir(&directory).unwrap().count();
        assert_eq!(after_one_unlink + 1, marked);

        // Simulate renewal loss by deliberately not invoking another step.
        // The crash marker and all remaining entries stay durable for takeover.
        assert!(directory.join(RETENTION_MARKER_FILE).exists());
        assert!(after_one_unlink > 1);
    }

    #[test]
    fn retention_refuses_selector_change_before_marker_creation() {
        let root = TestRoot::new();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let intent = intent(RouteSetPublicationKind::Projection);
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, intent.clone()).unwrap();
        let sealed = seal_generation(&mut generation);
        generation.publish(&prior).unwrap();
        generation.restore_prior(&prior).unwrap();
        let current = root.0.join(CURRENT_SELECTOR);
        let candidate = intent.name().selector_target();
        assert!(
            step_retained_route_set_generation_deletion_with_hook(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                (sealed.route_count, sealed.present_route_count),
                || {
                    std::fs::remove_file(&current).unwrap();
                    symlink(&candidate, &current).unwrap();
                },
            )
            .is_err()
        );
        assert!(!generation.path().join(RETENTION_MARKER_FILE).exists());
    }

    #[test]
    fn retention_classifies_same_identity_manifest_or_route_drift_as_content_integrity() {
        let root = TestRoot::new();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let intent = intent(RouteSetPublicationKind::Projection);
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, intent.clone()).unwrap();
        let sealed = seal_generation(&mut generation);
        generation.publish(&prior).unwrap();
        generation.restore_prior(&prior).unwrap();
        let route = std::fs::read_dir(generation.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "conf")
                    && path
                        .file_name()
                        .is_some_and(|name| name != ROUTE_SET_GENERATION_FILE)
            })
            .unwrap();
        std::fs::write(&route, b"tampered\n").unwrap();
        std::fs::set_permissions(&route, std::fs::Permissions::from_mode(FILE_MODE)).unwrap();
        drop(generation);
        assert!(matches!(
            step_retained_route_set_generation_deletion(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
                sealed.present_route_count,
            )
            .unwrap(),
            RouteSetRetentionStep::Complete(RouteSetRetentionDeletion::IdentityMismatch {
                mismatch: RouteSetRetentionMismatch::ContentIntegrity,
                observed_identity: Some(identity),
                ..
            }) if identity == sealed.identity
        ));
    }

    #[test]
    fn dormant_substrate_has_no_active_route_writer_callsite() {
        let driver_root = include_str!("../docker_driver.rs");
        assert_eq!(
            driver_root.matches("mod route_set_generation_fs;").count(),
            1
        );
        assert!(!driver_root.contains("use route_set_generation_fs"));
        assert!(!driver_root.contains("route_set_generation_fs::"));
        for active_source in [
            include_str!("startup.rs"),
            include_str!("release.rs"),
            include_str!("recovery.rs"),
            include_str!("gateway.rs"),
        ] {
            assert!(!active_source.contains("route_set_generation_fs"));
        }
        for active_source in [
            include_str!("startup.rs"),
            include_str!("release.rs"),
            include_str!("recovery.rs"),
            include_str!("gateway.rs"),
            include_str!("route_set_publication.rs"),
        ] {
            for recovery_api in [
                "inspect_pre_start_candidate",
                "dispose_pre_start_candidate",
                "inspect_post_start_publication",
                "resume_post_start_publication_forward",
            ] {
                assert!(!active_source.contains(recovery_api));
            }
        }
        let forward_resume = include_str!("route_set_generation_fs.rs")
            .split("pub(super) fn resume_post_start_publication_forward")
            .nth(1)
            .unwrap()
            .split("pub(super) fn observe_candidate_selector")
            .next()
            .unwrap();
        assert!(!forward_resume.contains("SelectorExchange::Restore"));
        assert!(!forward_resume.contains("restore_prior"));
        let production = include_str!("route_set_generation_fs.rs")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap();
        assert_eq!(
            production
                .matches("ExclusiveOriginalWriterResumeAuthority {")
                .count(),
            1,
            "the dormant capability must have no production minting path"
        );
        for exposed_legacy_primitive in [
            "pub(super) fn restore_prior",
            "pub(crate) fn restore_prior",
            "pub fn restore_prior",
            "pub(super) fn recover_exchange_artifact",
            "pub(crate) fn recover_exchange_artifact",
            "pub fn recover_exchange_artifact",
            "pub(super) enum SelectorExchange",
            "pub(crate) enum SelectorExchange",
            "pub enum SelectorExchange",
        ] {
            assert!(!production.contains(exposed_legacy_primitive));
        }
    }

    #[test]
    fn present_and_absent_routes_seal_publish_observe_and_restore_exactly() {
        let root = TestRoot::new();
        let publication = intent(RouteSetPublicationKind::Projection);
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, publication.clone()).unwrap();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let sealed = seal_generation(&mut generation);
        assert_eq!(sealed.route_count, 2);
        assert_eq!(sealed.present_route_count, 1);
        assert!(
            !generation
                .path()
                .join(format!("{}.conf", workshops()[1]))
                .exists()
        );
        assert_eq!(
            observe_candidate_selector(&root.0, &publication).unwrap(),
            sealed.selector
        );
        assert_eq!(
            observe_generation_identity(&root.0, &publication, 2, 1, false).unwrap(),
            sealed.identity
        );

        drop(generation);
        let mut generation = RouteSetGenerationDirectory::open_existing_sealed(
            &root.0,
            publication.clone(),
            &sealed.identity.route_set_digest,
            2,
            1,
        )
        .unwrap();
        assert_eq!(generation.publish(&prior).unwrap(), prior);
        assert_eq!(
            generation.observe_selected().unwrap().identity,
            sealed.identity
        );
        assert_eq!(
            observe_selected_identity(&root.0, &publication, &sealed.identity, 2, 1).unwrap(),
            sealed.selector
        );
        drop(generation);
        let mut reopened = RouteSetGenerationDirectory::open_existing_published(
            &root.0,
            publication,
            &sealed.identity.route_set_digest,
            2,
            1,
        )
        .unwrap();
        reopened.restore_prior(&prior).unwrap();
        assert_eq!(observe_current_selector(&root.0).unwrap(), prior);
        assert!(reopened.dispose().is_err());
    }

    #[test]
    fn digest_stream_has_exact_documented_byte_parity_and_is_context_independent() {
        let first_root = TestRoot::new();
        let mut first = RouteSetGenerationDirectory::create_or_open(
            &first_root.0,
            intent(RouteSetPublicationKind::Projection),
        )
        .unwrap();
        let first_seal = seal_generation(&mut first);
        assert_eq!(
            first_seal.identity.route_set_digest,
            "sha256:ed57e110d146e261900657e93e91e3ac339f04deed975d8422be1ab9d106569b"
        );

        let second_root = TestRoot::new();
        let mut second = RouteSetGenerationDirectory::create_or_open(
            &second_root.0,
            intent(RouteSetPublicationKind::RecoveryMaintenance),
        )
        .unwrap();
        let second_seal = seal_generation(&mut second);
        assert_eq!(
            first_seal.identity.route_set_digest,
            second_seal.identity.route_set_digest
        );
        assert_ne!(first_seal.identity, second_seal.identity);
    }

    #[test]
    fn staging_retry_requires_exact_intent_manifest_and_route_bytes() {
        let root = TestRoot::new();
        let publication = intent(RouteSetPublicationKind::RecoveryMaintenance);
        let mut first =
            RouteSetGenerationDirectory::create_or_open(&root.0, publication.clone()).unwrap();
        {
            let mut sealer = first.begin_seal().unwrap();
            sealer
                .stage_present(
                    workshops()[0],
                    4,
                    &digest('a'),
                    &digest('b'),
                    b"server { return 204; }\n",
                )
                .unwrap();
        }
        drop(first);
        let changed = RouteSetGenerationIntent::new(
            publication.publication_id,
            publication.publication_kind,
            42,
            publication.target_scope().unwrap().0,
            publication.target_scope().unwrap().1,
        )
        .unwrap();
        assert!(RouteSetGenerationDirectory::create_or_open(&root.0, changed).is_err());

        let mut retry = RouteSetGenerationDirectory::create_or_open(&root.0, publication).unwrap();
        let mut sealer = retry.begin_seal().unwrap();
        sealer
            .stage_present(
                workshops()[0],
                4,
                &digest('a'),
                &digest('b'),
                b"server { return 204; }\n",
            )
            .unwrap();
        sealer
            .stage_absent(workshops()[1], 8, &digest('c'), &digest('d'))
            .unwrap();
        sealer.finish().unwrap();
    }

    #[test]
    fn ordering_bounds_and_partial_create_only_evidence_fail_closed() {
        let root = TestRoot::new();
        let publication = intent(RouteSetPublicationKind::Projection);
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, publication).unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        sealer
            .stage_absent(workshops()[1], 1, &digest('a'), &digest('b'))
            .unwrap();
        assert!(
            sealer
                .stage_absent(workshops()[0], 1, &digest('a'), &digest('b'))
                .is_err()
        );
        drop(sealer);

        let partial_root = TestRoot::new();
        let partial_intent = intent(RouteSetPublicationKind::RecoveryRestore);
        let partial_generation =
            RouteSetGenerationDirectory::create_or_open(&partial_root.0, partial_intent.clone())
                .unwrap();
        let manifest = partial_generation.path().join(EVIDENCE_FILE);
        std::fs::write(&manifest, b"{\"workshop_id\":").unwrap();
        std::fs::set_permissions(&manifest, std::fs::Permissions::from_mode(FILE_MODE)).unwrap();
        drop(partial_generation);
        let mut reopened =
            RouteSetGenerationDirectory::create_or_open(&partial_root.0, partial_intent).unwrap();
        assert!(
            reopened
                .begin_seal()
                .unwrap()
                .stage_absent(workshops()[0], 1, &digest('a'), &digest('b'))
                .is_err()
        );
        assert_eq!(std::fs::read(manifest).unwrap(), b"{\"workshop_id\":");

        let empty_root = TestRoot::new();
        let empty_intent = intent(RouteSetPublicationKind::Projection);
        let mut empty =
            RouteSetGenerationDirectory::create_or_open(&empty_root.0, empty_intent.clone())
                .unwrap();
        assert!(empty.begin_seal().unwrap().finish().is_err());
        drop(empty);
        for (total, present) in [(0, 0), (MAX_ROUTES + 1, 0), (1, 2)] {
            assert!(
                RouteSetGenerationDirectory::open_existing_sealed(
                    &empty_root.0,
                    empty_intent.clone(),
                    &digest('a'),
                    total,
                    present,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn sealed_route_manifest_identity_and_membership_tampering_is_detected() {
        let root = TestRoot::new();
        let publication = intent(RouteSetPublicationKind::Projection);
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, publication).unwrap();
        let sealed = seal_generation(&mut generation);
        let route = generation.path().join(format!("{}.conf", workshops()[0]));
        let original_route = std::fs::read(&route).unwrap();
        std::fs::write(&route, b"server { return 500; }\n").unwrap();
        assert!(generation.verify_sealed_bytes().is_err());
        std::fs::write(&route, original_route).unwrap();

        let manifest = generation.path().join(EVIDENCE_FILE);
        let original_manifest = std::fs::read(&manifest).unwrap();
        let mut changed = original_manifest.clone();
        changed[0] = b'[';
        std::fs::write(&manifest, changed).unwrap();
        assert!(generation.verify_sealed_bytes().is_err());
        std::fs::write(&manifest, original_manifest).unwrap();

        let identity = generation.path().join(ROUTE_SET_GENERATION_FILE);
        let original_identity = std::fs::read(&identity).unwrap();
        std::fs::write(&identity, b"not canonical\n").unwrap();
        assert!(generation.verify_sealed_bytes().is_err());
        std::fs::write(&identity, original_identity).unwrap();

        let extra = generation.path().join(format!("{}.conf", Uuid::new_v4()));
        std::fs::write(&extra, b"server { return 418; }\n").unwrap();
        std::fs::set_permissions(&extra, std::fs::Permissions::from_mode(FILE_MODE)).unwrap();
        assert!(generation.verify_sealed_bytes().is_err());
        std::fs::remove_file(extra).unwrap();
        assert_eq!(generation.verify_sealed_bytes().unwrap(), ());
        assert_eq!(sealed.route_count, 2);
    }

    #[test]
    fn hostile_symlink_hardlink_mode_and_directory_replacement_fail_closed() {
        for attack in ["symlink", "hardlink", "mode"] {
            let root = TestRoot::new();
            let mut generation = RouteSetGenerationDirectory::create_or_open(
                &root.0,
                intent(RouteSetPublicationKind::Projection),
            )
            .unwrap();
            let route = generation.path().join(format!("{}.conf", workshops()[0]));
            let victim = root.0.join(format!("victim-{attack}"));
            std::fs::write(&victim, b"server { return 204; }\n").unwrap();
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(FILE_MODE)).unwrap();
            match attack {
                "symlink" => symlink(&victim, &route).unwrap(),
                "hardlink" => hard_link(&victim, &route).unwrap(),
                "mode" => {
                    std::fs::write(&route, b"server { return 204; }\n").unwrap();
                    std::fs::set_permissions(&route, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                generation
                    .begin_seal()
                    .unwrap()
                    .stage_present(
                        workshops()[0],
                        1,
                        &digest('a'),
                        &digest('b'),
                        b"server { return 204; }\n",
                    )
                    .is_err()
            );
            assert_eq!(std::fs::read(victim).unwrap(), b"server { return 204; }\n");
        }

        let root = TestRoot::new();
        let publication = intent(RouteSetPublicationKind::Projection);
        let generation = RouteSetGenerationDirectory::create_or_open(&root.0, publication).unwrap();
        let original = generation.path();
        let moved = root.0.join("generations/moved");
        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(STAGING_MODE)).unwrap();
        assert!(generation.dispose().is_err());
    }

    #[test]
    fn marker_before_exchange_is_permanent_and_selector_race_is_detected() {
        let root = TestRoot::new();
        let publication = intent(RouteSetPublicationKind::RecoveryMaintenance);
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, publication.clone()).unwrap();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let sealed = seal_generation(&mut generation);
        assert!(
            generation
                .publish_with_hooks(
                    &prior,
                    || Err(invalid_state("simulated marker crash")),
                    || Ok(()),
                )
                .is_err()
        );
        assert_eq!(observe_current_selector(&root.0).unwrap(), prior);
        assert!(dispose_exact_unpublished(&root.0, &publication).is_err());
        drop(generation);
        RouteSetGenerationDirectory::open_existing_published(
            &root.0,
            publication,
            &sealed.identity.route_set_digest,
            2,
            1,
        )
        .unwrap();

        let race_root = TestRoot::new();
        let race_intent = intent(RouteSetPublicationKind::Projection);
        let mut raced =
            RouteSetGenerationDirectory::create_or_open(&race_root.0, race_intent.clone()).unwrap();
        race_root.install_current("boot-live");
        let race_prior = observe_current_selector(&race_root.0).unwrap();
        let raced_seal = seal_generation(&mut raced);
        let path = race_root.0.clone();
        assert!(
            raced
                .publish_with_hooks(
                    &race_prior,
                    || {
                        std::fs::create_dir(path.join("generations/raced-live"))?;
                        std::fs::set_permissions(
                            path.join("generations/raced-live"),
                            std::fs::Permissions::from_mode(SEALED_MODE),
                        )?;
                        std::fs::remove_file(path.join(CURRENT_SELECTOR))?;
                        symlink("generations/raced-live", path.join(CURRENT_SELECTOR))
                    },
                    || Ok(()),
                )
                .is_err()
        );
        let selected_after_race = observe_current_selector(&race_root.0).unwrap();
        assert_eq!(selected_after_race.target(), "generations/raced-live");
        assert_ne!(selected_after_race, raced_seal.selector);
        assert!(dispose_exact_unpublished(&race_root.0, &race_intent).is_err());

        let tamper_root = TestRoot::new();
        let tamper_intent = intent(RouteSetPublicationKind::Projection);
        let mut tampered =
            RouteSetGenerationDirectory::create_or_open(&tamper_root.0, tamper_intent).unwrap();
        tamper_root.install_current("boot-live");
        let tamper_prior = observe_current_selector(&tamper_root.0).unwrap();
        let tamper_seal = seal_generation(&mut tampered);
        let route = tampered.path().join(format!("{}.conf", workshops()[0]));
        assert!(
            tampered
                .publish_with_hooks(
                    &tamper_prior,
                    || std::fs::write(&route, b"server { return 500; }\n"),
                    || Ok(()),
                )
                .is_err()
        );
        assert_eq!(
            observe_current_selector(&tamper_root.0).unwrap(),
            tamper_prior
        );
        assert_ne!(
            observe_current_selector(&tamper_root.0).unwrap(),
            tamper_seal.selector
        );
    }

    #[test]
    fn prepublication_disposal_and_exchange_artifact_recovery_are_exact() {
        let disposable_root = TestRoot::new();
        let disposable_intent = intent(RouteSetPublicationKind::Projection);
        let mut disposable = RouteSetGenerationDirectory::create_or_open(
            &disposable_root.0,
            disposable_intent.clone(),
        )
        .unwrap();
        seal_generation(&mut disposable);
        drop(disposable);
        dispose_exact_unpublished(&disposable_root.0, &disposable_intent).unwrap();
        assert!(
            !disposable_root
                .0
                .join(disposable_intent.name().selector_target())
                .exists()
        );

        let root = TestRoot::new();
        let publication = intent(RouteSetPublicationKind::RecoveryRestore);
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, publication.clone()).unwrap();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let sealed = seal_generation(&mut generation);
        assert!(
            generation
                .publish_with_hooks(
                    &prior,
                    || Ok(()),
                    || Err(invalid_state("simulated exchanged crash")),
                )
                .is_err()
        );
        assert_eq!(
            recover_exchange_artifact(
                &root.0,
                &publication,
                RouteSetPublicationEvidence {
                    identity: &sealed.identity,
                    route_count: 2,
                    present_route_count: 1,
                    candidate: &sealed.selector,
                },
                &prior,
                SelectorExchange::Publish,
            )
            .unwrap(),
            ExchangeRecovery::ExchangedArtifactRemoved
        );
        assert_eq!(
            recover_exchange_artifact(
                &root.0,
                &publication,
                RouteSetPublicationEvidence {
                    identity: &sealed.identity,
                    route_count: 2,
                    present_route_count: 1,
                    candidate: &sealed.selector,
                },
                &prior,
                SelectorExchange::Publish,
            )
            .unwrap(),
            ExchangeRecovery::AlreadyCleanCandidateSelected
        );
    }

    #[test]
    fn prepared_restore_and_foreign_exchange_artifacts_are_distinguished() {
        let prepared_root = TestRoot::new();
        let prepared_intent = intent(RouteSetPublicationKind::RecoveryMaintenance);
        let mut prepared =
            RouteSetGenerationDirectory::create_or_open(&prepared_root.0, prepared_intent.clone())
                .unwrap();
        prepared_root.install_current("boot-live");
        let prepared_prior = observe_current_selector(&prepared_root.0).unwrap();
        let prepared_seal = seal_generation(&mut prepared);
        prepared.install_publication_marker().unwrap();
        prepared.phase = GenerationPhase::Published;
        let prepared_artifact = exchange_artifact_name(&prepared_intent, SelectorExchange::Publish);
        symlink(
            prepared_intent.name().selector_target(),
            prepared_root.0.join(&prepared_artifact),
        )
        .unwrap();
        assert_eq!(
            recover_exchange_artifact(
                &prepared_root.0,
                &prepared_intent,
                RouteSetPublicationEvidence {
                    identity: &prepared_seal.identity,
                    route_count: 2,
                    present_route_count: 1,
                    candidate: &prepared_seal.selector,
                },
                &prepared_prior,
                SelectorExchange::Publish,
            )
            .unwrap(),
            ExchangeRecovery::PreparedArtifactRemoved
        );
        assert_eq!(
            recover_exchange_artifact(
                &prepared_root.0,
                &prepared_intent,
                RouteSetPublicationEvidence {
                    identity: &prepared_seal.identity,
                    route_count: 2,
                    present_route_count: 1,
                    candidate: &prepared_seal.selector,
                },
                &prepared_prior,
                SelectorExchange::Publish,
            )
            .unwrap(),
            ExchangeRecovery::AlreadyCleanPriorSelected
        );

        let restore_root = TestRoot::new();
        let restore_intent = intent(RouteSetPublicationKind::RecoveryRestore);
        let mut restore =
            RouteSetGenerationDirectory::create_or_open(&restore_root.0, restore_intent.clone())
                .unwrap();
        restore_root.install_current("boot-live");
        let restore_prior = observe_current_selector(&restore_root.0).unwrap();
        let restore_seal = seal_generation(&mut restore);
        restore.publish(&restore_prior).unwrap();
        let restore_artifact = exchange_artifact_name(&restore_intent, SelectorExchange::Restore);
        symlink(
            restore_prior.target(),
            restore_root.0.join(&restore_artifact),
        )
        .unwrap();
        let root_handle = open_directory(&restore_root.0).unwrap();
        rename_exchange(
            &root_handle,
            &cstring(&restore_artifact).unwrap(),
            &cstring(CURRENT_SELECTOR).unwrap(),
        )
        .unwrap();
        root_handle.sync_all().unwrap();
        assert_eq!(
            recover_exchange_artifact(
                &restore_root.0,
                &restore_intent,
                RouteSetPublicationEvidence {
                    identity: &restore_seal.identity,
                    route_count: 2,
                    present_route_count: 1,
                    candidate: &restore_seal.selector,
                },
                &restore_prior,
                SelectorExchange::Restore,
            )
            .unwrap(),
            ExchangeRecovery::ExchangedArtifactRemoved
        );

        let foreign = exchange_artifact_name(&restore_intent, SelectorExchange::Publish);
        symlink(restore_prior.target(), restore_root.0.join(&foreign)).unwrap();
        assert!(
            recover_exchange_artifact(
                &restore_root.0,
                &restore_intent,
                RouteSetPublicationEvidence {
                    identity: &restore_seal.identity,
                    route_count: 2,
                    present_route_count: 1,
                    candidate: &restore_seal.selector,
                },
                &restore_prior,
                SelectorExchange::Publish,
            )
            .is_err()
        );
        assert!(restore_root.0.join(foreign).is_symlink());
    }

    #[test]
    fn pre_start_inspection_classifies_absent_pristine_partial_and_sealed() {
        let absent_root = TestRoot::new();
        let absent_intent = intent(RouteSetPublicationKind::Projection);
        absent_root.install_current("boot-live");
        let absent_prior = observe_current_selector(&absent_root.0).unwrap();
        assert_eq!(
            inspect_pre_start_candidate(
                &absent_root.0,
                &absent_intent,
                &absent_prior,
                ExpectedPreStartState::Staging,
            )
            .unwrap(),
            PreStartCandidateInspection::UnstartedAbsent
        );

        let partial_root = TestRoot::new();
        let partial_intent = intent(RouteSetPublicationKind::Projection);
        partial_root.install_current("boot-live");
        let partial_prior = observe_current_selector(&partial_root.0).unwrap();
        let mut partial =
            RouteSetGenerationDirectory::create_or_open(&partial_root.0, partial_intent.clone())
                .unwrap();
        assert_eq!(
            inspect_pre_start_candidate(
                &partial_root.0,
                &partial_intent,
                &partial_prior,
                ExpectedPreStartState::Staging,
            )
            .unwrap(),
            PreStartCandidateInspection::Pristine
        );
        {
            let mut sealer = partial.begin_seal().unwrap();
            sealer
                .stage_present(
                    workshops()[0],
                    4,
                    &digest('a'),
                    &digest('b'),
                    b"server { return 204; }\n",
                )
                .unwrap();
        }
        assert_eq!(
            inspect_pre_start_candidate(
                &partial_root.0,
                &partial_intent,
                &partial_prior,
                ExpectedPreStartState::Staging,
            )
            .unwrap(),
            PreStartCandidateInspection::StagedPartial {
                record_count: 1,
                present_count: 1,
            }
        );
        assert_eq!(
            dispose_pre_start_candidate(
                &partial_root.0,
                &partial_intent,
                &partial_prior,
                ExpectedPreStartState::Staging,
            )
            .unwrap(),
            PreStartCandidateInspection::StagedPartial {
                record_count: 1,
                present_count: 1,
            }
        );
        assert!(!partial.path().exists());

        let sealed_root = TestRoot::new();
        let sealed_intent = intent(RouteSetPublicationKind::RecoveryRestore);
        sealed_root.install_current("boot-live");
        let sealed_prior = observe_current_selector(&sealed_root.0).unwrap();
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&sealed_root.0, sealed_intent.clone())
                .unwrap();
        let sealed = seal_generation(&mut generation);
        assert_eq!(
            inspect_pre_start_candidate(
                &sealed_root.0,
                &sealed_intent,
                &sealed_prior,
                ExpectedPreStartState::Sealed(publication_evidence(&sealed)),
            )
            .unwrap(),
            PreStartCandidateInspection::SealedNotPublished
        );
        generation.install_publication_marker().unwrap();
        generation.phase = GenerationPhase::Published;
        assert!(
            inspect_pre_start_candidate(
                &sealed_root.0,
                &sealed_intent,
                &sealed_prior,
                ExpectedPreStartState::Sealed(publication_evidence(&sealed)),
            )
            .is_err()
        );
        assert!(dispose_exact_unpublished(&sealed_root.0, &sealed_intent).is_err());
    }

    #[test]
    fn pre_start_inspection_rejects_same_publication_exchange_artifacts_untouched() {
        for exchange in [SelectorExchange::Publish, SelectorExchange::Restore] {
            let root = TestRoot::new();
            let publication = intent(RouteSetPublicationKind::Projection);
            root.install_current("boot-live");
            let prior = observe_current_selector(&root.0).unwrap();
            let artifact = root.0.join(exchange_artifact_name(&publication, exchange));
            symlink(publication.name().selector_target(), &artifact).unwrap();
            assert!(
                inspect_pre_start_candidate(
                    &root.0,
                    &publication,
                    &prior,
                    ExpectedPreStartState::Staging,
                )
                .is_err()
            );
            assert!(artifact.is_symlink());
        }
    }

    #[test]
    fn post_start_forward_resume_covers_every_exact_crash_shape_idempotently() {
        for crash in [
            "before_marker",
            "marker",
            "prepared",
            "exchanged",
            "selected",
        ] {
            let root = TestRoot::new();
            let publication = intent(RouteSetPublicationKind::Projection);
            root.install_current("boot-live");
            let prior = observe_current_selector(&root.0).unwrap();
            let mut generation =
                RouteSetGenerationDirectory::create_or_open(&root.0, publication.clone()).unwrap();
            let sealed = seal_generation(&mut generation);
            match crash {
                "before_marker" => {}
                "marker" => {
                    generation.install_publication_marker().unwrap();
                    generation.phase = GenerationPhase::Published;
                }
                "prepared" => {
                    generation.install_publication_marker().unwrap();
                    generation.phase = GenerationPhase::Published;
                    symlink(
                        sealed.selector.target(),
                        root.0.join(exchange_artifact_name(
                            &publication,
                            SelectorExchange::Publish,
                        )),
                    )
                    .unwrap();
                }
                "exchanged" => {
                    assert!(
                        generation
                            .publish_with_hooks(
                                &prior,
                                || Ok(()),
                                || Err(invalid_state("injected post-exchange crash")),
                            )
                            .is_err()
                    );
                }
                "selected" => {
                    generation.publish(&prior).unwrap();
                }
                _ => unreachable!(),
            }
            let expected = match crash {
                "before_marker" => PostStartPublicationInspection::SealedBeforeMarker,
                "marker" => PostStartPublicationInspection::MarkerBeforeExchange,
                "prepared" => PostStartPublicationInspection::PreparedExchange,
                "exchanged" => PostStartPublicationInspection::ExchangeDone,
                "selected" => PostStartPublicationInspection::CandidateSelected,
                _ => unreachable!(),
            };
            assert_eq!(
                inspect_post_start_publication(
                    &root.0,
                    &publication,
                    publication_evidence(&sealed),
                    &prior,
                )
                .unwrap(),
                expected,
                "{crash}"
            );
            resume_post_start_publication_forward(
                exclusive_original_writer_authority(),
                &root.0,
                &publication,
                publication_evidence(&sealed),
                &prior,
            )
            .unwrap();
            assert_eq!(observe_current_selector(&root.0).unwrap(), sealed.selector);
            assert_eq!(
                resume_post_start_publication_forward(
                    exclusive_original_writer_authority(),
                    &root.0,
                    &publication,
                    publication_evidence(&sealed),
                    &prior,
                )
                .unwrap(),
                ForwardPublicationResume::AlreadySelected,
                "{crash}"
            );
        }
    }

    #[test]
    fn post_start_inspection_refuses_complementary_restore_crash_artifacts() {
        for crash in ["prepared_restore", "exchanged_restore"] {
            let root = TestRoot::new();
            let publication = intent(RouteSetPublicationKind::RecoveryRestore);
            root.install_current("boot-live");
            let prior = observe_current_selector(&root.0).unwrap();
            let mut generation =
                RouteSetGenerationDirectory::create_or_open(&root.0, publication.clone()).unwrap();
            let sealed = seal_generation(&mut generation);
            generation.publish(&prior).unwrap();
            let restore_artifact = root.0.join(exchange_artifact_name(
                &publication,
                SelectorExchange::Restore,
            ));
            symlink(prior.target(), &restore_artifact).unwrap();
            if crash == "exchanged_restore" {
                std::fs::remove_file(root.0.join(CURRENT_SELECTOR)).unwrap();
                symlink(prior.target(), root.0.join(CURRENT_SELECTOR)).unwrap();
                std::fs::remove_file(&restore_artifact).unwrap();
                symlink(sealed.selector.target(), &restore_artifact).unwrap();
            }
            assert_eq!(
                inspect_post_start_publication(
                    &root.0,
                    &publication,
                    publication_evidence(&sealed),
                    &prior,
                )
                .unwrap(),
                PostStartPublicationInspection::ForeignOrInconclusive,
                "{crash}"
            );
            assert!(
                resume_post_start_publication_forward(
                    exclusive_original_writer_authority(),
                    &root.0,
                    &publication,
                    publication_evidence(&sealed),
                    &prior,
                )
                .is_err(),
                "{crash}"
            );
            assert!(restore_artifact.is_symlink(), "{crash}");
            let expected_current = if crash == "prepared_restore" {
                &sealed.selector
            } else {
                &prior
            };
            assert_eq!(
                observe_current_selector(&root.0).unwrap(),
                *expected_current,
                "{crash}"
            );
        }
    }

    #[test]
    fn recovery_inspection_rejects_foreign_artifacts_and_hostile_identity_files() {
        let root = TestRoot::new();
        let publication = intent(RouteSetPublicationKind::RecoveryMaintenance);
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, publication.clone()).unwrap();
        let sealed = seal_generation(&mut generation);
        generation.install_publication_marker().unwrap();
        generation.phase = GenerationPhase::Published;
        let artifact = exchange_artifact_name(&publication, SelectorExchange::Publish);
        symlink(prior.target(), root.0.join(&artifact)).unwrap();
        assert_eq!(
            inspect_post_start_publication(
                &root.0,
                &publication,
                publication_evidence(&sealed),
                &prior,
            )
            .unwrap(),
            PostStartPublicationInspection::ForeignOrInconclusive
        );
        assert!(
            resume_post_start_publication_forward(
                exclusive_original_writer_authority(),
                &root.0,
                &publication,
                publication_evidence(&sealed),
                &prior,
            )
            .is_err()
        );
        assert!(root.0.join(&artifact).is_symlink());

        std::fs::remove_file(root.0.join(&artifact)).unwrap();
        let marker = generation.path().join(PUBLICATION_MARKER_FILE);
        let victim = root.0.join("marker-victim");
        std::fs::write(&victim, identity_line(&sealed.identity).unwrap()).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(FILE_MODE)).unwrap();
        std::fs::remove_file(&marker).unwrap();
        hard_link(&victim, &marker).unwrap();
        assert!(
            inspect_post_start_publication(
                &root.0,
                &publication,
                publication_evidence(&sealed),
                &prior,
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            identity_line(&sealed.identity).unwrap()
        );
    }

    #[test]
    fn recovery_inspection_rejects_symlink_mode_intent_and_inode_drift() {
        for attack in ["symlink", "mode"] {
            let root = TestRoot::new();
            let publication = intent(RouteSetPublicationKind::Projection);
            root.install_current("boot-live");
            let prior = observe_current_selector(&root.0).unwrap();
            let mut generation =
                RouteSetGenerationDirectory::create_or_open(&root.0, publication.clone()).unwrap();
            let sealed = seal_generation(&mut generation);
            generation.install_publication_marker().unwrap();
            generation.phase = GenerationPhase::Published;
            let marker = generation.path().join(PUBLICATION_MARKER_FILE);
            match attack {
                "symlink" => {
                    let victim = root.0.join("marker-victim");
                    std::fs::write(&victim, identity_line(&sealed.identity).unwrap()).unwrap();
                    std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(FILE_MODE))
                        .unwrap();
                    std::fs::remove_file(&marker).unwrap();
                    symlink(&victim, &marker).unwrap();
                }
                "mode" => std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600))
                    .unwrap(),
                _ => unreachable!(),
            }
            assert!(
                inspect_post_start_publication(
                    &root.0,
                    &publication,
                    publication_evidence(&sealed),
                    &prior,
                )
                .is_err(),
                "{attack}"
            );
        }

        let root = TestRoot::new();
        let publication = intent(RouteSetPublicationKind::Projection);
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, publication.clone()).unwrap();
        let sealed = seal_generation(&mut generation);
        let foreign_intent = RouteSetGenerationIntent::new(
            Uuid::new_v4(),
            publication.publication_kind,
            publication.global_fence_token,
            publication.target_scope().unwrap().0,
            publication.target_scope().unwrap().1,
        )
        .unwrap();
        assert!(
            inspect_pre_start_candidate(
                &root.0,
                &foreign_intent,
                &prior,
                ExpectedPreStartState::Sealed(publication_evidence(&sealed)),
            )
            .is_err()
        );
        let wrong_inode = PriorSelector::from_recorded(
            sealed.selector.target().to_owned(),
            sealed.selector.directory_device(),
            sealed.selector.directory_inode() + 1,
        )
        .unwrap();
        assert!(
            inspect_pre_start_candidate(
                &root.0,
                &publication,
                &prior,
                ExpectedPreStartState::Sealed(RouteSetPublicationEvidence {
                    identity: &sealed.identity,
                    route_count: sealed.route_count,
                    present_route_count: sealed.present_route_count,
                    candidate: &wrong_inode,
                }),
            )
            .is_err()
        );
    }

    #[test]
    fn staging_does_not_read_bytes_from_current() {
        use std::ffi::CString;

        let root = TestRoot::new();
        let publication = intent(RouteSetPublicationKind::Projection);
        let mut generation =
            RouteSetGenerationDirectory::create_or_open(&root.0, publication).unwrap();
        root.install_current("boot-live");
        let live_fifo = root.0.join("generations/boot-live/trap.conf");
        let fifo = CString::new(live_fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: mkfifo retains no pointer and the C string is valid.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o640) }, 0);
        seal_generation(&mut generation);
    }
}
