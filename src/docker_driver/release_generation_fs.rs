//! Immutable filesystem substrate for projection-derived release overlays.
//!
//! The database owns authority and transition authentication. This module owns
//! only deterministic names, immutable bytes, directory/selector identity, and
//! the local publication boundary. It intentionally has no API that reads
//! route bytes from the live selector.
//!
//! **Cutover prohibition:** this substrate must remain dormant while normal
//! route writers can mutate files below `current`. Release publication may be
//! wired only after every normal route update is copy-on-write and publishes a
//! new immutable generation; otherwise a successful release seal could be
//! changed later through the selected directory.
#![allow(dead_code)]

use std::fs::File;
use std::io::{self, BufReader, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::gateway::{
    RELEASE_OVERLAY_GENERATION_FILE, ReleaseOverlayGenerationIdentity, ReleaseOverlayKind,
    ReleaseTargetSlot, parse_release_overlay_generation_config, release_overlay_generation_config,
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

const INTENT_FILE: &str = ".release-overlay-intent-v1";
const EVIDENCE_FILE: &str = ".release-overlay-evidence-v1";
const PUBLICATION_MARKER_FILE: &str = ".release-overlay-publication-started-v1";
const RETENTION_MARKER_FILE: &str = ".release-overlay-retention-v1";
const MAX_RELEASE_ROUTES: usize = 500;
const MAX_EVIDENCE_LINE_BYTES: usize = 512;
pub(super) const ACTIVE_RELEASE_CUTOVER_ALLOWED: bool = false;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ReleaseGenerationName(String);

impl ReleaseGenerationName {
    pub(super) fn new(fleet_run_id: Uuid, kind: ReleaseOverlayKind) -> Self {
        Self(format!(
            "release-{}-{}",
            fleet_run_id.simple(),
            kind.as_str()
        ))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn selector_target(&self) -> String {
        format!("{GENERATIONS_DIRECTORY}/{}", self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseGenerationIntent {
    protocol_version: u8,
    pub fleet_run_id: Uuid,
    pub driver_operation_id: Uuid,
    pub original_global_fence_token: i64,
    pub overlay_kind: ReleaseOverlayKind,
    pub target_slot: ReleaseTargetSlot,
}

impl ReleaseGenerationIntent {
    pub(super) fn new(
        fleet_run_id: Uuid,
        driver_operation_id: Uuid,
        original_global_fence_token: i64,
        overlay_kind: ReleaseOverlayKind,
        target_slot: &str,
    ) -> io::Result<Self> {
        let intent = Self {
            protocol_version: 1,
            fleet_run_id,
            driver_operation_id,
            original_global_fence_token,
            overlay_kind,
            target_slot: ReleaseTargetSlot::parse(target_slot)
                .map_err(|error| io::Error::other(error.1))?,
        };
        intent.validate()?;
        Ok(intent)
    }

    fn validate(&self) -> io::Result<()> {
        if self.protocol_version != 1
            || self.fleet_run_id.is_nil()
            || self.driver_operation_id.is_nil()
            || self.original_global_fence_token <= 0
        {
            return Err(invalid_input("release generation intent is invalid"));
        }
        Ok(())
    }

    fn name(&self) -> ReleaseGenerationName {
        ReleaseGenerationName::new(self.fleet_run_id, self.overlay_kind)
    }

    fn canonical_bytes(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = serde_json::to_vec(self).map_err(io::Error::other)?;
        bytes.push(b'\n');
        if bytes.len() > 1024 {
            return Err(invalid_input("release generation intent exceeds its bound"));
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct ReleaseRouteSealEvidence {
    pub workshop_id: Uuid,
    pub projection_generation: i64,
    pub projection_digest: String,
    pub applied_rendered_digest: String,
    pub rendered_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GenerationPhase {
    Staging,
    Sealed,
    Published,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseSelectorExchange {
    Publish,
    RestorePrior,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseExchangeRecovery {
    AlreadyClean,
    PreparedArtifactRemoved,
    ExchangedArtifactRemoved,
}

#[derive(Clone, Debug)]
pub(super) struct SealedReleaseGeneration {
    pub name: ReleaseGenerationName,
    pub identity: ReleaseOverlayGenerationIdentity,
    pub route_count: usize,
    /// Exact deterministic selector target plus the candidate directory's
    /// device/inode. The database freezes this before publication and must
    /// compare all three fields during every later transition.
    pub selector: PriorSelector,
}

pub(super) struct ReleaseGenerationSealer<'a> {
    generation: &'a mut ReleaseGenerationDirectory,
    hasher: Sha256,
    previous_workshop: Option<Uuid>,
    route_count: usize,
    manifest_reader: BufReader<File>,
    manifest_append: File,
    existing_manifest_exhausted: bool,
}

#[derive(Debug)]
pub(super) struct ReleaseGenerationDirectory {
    root_path: PathBuf,
    root: File,
    generations: File,
    directory: File,
    directory_dev: u64,
    directory_ino: u64,
    intent: ReleaseGenerationIntent,
    name: ReleaseGenerationName,
    phase: GenerationPhase,
    sealed: Option<SealedReleaseGeneration>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ReleaseGenerationRetentionDeletion {
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
        mismatch: ReleaseGenerationRetentionMismatch,
        observed_identity: Option<ReleaseOverlayGenerationIdentity>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ReleaseGenerationRetentionStep {
    InProgress,
    Complete(ReleaseGenerationRetentionDeletion),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseGenerationRetentionMismatch {
    DirectoryIdentity,
    ContentIdentity,
    ContentIntegrity,
}

#[derive(Serialize)]
struct ReleaseGenerationRetentionMarker<'a> {
    protocol_version: u8,
    directory_device: u64,
    directory_inode: u64,
    route_count: usize,
    intent: &'a ReleaseGenerationIntent,
    identity: &'a ReleaseOverlayGenerationIdentity,
}

impl ReleaseGenerationDirectory {
    /// Create a private generation or reopen an exact preexisting staging
    /// attempt. A preexisting directory is reusable only when its canonical
    /// intent binds the same operation, fence, kind, and target slot.
    pub(super) fn create_or_open(
        route_root: &Path,
        intent: ReleaseGenerationIntent,
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
        validate_directory(&directory, STAGING_MODE, "release staging directory")?;
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
                    let identity = read_identity(&generation.directory)?;
                    ensure_identity_matches_intent(&identity, &generation.intent)?;
                }
            } else if entries.route_count == 0
                && !entries.evidence_present
                && !entries.identity_present
                && !entries.publication_marker_present
            {
                // Recover the only safe mkdir-before-intent crash window.
                generation.write_intent()?;
            } else {
                return Err(invalid_state(
                    "preexisting release generation has no exact intent",
                ));
            }
        }
        Ok(generation)
    }

    pub(super) fn open_existing_sealed(
        route_root: &Path,
        intent: ReleaseGenerationIntent,
        route_set_digest: &str,
        route_count: usize,
    ) -> io::Result<Self> {
        Self::open_existing(
            route_root,
            intent,
            route_set_digest,
            route_count,
            GenerationPhase::Sealed,
        )
    }

    pub(super) fn open_existing_published(
        route_root: &Path,
        intent: ReleaseGenerationIntent,
        route_set_digest: &str,
        route_count: usize,
    ) -> io::Result<Self> {
        Self::open_existing(
            route_root,
            intent,
            route_set_digest,
            route_count,
            GenerationPhase::Published,
        )
    }

    fn open_existing(
        route_root: &Path,
        intent: ReleaseGenerationIntent,
        route_set_digest: &str,
        route_count: usize,
        phase: GenerationPhase,
    ) -> io::Result<Self> {
        intent.validate()?;
        validate_digest(route_set_digest, "release route-set digest")?;
        if !(1..=MAX_RELEASE_ROUTES).contains(&route_count) {
            return Err(invalid_input(
                "release generation route count is outside its bound",
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
        let name = intent.name();
        let directory = open_at_directory(&generations, &cstring(name.as_str())?)?;
        validate_directory(&directory, SEALED_MODE, "sealed release generation")?;
        ensure_same_filesystem(&generations, &directory)?;
        let metadata = directory.metadata()?;
        let identity = ReleaseOverlayGenerationIdentity::new(
            intent.fleet_run_id,
            intent.driver_operation_id,
            intent.original_global_fence_token,
            intent.overlay_kind,
            route_set_digest.to_owned(),
            intent.target_slot.as_str(),
        )
        .map_err(|error| io::Error::other(error.1))?;
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
            sealed: Some(SealedReleaseGeneration {
                name,
                identity,
                route_count,
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

    pub(super) fn begin_seal(&mut self) -> io::Result<ReleaseGenerationSealer<'_>> {
        if self.phase != GenerationPhase::Staging {
            return Err(invalid_state("release generation is not staging"));
        }
        self.validate_named_directory(STAGING_MODE)?;
        self.verify_intent()?;
        let manifest_name = cstring(EVIDENCE_FILE)?;
        match create_at_file(&self.directory, &manifest_name, FILE_MODE) {
            Ok(file) => {
                file.sync_all()?;
                file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
                validate_regular_file(&file, FILE_MODE, "release seal evidence manifest")?;
                self.directory.sync_all()?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let manifest_read = open_at_file(&self.directory, &manifest_name)?;
        validate_regular_file(&manifest_read, FILE_MODE, "release seal evidence manifest")?;
        let manifest_append = open_at_append_file(&self.directory, &manifest_name)?;
        validate_regular_file(
            &manifest_append,
            FILE_MODE,
            "release seal evidence manifest",
        )?;
        let mut hasher = Sha256::new();
        hasher.update(b"mb-release-route-overlay-v1\0");
        Ok(ReleaseGenerationSealer {
            generation: self,
            hasher,
            previous_workshop: None,
            route_count: 0,
            manifest_reader: BufReader::new(manifest_read),
            manifest_append,
            existing_manifest_exhausted: false,
        })
    }

    pub(super) fn sealed_evidence(&self) -> io::Result<&SealedReleaseGeneration> {
        self.sealed
            .as_ref()
            .ok_or_else(|| invalid_state("release generation is not sealed"))
    }

    fn finish_seal(
        &mut self,
        hasher: Sha256,
        route_count: usize,
    ) -> io::Result<&SealedReleaseGeneration> {
        if !(1..=MAX_RELEASE_ROUTES).contains(&route_count) {
            return Err(invalid_input(
                "release generation route count is outside its bound",
            ));
        }
        let entries = inspect_entries(&self.directory, true, true, false)?;
        if entries.route_count != route_count
            || !entries.intent_present
            || !entries.evidence_present
            || entries.publication_marker_present
        {
            return Err(invalid_state(
                "release staging directory does not match streamed evidence",
            ));
        }
        let route_set_digest = format!("sha256:{:x}", hasher.finalize());
        let identity = ReleaseOverlayGenerationIdentity::new(
            self.intent.fleet_run_id,
            self.intent.driver_operation_id,
            self.intent.original_global_fence_token,
            self.intent.overlay_kind,
            route_set_digest,
            self.intent.target_slot.as_str(),
        )
        .map_err(|error| io::Error::other(error.1))?;
        let config = release_overlay_generation_config(&identity)
            .map_err(|error| io::Error::other(error.1))?;
        write_create_only_or_verify(
            &self.directory,
            RELEASE_OVERLAY_GENERATION_FILE,
            config.as_bytes(),
            "release overlay identity",
        )?;
        let entries = inspect_entries(&self.directory, true, true, false)?;
        if entries.route_count != route_count
            || !entries.intent_present
            || !entries.evidence_present
            || !entries.identity_present
            || entries.publication_marker_present
        {
            return Err(invalid_state("release generation changed while sealing"));
        }
        self.directory
            .set_permissions(std::fs::Permissions::from_mode(SEALED_MODE))?;
        validate_directory(&self.directory, SEALED_MODE, "sealed release generation")?;
        self.directory.sync_all()?;
        self.generations.sync_all()?;
        self.validate_named_directory(SEALED_MODE)?;
        self.phase = GenerationPhase::Sealed;
        let selector = PriorSelector::from_recorded(
            self.name.selector_target(),
            self.directory_dev,
            self.directory_ino,
        )?;
        self.sealed = Some(SealedReleaseGeneration {
            name: self.name.clone(),
            identity,
            route_count,
            selector,
        });
        self.verify_sealed_bytes()?;
        self.validate_named_directory(SEALED_MODE)?;
        Ok(self.sealed.as_ref().expect("release seal was assigned"))
    }

    pub(super) fn publish(&mut self, expected_prior: &PriorSelector) -> io::Result<PriorSelector> {
        self.publish_with_pre_exchange(expected_prior, || Ok(()))
    }

    /// Resume the exact marker-before-exchange shape. The caller must have
    /// independently authenticated a durable recovery fence and the complete
    /// post-start filesystem shape before invoking this primitive.
    pub(super) fn resume_published_from_prior(
        &mut self,
        expected_prior: &PriorSelector,
    ) -> io::Result<PriorSelector> {
        if self.phase != GenerationPhase::Published {
            return Err(invalid_state(
                "release generation is not publication-started",
            ));
        }
        self.validate_named_directory(SEALED_MODE)?;
        self.verify_sealed_bytes()?;
        let sealed = self
            .sealed
            .as_ref()
            .ok_or_else(|| invalid_state("release generation has no seal"))?;
        verify_marker_identity(&self.directory, &sealed.identity)?;
        if observe_selector_from_handles(&self.root, &self.generations)? != *expected_prior {
            return Err(invalid_state(
                "current selector differs before release resume",
            ));
        }
        let candidate_target = self.name.selector_target();
        let exchange = cstring(exchange_artifact_name(
            &self.intent,
            ReleaseSelectorExchange::Publish,
        ))?;
        let current = cstring(CURRENT_SELECTOR)?;
        symlink_at(&cstring(&candidate_target)?, &self.root, &exchange)?;
        if let Err(error) = self.root.sync_all() {
            let _ = unlink_at(&self.root, &exchange, false);
            return Err(error);
        }
        if observe_selector_from_handles(&self.root, &self.generations)? != *expected_prior
            || observe_selector_target(&self.generations, candidate_target.clone())?
                != sealed.selector
        {
            let _ = unlink_at(&self.root, &exchange, false);
            let _ = self.root.sync_all();
            return Err(invalid_state(
                "release selector changed before resumed exchange",
            ));
        }
        if let Err(error) = rename_exchange(&self.root, &exchange, &current) {
            let _ = unlink_at(&self.root, &exchange, false);
            return Err(error);
        }
        self.root.sync_all()?;
        let captured =
            observe_selector_target(&self.generations, read_link_at(&self.root, &exchange)?)?;
        if captured != *expected_prior {
            return Err(invalid_state(
                "release resumed exchange captured a different prior",
            ));
        }
        self.observe_selected()?;
        unlink_at(&self.root, &exchange, false)?;
        self.root.sync_all()?;
        Ok(captured)
    }

    #[cfg(test)]
    pub(super) fn test_install_publication_marker(&mut self) -> io::Result<()> {
        if self.phase != GenerationPhase::Sealed {
            return Err(invalid_state("test release generation is not sealed"));
        }
        self.install_publication_marker()?;
        self.phase = GenerationPhase::Published;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn test_prepare_publish_exchange(&mut self) -> io::Result<()> {
        self.test_install_publication_marker()?;
        let exchange = cstring(exchange_artifact_name(
            &self.intent,
            ReleaseSelectorExchange::Publish,
        ))?;
        symlink_at(
            &cstring(self.name.selector_target())?,
            &self.root,
            &exchange,
        )?;
        self.root.sync_all()
    }

    #[cfg(test)]
    pub(super) fn test_crash_after_publish_exchange(
        &mut self,
        expected_prior: &PriorSelector,
    ) -> io::Result<()> {
        self.publish_with_exchange_hooks(
            expected_prior,
            || Ok(()),
            || Err(invalid_state("simulated post-exchange crash")),
        )
        .map(drop)
    }

    fn publish_with_pre_exchange(
        &mut self,
        expected_prior: &PriorSelector,
        before_exchange: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<PriorSelector> {
        self.publish_with_exchange_hooks(expected_prior, before_exchange, || Ok(()))
    }

    fn publish_with_exchange_hooks(
        &mut self,
        expected_prior: &PriorSelector,
        before_exchange: impl FnOnce() -> io::Result<()>,
        after_exchange: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<PriorSelector> {
        if self.phase != GenerationPhase::Sealed {
            return Err(invalid_state(
                "only a sealed release generation may be published",
            ));
        }
        self.validate_named_directory(SEALED_MODE)?;
        self.verify_sealed_bytes()?;
        let candidate_target = self.name.selector_target();
        let observed_before = observe_selector_from_handles(&self.root, &self.generations)?;
        if &observed_before != expected_prior {
            return Err(invalid_state(
                "current selector differs from the recorded prior selector",
            ));
        }
        self.install_publication_marker()?;
        self.phase = GenerationPhase::Published;
        before_exchange()?;

        let exchange_name = exchange_artifact_name(&self.intent, ReleaseSelectorExchange::Publish);
        let exchange = cstring(exchange_name)?;
        let current = cstring(CURRENT_SELECTOR)?;
        symlink_at(&cstring(&candidate_target)?, &self.root, &exchange)?;
        if let Err(error) = self.root.sync_all() {
            let _ = unlink_at(&self.root, &exchange, false);
            return Err(error);
        }
        if let Err(error) = rename_exchange(&self.root, &exchange, &current) {
            let _ = unlink_at(&self.root, &exchange, false);
            return Err(error);
        }
        self.root.sync_all()?;
        let prior_target = read_link_at(&self.root, &exchange)?;
        let captured_prior = observe_selector_target(&self.generations, prior_target)?;
        if &captured_prior != expected_prior {
            return Err(invalid_state(
                "selector changed after prior observation and before release publication",
            ));
        }
        self.observe_selected()?;
        after_exchange()?;
        unlink_at(&self.root, &exchange, false)?;
        self.root.sync_all()?;
        Ok(captured_prior)
    }

    pub(super) fn observe_selected(&self) -> io::Result<&SealedReleaseGeneration> {
        if self.phase != GenerationPhase::Published {
            return Err(invalid_state(
                "release generation has not crossed publication start",
            ));
        }
        let expected = self.name.selector_target();
        validate_current_selector(&self.root, &expected)?;
        self.validate_named_directory(SEALED_MODE)?;
        self.verify_sealed_bytes()?;
        validate_current_selector(&self.root, &expected)?;
        Ok(self
            .sealed
            .as_ref()
            .expect("published release generation must retain its seal"))
    }

    pub(super) fn restore_prior(&mut self, prior: &PriorSelector) -> io::Result<()> {
        if self.phase != GenerationPhase::Published {
            return Err(invalid_state(
                "only a published release generation may restore its prior",
            ));
        }
        self.observe_selected()?;
        let observed_prior = observe_selector_target(&self.generations, prior.target().to_owned())?;
        if &observed_prior != prior {
            return Err(invalid_state("recorded prior selector identity changed"));
        }
        let exchange_name =
            exchange_artifact_name(&self.intent, ReleaseSelectorExchange::RestorePrior);
        let exchange = cstring(exchange_name)?;
        let current = cstring(CURRENT_SELECTOR)?;
        symlink_at(&cstring(prior.target())?, &self.root, &exchange)?;
        if let Err(error) = self.root.sync_all() {
            let _ = unlink_at(&self.root, &exchange, false);
            return Err(error);
        }
        if let Err(error) = rename_exchange(&self.root, &exchange, &current) {
            let _ = unlink_at(&self.root, &exchange, false);
            return Err(error);
        }
        self.root.sync_all()?;
        if read_link_at(&self.root, &exchange)? != self.name.selector_target() {
            return Err(invalid_state("selector changed before prior restoration"));
        }
        if &observe_selector_from_handles(&self.root, &self.generations)? != prior {
            return Err(invalid_state(
                "restored selector differs from recorded prior",
            ));
        }
        unlink_at(&self.root, &exchange, false)?;
        self.root.sync_all()
    }

    pub(super) fn dispose(mut self) -> io::Result<()> {
        if self.phase == GenerationPhase::Published {
            return Err(invalid_state(
                "published release generation cannot be disposed",
            ));
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
            return Err(invalid_state("release generation has no intent"));
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
            "release generation intent",
        )
    }

    fn verify_intent(&self) -> io::Result<()> {
        let file = open_at_file(&self.directory, &cstring(INTENT_FILE)?)?;
        validate_regular_file(&file, FILE_MODE, "release generation intent")?;
        if read_bounded(file, 1024)? != self.intent.canonical_bytes()? {
            return Err(invalid_state("release generation intent changed"));
        }
        Ok(())
    }

    fn publication_marker_bytes(&self) -> io::Result<Vec<u8>> {
        let identity = &self
            .sealed
            .as_ref()
            .ok_or_else(|| invalid_state("release generation has no seal"))?
            .identity;
        let mut bytes = serde_json::to_vec(identity).map_err(io::Error::other)?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    fn install_publication_marker(&self) -> io::Result<()> {
        write_create_only_or_verify(
            &self.directory,
            PUBLICATION_MARKER_FILE,
            &self.publication_marker_bytes()?,
            "release publication marker",
        )
    }

    fn verify_publication_marker(&self) -> io::Result<()> {
        let file = open_at_file(&self.directory, &cstring(PUBLICATION_MARKER_FILE)?)?;
        validate_regular_file(&file, FILE_MODE, "release publication marker")?;
        if read_bounded(file, 1024)? != self.publication_marker_bytes()? {
            return Err(invalid_state("release publication marker changed"));
        }
        Ok(())
    }

    fn verify_sealed_bytes(&self) -> io::Result<()> {
        self.verify_intent()?;
        let sealed = self
            .sealed
            .as_ref()
            .ok_or_else(|| invalid_state("release generation has no seal"))?;
        let identity = read_identity(&self.directory)?;
        if identity != sealed.identity {
            return Err(invalid_state("release overlay identity changed"));
        }
        verify_evidence_manifest(
            &self.directory,
            sealed.route_count,
            &sealed.identity.route_set_digest,
        )?;
        let published = self.phase == GenerationPhase::Published;
        let entries = inspect_entries(&self.directory, true, true, published)?;
        if entries.route_count != sealed.route_count
            || !entries.intent_present
            || !entries.evidence_present
            || !entries.identity_present
            || entries.publication_marker_present != published
        {
            return Err(invalid_state(
                "sealed release generation membership changed",
            ));
        }
        if published {
            self.verify_publication_marker()?;
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
            Ok(target) if target == self.name.selector_target() => Err(invalid_state(
                "selected release generation is not disposable",
            )),
            Ok(target) => validate_selector_target(&target),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl<'a> ReleaseGenerationSealer<'a> {
    pub(super) const fn fleet_run_id(&self) -> Uuid {
        self.generation.intent.fleet_run_id
    }

    pub(super) const fn driver_operation_id(&self) -> Uuid {
        self.generation.intent.driver_operation_id
    }

    pub(super) const fn original_global_fence_token(&self) -> i64 {
        self.generation.intent.original_global_fence_token
    }

    pub(super) const fn overlay_kind(&self) -> ReleaseOverlayKind {
        self.generation.intent.overlay_kind
    }

    pub(super) const fn target_slot(&self) -> ReleaseTargetSlot {
        self.generation.intent.target_slot
    }

    pub(super) fn stage_route(
        &mut self,
        workshop_id: Uuid,
        projection_generation: i64,
        projection_digest: &str,
        applied_rendered_digest: &str,
        contents: &[u8],
    ) -> io::Result<ReleaseRouteSealEvidence> {
        self.validate_next(workshop_id)?;
        self.validate_capacity()?;
        if projection_generation <= 0 {
            return Err(invalid_input("projection generation must be positive"));
        }
        validate_digest(projection_digest, "projection digest")?;
        validate_digest(applied_rendered_digest, "applied rendered digest")?;
        validate_route_bytes(contents)?;
        write_create_only_or_verify(
            &self.generation.directory,
            &format!("{workshop_id}.conf"),
            contents,
            "release overlay route",
        )?;
        let evidence = ReleaseRouteSealEvidence {
            workshop_id,
            projection_generation,
            projection_digest: projection_digest.to_owned(),
            applied_rendered_digest: applied_rendered_digest.to_owned(),
            rendered_digest: digest_bytes(contents),
        };
        self.record(&evidence)?;
        Ok(evidence)
    }

    pub(super) fn record(&mut self, evidence: &ReleaseRouteSealEvidence) -> io::Result<()> {
        self.validate_next(evidence.workshop_id)?;
        self.validate_capacity()?;
        if evidence.projection_generation <= 0 {
            return Err(invalid_input("projection generation must be positive"));
        }
        validate_digest(&evidence.projection_digest, "projection digest")?;
        validate_digest(&evidence.applied_rendered_digest, "applied rendered digest")?;
        validate_digest(&evidence.rendered_digest, "rendered digest")?;
        let file = open_at_file(
            &self.generation.directory,
            &cstring(format!("{}.conf", evidence.workshop_id))?,
        )?;
        validate_regular_file(&file, FILE_MODE, "release overlay route")?;
        let bytes = read_bounded(file, MAX_ROUTE_BYTES)?;
        validate_route_bytes(&bytes)?;
        if digest_bytes(&bytes) != evidence.rendered_digest {
            return Err(invalid_state(
                "staged release route differs from its evidence",
            ));
        }
        let canonical_line = evidence_line(evidence)?;
        if !self.existing_manifest_exhausted {
            match read_evidence_line(&mut self.manifest_reader)? {
                Some(existing) if existing == canonical_line => {}
                Some(_) => {
                    return Err(invalid_state("preexisting release seal evidence differs"));
                }
                None => {
                    self.existing_manifest_exhausted = true;
                    self.manifest_append.write_all(&canonical_line)?;
                    self.manifest_append.sync_all()?;
                    self.generation.directory.sync_all()?;
                }
            }
        } else {
            self.manifest_append.write_all(&canonical_line)?;
            self.manifest_append.sync_all()?;
            self.generation.directory.sync_all()?;
        }
        fold_evidence(&mut self.hasher, evidence)?;
        self.previous_workshop = Some(evidence.workshop_id);
        self.route_count = self
            .route_count
            .checked_add(1)
            .ok_or_else(|| invalid_input("release route count overflowed"))?;
        Ok(())
    }

    fn validate_next(&self, workshop_id: Uuid) -> io::Result<()> {
        if self
            .previous_workshop
            .is_some_and(|previous| previous >= workshop_id)
        {
            return Err(invalid_input(
                "release seal evidence must be strictly workshop ordered",
            ));
        }
        Ok(())
    }

    fn validate_capacity(&self) -> io::Result<()> {
        if self.route_count >= MAX_RELEASE_ROUTES {
            return Err(invalid_input(
                "release generation route count is outside its bound",
            ));
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> io::Result<&'a SealedReleaseGeneration> {
        if !self.existing_manifest_exhausted
            && read_evidence_line(&mut self.manifest_reader)?.is_some()
        {
            return Err(invalid_state(
                "release seal evidence manifest has unconsumed rows",
            ));
        }
        self.manifest_append.sync_all()?;
        self.generation.finish_seal(self.hasher, self.route_count)
    }
}

fn evidence_line(evidence: &ReleaseRouteSealEvidence) -> io::Result<Vec<u8>> {
    if evidence.projection_generation <= 0 {
        return Err(invalid_input("projection generation must be positive"));
    }
    validate_digest(&evidence.projection_digest, "projection digest")?;
    validate_digest(&evidence.applied_rendered_digest, "applied rendered digest")?;
    validate_digest(&evidence.rendered_digest, "rendered digest")?;
    let mut line = serde_json::to_vec(evidence).map_err(io::Error::other)?;
    line.push(b'\n');
    if line.len() > MAX_EVIDENCE_LINE_BYTES {
        return Err(invalid_input("release seal evidence exceeds its bound"));
    }
    Ok(line)
}

fn read_evidence_line(reader: &mut BufReader<File>) -> io::Result<Option<Vec<u8>>> {
    let mut line = Vec::with_capacity(MAX_EVIDENCE_LINE_BYTES);
    let mut byte = [0_u8; 1];
    loop {
        match reader.read(&mut byte)? {
            0 if line.is_empty() => return Ok(None),
            0 => return Err(invalid_state("release seal evidence is truncated")),
            _ => {
                line.push(byte[0]);
                if line.len() > MAX_EVIDENCE_LINE_BYTES {
                    return Err(invalid_state("release seal evidence exceeds its bound"));
                }
                if byte[0] == b'\n' {
                    return Ok(Some(line));
                }
            }
        }
    }
}

fn fold_evidence(hasher: &mut Sha256, evidence: &ReleaseRouteSealEvidence) -> io::Result<()> {
    hasher.update(evidence.workshop_id.as_bytes());
    hasher.update(evidence.projection_generation.to_be_bytes());
    update_field(hasher, evidence.projection_digest.as_bytes())?;
    update_field(hasher, evidence.applied_rendered_digest.as_bytes())?;
    update_field(hasher, evidence.rendered_digest.as_bytes())
}

/// Compute the exact digest that sealing will persist, without touching the
/// filesystem. Recovery uses this only to authenticate a sealed generation
/// left by a crash before its database seal was recorded.
pub(super) fn release_route_set_digest(
    evidence: &[ReleaseRouteSealEvidence],
) -> io::Result<String> {
    if !(1..=MAX_RELEASE_ROUTES).contains(&evidence.len()) {
        return Err(invalid_input(
            "release generation route count is outside its bound",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(b"mb-release-route-overlay-v1\0");
    let mut previous = None;
    for item in evidence {
        if previous.is_some_and(|workshop| workshop >= item.workshop_id) {
            return Err(invalid_input(
                "release seal evidence must be strictly workshop ordered",
            ));
        }
        fold_evidence(&mut hasher, item)?;
        previous = Some(item.workshop_id);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn verify_evidence_manifest(
    directory: &File,
    expected_route_count: usize,
    expected_digest: &str,
) -> io::Result<()> {
    if !(1..=MAX_RELEASE_ROUTES).contains(&expected_route_count) {
        return Err(invalid_input(
            "release generation route count is outside its bound",
        ));
    }
    validate_digest(expected_digest, "release route-set digest")?;
    let manifest = open_at_file(directory, &cstring(EVIDENCE_FILE)?)?;
    validate_regular_file(&manifest, FILE_MODE, "release seal evidence manifest")?;
    let mut reader = BufReader::new(manifest);
    let mut hasher = Sha256::new();
    hasher.update(b"mb-release-route-overlay-v1\0");
    let mut previous = None;
    let mut count = 0_usize;
    while let Some(line) = read_evidence_line(&mut reader)? {
        let json = line
            .strip_suffix(b"\n")
            .ok_or_else(|| invalid_state("release seal evidence is not canonical"))?;
        let evidence: ReleaseRouteSealEvidence = serde_json::from_slice(json)
            .map_err(|_| invalid_state("release seal evidence is invalid"))?;
        if evidence_line(&evidence)? != line {
            return Err(invalid_state("release seal evidence is not canonical"));
        }
        if previous.is_some_and(|prior| prior >= evidence.workshop_id) {
            return Err(invalid_state(
                "release seal evidence is not strictly workshop ordered",
            ));
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid_state("release route count overflowed"))?;
        if count > MAX_RELEASE_ROUTES {
            return Err(invalid_state(
                "release generation route count is outside its bound",
            ));
        }
        let route = open_at_file(
            directory,
            &cstring(format!("{}.conf", evidence.workshop_id))?,
        )?;
        validate_regular_file(&route, FILE_MODE, "sealed release overlay route")?;
        let bytes = read_bounded(route, MAX_ROUTE_BYTES)?;
        validate_route_bytes(&bytes)?;
        if digest_bytes(&bytes) != evidence.rendered_digest {
            return Err(invalid_state(
                "sealed release route differs from its evidence",
            ));
        }
        fold_evidence(&mut hasher, &evidence)?;
        previous = Some(evidence.workshop_id);
    }
    if count != expected_route_count {
        return Err(invalid_state("release seal evidence cardinality differs"));
    }
    let observed_digest = format!("sha256:{:x}", hasher.finalize());
    if observed_digest != expected_digest {
        return Err(invalid_state("release route-set digest differs from bytes"));
    }
    Ok(())
}

/// Bind the deterministic release child to its current directory device and
/// inode without reading or changing the live selector.
pub(super) fn observe_candidate_selector(
    route_root: &Path,
    intent: &ReleaseGenerationIntent,
) -> io::Result<PriorSelector> {
    intent.validate()?;
    observe_generation_selector(route_root, &intent.name().selector_target())
}

/// Observe a release generation by its deterministic name without consulting
/// or changing `current`. This is suitable for interrupted-publication
/// classification where selected and running identities are separate facts.
pub(super) fn observe_generation_identity(
    route_root: &Path,
    intent: &ReleaseGenerationIntent,
    expected_route_count: usize,
    publication_started: bool,
) -> io::Result<ReleaseOverlayGenerationIdentity> {
    intent.validate()?;
    if !(1..=MAX_RELEASE_ROUTES).contains(&expected_route_count) {
        return Err(invalid_input(
            "release generation route count is outside its bound",
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
    let directory = open_at_directory(&generations, &cstring(intent.name().as_str())?)?;
    validate_directory(&directory, SEALED_MODE, "release generation")?;
    ensure_same_filesystem(&generations, &directory)?;
    let directory_metadata = directory.metadata()?;
    verify_intent_file(&directory, intent)?;
    let identity = read_identity(&directory)?;
    ensure_identity_matches_intent(&identity, intent)?;
    verify_evidence_manifest(&directory, expected_route_count, &identity.route_set_digest)?;
    let entries = inspect_entries(&directory, true, true, publication_started)?;
    if entries.route_count != expected_route_count
        || !entries.intent_present
        || !entries.evidence_present
        || !entries.identity_present
        || entries.publication_marker_present != publication_started
    {
        return Err(invalid_state(
            "release generation membership differs from its observation",
        ));
    }
    if publication_started {
        verify_marker_identity(&directory, &identity)?;
    }
    validate_named_identity(
        &generations,
        &directory,
        intent.name().as_str(),
        SEALED_MODE,
        directory_metadata.dev(),
        directory_metadata.ino(),
    )?;
    Ok(identity)
}

pub(super) fn observe_selected_identity(
    route_root: &Path,
    intent: &ReleaseGenerationIntent,
    expected: &ReleaseOverlayGenerationIdentity,
    expected_route_count: usize,
) -> io::Result<PriorSelector> {
    ensure_identity_matches_intent(expected, intent)?;
    let first = observe_current_selector(route_root)?;
    if first.target() != intent.name().selector_target() {
        return Err(invalid_state("release generation is not selected"));
    }
    if observe_generation_identity(route_root, intent, expected_route_count, true)? != *expected {
        return Err(invalid_state(
            "selected release generation identity differs",
        ));
    }
    let second = observe_current_selector(route_root)?;
    if second != first {
        return Err(invalid_state(
            "route selector changed during release observation",
        ));
    }
    Ok(second)
}

pub(super) fn validate_release_retention_generation_authority(
    intent: &ReleaseGenerationIntent,
    identity: &ReleaseOverlayGenerationIdentity,
) -> io::Result<()> {
    intent.validate()?;
    ensure_identity_matches_intent(identity, intent)
}

/// Delete one database-authorized immutable release overlay. Each call removes
/// at most one child after repeating the live-selector proof, allowing the
/// coordinator to renew its database fence before every destructive step.
pub(super) fn step_retained_release_generation_deletion(
    route_root: &Path,
    intent: &ReleaseGenerationIntent,
    identity: &ReleaseOverlayGenerationIdentity,
    expected_directory_device: u64,
    expected_directory_inode: u64,
    route_count: usize,
) -> io::Result<ReleaseGenerationRetentionStep> {
    step_retained_release_generation_deletion_with_hook(
        route_root,
        intent,
        identity,
        expected_directory_device,
        expected_directory_inode,
        route_count,
        || {},
    )
}

fn step_retained_release_generation_deletion_with_hook(
    route_root: &Path,
    intent: &ReleaseGenerationIntent,
    identity: &ReleaseOverlayGenerationIdentity,
    expected_directory_device: u64,
    expected_directory_inode: u64,
    route_count: usize,
    before_marker_creation: impl FnOnce(),
) -> io::Result<ReleaseGenerationRetentionStep> {
    intent.validate()?;
    ensure_identity_matches_intent(identity, intent)?;
    if !(1..=MAX_RELEASE_ROUTES).contains(&route_count)
        || expected_directory_device == 0
        || expected_directory_inode == 0
    {
        return Err(invalid_input("release retention authority is invalid"));
    }
    let name = intent.name();
    let target = name.selector_target();
    let selected = observe_current_selector(route_root)?;
    if selected.target() == target {
        return Ok(ReleaseGenerationRetentionStep::Complete(
            ReleaseGenerationRetentionDeletion::ProtectedCurrent {
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
            return Ok(ReleaseGenerationRetentionStep::Complete(
                ReleaseGenerationRetentionDeletion::AlreadyAbsent,
            ));
        }
        Err(error) => return Err(error),
    };
    ensure_same_filesystem(&generations, &directory)?;
    let metadata = directory.metadata()?;
    if metadata.dev() != expected_directory_device || metadata.ino() != expected_directory_inode {
        return Ok(ReleaseGenerationRetentionStep::Complete(
            ReleaseGenerationRetentionDeletion::IdentityMismatch {
                directory_device: metadata.dev(),
                directory_inode: metadata.ino(),
                mismatch: ReleaseGenerationRetentionMismatch::DirectoryIdentity,
                observed_identity: None,
            },
        ));
    }
    validate_directory(&directory, SEALED_MODE, "retained release generation")?;
    let marker = ReleaseGenerationRetentionMarker {
        protocol_version: 1,
        directory_device: expected_directory_device,
        directory_inode: expected_directory_inode,
        route_count,
        intent,
        identity,
    };
    let mut marker_bytes = serde_json::to_vec(&marker).map_err(io::Error::other)?;
    marker_bytes.push(b'\n');
    if marker_bytes.len() > 4_096 {
        return Err(invalid_input("release retention marker exceeds its bound"));
    }
    let names = release_retention_entry_names(&directory)?;
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
                "route selector changed before release directory unlink",
            ));
        }
        unlink_at(&generations, &cstring(name.as_str())?, true)?;
        generations.sync_all()?;
        return Ok(ReleaseGenerationRetentionStep::Complete(
            ReleaseGenerationRetentionDeletion::Deleted {
                directory_device: expected_directory_device,
                directory_inode: expected_directory_inode,
            },
        ));
    }
    if names.iter().any(|entry| entry == RETENTION_MARKER_FILE) {
        verify_release_retention_marker(&directory, &marker_bytes)?;
    } else {
        verify_intent_file(&directory, intent)?;
        let observed_identity = read_identity(&directory)?;
        if observed_identity != *identity {
            return Ok(ReleaseGenerationRetentionStep::Complete(
                ReleaseGenerationRetentionDeletion::IdentityMismatch {
                    directory_device: metadata.dev(),
                    directory_inode: metadata.ino(),
                    mismatch: ReleaseGenerationRetentionMismatch::ContentIdentity,
                    observed_identity: Some(observed_identity),
                },
            ));
        }
        if !matches!(
            observe_generation_identity(route_root, intent, route_count, true),
            Ok(ref observed) if observed == identity
        ) {
            return Ok(ReleaseGenerationRetentionStep::Complete(
                ReleaseGenerationRetentionDeletion::IdentityMismatch {
                    directory_device: metadata.dev(),
                    directory_inode: metadata.ino(),
                    mismatch: ReleaseGenerationRetentionMismatch::ContentIntegrity,
                    observed_identity: Some(observed_identity),
                },
            ));
        }
        before_marker_creation();
        if observe_current_selector(route_root)? != selected {
            return Err(invalid_state(
                "route selector changed before release retention marker",
            ));
        }
        write_create_only_or_verify(
            &directory,
            RETENTION_MARKER_FILE,
            &marker_bytes,
            "release retention marker",
        )?;
        return Ok(ReleaseGenerationRetentionStep::InProgress);
    }
    delete_one_release_retention_entry(route_root, &selected, &directory, &marker_bytes)?;
    Ok(ReleaseGenerationRetentionStep::InProgress)
}

fn release_retention_entry_names(directory: &File) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    visit_generation_entries(directory, |name| {
        names.push(name.to_owned());
        if names.len() > MAX_RELEASE_ROUTES + 5 {
            return Err(invalid_state(
                "retained release membership exceeds its bound",
            ));
        }
        Ok(())
    })?;
    Ok(names)
}

fn verify_release_retention_marker(directory: &File, expected: &[u8]) -> io::Result<()> {
    let file = open_at_file(directory, &cstring(RETENTION_MARKER_FILE)?)?;
    validate_regular_file(&file, FILE_MODE, "release retention marker")?;
    if read_bounded(file, 4_096)? != expected {
        return Err(invalid_state("release retention marker differs"));
    }
    Ok(())
}

fn delete_one_release_retention_entry(
    route_root: &Path,
    selected: &PriorSelector,
    directory: &File,
    marker_bytes: &[u8],
) -> io::Result<()> {
    let names = release_retention_entry_names(directory)?;
    if !names.iter().any(|entry| entry == RETENTION_MARKER_FILE) {
        return Err(invalid_state("release retention marker is absent"));
    }
    verify_release_retention_marker(directory, marker_bytes)?;
    let mut next = None;
    for name in &names {
        if name == RETENTION_MARKER_FILE {
            continue;
        }
        let valid = matches!(
            name.as_str(),
            INTENT_FILE | EVIDENCE_FILE | RELEASE_OVERLAY_GENERATION_FILE | PUBLICATION_MARKER_FILE
        ) || name
            .strip_suffix(".conf")
            .is_some_and(|stem| Uuid::parse_str(stem).is_ok());
        if !valid {
            return Err(invalid_state("retained release contains an unowned entry"));
        }
        let child = cstring(name)?;
        let file = open_at_file(directory, &child)?;
        validate_regular_file(&file, FILE_MODE, "retained release child")?;
        if next.is_none() {
            next = Some(child);
        }
    }
    let child = next.unwrap_or(cstring(RETENTION_MARKER_FILE)?);
    if observe_current_selector(route_root)? != *selected {
        return Err(invalid_state(
            "route selector changed before retained release unlink",
        ));
    }
    unlink_at(directory, &child, false)?;
    directory.sync_all()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleasePostStartInspection {
    SealedBeforeMarker,
    MarkerBeforeExchange,
    PreparedExchange,
    ExchangeDone,
    CandidateSelected,
    ForeignOrInconclusive,
}

/// Classify the complete post-start selector/artifact state without mutation.
/// Every recognized shape is bound to exact candidate/prior dev+inode and the
/// strict release identity; foreign artifacts are retained as inconclusive.
pub(super) fn inspect_post_start_release_publication(
    route_root: &Path,
    intent: &ReleaseGenerationIntent,
    expected_identity: &ReleaseOverlayGenerationIdentity,
    expected_route_count: usize,
    candidate: &PriorSelector,
    prior: &PriorSelector,
) -> io::Result<ReleasePostStartInspection> {
    intent.validate()?;
    ensure_identity_matches_intent(expected_identity, intent)?;
    if candidate.target() != intent.name().selector_target() || candidate == prior {
        return Err(invalid_input(
            "release post-start selector identities are invalid",
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
    if observe_selector_target(&generations, candidate.target().to_owned())? != *candidate
        || observe_selector_target(&generations, prior.target().to_owned())? != *prior
    {
        return Err(invalid_state(
            "release post-start directory identity changed",
        ));
    }
    let directory = open_at_directory(&generations, &cstring(intent.name().as_str())?)?;
    validate_directory(&directory, SEALED_MODE, "post-start release generation")?;
    let entries = inspect_entries(&directory, true, true, true)?;
    let marker = entries.publication_marker_present;
    if observe_generation_identity(route_root, intent, expected_route_count, marker)?
        != *expected_identity
    {
        return Err(invalid_state("release post-start identity differs"));
    }
    let current = observe_selector_from_handles(&root, &generations)?;
    let restore = cstring(exchange_artifact_name(
        intent,
        ReleaseSelectorExchange::RestorePrior,
    ))?;
    match read_link_at(&root, &restore) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Ok(_) | Err(_) => return Ok(ReleasePostStartInspection::ForeignOrInconclusive),
    }
    let artifact = cstring(exchange_artifact_name(
        intent,
        ReleaseSelectorExchange::Publish,
    ))?;
    let artifact_target = match read_link_at(&root, &artifact) {
        Ok(target) => Some(target),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    if !marker {
        return Ok(if artifact_target.is_none() && current == *prior {
            ReleasePostStartInspection::SealedBeforeMarker
        } else {
            ReleasePostStartInspection::ForeignOrInconclusive
        });
    }
    Ok(match (current, artifact_target.as_deref()) {
        (current, None) if current == *prior => ReleasePostStartInspection::MarkerBeforeExchange,
        (current, None) if current == *candidate => ReleasePostStartInspection::CandidateSelected,
        (current, Some(target)) if current == *prior && target == candidate.target() => {
            ReleasePostStartInspection::PreparedExchange
        }
        (current, Some(target)) if current == *candidate && target == prior.target() => {
            ReleasePostStartInspection::ExchangeDone
        }
        _ => ReleasePostStartInspection::ForeignOrInconclusive,
    })
}

fn exchange_artifact_name(
    intent: &ReleaseGenerationIntent,
    exchange: ReleaseSelectorExchange,
) -> String {
    let infix = match exchange {
        ReleaseSelectorExchange::Publish => "",
        ReleaseSelectorExchange::RestorePrior => "-restore",
    };
    format!(
        ".current-release{infix}-{}-{}",
        intent.driver_operation_id.simple(),
        intent.overlay_kind.as_str()
    )
}

/// Remove only the deterministic selector-exchange symlink owned by this
/// exact release intent. Both the prepared and post-exchange shapes are
/// authenticated against the database-recorded candidate and prior
/// target/device/inode triples. Any other shape is left untouched.
pub(super) fn recover_exchange_artifact(
    route_root: &Path,
    intent: &ReleaseGenerationIntent,
    expected_identity: &ReleaseOverlayGenerationIdentity,
    expected_route_count: usize,
    candidate: &PriorSelector,
    prior: &PriorSelector,
    exchange: ReleaseSelectorExchange,
) -> io::Result<ReleaseExchangeRecovery> {
    intent.validate()?;
    ensure_identity_matches_intent(expected_identity, intent)?;
    if candidate.target() != intent.name().selector_target() || candidate == prior {
        return Err(invalid_input(
            "release selector exchange identities are invalid",
        ));
    }
    if observe_generation_identity(route_root, intent, expected_route_count, true)?
        != *expected_identity
    {
        return Err(invalid_state("release exchange candidate identity differs"));
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
    if &observe_selector_target(&generations, candidate.target().to_owned())? != candidate
        || &observe_selector_target(&generations, prior.target().to_owned())? != prior
    {
        return Err(invalid_state(
            "release exchange selector directory identity changed",
        ));
    }

    let artifact_name = cstring(exchange_artifact_name(intent, exchange))?;
    let first_artifact = match read_link_at(&root, &artifact_name) {
        Ok(target) => target,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let current = observe_selector_from_handles(&root, &generations)?;
            if current != *candidate && current != *prior {
                return Err(invalid_state(
                    "clean release selector exchange has an unknown current selector",
                ));
            }
            return Ok(ReleaseExchangeRecovery::AlreadyClean);
        }
        Err(error) => return Err(error),
    };
    validate_selector_target(&first_artifact)?;
    let first_current = observe_selector_from_handles(&root, &generations)?;
    let outcome = match exchange {
        ReleaseSelectorExchange::Publish
            if first_current == *prior && first_artifact == candidate.target() =>
        {
            ReleaseExchangeRecovery::PreparedArtifactRemoved
        }
        ReleaseSelectorExchange::Publish
            if first_current == *candidate && first_artifact == prior.target() =>
        {
            ReleaseExchangeRecovery::ExchangedArtifactRemoved
        }
        ReleaseSelectorExchange::RestorePrior
            if first_current == *candidate && first_artifact == prior.target() =>
        {
            ReleaseExchangeRecovery::PreparedArtifactRemoved
        }
        ReleaseSelectorExchange::RestorePrior
            if first_current == *prior && first_artifact == candidate.target() =>
        {
            ReleaseExchangeRecovery::ExchangedArtifactRemoved
        }
        _ => {
            return Err(invalid_state(
                "release selector exchange artifact is not exact-owned",
            ));
        }
    };

    let artifact_selector = observe_selector_target(&generations, first_artifact.clone())?;
    let expected_artifact = if first_artifact == candidate.target() {
        candidate
    } else {
        prior
    };
    if &artifact_selector != expected_artifact
        || read_link_at(&root, &artifact_name)? != first_artifact
        || observe_selector_from_handles(&root, &generations)? != first_current
    {
        return Err(invalid_state(
            "release selector exchange changed during recovery",
        ));
    }
    unlink_at(&root, &artifact_name, false)?;
    root.sync_all()?;
    if observe_selector_from_handles(&root, &generations)? != first_current {
        return Err(invalid_state(
            "route selector changed during exchange artifact cleanup",
        ));
    }
    match read_link_at(&root, &artifact_name) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(outcome),
        Ok(_) => Err(invalid_state(
            "release selector exchange artifact cleanup was incomplete",
        )),
        Err(error) => Err(error),
    }
}

/// Dispose an exact prepublication release generation without needing to know
/// its seal digest. Canonical intent and identity are still verified; a marker
/// or live selection makes the generation permanently ineligible.
pub(super) fn dispose_exact_unpublished(
    route_root: &Path,
    intent: &ReleaseGenerationIntent,
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
    let directory_metadata = directory.metadata()?;
    let mode = directory.metadata()?.mode() & 0o7777;
    if mode != STAGING_MODE && mode != SEALED_MODE {
        return Err(invalid_state("release generation has an unsafe mode"));
    }
    validate_directory(&directory, mode, "release generation")?;
    match read_link_at(&root, &cstring(CURRENT_SELECTOR)?) {
        Ok(target) if target == name.selector_target() => {
            return Err(invalid_state(
                "selected release generation is not disposable",
            ));
        }
        Ok(target) => validate_selector_target(&target)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    verify_intent_file(&directory, intent)?;
    let entries = inspect_entries(&directory, true, true, true)?;
    if entries.publication_marker_present {
        return Err(invalid_state(
            "publication-started release generation is not disposable",
        ));
    }
    if entries.identity_present {
        let file = open_at_file(&directory, &cstring(RELEASE_OVERLAY_GENERATION_FILE)?)?;
        validate_regular_file(&file, FILE_MODE, "release overlay identity")?;
        let identity =
            parse_release_overlay_generation_config(&read_bounded(file, MAX_ROUTE_BYTES)?)
                .map_err(|error| io::Error::other(error.1))?;
        ensure_identity_matches_intent(&identity, intent)?;
    }
    dispose_entries(&directory, entries.identity_present)?;
    directory.sync_all()?;
    validate_directory(&directory, mode, "release generation")?;
    validate_named_identity(
        &generations,
        &directory,
        name.as_str(),
        mode,
        directory_metadata.dev(),
        directory_metadata.ino(),
    )?;
    unlink_at(&generations, &cstring(name.as_str())?, true)?;
    generations.sync_all()
}

fn ensure_identity_matches_intent(
    identity: &ReleaseOverlayGenerationIdentity,
    intent: &ReleaseGenerationIntent,
) -> io::Result<()> {
    identity
        .validate()
        .map_err(|error| io::Error::other(error.1))?;
    if identity.fleet_run_id != intent.fleet_run_id
        || identity.driver_operation_id != intent.driver_operation_id
        || identity.original_global_fence_token != intent.original_global_fence_token
        || identity.overlay_kind != intent.overlay_kind
        || identity.target_slot != intent.target_slot
    {
        return Err(invalid_state(
            "release overlay identity differs from its intent",
        ));
    }
    Ok(())
}

fn verify_intent_file(directory: &File, intent: &ReleaseGenerationIntent) -> io::Result<()> {
    let file = open_at_file(directory, &cstring(INTENT_FILE)?)?;
    validate_regular_file(&file, FILE_MODE, "release generation intent")?;
    if read_bounded(file, 1024)? != intent.canonical_bytes()? {
        return Err(invalid_state("release generation intent changed"));
    }
    Ok(())
}

fn read_identity(directory: &File) -> io::Result<ReleaseOverlayGenerationIdentity> {
    let file = open_at_file(directory, &cstring(RELEASE_OVERLAY_GENERATION_FILE)?)?;
    validate_regular_file(&file, FILE_MODE, "release overlay identity")?;
    parse_release_overlay_generation_config(&read_bounded(file, MAX_ROUTE_BYTES)?)
        .map_err(|error| io::Error::other(error.1))
}

fn verify_marker_identity(
    directory: &File,
    identity: &ReleaseOverlayGenerationIdentity,
) -> io::Result<()> {
    let file = open_at_file(directory, &cstring(PUBLICATION_MARKER_FILE)?)?;
    validate_regular_file(&file, FILE_MODE, "release publication marker")?;
    let mut expected = serde_json::to_vec(identity).map_err(io::Error::other)?;
    expected.push(b'\n');
    if read_bounded(file, 1024)? != expected {
        return Err(invalid_state("release publication marker changed"));
    }
    Ok(())
}

fn validate_named_identity(
    generations: &File,
    directory: &File,
    name: &str,
    mode: u32,
    expected_dev: u64,
    expected_ino: u64,
) -> io::Result<()> {
    validate_directory(directory, mode, "release generation")?;
    let named = open_at_directory(generations, &cstring(name)?)?;
    validate_directory(&named, mode, "named release generation")?;
    let metadata = named.metadata()?;
    if metadata.dev() != expected_dev || metadata.ino() != expected_ino {
        return Err(invalid_state("release generation path identity changed"));
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
        Ok(mut file) => (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
            validate_regular_file(&file, FILE_MODE, description)?;
            directory.sync_all()
        })(),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let file = open_at_file(directory, &name)?;
            validate_regular_file(&file, FILE_MODE, description)?;
            if read_bounded(file, MAX_ROUTE_BYTES)? != bytes {
                return Err(invalid_state(format!(
                    "preexisting {description} bytes differ"
                )));
            }
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn update_field(hasher: &mut Sha256, value: &[u8]) -> io::Result<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| invalid_input("release seal field exceeds its bound"))?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

#[derive(Default)]
struct GenerationEntries {
    route_count: usize,
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
        validate_regular_file(&file, FILE_MODE, "release generation child")?;
        match name {
            INTENT_FILE if intent_allowed && !entries.intent_present => {
                entries.intent_present = true;
            }
            EVIDENCE_FILE if !entries.evidence_present => {
                entries.evidence_present = true;
            }
            RELEASE_OVERLAY_GENERATION_FILE if identity_allowed && !entries.identity_present => {
                entries.identity_present = true;
            }
            PUBLICATION_MARKER_FILE if marker_allowed && !entries.publication_marker_present => {
                entries.publication_marker_present = true;
            }
            _ if name
                .strip_suffix(".conf")
                .is_some_and(|stem| Uuid::parse_str(stem).is_ok()) =>
            {
                entries.route_count = entries
                    .route_count
                    .checked_add(1)
                    .ok_or_else(|| invalid_state("release generation route count overflowed"))?;
            }
            _ => {
                return Err(invalid_state(
                    "release generation contains an unexpected entry",
                ));
            }
        }
        Ok(())
    })?;
    Ok(entries)
}

fn dispose_entries(directory: &File, identity_allowed: bool) -> io::Result<()> {
    visit_generation_entries(directory, |name| {
        let valid = name == INTENT_FILE
            || name == EVIDENCE_FILE
            || (identity_allowed && name == RELEASE_OVERLAY_GENERATION_FILE)
            || name
                .strip_suffix(".conf")
                .is_some_and(|stem| Uuid::parse_str(stem).is_ok());
        if !valid {
            return Err(invalid_state(
                "release generation contains an unowned entry",
            ));
        }
        let child = cstring(name)?;
        let file = open_at_file(directory, &child)?;
        validate_regular_file(&file, FILE_MODE, "release generation child")?;
        unlink_at(directory, &child, false)
    })
}

#[cfg(test)]
mod tests {
    use std::fs::{DirBuilder, hard_link};
    use std::os::unix::fs::{DirBuilderExt as _, symlink};

    use super::*;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("mb-release-generation-{}", Uuid::new_v4()));
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

    fn intent(
        fleet_run_id: Uuid,
        operation_id: Uuid,
        kind: ReleaseOverlayKind,
    ) -> ReleaseGenerationIntent {
        ReleaseGenerationIntent::new(fleet_run_id, operation_id, 17, kind, "green").unwrap()
    }

    fn workshops() -> [Uuid; 2] {
        [
            Uuid::parse_str("10000000-0000-0000-0000-000000000001").unwrap(),
            Uuid::parse_str("20000000-0000-0000-0000-000000000002").unwrap(),
        ]
    }

    fn seal_two(generation: &mut ReleaseGenerationDirectory) -> SealedReleaseGeneration {
        let mut sealer = generation.begin_seal().unwrap();
        sealer
            .stage_route(
                workshops()[0],
                4,
                &digest('a'),
                &digest('b'),
                b"server { return 503; }\n",
            )
            .unwrap();
        sealer
            .stage_route(
                workshops()[1],
                8,
                &digest('c'),
                &digest('d'),
                b"server { return 204; }\n",
            )
            .unwrap();
        sealer.finish().unwrap().clone()
    }

    fn delete_retained_release_generation(
        route_root: &Path,
        intent: &ReleaseGenerationIntent,
        sealed: &SealedReleaseGeneration,
    ) -> io::Result<ReleaseGenerationRetentionDeletion> {
        loop {
            match step_retained_release_generation_deletion(
                route_root,
                intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
            )? {
                ReleaseGenerationRetentionStep::InProgress => {}
                ReleaseGenerationRetentionStep::Complete(outcome) => return Ok(outcome),
            }
        }
    }

    #[test]
    fn retained_published_release_deletion_is_exact_current_safe_and_retryable() {
        let root = TestRoot::new();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Candidate,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, intent.clone()).unwrap();
        let sealed = seal_two(&mut generation);
        generation.publish(&prior).unwrap();
        assert!(matches!(
            delete_retained_release_generation(&root.0, &intent, &sealed).unwrap(),
            ReleaseGenerationRetentionDeletion::ProtectedCurrent { .. }
        ));
        generation.restore_prior(&prior).unwrap();
        drop(generation);
        assert!(matches!(
            step_retained_release_generation_deletion(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device() + 1,
                sealed.selector.directory_inode(),
                sealed.route_count,
            )
            .unwrap(),
            ReleaseGenerationRetentionStep::Complete(
                ReleaseGenerationRetentionDeletion::IdentityMismatch {
                    mismatch: ReleaseGenerationRetentionMismatch::DirectoryIdentity,
                    observed_identity: None,
                    ..
                }
            )
        ));
        assert!(matches!(
            delete_retained_release_generation(&root.0, &intent, &sealed).unwrap(),
            ReleaseGenerationRetentionDeletion::Deleted { .. }
        ));
        assert!(matches!(
            delete_retained_release_generation(&root.0, &intent, &sealed).unwrap(),
            ReleaseGenerationRetentionDeletion::AlreadyAbsent
        ));
    }

    #[test]
    fn release_retention_step_marks_then_unlinks_at_most_one_child() {
        let root = TestRoot::new();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Maintenance,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, intent.clone()).unwrap();
        let sealed = seal_two(&mut generation);
        generation.publish(&prior).unwrap();
        generation.restore_prior(&prior).unwrap();
        let directory = generation.path();
        let before = std::fs::read_dir(&directory).unwrap().count();
        assert_eq!(
            step_retained_release_generation_deletion(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
            )
            .unwrap(),
            ReleaseGenerationRetentionStep::InProgress
        );
        let marked = std::fs::read_dir(&directory).unwrap().count();
        assert_eq!(marked, before + 1);
        assert!(directory.join(RETENTION_MARKER_FILE).exists());

        let current = root.0.join(CURRENT_SELECTOR);
        std::fs::remove_file(&current).unwrap();
        symlink(intent.name().selector_target(), &current).unwrap();
        assert!(matches!(
            step_retained_release_generation_deletion(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
            )
            .unwrap(),
            ReleaseGenerationRetentionStep::Complete(
                ReleaseGenerationRetentionDeletion::ProtectedCurrent { .. }
            )
        ));
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), marked);
        std::fs::remove_file(&current).unwrap();
        symlink(prior.target(), &current).unwrap();
        assert_eq!(
            step_retained_release_generation_deletion(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
            )
            .unwrap(),
            ReleaseGenerationRetentionStep::InProgress
        );
        assert_eq!(std::fs::read_dir(&directory).unwrap().count() + 1, marked);
    }

    #[test]
    fn marked_release_retention_resumes_without_retrusting_deleted_bytes() {
        let root = TestRoot::new();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Candidate,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, intent.clone()).unwrap();
        let sealed = seal_two(&mut generation);
        generation.publish(&prior).unwrap();
        generation.restore_prior(&prior).unwrap();
        assert_eq!(
            step_retained_release_generation_deletion(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
            )
            .unwrap(),
            ReleaseGenerationRetentionStep::InProgress
        );
        std::fs::remove_file(generation.path().join(INTENT_FILE)).unwrap();
        drop(generation);
        assert!(matches!(
            delete_retained_release_generation(&root.0, &intent, &sealed).unwrap(),
            ReleaseGenerationRetentionDeletion::Deleted { .. }
        ));
    }

    #[test]
    fn release_retention_distinguishes_identity_from_content_integrity_drift() {
        let make = || {
            let root = TestRoot::new();
            root.install_current("boot-live");
            let prior = observe_current_selector(&root.0).unwrap();
            let intent = intent(
                Uuid::new_v4(),
                Uuid::new_v4(),
                ReleaseOverlayKind::Candidate,
            );
            let mut generation =
                ReleaseGenerationDirectory::create_or_open(&root.0, intent.clone()).unwrap();
            let sealed = seal_two(&mut generation);
            generation.publish(&prior).unwrap();
            generation.restore_prior(&prior).unwrap();
            (root, intent, generation, sealed)
        };

        let (root, intent, generation, sealed) = make();
        let observed = ReleaseOverlayGenerationIdentity::new(
            intent.fleet_run_id,
            intent.driver_operation_id,
            intent.original_global_fence_token,
            intent.overlay_kind,
            digest('f'),
            intent.target_slot.as_str(),
        )
        .unwrap();
        let identity_path = generation.path().join(RELEASE_OVERLAY_GENERATION_FILE);
        std::fs::write(
            &identity_path,
            release_overlay_generation_config(&observed).unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(FILE_MODE))
            .unwrap();
        drop(generation);
        assert!(matches!(
            step_retained_release_generation_deletion(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
            )
            .unwrap(),
            ReleaseGenerationRetentionStep::Complete(ReleaseGenerationRetentionDeletion::IdentityMismatch {
                mismatch: ReleaseGenerationRetentionMismatch::ContentIdentity,
                observed_identity: Some(identity),
                ..
            }) if identity == observed
        ));

        let (root, intent, generation, sealed) = make();
        let route = generation.path().join(format!("{}.conf", workshops()[0]));
        std::fs::write(&route, b"tampered\n").unwrap();
        std::fs::set_permissions(&route, std::fs::Permissions::from_mode(FILE_MODE)).unwrap();
        drop(generation);
        assert!(matches!(
            step_retained_release_generation_deletion(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
            )
            .unwrap(),
            ReleaseGenerationRetentionStep::Complete(ReleaseGenerationRetentionDeletion::IdentityMismatch {
                mismatch: ReleaseGenerationRetentionMismatch::ContentIntegrity,
                observed_identity: Some(identity),
                ..
            }) if identity == sealed.identity
        ));
    }

    #[test]
    fn release_retention_refuses_selector_race_and_changed_marker() {
        let root = TestRoot::new();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Maintenance,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, intent.clone()).unwrap();
        let sealed = seal_two(&mut generation);
        generation.publish(&prior).unwrap();
        generation.restore_prior(&prior).unwrap();
        let current = root.0.join(CURRENT_SELECTOR);
        let candidate = intent.name().selector_target();
        assert!(
            step_retained_release_generation_deletion_with_hook(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
                || {
                    std::fs::remove_file(&current).unwrap();
                    symlink(&candidate, &current).unwrap();
                },
            )
            .is_err()
        );
        assert!(!generation.path().join(RETENTION_MARKER_FILE).exists());

        std::fs::remove_file(&current).unwrap();
        symlink(prior.target(), &current).unwrap();
        assert_eq!(
            step_retained_release_generation_deletion(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
            )
            .unwrap(),
            ReleaseGenerationRetentionStep::InProgress
        );
        let marker = generation.path().join(RETENTION_MARKER_FILE);
        std::fs::write(&marker, b"{}\n").unwrap();
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(FILE_MODE)).unwrap();
        assert!(
            step_retained_release_generation_deletion(
                &root.0,
                &intent,
                &sealed.identity,
                sealed.selector.directory_device(),
                sealed.selector.directory_inode(),
                sealed.route_count,
            )
            .is_err()
        );
    }

    #[test]
    fn release_retention_rejects_cross_intent_identity_and_invalid_counts() {
        let fleet = Uuid::new_v4();
        let expected_intent = intent(fleet, Uuid::new_v4(), ReleaseOverlayKind::Candidate);
        let wrong_intent = intent(fleet, Uuid::new_v4(), ReleaseOverlayKind::Candidate);
        let identity = ReleaseOverlayGenerationIdentity::new(
            wrong_intent.fleet_run_id,
            wrong_intent.driver_operation_id,
            wrong_intent.original_global_fence_token,
            wrong_intent.overlay_kind,
            digest('a'),
            wrong_intent.target_slot.as_str(),
        )
        .unwrap();
        assert!(
            validate_release_retention_generation_authority(&expected_intent, &identity).is_err()
        );

        let root = TestRoot::new();
        root.install_current("boot-live");
        assert!(
            step_retained_release_generation_deletion(&root.0, &wrong_intent, &identity, 1, 1, 0)
                .is_err()
        );
        assert!(
            step_retained_release_generation_deletion(
                &root.0,
                &wrong_intent,
                &identity,
                1,
                1,
                MAX_RELEASE_ROUTES + 1,
            )
            .is_err()
        );
        assert!(
            step_retained_release_generation_deletion(&root.0, &wrong_intent, &identity, 0, 1, 1,)
                .is_err()
        );
    }

    #[test]
    fn deterministic_names_keep_maintenance_and_candidate_separate() {
        let fleet = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        let operation = Uuid::new_v4();
        let maintenance = intent(fleet, operation, ReleaseOverlayKind::Maintenance);
        let candidate = intent(fleet, operation, ReleaseOverlayKind::Candidate);
        assert_eq!(
            maintenance.name().as_str(),
            "release-aaaaaaaabbbbccccddddeeeeeeeeeeee-maintenance"
        );
        assert_eq!(
            candidate.name().selector_target(),
            "generations/release-aaaaaaaabbbbccccddddeeeeeeeeeeee-candidate"
        );
        assert!(maintenance.name().as_str().len() <= 64);
        assert_ne!(maintenance.name(), candidate.name());

        let root = TestRoot::new();
        let maintenance_generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, maintenance).unwrap();
        let candidate_generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, candidate).unwrap();
        assert_ne!(maintenance_generation.path(), candidate_generation.path());
    }

    #[test]
    fn active_cutover_remains_forbidden_until_normal_route_writes_are_copy_on_write() {
        assert!(!std::hint::black_box(ACTIVE_RELEASE_CUTOVER_ALLOWED));
        let gateway_source = include_str!("gateway.rs");
        assert!(gateway_source.contains("selected_route_root(&state.config.route_root)"));
        assert!(gateway_source.contains("write_gateway_file"));
    }

    #[test]
    fn empty_and_out_of_contract_reopen_counts_are_rejected() {
        let root = TestRoot::new();
        let release_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Candidate,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent.clone()).unwrap();
        assert!(generation.begin_seal().unwrap().finish().is_err());
        drop(generation);
        for invalid_count in [0, MAX_RELEASE_ROUTES + 1] {
            assert!(
                ReleaseGenerationDirectory::open_existing_sealed(
                    &root.0,
                    release_intent.clone(),
                    &digest('a'),
                    invalid_count,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn stages_seals_publishes_observes_and_restores_exact_selector() {
        let root = TestRoot::new();
        let release_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Maintenance,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent.clone()).unwrap();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let seal = seal_two(&mut generation);
        assert_eq!(seal.route_count, 2);
        assert_eq!(seal.identity.overlay_kind, ReleaseOverlayKind::Maintenance);
        assert_eq!(
            observe_candidate_selector(&root.0, &release_intent).unwrap(),
            seal.selector
        );
        assert_eq!(
            seal.selector.target(),
            release_intent.name().selector_target()
        );
        assert_eq!(
            observe_generation_identity(&root.0, &release_intent, seal.route_count, false).unwrap(),
            seal.identity
        );

        let captured = generation.publish(&prior).unwrap();
        assert_eq!(captured, prior);
        assert_eq!(
            generation.observe_selected().unwrap().identity,
            seal.identity
        );
        let selected =
            observe_selected_identity(&root.0, &release_intent, &seal.identity, seal.route_count)
                .unwrap();
        assert_eq!(selected.target(), release_intent.name().selector_target());

        drop(generation);
        let mut reopened = ReleaseGenerationDirectory::open_existing_published(
            &root.0,
            release_intent,
            &seal.identity.route_set_digest,
            seal.route_count,
        )
        .unwrap();
        reopened.restore_prior(&prior).unwrap();
        assert_eq!(
            observe_current_selector(&root.0).unwrap().target(),
            "generations/boot-live"
        );
        assert!(reopened.dispose().is_err());
    }

    #[test]
    fn identical_streams_have_a_context_independent_deterministic_route_set_digest() {
        let fleet = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let exact_intent = intent(fleet, operation, ReleaseOverlayKind::Candidate);
        let first_root = TestRoot::new();
        let second_root = TestRoot::new();
        let mut first =
            ReleaseGenerationDirectory::create_or_open(&first_root.0, exact_intent.clone())
                .unwrap();
        let mut second =
            ReleaseGenerationDirectory::create_or_open(&second_root.0, exact_intent).unwrap();
        let first_seal = seal_two(&mut first);
        let second_seal = seal_two(&mut second);
        assert_eq!(
            first_seal.identity.route_set_digest,
            "sha256:6e9cf63505ae80128790172e7723db882310e75df07609c557927978994374a2"
        );
        assert_eq!(
            first_seal.identity.route_set_digest,
            second_seal.identity.route_set_digest
        );

        let third_root = TestRoot::new();
        let mut maintenance = ReleaseGenerationDirectory::create_or_open(
            &third_root.0,
            intent(fleet, operation, ReleaseOverlayKind::Maintenance),
        )
        .unwrap();
        let maintenance_seal = seal_two(&mut maintenance);
        assert_eq!(
            first_seal.identity.route_set_digest,
            maintenance_seal.identity.route_set_digest
        );
        assert_ne!(first_seal.identity, maintenance_seal.identity);
    }

    #[test]
    fn preexisting_retries_require_exact_intent_and_exact_route_bytes() {
        let root = TestRoot::new();
        let fleet = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let release_intent = intent(fleet, operation, ReleaseOverlayKind::Candidate);
        let mut first =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent.clone()).unwrap();
        {
            let mut sealer = first.begin_seal().unwrap();
            sealer
                .stage_route(
                    workshops()[0],
                    1,
                    &digest('a'),
                    &digest('b'),
                    b"server { return 204; }\n",
                )
                .unwrap();
        }
        drop(first);

        let mismatched = intent(fleet, Uuid::new_v4(), ReleaseOverlayKind::Candidate);
        assert!(ReleaseGenerationDirectory::create_or_open(&root.0, mismatched).is_err());

        let mut retry =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent).unwrap();
        {
            let mut sealer = retry.begin_seal().unwrap();
            sealer
                .stage_route(
                    workshops()[0],
                    1,
                    &digest('a'),
                    &digest('b'),
                    b"server { return 204; }\n",
                )
                .unwrap();
            assert!(
                sealer
                    .stage_route(
                        workshops()[1],
                        2,
                        &digest('c'),
                        &digest('d'),
                        b"server { return 404; }\n",
                    )
                    .is_ok()
            );
        }

        let conflicting_root = TestRoot::new();
        let conflicting_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Candidate,
        );
        let mut conflicting =
            ReleaseGenerationDirectory::create_or_open(&conflicting_root.0, conflicting_intent)
                .unwrap();
        std::fs::write(
            conflicting.path().join(format!("{}.conf", workshops()[0])),
            b"server { return 500; }\n",
        )
        .unwrap();
        std::fs::set_permissions(
            conflicting.path().join(format!("{}.conf", workshops()[0])),
            std::fs::Permissions::from_mode(FILE_MODE),
        )
        .unwrap();
        assert!(
            conflicting
                .begin_seal()
                .unwrap()
                .stage_route(
                    workshops()[0],
                    1,
                    &digest('a'),
                    &digest('b'),
                    b"server { return 204; }\n",
                )
                .is_err()
        );
    }

    #[test]
    fn partial_create_only_bytes_remain_as_evidence_and_ordering_is_strict() {
        let root = TestRoot::new();
        let release_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Candidate,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent).unwrap();
        let route_name = format!("{}.conf", workshops()[0]);
        let partial = b"server {";
        let mut partial_file = create_at_file(
            &generation.directory,
            &cstring(&route_name).unwrap(),
            FILE_MODE,
        )
        .unwrap();
        partial_file.write_all(partial).unwrap();
        partial_file.sync_all().unwrap();
        drop(partial_file);
        assert!(
            generation
                .begin_seal()
                .unwrap()
                .stage_route(
                    workshops()[0],
                    1,
                    &digest('a'),
                    &digest('b'),
                    b"server { return 204; }\n",
                )
                .is_err()
        );
        assert_eq!(
            std::fs::read(generation.path().join(route_name)).unwrap(),
            partial
        );

        let ordered_root = TestRoot::new();
        let mut ordered = ReleaseGenerationDirectory::create_or_open(
            &ordered_root.0,
            intent(
                Uuid::new_v4(),
                Uuid::new_v4(),
                ReleaseOverlayKind::Maintenance,
            ),
        )
        .unwrap();
        let mut sealer = ordered.begin_seal().unwrap();
        sealer
            .stage_route(
                workshops()[1],
                1,
                &digest('a'),
                &digest('b'),
                b"server { return 503; }\n",
            )
            .unwrap();
        assert!(
            sealer
                .stage_route(
                    workshops()[0],
                    1,
                    &digest('a'),
                    &digest('b'),
                    b"server { return 503; }\n",
                )
                .is_err()
        );
        assert!(
            sealer
                .record(&ReleaseRouteSealEvidence {
                    workshop_id: workshops()[1],
                    projection_generation: 1,
                    projection_digest: digest('a'),
                    applied_rendered_digest: digest('b'),
                    rendered_digest: digest('c'),
                })
                .is_err()
        );
    }

    #[test]
    fn exact_identity_write_before_mode_transition_is_retryable_but_partial_is_not_erased() {
        let fleet = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let release_intent = intent(fleet, operation, ReleaseOverlayKind::Candidate);
        let reference_root = TestRoot::new();
        let mut reference =
            ReleaseGenerationDirectory::create_or_open(&reference_root.0, release_intent.clone())
                .unwrap();
        let expected = seal_two(&mut reference);

        let retry_root = TestRoot::new();
        let mut interrupted =
            ReleaseGenerationDirectory::create_or_open(&retry_root.0, release_intent.clone())
                .unwrap();
        {
            let mut sealer = interrupted.begin_seal().unwrap();
            sealer
                .stage_route(
                    workshops()[0],
                    4,
                    &digest('a'),
                    &digest('b'),
                    b"server { return 503; }\n",
                )
                .unwrap();
            sealer
                .stage_route(
                    workshops()[1],
                    8,
                    &digest('c'),
                    &digest('d'),
                    b"server { return 204; }\n",
                )
                .unwrap();
        }
        write_create_only_or_verify(
            &interrupted.directory,
            RELEASE_OVERLAY_GENERATION_FILE,
            release_overlay_generation_config(&expected.identity)
                .unwrap()
                .as_bytes(),
            "release overlay identity",
        )
        .unwrap();
        drop(interrupted);
        let mut retried =
            ReleaseGenerationDirectory::create_or_open(&retry_root.0, release_intent).unwrap();
        assert_eq!(seal_two(&mut retried).identity, expected.identity);

        let partial_root = TestRoot::new();
        let partial_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Maintenance,
        );
        let partial_generation =
            ReleaseGenerationDirectory::create_or_open(&partial_root.0, partial_intent.clone())
                .unwrap();
        let identity_path = partial_generation
            .path()
            .join(RELEASE_OVERLAY_GENERATION_FILE);
        std::fs::write(&identity_path, b"server {\n").unwrap();
        std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(FILE_MODE))
            .unwrap();
        drop(partial_generation);
        assert!(
            ReleaseGenerationDirectory::create_or_open(&partial_root.0, partial_intent).is_err()
        );
        assert_eq!(std::fs::read(identity_path).unwrap(), b"server {\n");
    }

    #[test]
    fn symlink_hardlink_and_mode_substitutions_fail_closed() {
        for attack in ["symlink", "hardlink", "mode"] {
            let root = TestRoot::new();
            let release_intent = intent(
                Uuid::new_v4(),
                Uuid::new_v4(),
                ReleaseOverlayKind::Maintenance,
            );
            let mut generation =
                ReleaseGenerationDirectory::create_or_open(&root.0, release_intent).unwrap();
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
            let result = generation.begin_seal().unwrap().stage_route(
                workshops()[0],
                1,
                &digest('a'),
                &digest('b'),
                b"server { return 204; }\n",
            );
            assert!(result.is_err(), "{attack} substitution was accepted");
            assert_eq!(std::fs::read(&victim).unwrap(), b"server { return 204; }\n");
        }
    }

    #[test]
    fn directory_identity_mode_and_cross_filesystem_checks_fail_closed() {
        let root = TestRoot::new();
        let release_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Candidate,
        );
        let generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent).unwrap();
        std::fs::set_permissions(generation.path(), std::fs::Permissions::from_mode(0o750))
            .unwrap();
        assert!(generation.dispose().is_err());

        let temp = File::open(std::env::temp_dir()).unwrap();
        if Path::new("/dev/shm").is_dir() {
            let shared_memory = File::open("/dev/shm").unwrap();
            if temp.metadata().unwrap().dev() != shared_memory.metadata().unwrap().dev() {
                assert!(ensure_same_filesystem(&temp, &shared_memory).is_err());
            }
        }

        // CI normally runs unprivileged. When this test does run as root, also
        // exercise the ownership branch instead of merely relying on the same
        // audited validator's startup coverage.
        if unsafe { libc::geteuid() } == 0 {
            use std::os::fd::AsRawFd as _;

            let owned_path = root.0.join("wrong-owner");
            std::fs::write(&owned_path, b"evidence").unwrap();
            std::fs::set_permissions(&owned_path, std::fs::Permissions::from_mode(FILE_MODE))
                .unwrap();
            let owned = File::open(owned_path).unwrap();
            // SAFETY: the descriptor is live; fchown retains no reference.
            assert_eq!(
                unsafe { libc::fchown(owned.as_raw_fd(), 65_534, 65_534) },
                0
            );
            assert!(validate_regular_file(&owned, FILE_MODE, "wrong owner").is_err());
        }
    }

    #[test]
    fn publication_marker_is_a_permanent_cleanup_boundary_even_before_exchange() {
        let root = TestRoot::new();
        let release_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Maintenance,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent.clone()).unwrap();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let seal = seal_two(&mut generation);
        let error = generation
            .publish_with_pre_exchange(&prior, || Err(invalid_state("simulated crash")))
            .unwrap_err();
        assert_eq!(error.to_string(), "simulated crash");
        assert_eq!(
            observe_current_selector(&root.0).unwrap().target(),
            "generations/boot-live"
        );
        assert!(dispose_exact_unpublished(&root.0, &release_intent).is_err());
        drop(generation);
        ReleaseGenerationDirectory::open_existing_published(
            &root.0,
            release_intent,
            &seal.identity.route_set_digest,
            seal.route_count,
        )
        .unwrap();
    }

    #[test]
    fn selector_race_is_detected_and_crossed_candidate_is_never_disposable() {
        let root = TestRoot::new();
        let release_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Candidate,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent.clone()).unwrap();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        seal_two(&mut generation);
        let route_root = root.0.clone();
        assert!(
            generation
                .publish_with_pre_exchange(&prior, || {
                    std::fs::create_dir(route_root.join("generations/raced-live"))?;
                    std::fs::set_permissions(
                        route_root.join("generations/raced-live"),
                        std::fs::Permissions::from_mode(SEALED_MODE),
                    )?;
                    std::fs::remove_file(route_root.join(CURRENT_SELECTOR))?;
                    symlink("generations/raced-live", route_root.join(CURRENT_SELECTOR))
                })
                .is_err()
        );
        assert!(dispose_exact_unpublished(&root.0, &release_intent).is_err());
    }

    #[test]
    fn publish_exchange_artifact_recovery_is_exact_and_idempotent() {
        let root = TestRoot::new();
        let release_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Candidate,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent.clone()).unwrap();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let seal = seal_two(&mut generation);
        assert!(
            generation
                .publish_with_exchange_hooks(
                    &prior,
                    || Ok(()),
                    || Err(invalid_state("simulated post-exchange crash")),
                )
                .is_err()
        );
        assert_eq!(observe_current_selector(&root.0).unwrap(), seal.selector);
        assert_eq!(
            recover_exchange_artifact(
                &root.0,
                &release_intent,
                &seal.identity,
                seal.route_count,
                &seal.selector,
                &prior,
                ReleaseSelectorExchange::Publish,
            )
            .unwrap(),
            ReleaseExchangeRecovery::ExchangedArtifactRemoved
        );
        assert_eq!(
            recover_exchange_artifact(
                &root.0,
                &release_intent,
                &seal.identity,
                seal.route_count,
                &seal.selector,
                &prior,
                ReleaseSelectorExchange::Publish,
            )
            .unwrap(),
            ReleaseExchangeRecovery::AlreadyClean
        );
    }

    #[test]
    fn prepared_and_restore_exchange_artifacts_are_classified_without_foreign_cleanup() {
        let root = TestRoot::new();
        let release_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Maintenance,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent.clone()).unwrap();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let seal = seal_two(&mut generation);
        generation.install_publication_marker().unwrap();
        generation.phase = GenerationPhase::Published;

        let publish_artifact =
            exchange_artifact_name(&release_intent, ReleaseSelectorExchange::Publish);
        symlink(
            release_intent.name().selector_target(),
            root.0.join(&publish_artifact),
        )
        .unwrap();
        assert_eq!(
            recover_exchange_artifact(
                &root.0,
                &release_intent,
                &seal.identity,
                seal.route_count,
                &seal.selector,
                &prior,
                ReleaseSelectorExchange::Publish,
            )
            .unwrap(),
            ReleaseExchangeRecovery::PreparedArtifactRemoved
        );
        assert_eq!(observe_current_selector(&root.0).unwrap(), prior);

        // Complete publication, then synthesize the exact rename-exchanged
        // restore boundary: current=prior and artifact=candidate.
        let restore_root = TestRoot::new();
        let restore_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Maintenance,
        );
        let mut restore_generation =
            ReleaseGenerationDirectory::create_or_open(&restore_root.0, restore_intent.clone())
                .unwrap();
        restore_root.install_current("boot-live");
        let restore_prior = observe_current_selector(&restore_root.0).unwrap();
        let restore_seal = seal_two(&mut restore_generation);
        restore_generation.publish(&restore_prior).unwrap();
        let restore_artifact =
            exchange_artifact_name(&restore_intent, ReleaseSelectorExchange::RestorePrior);
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
            observe_current_selector(&restore_root.0).unwrap(),
            restore_prior
        );
        assert_eq!(
            recover_exchange_artifact(
                &restore_root.0,
                &restore_intent,
                &restore_seal.identity,
                restore_seal.route_count,
                &restore_seal.selector,
                &restore_prior,
                ReleaseSelectorExchange::RestorePrior,
            )
            .unwrap(),
            ReleaseExchangeRecovery::ExchangedArtifactRemoved
        );

        // An artifact with the deterministic name but the wrong exact target
        // is foreign evidence and must remain untouched.
        let foreign_artifact =
            exchange_artifact_name(&restore_intent, ReleaseSelectorExchange::Publish);
        symlink(
            restore_prior.target(),
            restore_root.0.join(&foreign_artifact),
        )
        .unwrap();
        assert!(
            recover_exchange_artifact(
                &restore_root.0,
                &restore_intent,
                &restore_seal.identity,
                restore_seal.route_count,
                &restore_seal.selector,
                &restore_prior,
                ReleaseSelectorExchange::Publish,
            )
            .is_err()
        );
        assert!(restore_root.0.join(foreign_artifact).is_symlink());
    }

    #[test]
    fn prepublication_disposal_is_exact_nonrecursive_and_rejects_marker_or_selection() {
        let root = TestRoot::new();
        let release_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Maintenance,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent.clone()).unwrap();
        seal_two(&mut generation);
        drop(generation);
        dispose_exact_unpublished(&root.0, &release_intent).unwrap();
        assert!(
            !root
                .0
                .join(release_intent.name().selector_target())
                .exists()
        );

        let selected_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Candidate,
        );
        let selected =
            ReleaseGenerationDirectory::create_or_open(&root.0, selected_intent.clone()).unwrap();
        symlink(
            selected_intent.name().selector_target(),
            root.0.join(CURRENT_SELECTOR),
        )
        .unwrap();
        drop(selected);
        assert!(dispose_exact_unpublished(&root.0, &selected_intent).is_err());

        std::fs::remove_file(root.0.join(CURRENT_SELECTOR)).unwrap();
        let nested_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Candidate,
        );
        let nested =
            ReleaseGenerationDirectory::create_or_open(&root.0, nested_intent.clone()).unwrap();
        std::fs::create_dir(nested.path().join("unexpected")).unwrap();
        drop(nested);
        assert!(dispose_exact_unpublished(&root.0, &nested_intent).is_err());
        assert!(root.0.join(nested_intent.name().selector_target()).exists());
    }

    #[test]
    fn sealed_membership_and_identity_mutations_are_detected() {
        let root = TestRoot::new();
        let release_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Candidate,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent.clone()).unwrap();
        root.install_current("boot-live");
        let seal = seal_two(&mut generation);
        let route_path = generation.path().join(format!("{}.conf", workshops()[0]));
        let original_route = std::fs::read(&route_path).unwrap();
        std::fs::write(&route_path, b"server { return 500; }\n").unwrap();
        assert!(generation.verify_sealed_bytes().is_err());
        std::fs::write(&route_path, original_route).unwrap();
        assert!(generation.verify_sealed_bytes().is_ok());
        let evidence_path = generation.path().join(EVIDENCE_FILE);
        let original_evidence = std::fs::read(&evidence_path).unwrap();
        let mut changed_evidence = original_evidence.clone();
        let offset = changed_evidence
            .windows(b"sha256:".len())
            .position(|window| window == b"sha256:")
            .unwrap()
            + b"sha256:".len();
        changed_evidence[offset] = if changed_evidence[offset] == b'a' {
            b'b'
        } else {
            b'a'
        };
        std::fs::write(&evidence_path, changed_evidence).unwrap();
        assert!(generation.verify_sealed_bytes().is_err());
        std::fs::write(&evidence_path, original_evidence).unwrap();
        let injected = generation.path().join(format!("{}.conf", Uuid::new_v4()));
        std::fs::write(&injected, b"server { return 418; }\n").unwrap();
        std::fs::set_permissions(&injected, std::fs::Permissions::from_mode(FILE_MODE)).unwrap();
        assert!(generation.verify_sealed_bytes().is_err());
        std::fs::remove_file(injected).unwrap();

        let identity_path = generation.path().join(RELEASE_OVERLAY_GENERATION_FILE);
        let original = std::fs::read(&identity_path).unwrap();
        std::fs::write(&identity_path, b"not canonical\n").unwrap();
        assert!(generation.verify_sealed_bytes().is_err());
        let mismatched = ReleaseOverlayGenerationIdentity::new(
            release_intent.fleet_run_id,
            Uuid::new_v4(),
            release_intent.original_global_fence_token,
            release_intent.overlay_kind,
            seal.identity.route_set_digest.clone(),
            release_intent.target_slot.as_str(),
        )
        .unwrap();
        std::fs::write(
            &identity_path,
            release_overlay_generation_config(&mismatched).unwrap(),
        )
        .unwrap();
        assert!(
            observe_generation_identity(&root.0, &release_intent, seal.route_count, false).is_err()
        );
        std::fs::write(&identity_path, original).unwrap();
        assert_eq!(
            observe_generation_identity(&root.0, &release_intent, seal.route_count, false).unwrap(),
            seal.identity
        );
    }

    #[test]
    fn staging_never_reads_route_bytes_from_the_live_generation() {
        use std::ffi::CString;

        let root = TestRoot::new();
        let release_intent = intent(
            Uuid::new_v4(),
            Uuid::new_v4(),
            ReleaseOverlayKind::Maintenance,
        );
        let mut generation =
            ReleaseGenerationDirectory::create_or_open(&root.0, release_intent).unwrap();
        root.install_current("boot-live");
        let live_fifo = root.0.join("generations/boot-live/trap.conf");
        let fifo = CString::new(live_fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the path is a valid C string and mkfifo retains no pointer.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o640) }, 0);
        seal_two(&mut generation);
    }
}
