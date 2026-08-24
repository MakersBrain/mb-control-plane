//! Filesystem half of staged startup route publication.
//!
//! This module contains no database access. Keeping it separate lets the
//! durable protocol authenticate transitions while filesystem code enforces
//! path, sealing, selector, and disposal invariants at the effect boundary.
#![allow(dead_code)]

use std::fs::File;
use std::io::{self, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::gateway::{
    GatewayGenerationIdentity, gateway_generation_config, parse_gateway_generation_config,
};
use super::route_generation_fs::{
    CURRENT_SELECTOR, FILE_MODE, GENERATIONS_DIRECTORY, GENERATIONS_MODE, MAX_ROUTE_BYTES,
    ROUTE_ROOT_MODE, SEALED_MODE, STAGING_MODE, create_at_file, cstring, digest_bytes,
    ensure_same_filesystem, invalid_input, invalid_state, mkdir_at, observe_selector_from_handles,
    observe_selector_target, open_at_directory, open_at_file, open_directory, read_bounded,
    read_link_at, rename_exchange, selector_generation_name, symlink_at, unlink_at,
    validate_current_selector, validate_digest, validate_directory, validate_regular_file,
    validate_route_bytes, validate_selector_target, visit_generation_entries,
};
pub(super) use super::route_generation_fs::{
    PriorSelector, observe_current_selector, observe_generation_selector,
};

pub(super) const STARTUP_GATEWAY_GENERATION_FILE: &str = "mb-generation.conf";
const PUBLICATION_MARKER_FILE: &str = ".publication-started-v1";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct StartupGenerationName(String);

impl StartupGenerationName {
    pub(super) fn for_effect(effect_run_id: Uuid) -> Self {
        Self(format!("startup-{effect_run_id}"))
    }

    fn selector_target(&self) -> String {
        format!("{GENERATIONS_DIRECTORY}/{}", self.0)
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Read the generation identity bound to an already observed selector.
/// `boot-live` is the sole legacy generation allowed to have no identity;
/// every staged generation must contain the exact canonical Nginx snippet.
pub(super) fn observe_prior_gateway_identity(
    route_root: &Path,
    prior: &PriorSelector,
) -> io::Result<Option<GatewayGenerationIdentity>> {
    let root = open_directory(route_root)?;
    validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
    let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
    validate_directory(
        &generations,
        GENERATIONS_MODE,
        "route generations directory",
    )?;
    ensure_same_filesystem(&root, &generations)?;
    let observed = observe_selector_target(&generations, prior.target().to_owned())?;
    if &observed != prior {
        return Err(invalid_state(
            "recorded prior selector directory identity changed",
        ));
    }
    let generation_name = selector_generation_name(prior.target())?;
    let directory = open_at_directory(&generations, &cstring(generation_name)?)?;
    validate_directory(&directory, SEALED_MODE, "prior route generation")?;
    let identity_file = match open_at_file(&directory, &cstring(STARTUP_GATEWAY_GENERATION_FILE)?) {
        Ok(file) => file,
        Err(error)
            if error.kind() == io::ErrorKind::NotFound
                && prior.target() == "generations/boot-live" =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    validate_regular_file(&identity_file, FILE_MODE, "prior generation identity")?;
    let bytes = read_bounded(identity_file, MAX_ROUTE_BYTES)?;
    parse_gateway_generation_config(&bytes)
        .map(Some)
        .map_err(|error| io::Error::other(error.1))
}

/// Dispose an exact candidate whose database phase proves that selector
/// publication was never authorized. This deliberately accepts both the
/// private staging mode and the sealed mode: a crash may occur after the
/// identity file and mode transition but before the database seal commits.
/// No digest or count is guessed, and a publication marker always makes the
/// candidate ineligible for this cleanup path.
pub(super) fn dispose_exact_unpublished_candidate(
    route_root: &Path,
    effect_run_id: Uuid,
) -> io::Result<()> {
    let root = open_directory(route_root)?;
    validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
    let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
    validate_directory(
        &generations,
        GENERATIONS_MODE,
        "route generations directory",
    )?;
    ensure_same_filesystem(&root, &generations)?;

    let name = StartupGenerationName::for_effect(effect_run_id);
    let directory = open_at_directory(&generations, &cstring(name.as_str())?)?;
    ensure_same_filesystem(&generations, &directory)?;
    let mode = directory.metadata()?.mode() & 0o7777;
    if mode != STAGING_MODE && mode != SEALED_MODE {
        return Err(invalid_state(
            "unpublished startup generation has an unsafe mode",
        ));
    }
    validate_directory(&directory, mode, "unpublished startup generation")?;

    let candidate_target = name.selector_target();
    match read_link_at(&root, &cstring(CURRENT_SELECTOR)?) {
        Ok(target) if target == candidate_target => {
            return Err(invalid_state(
                "selected startup generation is not disposable",
            ));
        }
        Ok(target) => validate_selector_target(&target)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let entries = inspect_generation_entries(&directory, true, false)?;
    if entries.publication_marker_present {
        return Err(invalid_state(
            "publication-started generation is not disposable",
        ));
    }
    dispose_generation_entries(&directory, true)?;
    if inspect_generation_entries(&directory, false, false)?.route_count != 0 {
        return Err(invalid_state("startup generation disposal was incomplete"));
    }
    directory.sync_all()?;
    validate_directory(&directory, mode, "unpublished startup generation")?;
    unlink_at(&generations, &cstring(name.as_str())?, true)?;
    generations.sync_all()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct StartupRouteSealEvidence {
    pub workshop_id: Uuid,
    pub projection_generation: i64,
    pub projection_digest: String,
    pub disposition: String,
    pub action: String,
    pub rendered_digest: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GenerationPhase {
    Staging,
    Sealed,
    Published,
}

#[derive(Clone, Debug)]
pub(super) struct SealedStartupGeneration {
    pub name: StartupGenerationName,
    pub identity: GatewayGenerationIdentity,
    pub route_count: usize,
    pub sealed_digest: String,
    present_route_count: usize,
}

pub(super) struct StartupGenerationSealer<'a> {
    generation: &'a mut StartupGenerationDirectory,
    hasher: Sha256,
    previous_workshop: Option<Uuid>,
    route_count: usize,
    present_route_count: usize,
}

#[derive(Debug)]
pub(super) struct StartupGenerationDirectory {
    root_path: PathBuf,
    root: File,
    generations: File,
    directory: File,
    directory_dev: u64,
    directory_ino: u64,
    effect_run_id: Uuid,
    name: StartupGenerationName,
    phase: GenerationPhase,
    sealed: Option<SealedStartupGeneration>,
}

impl StartupGenerationDirectory {
    /// Create a fresh, private staging directory. Existing names are never
    /// reused because they may be evidence from an interrupted effect run.
    pub(super) fn create(route_root: &Path, effect_run_id: Uuid) -> io::Result<Self> {
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

        let name = StartupGenerationName::for_effect(effect_run_id);
        let generation_name = cstring(name.as_str())?;
        mkdir_at(&generations, &generation_name, STAGING_MODE)?;
        generations.sync_all()?;
        let directory = open_at_directory(&generations, &generation_name)?;
        validate_directory(&directory, STAGING_MODE, "startup staging directory")?;
        ensure_same_filesystem(&generations, &directory)?;
        let metadata = directory.metadata()?;

        let generation = Self {
            root_path: route_root.to_owned(),
            root,
            generations,
            directory,
            directory_dev: metadata.dev(),
            directory_ino: metadata.ino(),
            effect_run_id,
            name,
            phase: GenerationPhase::Staging,
            sealed: None,
        };
        generation.validate_named_directory(STAGING_MODE)?;
        generation.refuse_if_selected()?;
        Ok(generation)
    }

    pub(super) fn open_existing_staging(
        route_root: &Path,
        effect_run_id: Uuid,
    ) -> io::Result<Self> {
        Self::open_existing(route_root, effect_run_id, GenerationPhase::Staging, None)
    }

    pub(super) fn open_existing_sealed(
        route_root: &Path,
        effect_run_id: Uuid,
        sealed_digest: &str,
        route_count: usize,
        present_route_count: usize,
    ) -> io::Result<Self> {
        Self::open_existing(
            route_root,
            effect_run_id,
            GenerationPhase::Sealed,
            Some((sealed_digest, route_count, present_route_count)),
        )
    }

    pub(super) fn open_existing_published(
        route_root: &Path,
        effect_run_id: Uuid,
        sealed_digest: &str,
        route_count: usize,
        present_route_count: usize,
    ) -> io::Result<Self> {
        Self::open_existing(
            route_root,
            effect_run_id,
            GenerationPhase::Published,
            Some((sealed_digest, route_count, present_route_count)),
        )
    }

    fn open_existing(
        route_root: &Path,
        effect_run_id: Uuid,
        phase: GenerationPhase,
        seal: Option<(&str, usize, usize)>,
    ) -> io::Result<Self> {
        let root = open_directory(route_root)?;
        validate_directory(&root, ROUTE_ROOT_MODE, "route root")?;
        let generations = open_at_directory(&root, &cstring(GENERATIONS_DIRECTORY)?)?;
        validate_directory(
            &generations,
            GENERATIONS_MODE,
            "route generations directory",
        )?;
        ensure_same_filesystem(&root, &generations)?;
        let name = StartupGenerationName::for_effect(effect_run_id);
        let directory = open_at_directory(&generations, &cstring(name.as_str())?)?;
        let expected_mode = if phase == GenerationPhase::Staging {
            STAGING_MODE
        } else {
            SEALED_MODE
        };
        validate_directory(&directory, expected_mode, "startup generation")?;
        ensure_same_filesystem(&generations, &directory)?;
        let metadata = directory.metadata()?;
        let sealed = match seal {
            Some((sealed_digest, route_count, present_route_count)) => {
                validate_digest(sealed_digest, "startup sealed digest")?;
                if present_route_count > route_count {
                    return Err(invalid_input(
                        "present startup route count exceeds total route count",
                    ));
                }
                Some(SealedStartupGeneration {
                    name: name.clone(),
                    identity: GatewayGenerationIdentity {
                        effect_run_id,
                        sealed_digest: sealed_digest.to_owned(),
                    },
                    route_count,
                    sealed_digest: sealed_digest.to_owned(),
                    present_route_count,
                })
            }
            None => None,
        };
        let generation = Self {
            root_path: route_root.to_owned(),
            root,
            generations,
            directory,
            directory_dev: metadata.dev(),
            directory_ino: metadata.ino(),
            effect_run_id,
            name,
            phase,
            sealed,
        };
        generation.validate_named_directory(expected_mode)?;
        if phase == GenerationPhase::Staging {
            generation.refuse_if_selected()?;
            inspect_generation_entries(&generation.directory, false, false)?;
        } else {
            generation.verify_sealed_bytes()?;
        }
        Ok(generation)
    }

    #[cfg(test)]
    fn path(&self) -> PathBuf {
        self.root_path
            .join(GENERATIONS_DIRECTORY)
            .join(self.name.as_str())
    }

    /// Write one immutable pre-publication route. The direct-child filename is
    /// derived solely from the workshop UUID and is opened create-only.
    pub(super) fn write_route(
        &mut self,
        workshop_id: Uuid,
        projection_generation: i64,
        projection_digest: &str,
        contents: &[u8],
    ) -> io::Result<StartupRouteSealEvidence> {
        if self.phase != GenerationPhase::Staging {
            return Err(invalid_state("routes may only be written while staging"));
        }
        self.validate_named_directory(STAGING_MODE)?;
        validate_digest(projection_digest, "projection digest")?;
        if projection_generation <= 0 {
            return Err(invalid_input("projection generation must be positive"));
        }
        validate_route_bytes(contents)?;

        let file_name = format!("{workshop_id}.conf");
        let name = cstring(&file_name)?;
        let mut file = create_at_file(&self.directory, &name, FILE_MODE)?;
        let result = (|| {
            file.write_all(contents)?;
            file.sync_all()?;
            file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
            validate_regular_file(&file, FILE_MODE, "staged route")?;
            self.directory.sync_all()
        })();
        if let Err(error) = result {
            let _ = unlink_at(&self.directory, &name, false);
            return Err(error);
        }

        Ok(present_evidence(
            workshop_id,
            projection_generation,
            projection_digest,
            contents,
        ))
    }

    /// Record a reserved workshop whose canonical candidate is file absence.
    /// It participates in the sealed set with the SHA-256 digest of empty bytes
    /// but deliberately creates no filesystem child.
    pub(super) fn record_absent(
        &mut self,
        workshop_id: Uuid,
        projection_generation: i64,
        projection_digest: &str,
    ) -> io::Result<StartupRouteSealEvidence> {
        if self.phase != GenerationPhase::Staging {
            return Err(invalid_state("routes may only be recorded while staging"));
        }
        self.validate_named_directory(STAGING_MODE)?;
        validate_digest(projection_digest, "projection digest")?;
        if projection_generation <= 0 {
            return Err(invalid_input("projection generation must be positive"));
        }
        let evidence = StartupRouteSealEvidence {
            workshop_id,
            projection_generation,
            projection_digest: projection_digest.to_owned(),
            disposition: "absent".to_owned(),
            action: "remove-absent".to_owned(),
            rendered_digest: digest_bytes(&[]),
        };
        Ok(evidence)
    }

    /// Begin an O(1)-memory seal. The caller streams database-owned evidence in
    /// strict workshop order with `record`; no fleet-sized Rust collection is
    /// accepted or retained by this API. The v1 digest preimage is the literal
    /// domain `mb-startup-route-generation-v1\0`, followed for each row by its
    /// 16 UUID bytes, signed i64 generation in big-endian order, then the
    /// projection digest, disposition, action, and rendered digest. Each text
    /// field is prefixed by an unsigned big-endian u32 byte length.
    pub(super) fn begin_seal(&mut self) -> io::Result<StartupGenerationSealer<'_>> {
        if self.phase != GenerationPhase::Staging {
            return Err(invalid_state("startup generation is not staging"));
        }
        self.validate_named_directory(STAGING_MODE)?;
        let mut hasher = Sha256::new();
        hasher.update(b"mb-startup-route-generation-v1\0");
        Ok(StartupGenerationSealer {
            generation: self,
            hasher,
            previous_workshop: None,
            route_count: 0,
            present_route_count: 0,
        })
    }

    fn finish_seal(
        &mut self,
        hasher: Sha256,
        route_count: usize,
        present_route_count: usize,
    ) -> io::Result<&SealedStartupGeneration> {
        let entries = inspect_generation_entries(&self.directory, false, false)?;
        if entries.route_count != present_route_count || entries.identity_present {
            return Err(invalid_state(
                "startup staging directory does not match streamed evidence",
            ));
        }
        let sealed_digest = format!("sha256:{:x}", hasher.finalize());
        let identity = GatewayGenerationIdentity {
            effect_run_id: self.effect_run_id,
            sealed_digest: sealed_digest.clone(),
        };
        let snippet =
            gateway_generation_config(&identity).map_err(|error| io::Error::other(error.1))?;
        validate_route_bytes(snippet.as_bytes())?;
        let identity_name = cstring(STARTUP_GATEWAY_GENERATION_FILE)?;
        let mut file = create_at_file(&self.directory, &identity_name, FILE_MODE)?;
        let result = (|| {
            file.write_all(snippet.as_bytes())?;
            file.sync_all()?;
            file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
            validate_regular_file(&file, FILE_MODE, "generation identity")?;
            self.directory.sync_all()
        })();
        if let Err(error) = result {
            let _ = unlink_at(&self.directory, &identity_name, false);
            return Err(error);
        }

        let entries = inspect_generation_entries(&self.directory, true, false)?;
        if entries.route_count != present_route_count
            || !entries.identity_present
            || entries.publication_marker_present
        {
            return Err(invalid_state("startup generation changed while sealing"));
        }
        self.verify_identity_bytes(snippet.as_bytes())?;
        self.directory
            .set_permissions(std::fs::Permissions::from_mode(SEALED_MODE))?;
        validate_directory(&self.directory, SEALED_MODE, "sealed startup generation")?;
        self.directory.sync_all()?;
        self.generations.sync_all()?;
        self.validate_named_directory(SEALED_MODE)?;

        self.phase = GenerationPhase::Sealed;
        self.sealed = Some(SealedStartupGeneration {
            name: self.name.clone(),
            identity,
            route_count,
            sealed_digest,
            present_route_count,
        });
        Ok(self
            .sealed
            .as_ref()
            .expect("sealed generation was assigned"))
    }

    /// Atomically exchange `current` with a deterministic candidate symlink.
    /// After the exchange, the same staging name contains the selector that was
    /// current at the instant of publication; that is the authoritative prior
    /// selector captured for reconciliation.
    pub(super) fn publish(&mut self, expected_prior: &PriorSelector) -> io::Result<PriorSelector> {
        self.publish_with_pre_exchange(expected_prior, || Ok(()))
    }

    fn publish_with_pre_exchange(
        &mut self,
        expected_prior: &PriorSelector,
        before_exchange: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<PriorSelector> {
        if self.phase != GenerationPhase::Sealed {
            return Err(invalid_state("only a sealed generation may be published"));
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
        // Creating the durable marker is the local publication-start boundary.
        // Even if selector exchange is never attempted, cleanup is no longer
        // allowed to treat this candidate as disposable staging.
        self.phase = GenerationPhase::Published;
        before_exchange()?;
        let exchange_name = format!(".current-prior-{}", self.effect_run_id);
        let exchange = cstring(&exchange_name)?;
        let current = cstring(CURRENT_SELECTOR)?;
        let target = cstring(&candidate_target)?;
        symlink_at(&target, &self.root, &exchange)?;
        if let Err(error) = self.root.sync_all() {
            let _ = unlink_at(&self.root, &exchange, false);
            return Err(error);
        }

        if let Err(error) = rename_exchange(&self.root, &exchange, &current) {
            let _ = unlink_at(&self.root, &exchange, false);
            return Err(error);
        }
        // Publication has physically happened. No later error may make this
        // object eligible for pre-publication disposal.
        self.root.sync_all()?;

        let prior_target = read_link_at(&self.root, &exchange)?;
        let captured_prior = observe_selector_target(&self.generations, prior_target)?;
        if &captured_prior != expected_prior {
            return Err(invalid_state(
                "selector changed after prior observation and before publication",
            ));
        }
        self.observe_selected()?;
        unlink_at(&self.root, &exchange, false)?;
        self.root.sync_all()?;
        Ok(captured_prior)
    }

    /// Observe both the exact selector target and the exact sealed bytes. A
    /// second selector read closes the observation window against replacement.
    pub(super) fn observe_selected(&self) -> io::Result<&SealedStartupGeneration> {
        if self.phase != GenerationPhase::Published {
            return Err(invalid_state("startup generation has not been published"));
        }
        let expected = self.name.selector_target();
        validate_current_selector(&self.root, &expected)?;
        self.validate_named_directory(SEALED_MODE)?;
        self.verify_sealed_bytes()?;
        validate_current_selector(&self.root, &expected)?;
        Ok(self
            .sealed
            .as_ref()
            .expect("published generation must retain its seal"))
    }

    /// Restore a database-recorded prior selector through the same atomic
    /// boundary. This never makes the candidate disposable: only higher-level
    /// reconciliation can establish whether Nginx ever loaded it.
    pub(super) fn restore_prior(&mut self, prior: &PriorSelector) -> io::Result<()> {
        if self.phase != GenerationPhase::Published {
            return Err(invalid_state(
                "only a published generation may restore its prior",
            ));
        }
        self.observe_selected()?;
        let observed_prior = observe_selector_target(&self.generations, prior.target().to_owned())?;
        if &observed_prior != prior {
            return Err(invalid_state(
                "recorded prior selector directory identity changed",
            ));
        }
        let exchange_name = format!(".current-restore-{}", self.effect_run_id);
        let exchange = cstring(&exchange_name)?;
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
        let captured_candidate = read_link_at(&self.root, &exchange)?;
        if captured_candidate != self.name.selector_target() {
            return Err(invalid_state("selector changed before prior restoration"));
        }
        let restored = observe_selector_from_handles(&self.root, &self.generations)?;
        if &restored != prior {
            return Err(invalid_state(
                "restored selector does not match recorded prior",
            ));
        }
        unlink_at(&self.root, &exchange, false)?;
        self.root.sync_all()
    }

    /// Dispose only a generation that has never crossed the selector boundary.
    /// Every direct child must be one this object created and must still be a
    /// safe regular file. There is intentionally no recursive deletion.
    pub(super) fn dispose(mut self) -> io::Result<()> {
        if self.phase == GenerationPhase::Published {
            return Err(invalid_state("a published generation cannot be disposed"));
        }
        self.refuse_if_selected()?;
        let expected_mode = if self.phase == GenerationPhase::Sealed {
            SEALED_MODE
        } else {
            STAGING_MODE
        };
        self.validate_named_directory(expected_mode)?;
        inspect_generation_entries(
            &self.directory,
            self.phase == GenerationPhase::Sealed,
            false,
        )?;
        dispose_generation_entries(&self.directory, self.phase == GenerationPhase::Sealed)?;
        if inspect_generation_entries(&self.directory, false, false)?.route_count != 0 {
            return Err(invalid_state("startup generation disposal was incomplete"));
        }
        self.directory.sync_all()?;
        self.validate_named_directory(expected_mode)?;
        unlink_at(&self.generations, &cstring(self.name.as_str())?, true)?;
        self.generations.sync_all()?;
        self.phase = GenerationPhase::Published; // prevents accidental future cleanup semantics
        Ok(())
    }

    fn refuse_if_selected(&self) -> io::Result<()> {
        match read_link_at(&self.root, &cstring(CURRENT_SELECTOR)?) {
            Ok(target) if target == self.name.selector_target() => Err(invalid_state(
                "selected startup generation is not disposable",
            )),
            Ok(target) => validate_selector_target(&target),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn validate_named_directory(&self, mode: u32) -> io::Result<()> {
        validate_directory(&self.directory, mode, "startup generation")?;
        let named = open_at_directory(&self.generations, &cstring(self.name.as_str())?)?;
        validate_directory(&named, mode, "named startup generation")?;
        let metadata = named.metadata()?;
        if metadata.dev() != self.directory_dev || metadata.ino() != self.directory_ino {
            return Err(invalid_state("startup generation path identity changed"));
        }
        Ok(())
    }

    fn verify_identity_bytes(&self, expected_snippet: &[u8]) -> io::Result<()> {
        let file = open_at_file(&self.directory, &cstring(STARTUP_GATEWAY_GENERATION_FILE)?)?;
        validate_regular_file(&file, FILE_MODE, "generation identity")?;
        if read_bounded(file, MAX_ROUTE_BYTES)? != expected_snippet {
            return Err(invalid_state("generation identity bytes changed"));
        }
        Ok(())
    }

    fn publication_marker_bytes(&self) -> io::Result<Vec<u8>> {
        let sealed = self
            .sealed
            .as_ref()
            .ok_or_else(|| invalid_state("startup generation has no seal"))?;
        Ok(format!(
            "protocol=1\neffect_run_id={}\nsealed_digest={}\n",
            self.effect_run_id, sealed.sealed_digest
        )
        .into_bytes())
    }

    fn install_publication_marker(&self) -> io::Result<()> {
        let bytes = self.publication_marker_bytes()?;
        let name = cstring(PUBLICATION_MARKER_FILE)?;
        let mut file = create_at_file(&self.directory, &name, FILE_MODE)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))?;
            validate_regular_file(&file, FILE_MODE, "startup publication marker")?;
            self.directory.sync_all()
        })();
        if let Err(error) = result {
            let _ = unlink_at(&self.directory, &name, false);
            return Err(error);
        }
        Ok(())
    }

    fn verify_publication_marker(&self) -> io::Result<()> {
        let file = open_at_file(&self.directory, &cstring(PUBLICATION_MARKER_FILE)?)?;
        validate_regular_file(&file, FILE_MODE, "startup publication marker")?;
        if read_bounded(file, MAX_ROUTE_BYTES)? != self.publication_marker_bytes()? {
            return Err(invalid_state("startup publication marker bytes changed"));
        }
        Ok(())
    }

    fn verify_sealed_bytes(&self) -> io::Result<()> {
        let sealed = self
            .sealed
            .as_ref()
            .ok_or_else(|| invalid_state("startup generation has no seal"))?;
        let snippet = gateway_generation_config(&sealed.identity)
            .map_err(|error| io::Error::other(error.1))?;
        self.verify_identity_bytes(snippet.as_bytes())?;
        let publication_started = self.phase == GenerationPhase::Published;
        let entries = inspect_generation_entries(&self.directory, true, publication_started)?;
        if entries.route_count != sealed.present_route_count
            || !entries.identity_present
            || entries.publication_marker_present != publication_started
        {
            return Err(invalid_state(
                "sealed startup generation membership changed",
            ));
        }
        if publication_started {
            self.verify_publication_marker()?;
        }
        Ok(())
    }
}

impl<'a> StartupGenerationSealer<'a> {
    /// Stage one present candidate and immediately fold its exact evidence into
    /// the streaming seal. An interrupted prior attempt is reusable only when
    /// the existing direct-child file passes every safety check and has exactly
    /// the same bytes; a conflicting or substituted entry fails closed.
    pub(super) fn stage_present(
        &mut self,
        workshop_id: Uuid,
        projection_generation: i64,
        projection_digest: &str,
        contents: &[u8],
    ) -> io::Result<StartupRouteSealEvidence> {
        self.validate_next(workshop_id)?;
        let evidence = match self.generation.write_route(
            workshop_id,
            projection_generation,
            projection_digest,
            contents,
        ) {
            Ok(evidence) => evidence,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                validate_digest(projection_digest, "projection digest")?;
                if projection_generation <= 0 {
                    return Err(invalid_input("projection generation must be positive"));
                }
                validate_route_bytes(contents)?;
                present_evidence(
                    workshop_id,
                    projection_generation,
                    projection_digest,
                    contents,
                )
            }
            Err(error) => return Err(error),
        };
        self.record(&evidence)?;
        Ok(evidence)
    }

    /// Record an absent candidate and immediately fold its canonical empty-byte
    /// evidence into the streaming seal without creating a filesystem child.
    pub(super) fn stage_absent(
        &mut self,
        workshop_id: Uuid,
        projection_generation: i64,
        projection_digest: &str,
    ) -> io::Result<StartupRouteSealEvidence> {
        self.validate_next(workshop_id)?;
        let evidence =
            self.generation
                .record_absent(workshop_id, projection_generation, projection_digest)?;
        self.record(&evidence)?;
        Ok(evidence)
    }

    /// Verify one exact staged row and add it to the deterministic seal. Calls
    /// must follow the database keyset order; duplicate or descending UUIDs are
    /// rejected without retaining earlier rows.
    pub(super) fn record(&mut self, evidence: &StartupRouteSealEvidence) -> io::Result<()> {
        validate_evidence(evidence)?;
        self.validate_next(evidence.workshop_id)?;
        let file_name = cstring(format!("{}.conf", evidence.workshop_id))?;
        match (evidence.disposition.as_str(), evidence.action.as_str()) {
            ("present", "render") => {
                let file = open_at_file(&self.generation.directory, &file_name)?;
                validate_regular_file(&file, FILE_MODE, "staged route")?;
                let bytes = read_bounded(file, MAX_ROUTE_BYTES)?;
                validate_route_bytes(&bytes)?;
                if digest_bytes(&bytes) != evidence.rendered_digest {
                    return Err(invalid_state(
                        "staged route bytes differ from candidate evidence",
                    ));
                }
                self.present_route_count = self
                    .present_route_count
                    .checked_add(1)
                    .ok_or_else(|| invalid_input("startup route count overflowed"))?;
            }
            ("absent", "remove-absent") => {
                if evidence.rendered_digest != digest_bytes(&[]) {
                    return Err(invalid_input(
                        "absent startup route must use the canonical empty digest",
                    ));
                }
                match open_at_file(&self.generation.directory, &file_name) {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Ok(_) => return Err(invalid_state("absent startup route has staged bytes")),
                    Err(error) => return Err(error),
                }
            }
            _ => return Err(invalid_input("startup route disposition/action is invalid")),
        }

        self.hasher.update(evidence.workshop_id.as_bytes());
        self.hasher
            .update(evidence.projection_generation.to_be_bytes());
        update_digest_field(&mut self.hasher, evidence.projection_digest.as_bytes())?;
        update_digest_field(&mut self.hasher, evidence.disposition.as_bytes())?;
        update_digest_field(&mut self.hasher, evidence.action.as_bytes())?;
        update_digest_field(&mut self.hasher, evidence.rendered_digest.as_bytes())?;
        self.previous_workshop = Some(evidence.workshop_id);
        self.route_count = self
            .route_count
            .checked_add(1)
            .ok_or_else(|| invalid_input("startup route count overflowed"))?;
        Ok(())
    }

    fn validate_next(&self, workshop_id: Uuid) -> io::Result<()> {
        if self
            .previous_workshop
            .is_some_and(|previous| previous >= workshop_id)
        {
            return Err(invalid_input(
                "startup seal evidence must be strictly workshop ordered",
            ));
        }
        Ok(())
    }

    pub(super) fn finish(self) -> io::Result<&'a SealedStartupGeneration> {
        self.generation
            .finish_seal(self.hasher, self.route_count, self.present_route_count)
    }
}

fn present_evidence(
    workshop_id: Uuid,
    projection_generation: i64,
    projection_digest: &str,
    contents: &[u8],
) -> StartupRouteSealEvidence {
    StartupRouteSealEvidence {
        workshop_id,
        projection_generation,
        projection_digest: projection_digest.to_owned(),
        disposition: "present".to_owned(),
        action: "render".to_owned(),
        rendered_digest: digest_bytes(contents),
    }
}

fn validate_evidence(evidence: &StartupRouteSealEvidence) -> io::Result<()> {
    if evidence.projection_generation <= 0 {
        return Err(invalid_input("projection generation must be positive"));
    }
    validate_digest(&evidence.projection_digest, "projection digest")?;
    validate_digest(&evidence.rendered_digest, "rendered digest")
}

fn update_digest_field(hasher: &mut Sha256, value: &[u8]) -> io::Result<()> {
    let length = u32::try_from(value.len())
        .map_err(|_| invalid_input("startup seal field exceeds its bound"))?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

#[derive(Default)]
struct GenerationEntries {
    route_count: usize,
    identity_present: bool,
    publication_marker_present: bool,
}

fn inspect_generation_entries(
    directory: &File,
    identity_allowed: bool,
    publication_marker_allowed: bool,
) -> io::Result<GenerationEntries> {
    let mut result = GenerationEntries::default();
    visit_generation_entries(directory, |name| {
        let c_name = cstring(name)?;
        let file = open_at_file(directory, &c_name)?;
        validate_regular_file(&file, FILE_MODE, "startup generation child")?;
        if name == STARTUP_GATEWAY_GENERATION_FILE {
            if !identity_allowed || result.identity_present {
                return Err(invalid_state(
                    "startup generation has an unexpected identity file",
                ));
            }
            result.identity_present = true;
        } else if name == PUBLICATION_MARKER_FILE {
            if !publication_marker_allowed || result.publication_marker_present {
                return Err(invalid_state(
                    "startup generation has an unexpected publication marker",
                ));
            }
            result.publication_marker_present = true;
        } else if name
            .strip_suffix(".conf")
            .is_some_and(|stem| Uuid::parse_str(stem).is_ok())
        {
            result.route_count = result
                .route_count
                .checked_add(1)
                .ok_or_else(|| invalid_state("startup generation route count overflowed"))?;
        } else {
            return Err(invalid_state(
                "startup generation contains an unexpected entry",
            ));
        }
        Ok(())
    })?;
    Ok(result)
}

fn dispose_generation_entries(directory: &File, identity_allowed: bool) -> io::Result<()> {
    visit_generation_entries(directory, |name| {
        let valid = name
            .strip_suffix(".conf")
            .is_some_and(|stem| Uuid::parse_str(stem).is_ok())
            || (identity_allowed && name == STARTUP_GATEWAY_GENERATION_FILE);
        if !valid {
            return Err(invalid_state(
                "startup generation contains an unowned entry",
            ));
        }
        let c_name = cstring(name)?;
        let file = open_at_file(directory, &c_name)?;
        validate_regular_file(&file, FILE_MODE, "startup generation child")?;
        unlink_at(directory, &c_name, false)
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
                std::env::temp_dir().join(format!("mb-startup-generation-{}", Uuid::new_v4()));
            DirBuilder::new()
                .mode(ROUTE_ROOT_MODE)
                .create(&path)
                .unwrap();
            Self(path)
        }

        fn install_current(&self, name: &str) {
            std::fs::create_dir_all(self.0.join(GENERATIONS_DIRECTORY).join(name)).unwrap();
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

    fn projection(marker: char) -> String {
        format!("sha256:{}", marker.to_string().repeat(64))
    }

    fn sorted_workshops() -> [Uuid; 2] {
        [
            Uuid::parse_str("10000000-0000-0000-0000-000000000001").unwrap(),
            Uuid::parse_str("20000000-0000-0000-0000-000000000002").unwrap(),
        ]
    }

    fn seal_generation(
        generation: &mut StartupGenerationDirectory,
        evidence: &[StartupRouteSealEvidence],
    ) -> io::Result<SealedStartupGeneration> {
        let mut sealer = generation.begin_seal()?;
        for row in evidence {
            sealer.record(row)?;
        }
        sealer.finish().cloned()
    }

    #[test]
    fn stages_seals_publishes_and_captures_the_exact_prior_selector() {
        let root = TestRoot::new();
        let effect = Uuid::new_v4();
        let mut generation = StartupGenerationDirectory::create(&root.0, effect).unwrap();
        root.install_current("boot-live");
        let expected_prior = observe_current_selector(&root.0).unwrap();
        assert_eq!(
            observe_prior_gateway_identity(&root.0, &expected_prior).unwrap(),
            None
        );
        let workshops = sorted_workshops();
        let first = generation
            .write_route(
                workshops[0],
                7,
                &projection('a'),
                b"server { return 204; }\n",
            )
            .unwrap();
        let second = generation
            .write_route(
                workshops[1],
                9,
                &projection('b'),
                b"server { return 404; }\n",
            )
            .unwrap();
        let seal = seal_generation(&mut generation, &[first, second]).unwrap();
        assert_eq!(seal.route_count, 2);
        assert_eq!(seal.identity.effect_run_id, effect);
        assert_eq!(seal.identity.sealed_digest, seal.sealed_digest);

        let prior = generation.publish(&expected_prior).unwrap();
        assert_eq!(prior.target(), "generations/boot-live");
        assert_eq!(
            std::fs::read_link(root.0.join(CURRENT_SELECTOR)).unwrap(),
            PathBuf::from(format!("generations/startup-{effect}"))
        );
        assert_eq!(generation.observe_selected().unwrap().route_count, 2);
        let selected_candidate = observe_current_selector(&root.0).unwrap();
        assert_eq!(
            observe_prior_gateway_identity(&root.0, &selected_candidate)
                .unwrap()
                .unwrap(),
            seal.identity
        );
        drop(generation);

        let mut reopened = StartupGenerationDirectory::open_existing_published(
            &root.0,
            effect,
            &seal.sealed_digest,
            seal.route_count,
            seal.present_route_count,
        )
        .unwrap();
        reopened.observe_selected().unwrap();
        reopened.restore_prior(&prior).unwrap();
        assert_eq!(
            std::fs::read_link(root.0.join(CURRENT_SELECTOR)).unwrap(),
            PathBuf::from("generations/boot-live")
        );
        assert!(reopened.dispose().is_err());
    }

    #[test]
    fn interrupted_prepublication_generations_can_be_reopened_and_safely_disposed() {
        let root = TestRoot::new();
        let effect = Uuid::new_v4();
        let mut generation = StartupGenerationDirectory::create(&root.0, effect).unwrap();
        let evidence = generation
            .write_route(
                sorted_workshops()[0],
                1,
                &projection('a'),
                b"server { return 204; }\n",
            )
            .unwrap();
        let seal = seal_generation(&mut generation, &[evidence]).unwrap();
        drop(generation);
        let reopened = StartupGenerationDirectory::open_existing_sealed(
            &root.0,
            effect,
            &seal.sealed_digest,
            seal.route_count,
            seal.present_route_count,
        )
        .unwrap();
        reopened.dispose().unwrap();
        assert!(
            !root
                .0
                .join(GENERATIONS_DIRECTORY)
                .join(format!("startup-{effect}"))
                .exists()
        );

        let staging_effect = Uuid::new_v4();
        let staging = StartupGenerationDirectory::create(&root.0, staging_effect).unwrap();
        drop(staging);
        StartupGenerationDirectory::open_existing_staging(&root.0, staging_effect)
            .unwrap()
            .dispose()
            .unwrap();
    }

    #[test]
    fn database_staging_claim_can_dispose_a_filesystem_seal_without_guessing_its_seal() {
        let root = TestRoot::new();
        let effect = Uuid::new_v4();
        let mut generation = StartupGenerationDirectory::create(&root.0, effect).unwrap();
        root.install_current("boot-live");
        let evidence = generation
            .write_route(
                sorted_workshops()[0],
                1,
                &projection('a'),
                b"server { return 204; }\n",
            )
            .unwrap();
        seal_generation(&mut generation, &[evidence]).unwrap();
        drop(generation);

        dispose_exact_unpublished_candidate(&root.0, effect).unwrap();
        assert!(
            !root
                .0
                .join(GENERATIONS_DIRECTORY)
                .join(format!("startup-{effect}"))
                .exists()
        );
        assert_eq!(
            observe_current_selector(&root.0).unwrap().target(),
            "generations/boot-live"
        );
    }

    #[test]
    fn unpublished_candidate_absence_is_distinct_from_unsafe_present_evidence() {
        let root = TestRoot::new();
        let existing = Uuid::new_v4();
        let generation = StartupGenerationDirectory::create(&root.0, existing).unwrap();
        root.install_current("boot-live");
        drop(generation);

        let missing = dispose_exact_unpublished_candidate(&root.0, Uuid::new_v4()).unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);

        let unsafe_file = root
            .0
            .join(GENERATIONS_DIRECTORY)
            .join(format!("startup-{existing}"))
            .join("foreign");
        std::fs::write(&unsafe_file, b"foreign").unwrap();
        std::fs::set_permissions(&unsafe_file, std::fs::Permissions::from_mode(FILE_MODE)).unwrap();
        let unsafe_present = dispose_exact_unpublished_candidate(&root.0, existing).unwrap_err();
        assert_ne!(unsafe_present.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn rejects_traversing_nested_absolute_and_symlinked_selectors() {
        for target in [
            "../outside",
            "generations/boot-live/nested",
            "/generations/boot-live",
            "generations/../outside",
        ] {
            let root = TestRoot::new();
            std::fs::create_dir_all(root.0.join(GENERATIONS_DIRECTORY)).unwrap();
            std::fs::set_permissions(
                root.0.join(GENERATIONS_DIRECTORY),
                std::fs::Permissions::from_mode(GENERATIONS_MODE),
            )
            .unwrap();
            symlink(target, root.0.join(CURRENT_SELECTOR)).unwrap();
            assert!(StartupGenerationDirectory::create(&root.0, Uuid::new_v4()).is_err());
        }

        let root = TestRoot::new();
        let outside = TestRoot::new();
        symlink(&outside.0, root.0.join(GENERATIONS_DIRECTORY)).unwrap();
        assert!(StartupGenerationDirectory::create(&root.0, Uuid::new_v4()).is_err());
    }

    #[test]
    fn rejects_directory_replacement_and_changed_route_bytes() {
        let root = TestRoot::new();
        let mut generation = StartupGenerationDirectory::create(&root.0, Uuid::new_v4()).unwrap();
        let workshop = sorted_workshops()[0];
        let evidence = generation
            .write_route(workshop, 1, &projection('c'), b"server { return 200; }\n")
            .unwrap();
        let route_path = generation.path().join(format!("{workshop}.conf"));
        std::fs::write(&route_path, b"server { return 500; }\n").unwrap();
        assert!(seal_generation(&mut generation, std::slice::from_ref(&evidence)).is_err());

        let root = TestRoot::new();
        let mut generation = StartupGenerationDirectory::create(&root.0, Uuid::new_v4()).unwrap();
        let original = generation.path();
        let displaced = original.with_extension("displaced");
        std::fs::rename(&original, &displaced).unwrap();
        DirBuilder::new()
            .mode(STAGING_MODE)
            .create(&original)
            .unwrap();
        assert!(
            generation
                .write_route(workshop, 1, &projection('d'), b"server { return 200; }\n")
                .is_err()
        );
    }

    #[test]
    fn seal_is_order_sensitive_and_binds_projection_and_rendered_evidence() {
        let root = TestRoot::new();
        let mut generation = StartupGenerationDirectory::create(&root.0, Uuid::new_v4()).unwrap();
        let workshops = sorted_workshops();
        let first = generation
            .write_route(
                workshops[0],
                1,
                &projection('a'),
                b"server { return 201; }\n",
            )
            .unwrap();
        let second = generation
            .write_route(
                workshops[1],
                2,
                &projection('b'),
                b"server { return 202; }\n",
            )
            .unwrap();
        assert!(seal_generation(&mut generation, &[second.clone(), first.clone()]).is_err());

        let mut invalid_action = first.clone();
        invalid_action.action = "remove-absent".to_owned();
        assert!(seal_generation(&mut generation, &[invalid_action, second.clone()]).is_err());
        let seal = seal_generation(&mut generation, &[first, second]).unwrap();

        let root_same = TestRoot::new();
        let mut same_generation =
            StartupGenerationDirectory::create(&root_same.0, Uuid::new_v4()).unwrap();
        let same_first = same_generation
            .write_route(
                workshops[0],
                1,
                &projection('a'),
                b"server { return 201; }\n",
            )
            .unwrap();
        let same_second = same_generation
            .write_route(
                workshops[1],
                2,
                &projection('b'),
                b"server { return 202; }\n",
            )
            .unwrap();
        let same = seal_generation(&mut same_generation, &[same_first, same_second]).unwrap();
        assert_eq!(seal.sealed_digest, same.sealed_digest);

        let root_changed = TestRoot::new();
        let mut changed_generation =
            StartupGenerationDirectory::create(&root_changed.0, Uuid::new_v4()).unwrap();
        let changed_first = changed_generation
            .write_route(
                workshops[0],
                1,
                &projection('e'),
                b"server { return 201; }\n",
            )
            .unwrap();
        let changed_second = changed_generation
            .write_route(
                workshops[1],
                2,
                &projection('b'),
                b"server { return 202; }\n",
            )
            .unwrap();
        let changed =
            seal_generation(&mut changed_generation, &[changed_first, changed_second]).unwrap();
        assert_ne!(seal.sealed_digest, changed.sealed_digest);
    }

    #[test]
    fn absent_routes_participate_in_the_seal_without_creating_files() {
        let root = TestRoot::new();
        let mut generation = StartupGenerationDirectory::create(&root.0, Uuid::new_v4()).unwrap();
        let workshops = sorted_workshops();
        let present = generation
            .write_route(
                workshops[0],
                1,
                &projection('a'),
                b"server { return 201; }\n",
            )
            .unwrap();
        let absent = generation
            .record_absent(workshops[1], 2, &projection('b'))
            .unwrap();
        assert_eq!(absent.rendered_digest, digest_bytes(&[]));
        let seal = seal_generation(&mut generation, &[present, absent]).unwrap();
        assert_eq!(seal.route_count, 2);
        let entries = inspect_generation_entries(&generation.directory, true, false).unwrap();
        assert_eq!(entries.route_count, 1);
        assert!(entries.identity_present);
    }

    #[test]
    fn sealer_stages_in_one_pass_and_only_reuses_exact_interrupted_bytes() {
        let workshops = sorted_workshops();
        let root = TestRoot::new();
        let mut generation = StartupGenerationDirectory::create(&root.0, Uuid::new_v4()).unwrap();
        // Simulate a crash after the filesystem write but before candidate CAS.
        generation
            .write_route(
                workshops[0],
                1,
                &projection('a'),
                b"server { return 201; }\n",
            )
            .unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        let present = sealer
            .stage_present(
                workshops[0],
                1,
                &projection('a'),
                b"server { return 201; }\n",
            )
            .unwrap();
        let absent = sealer
            .stage_absent(workshops[1], 2, &projection('b'))
            .unwrap();
        assert_eq!(
            (present.disposition.as_str(), present.action.as_str()),
            ("present", "render")
        );
        assert_eq!(
            (absent.disposition.as_str(), absent.action.as_str()),
            ("absent", "remove-absent")
        );
        assert_eq!(sealer.finish().unwrap().route_count, 2);

        let root = TestRoot::new();
        let mut generation = StartupGenerationDirectory::create(&root.0, Uuid::new_v4()).unwrap();
        generation
            .write_route(
                workshops[0],
                1,
                &projection('a'),
                b"server { return 201; }\n",
            )
            .unwrap();
        let mut sealer = generation.begin_seal().unwrap();
        assert!(
            sealer
                .stage_present(
                    workshops[0],
                    1,
                    &projection('a'),
                    b"server { return 500; }\n",
                )
                .is_err()
        );
    }

    #[test]
    fn rejects_symlink_hardlink_mode_and_unowned_disposal_entries() {
        let root = TestRoot::new();
        let mut generation = StartupGenerationDirectory::create(&root.0, Uuid::new_v4()).unwrap();
        let workshop = sorted_workshops()[0];
        let evidence = generation
            .write_route(workshop, 1, &projection('f'), b"server { return 203; }\n")
            .unwrap();
        let route = generation.path().join(format!("{workshop}.conf"));
        hard_link(&route, generation.path().join("unexpected-link")).unwrap();
        assert!(seal_generation(&mut generation, std::slice::from_ref(&evidence)).is_err());
        assert!(generation.dispose().is_err());

        let root = TestRoot::new();
        let mut generation = StartupGenerationDirectory::create(&root.0, Uuid::new_v4()).unwrap();
        let victim = root.0.join("victim");
        std::fs::write(&victim, b"server { return 204; }\n").unwrap();
        symlink(&victim, generation.path().join(format!("{workshop}.conf"))).unwrap();
        assert!(
            generation
                .write_route(workshop, 1, &projection('a'), b"server { return 204; }\n")
                .is_err()
        );

        let root = TestRoot::new();
        let generation = StartupGenerationDirectory::create(&root.0, Uuid::new_v4()).unwrap();
        std::fs::set_permissions(generation.path(), std::fs::Permissions::from_mode(0o750))
            .unwrap();
        assert!(generation.dispose().is_err());
    }

    #[test]
    fn bounded_create_only_writes_and_selector_races_fail_closed() {
        let root = TestRoot::new();
        let mut generation = StartupGenerationDirectory::create(&root.0, Uuid::new_v4()).unwrap();
        let workshop = sorted_workshops()[0];
        let oversized = vec![b'x'; MAX_ROUTE_BYTES + 1];
        assert!(
            generation
                .write_route(workshop, 1, &projection('a'), &oversized)
                .is_err()
        );
        generation
            .write_route(workshop, 1, &projection('a'), b"server { return 204; }\n")
            .unwrap();
        assert!(
            generation
                .write_route(workshop, 1, &projection('a'), b"server { return 205; }\n")
                .is_err()
        );

        let root = TestRoot::new();
        let effect = Uuid::new_v4();
        let mut generation = StartupGenerationDirectory::create(&root.0, effect).unwrap();
        root.install_current("boot-live");
        let expected_prior = observe_current_selector(&root.0).unwrap();
        seal_generation(&mut generation, &[]).unwrap();
        std::fs::remove_file(root.0.join(CURRENT_SELECTOR)).unwrap();
        std::fs::write(root.0.join(CURRENT_SELECTOR), b"not a selector").unwrap();
        assert!(generation.publish(&expected_prior).is_err());
        assert_ne!(generation.phase, GenerationPhase::Published);

        let root = TestRoot::new();
        let effect = Uuid::new_v4();
        let mut generation = StartupGenerationDirectory::create(&root.0, effect).unwrap();
        root.install_current("boot-live");
        std::fs::create_dir(root.0.join(GENERATIONS_DIRECTORY).join("raced-live")).unwrap();
        std::fs::set_permissions(
            root.0.join(GENERATIONS_DIRECTORY).join("raced-live"),
            std::fs::Permissions::from_mode(SEALED_MODE),
        )
        .unwrap();
        let expected_prior = observe_current_selector(&root.0).unwrap();
        seal_generation(&mut generation, &[]).unwrap();
        let selector = root.0.join(CURRENT_SELECTOR);
        assert!(
            generation
                .publish_with_pre_exchange(&expected_prior, || {
                    std::fs::remove_file(&selector)?;
                    symlink("generations/raced-live", &selector)
                })
                .is_err()
        );
        assert_eq!(generation.phase, GenerationPhase::Published);
        assert_eq!(
            std::fs::read_link(&selector).unwrap(),
            PathBuf::from(format!("generations/startup-{effect}"))
        );
        assert!(generation.dispose().is_err());
    }

    #[test]
    fn publication_start_is_never_disposable_and_post_exchange_membership_is_exact() {
        let root = TestRoot::new();
        let effect = Uuid::new_v4();
        let mut generation = StartupGenerationDirectory::create(&root.0, effect).unwrap();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        let seal = seal_generation(&mut generation, &[]).unwrap();
        assert!(
            generation
                .publish_with_pre_exchange(&prior, || Err(invalid_state("injected stop")))
                .is_err()
        );
        assert_eq!(generation.phase, GenerationPhase::Published);
        assert!(generation.dispose().is_err());
        assert!(
            StartupGenerationDirectory::open_existing_sealed(
                &root.0,
                effect,
                &seal.sealed_digest,
                0,
                0,
            )
            .is_err()
        );
        StartupGenerationDirectory::open_existing_published(
            &root.0,
            effect,
            &seal.sealed_digest,
            0,
            0,
        )
        .unwrap();

        let root = TestRoot::new();
        let effect = Uuid::new_v4();
        let mut generation = StartupGenerationDirectory::create(&root.0, effect).unwrap();
        root.install_current("boot-live");
        let prior = observe_current_selector(&root.0).unwrap();
        seal_generation(&mut generation, &[]).unwrap();
        generation.publish(&prior).unwrap();
        let injected = generation
            .path()
            .join(format!("{}.conf", sorted_workshops()[0]));
        std::fs::write(&injected, b"server { return 500; }\n").unwrap();
        std::fs::set_permissions(&injected, std::fs::Permissions::from_mode(FILE_MODE)).unwrap();
        assert!(generation.observe_selected().is_err());
    }
}
