#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::RwLock;

use rs_console_policy::{
    GatewayAcknowledgement, GatewayId, GatewayStateReport, ManifestDigest, PeerDelivery,
    PeerManifest, PolicyError,
};
use thiserror::Error;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum StoreError {
    #[error("gateway state store is unavailable")]
    Unavailable,
}

pub trait GatewayStateStore: Send + Sync {
    fn desired_manifest(&self, gateway_id: &GatewayId) -> Result<Option<PeerManifest>, StoreError>;

    fn record_applied(
        &self,
        gateway_id: &GatewayId,
        manifest: &PeerManifest,
        digest: &ManifestDigest,
    ) -> Result<(), StoreError>;
}

#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum SyncError {
    #[error("gateway state report is unsupported or malformed")]
    InvalidReport,
    #[error("gateway has no assigned desired state")]
    UnconfiguredGateway,
    #[error("gateway reports a generation newer than console desired state")]
    GatewayAhead,
    #[error("gateway reports the desired generation with a conflicting digest")]
    AppliedConflict,
    #[error("gateway acknowledgement does not match the exact desired delivery")]
    AcknowledgementMismatch,
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

pub struct GatewaySyncService<S> {
    store: S,
}

impl<S> GatewaySyncService<S>
where
    S: GatewayStateStore,
{
    #[must_use]
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn poll(&self, report: &GatewayStateReport) -> Result<Option<PeerDelivery>, SyncError> {
        if !report.is_supported() {
            return Err(SyncError::InvalidReport);
        }
        let desired = self
            .store
            .desired_manifest(report.gateway_id())?
            .ok_or(SyncError::UnconfiguredGateway)?;
        let desired_digest = desired.digest()?;

        let Some(applied) = report.wg_users() else {
            return PeerDelivery::new(report.gateway_id().clone(), desired)
                .map(Some)
                .map_err(Into::into);
        };

        match applied.generation().cmp(&desired.generation()) {
            std::cmp::Ordering::Less => PeerDelivery::new(report.gateway_id().clone(), desired)
                .map(Some)
                .map_err(Into::into),
            std::cmp::Ordering::Greater => Err(SyncError::GatewayAhead),
            std::cmp::Ordering::Equal if applied.manifest_digest() == &desired_digest => Ok(None),
            std::cmp::Ordering::Equal => Err(SyncError::AppliedConflict),
        }
    }

    pub fn acknowledge(&self, acknowledgement: &GatewayAcknowledgement) -> Result<(), SyncError> {
        let desired = self
            .store
            .desired_manifest(acknowledgement.gateway_id())?
            .ok_or(SyncError::UnconfiguredGateway)?;
        let delivery = PeerDelivery::new(acknowledgement.gateway_id().clone(), desired.clone())?;
        if !acknowledgement.matches(&delivery) {
            return Err(SyncError::AcknowledgementMismatch);
        }
        self.store.record_applied(
            acknowledgement.gateway_id(),
            &desired,
            delivery.manifest_digest(),
        )?;
        Ok(())
    }
}

#[derive(Default)]
pub struct InMemoryGatewayStateStore {
    desired: RwLock<HashMap<GatewayId, PeerManifest>>,
    applied: RwLock<HashMap<GatewayId, (PeerManifest, ManifestDigest)>>,
}

impl InMemoryGatewayStateStore {
    pub fn set_desired(
        &self,
        gateway_id: GatewayId,
        manifest: PeerManifest,
    ) -> Result<(), StoreError> {
        self.desired
            .write()
            .map_err(|_| StoreError::Unavailable)?
            .insert(gateway_id, manifest);
        Ok(())
    }

    pub fn applied(
        &self,
        gateway_id: &GatewayId,
    ) -> Result<Option<(PeerManifest, ManifestDigest)>, StoreError> {
        Ok(self
            .applied
            .read()
            .map_err(|_| StoreError::Unavailable)?
            .get(gateway_id)
            .cloned())
    }
}

impl GatewayStateStore for InMemoryGatewayStateStore {
    fn desired_manifest(&self, gateway_id: &GatewayId) -> Result<Option<PeerManifest>, StoreError> {
        Ok(self
            .desired
            .read()
            .map_err(|_| StoreError::Unavailable)?
            .get(gateway_id)
            .cloned())
    }

    fn record_applied(
        &self,
        gateway_id: &GatewayId,
        manifest: &PeerManifest,
        digest: &ManifestDigest,
    ) -> Result<(), StoreError> {
        self.applied
            .write()
            .map_err(|_| StoreError::Unavailable)?
            .insert(gateway_id.clone(), (manifest.clone(), digest.clone()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use rs_console_policy::{
        AppliedInterface, Generation, PeerId, UserId, VpnPolicy, WireGuardPublicKey,
    };

    use super::*;

    fn gateway_id() -> GatewayId {
        GatewayId::new("gateway-1").expect("valid ID")
    }

    fn desired_manifest() -> PeerManifest {
        let mut policy = VpnPolicy::default();
        policy
            .enroll(
                UserId::new("user-1").expect("valid ID"),
                PeerId::new("peer-1").expect("valid ID"),
                WireGuardPublicKey::new(STANDARD.encode([1_u8; 32])).expect("valid key"),
                false,
            )
            .expect("peer enrolls");
        policy
            .manifest("2026-08-01T20:00:00Z")
            .expect("manifest builds")
    }

    #[test]
    fn missing_or_stale_applied_state_receives_the_complete_manifest() {
        let store = InMemoryGatewayStateStore::default();
        store
            .set_desired(gateway_id(), desired_manifest())
            .expect("store is available");
        let service = GatewaySyncService::new(store);

        let initial = service
            .poll(&GatewayStateReport::new(gateway_id(), vec![]))
            .expect("poll succeeds")
            .expect("delivery is required");
        assert_eq!(initial.manifest().peer_count(), 1);

        let stale = AppliedInterface::wg_users(
            Generation::new(1).expect("positive generation"),
            ManifestDigest::new("0".repeat(64)).expect("valid digest"),
        );
        assert!(service
            .poll(&GatewayStateReport::new(gateway_id(), vec![stale]))
            .expect("poll succeeds")
            .is_some());
    }

    #[test]
    fn converged_state_returns_no_delivery() {
        let store = InMemoryGatewayStateStore::default();
        let desired = desired_manifest();
        let state = AppliedInterface::wg_users(
            desired.generation(),
            desired.digest().expect("digest succeeds"),
        );
        store
            .set_desired(gateway_id(), desired)
            .expect("store is available");
        let service = GatewaySyncService::new(store);

        assert!(service
            .poll(&GatewayStateReport::new(gateway_id(), vec![state]))
            .expect("poll succeeds")
            .is_none());
    }

    #[test]
    fn same_generation_with_another_digest_fails_closed() {
        let store = InMemoryGatewayStateStore::default();
        let desired = desired_manifest();
        let state = AppliedInterface::wg_users(
            desired.generation(),
            ManifestDigest::new("0".repeat(64)).expect("valid digest"),
        );
        store
            .set_desired(gateway_id(), desired)
            .expect("store is available");
        let service = GatewaySyncService::new(store);

        assert_eq!(
            service.poll(&GatewayStateReport::new(gateway_id(), vec![state])),
            Err(SyncError::AppliedConflict)
        );
    }

    #[test]
    fn exact_acknowledgement_records_applied_state() {
        let store = InMemoryGatewayStateStore::default();
        store
            .set_desired(gateway_id(), desired_manifest())
            .expect("store is available");
        let service = GatewaySyncService::new(store);
        let delivery = service
            .poll(&GatewayStateReport::new(gateway_id(), vec![]))
            .expect("poll succeeds")
            .expect("delivery is required");
        let acknowledgement = GatewayAcknowledgement::applied(&delivery);

        service
            .acknowledge(&acknowledgement)
            .expect("acknowledgement matches");
        assert!(service
            .store
            .applied(&gateway_id())
            .expect("store is available")
            .is_some());
    }
}
