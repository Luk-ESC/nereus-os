use scheduler::memory::AddressSpaceError;

use crate::vmm::error::VmmError;

#[derive(Debug, thiserror::Error)]
pub(crate) enum SchedulerError {
    #[error("{0}")]
    Vmm(#[from] VmmError),
    #[error("{0}")]
    AddressSpace(#[from] AddressSpaceError),
}
