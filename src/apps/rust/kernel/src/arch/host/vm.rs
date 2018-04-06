use base::dtu::EpId;
use base::errors::{Code, Error};
use base::goff;
use base::kif::{CapSel, PEDesc};
use base::GlobAddr;

use cap::MapFlags;
use pes::VPEDesc;

pub struct AddrSpace {
}

impl AddrSpace {
    pub fn new(_pe: &PEDesc) -> Result<Self, Error> {
        Ok(AddrSpace {})
    }

    pub fn new_with_pager(_pe: &PEDesc, _sep: EpId, _rep: EpId, _sgate: CapSel) -> Result<Self, Error> {
        Err(Error::new(Code::NotSup))
    }

    pub fn sep(&self) -> Option<EpId> {
        None
    }
    pub fn sgate_sel(&self) -> Option<CapSel> {
        None
    }

    pub fn setup(&self) {
    }

    pub fn map_pages(&self, _vpe: &VPEDesc, _virt: goff, _phys: GlobAddr,
                     _pages: usize, _attr: MapFlags) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }

    pub fn unmap_pages(&self, _vpe: &VPEDesc, _virt: goff, _pages: usize) -> Result<(), Error> {
        Err(Error::new(Code::NotSup))
    }
}
