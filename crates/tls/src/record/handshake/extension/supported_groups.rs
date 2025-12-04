use anyhow::Result;

use super::named_group::NamedGroup;
use crate::parse::{DataVec16, Parse};

#[derive(Clone, Debug)]
pub struct SupportedGroups {
    pub named_group_list: Box<[NamedGroup]>,
}

impl SupportedGroups {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let named_group_list = DataVec16::<NamedGroup>::parse(raw)?.into_inner();

        Ok(Self { named_group_list })
    }
}
