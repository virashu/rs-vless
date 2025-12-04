#[repr(u8)]
pub enum KeyUpdateRequest {
    update_not_requested,
    update_requested,
}

pub struct KeyUpdate {
    request_update: KeyUpdateRequest,
}
