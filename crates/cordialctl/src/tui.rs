use crate::Ctx;
use hrd_core::Result;
pub fn run(_ctx: &Ctx) -> Result<()> {
    Err(hrd_core::Error::unavailable(
        "the terminal panel is not written yet",
    ))
}
