use crate::clipboards::ClipboardType;
use std::collections::HashMap;
use std::error::Error;

pub struct EmptyClipboardContext {}

impl EmptyClipboardContext
{
    pub fn new() -> Result<EmptyClipboardContext, Box<dyn Error>>
    {
        return Ok(EmptyClipboardContext {});
    }

    pub fn get_target_contents(&mut self, _: ClipboardType) -> Result<Vec<u8>, Box<dyn Error>>
    {
        return Ok(vec![]);
    }

    pub fn set_target_contents(
        &mut self,
        _: ClipboardType,
        contents: &[u8],
    ) -> Result<(), Box<dyn Error>>
    {
        return Ok(());
    }

    pub fn set_multiple_targets(
        &mut self,
        targets: HashMap<ClipboardType, &[u8]>,
    ) -> Result<(), Box<dyn Error>>
    {
        return Ok(());
    }
}
