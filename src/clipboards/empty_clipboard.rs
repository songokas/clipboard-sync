use std::error::Error;
use std::thread::sleep;
use std::time::Duration;

use crate::clipboards::ClipboardTargets;
use crate::clipboards::ClipboardType;

pub struct EmptyClipboardContext {}

impl EmptyClipboardContext {
    pub fn new() -> Result<EmptyClipboardContext, Box<dyn Error>> {
        return Ok(EmptyClipboardContext {});
    }

    pub fn get_target_contents(&mut self, _: ClipboardType) -> Result<Vec<u8>, Box<dyn Error>> {
        return Ok(vec![]);
    }

    pub fn wait_for_target_contents(
        &mut self,
        _: ClipboardType,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        sleep(Duration::from_secs(3));
        return Ok(vec![]);
    }

    pub fn set_target_contents(
        &mut self,
        _: ClipboardType,
        _: Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        return Ok(());
    }

    pub fn set_multiple_targets(&mut self, _: ClipboardTargets) -> Result<(), Box<dyn Error>> {
        return Ok(());
    }
}
