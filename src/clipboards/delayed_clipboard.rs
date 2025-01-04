use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

use crate::clipboards::ClipboardType;

pub struct DelayedClipboardContext {
    context: Option<ClipboardContext>,
}

impl DelayedClipboardContext {
    pub fn new() -> Result<DelayedClipboardContext, Box<dyn Error>> {
        Ok(DelayedClipboardContext { context: None })
    }

    pub fn get_target_contents(
        &mut self,
        target: ClipboardType,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.start()?
            .get_target_contents(target.into(), Duration::from_millis(100))
    }

    pub fn wait_for_target_contents(
        &mut self,
        target: ClipboardType,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        self.start()?
            .wait_for_target_contents(target.into(), Duration::from_millis(500))
    }

    pub fn set_target_contents(
        &mut self,
        clipboard_type: ClipboardType,
        contents: Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        self.start()?
            .set_target_contents(clipboard_type.into(), contents)
    }

    pub fn set_multiple_targets(
        &mut self,
        targets: HashMap<ClipboardType, Vec<u8>>,
    ) -> Result<(), Box<dyn Error>> {
        self.start()?
            .set_multiple_targets(targets.into_iter().map(|(k, v)| (k.into(), v)))
    }

    fn start(&mut self) -> Result<&mut ClipboardContext, Box<dyn Error>> {
        if self.context.is_none() {
            self.context = Some(
                ClipboardContext::new()
                .map_err(|e| format!("Unable to initialize clipboard. Possibly missing xcb libraries or no x server {}", e))?
            );
        }
        Ok(self
            .context
            .as_mut()
            .expect("Delayed clipboard should be initialized"))
    }
}
