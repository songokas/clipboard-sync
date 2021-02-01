use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use std::collections::HashMap;
use std::error::Error;

use crate::clipboards::ClipboardType;

pub struct DelayedClipboardContext
{
    context: Option<ClipboardContext>,
}

impl DelayedClipboardContext
{
    pub fn new() -> Result<DelayedClipboardContext, Box<dyn Error>>
    {
        return Ok(DelayedClipboardContext { context: None });
    }

    pub fn get_target_contents(
        &mut self,
        clipboard_type: ClipboardType,
    ) -> Result<Vec<u8>, Box<dyn Error>>
    {
        return self.start()?.get_target_contents(clipboard_type);
    }

    pub fn set_target_contents(
        &mut self,
        clipboard_type: ClipboardType,
        contents: &[u8],
    ) -> Result<(), Box<dyn Error>>
    {
        return self.start()?.set_target_contents(clipboard_type, contents);
    }

    pub fn set_multiple_targets(
        &mut self,
        targets: HashMap<ClipboardType, &[u8]>,
    ) -> Result<(), Box<dyn Error>>
    {
        return self.start()?.set_multiple_targets(targets);
    }

    fn start(&mut self) -> Result<&mut ClipboardContext, Box<dyn Error>>
    {
        if self.context.is_none() {
            self.context = Some(
                ClipboardContext::new()
                .map_err(|e| format!("Unable to initialize clipboard. Possibly missing xcb libraries or no x server {}", e))?
            );
        }
        return Ok(self
            .context
            .as_mut()
            .expect("Delayed clipboard should be initialized"));
    }
}
