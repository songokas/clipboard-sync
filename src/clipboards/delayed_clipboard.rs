use std::error::Error;
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;

pub struct DelayedClipboardContext
{
    context: Option<ClipboardContext>
}

impl DelayedClipboardContext
{
    pub fn new() -> Result<DelayedClipboardContext, Box<dyn Error>>
    {
        return Ok(DelayedClipboardContext { context: None });
    }

    pub fn get_contents(&mut self) -> Result<String, Box<dyn Error>>
    {
        return self.start()?.get_contents();
    }

    pub fn set_contents(&mut self, contents: String) -> Result<(), Box<dyn Error>>
    {
        return self.start()?.set_contents(contents);
    }

    fn start(&mut self) -> Result<&mut ClipboardContext, Box<dyn Error>>
    {
        if self.context.is_none() {
            self.context = Some(
                ClipboardContext::new()
                .map_err(|e| format!("Unable to initialize clipboard. Possibly missing xcb libraries or no x server {}", e))?
            );
        }
        return Ok(self.context.as_mut().expect("Delayed clipboard should be initialized"));
    }
}
