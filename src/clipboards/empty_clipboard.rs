use std::error::Error;

pub struct EmptyClipboardContext {}

impl EmptyClipboardContext
{
    pub fn new() -> Result<EmptyClipboardContext, Box<dyn Error>>
    {
        return Ok(EmptyClipboardContext {});
    }

    pub fn get_contents(&mut self) -> Result<String, Box<dyn Error>>
    {
        return Ok(String::from(""));
    }

    pub fn set_contents(&mut self, _: String) -> Result<(), Box<dyn Error>>
    {
        return Ok(());
    }
}
