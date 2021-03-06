use flume::{Receiver, Sender};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use crate::clipboards::ClipboardType;

pub struct ChannelClipboardContext
{
    sender: Arc<Sender<String>>,
    receiver: Option<Receiver<String>>,
}

pub fn err(s: &str) -> Box<dyn Error>
{
    Box::<dyn Error + Send + Sync>::from(s)
}

impl ChannelClipboardContext
{
    pub fn get_receiver(&mut self) -> Option<Receiver<String>>
    {
        return self.receiver.take();
    }

    pub fn get_sender(&self) -> Arc<Sender<String>>
    {
        return Arc::clone(&self.sender);
    }

    pub fn new() -> Result<ChannelClipboardContext, Box<dyn Error>>
    {
        let (clipboard_sender, clipboard_receiver) = flume::bounded(60000);
        let sender = Arc::new(clipboard_sender);
        return Ok(ChannelClipboardContext {
            sender,
            receiver: Some(clipboard_receiver),
        });
    }

    pub fn get_target_contents(&mut self, target: impl ToString)
        -> Result<Vec<u8>, Box<dyn Error>>
    {
        let clipboard_target = target.to_string();
        if clipboard_target != "UTF8_STRING" {
            let message = format!("Clipboard target {} not implemented", clipboard_target);
            return Err(err(&message));
        }
        if let Some(r) = &mut self.receiver {
            let mut last = String::from("");
            while let Ok(contents) = r.try_recv() {
                last = contents;
            }
            return Ok(last.as_bytes().to_vec());
        }
        return Err(format!("Receiver not found").into());
    }

    pub fn set_target_contents(
        &mut self,
        target: impl ToString,
        contents: &[u8],
    ) -> Result<(), Box<dyn Error>>
    {
        let clipboard_target = target.to_string();
        if clipboard_target != "UTF8_STRING" {
            let message = format!("Clipboard target {} not implemented", clipboard_target);
            return Err(err(&message));
        }
        let str = String::from_utf8(contents.to_vec())?;
        if let Err(e) = self.sender.try_send(str) {
            return Err(format!("Unable to send clipboard on channel {}", e).into());
        }
        return Ok(());
    }

    pub fn set_multiple_targets(
        &mut self,
        targets: HashMap<ClipboardType, &[u8]>,
    ) -> Result<(), Box<dyn Error>>
    {
        for (key, value) in targets {
            return self.set_target_contents(key, value);
        }
        return Ok(());
    }
}
