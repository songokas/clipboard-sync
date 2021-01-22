use std::error::Error;
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver, Sender};

pub struct ChannelClipboardContext
{
    sender: Arc<Sender<String>>,
    receiver: Option<Receiver<String>>,
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
        let (clipboard_sender, clipboard_receiver) = channel(60000);
        let sender = Arc::new(clipboard_sender);
        return Ok(ChannelClipboardContext {
            sender,
            receiver: Some(clipboard_receiver),
        });
    }

    pub fn get_contents(&mut self) -> Result<String, Box<dyn Error>>
    {
        if let Some(r) = &mut self.receiver {
            let mut last = String::from("");
            while let Ok(contents) = r.try_recv() {
                last = contents;
            }
            return Ok(last);
        }
        return Err(format!("Receiver not found").into());
    }

    pub fn set_contents(&mut self, contents: String) -> Result<(), Box<dyn Error>>
    {
        if let Err(e) = self.sender.try_send(contents) {
            return Err(format!("Unable to send clipboard on channel {}", e).into());
        }
        return Ok(());
    }
}
