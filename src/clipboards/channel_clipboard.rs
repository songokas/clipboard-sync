use flume::{Receiver, Sender};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use crate::clipboards::ClipboardType;
use crate::message::MessageType;

pub type ClipData = (Vec<u8>, MessageType);
pub struct ChannelClipboardContext
{
    sender: Arc<Sender<ClipData>>,
    receiver: Option<Receiver<ClipData>>,
    last_received: HashMap<MessageType, Vec<u8>>,
}

pub fn err(s: &str) -> Box<dyn Error>
{
    Box::<dyn Error + Send + Sync>::from(s)
}

impl ChannelClipboardContext
{
    pub fn get_receiver(&mut self) -> Option<Receiver<ClipData>>
    {
        return self.receiver.take();
    }

    pub fn get_sender(&self) -> Arc<Sender<ClipData>>
    {
        return Arc::clone(&self.sender);
    }

    pub fn new() -> Result<ChannelClipboardContext, Box<dyn Error>>
    {
        let (clipboard_sender, clipboard_receiver) = flume::bounded(100);
        let sender = Arc::new(clipboard_sender);
        return Ok(ChannelClipboardContext {
            sender,
            receiver: Some(clipboard_receiver),
            last_received: HashMap::new(),
        });
    }

    pub fn get_target_contents(&mut self, target: ClipboardType)
        -> Result<Vec<u8>, Box<dyn Error>>
    {
        let expected_type = match target {
            ClipboardType::Text => MessageType::Text,
            ClipboardType::Files => MessageType::Files,
            _ => {
                let message = format!("Clipboard target {} not implemented", target);
                return Err(err(&message));
            }
        };

        if self.last_received.contains_key(&expected_type) {
            return self
                .last_received
                .remove(&expected_type)
                .ok_or(err("Last received message type not found"));
        }

        if let Some(r) = &mut self.receiver {
            while let Ok((bytes, message_type)) = r.try_recv() {
                if message_type == expected_type {
                    return Ok(bytes);
                } else {
                    self.last_received.insert(message_type, bytes);
                }
            }
        }
        Err(format!("Receiver not found").into())
    }

    pub fn set_target_contents(
        &mut self,
        target: ClipboardType,
        contents: &[u8],
    ) -> Result<(), Box<dyn Error>>
    {
        let expected_type = match target {
            ClipboardType::Text => MessageType::Text,
            ClipboardType::Files => MessageType::Files,
            _ => {
                let message = format!("Clipboard target {} not implemented", target);
                return Err(err(&message));
            }
        };
        if let Err(e) = self.sender.try_send((contents.to_vec(), expected_type)) {
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
