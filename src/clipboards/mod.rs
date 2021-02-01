use std::fmt;

#[cfg(target_os = "android")]
pub mod channel_clipboard;
#[cfg(all(feature = "clipboard", not(target_os = "android")))]
pub mod delayed_clipboard;
#[cfg(all(not(feature = "clipboard"), not(target_os = "android")))]
pub mod empty_clipboard;

#[cfg(target_os = "android")]
use self::channel_clipboard::ChannelClipboardContext;
#[cfg(all(feature = "clipboard", not(target_os = "android")))]
use self::delayed_clipboard::DelayedClipboardContext;
#[cfg(all(not(feature = "clipboard"), not(target_os = "android")))]
use self::empty_clipboard::EmptyClipboardContext;

#[cfg(target_os = "android")]
pub type Clipboard = ChannelClipboardContext;
#[cfg(all(feature = "clipboard", not(target_os = "android")))]
pub type Clipboard = DelayedClipboardContext;
#[cfg(all(not(feature = "clipboard"), not(target_os = "android")))]
pub type Clipboard = EmptyClipboardContext;

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum ClipboardType
{
    Text,
    Files,
    CopyFiles,
    CutFiles,
}

impl fmt::Display for ClipboardType
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match self {
            Self::Text => write!(f, "UTF8_STRING"),
            //@TODO test different variants kde, gnome, mate. n
            //x-special/mate-copied-files
            //application/x-kde-cutselections
            Self::CopyFiles | Self::CutFiles => write!(f, "x-special/gnome-copied-files"),
            Self::Files => write!(f, "text/uri-list"),
        }
    }
}
