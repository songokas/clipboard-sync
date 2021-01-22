#[cfg(target_os = "android")]
pub mod channel_clipboard;
#[cfg(all(not(feature = "clipboard"), not(target_os = "android")))]
pub mod empty_clipboard;
#[cfg(all(feature = "clipboard", not(target_os = "android")))]
pub mod delayed_clipboard;

#[cfg(all(not(feature = "clipboard"), not(target_os = "android")))]
use self::empty_clipboard::EmptyClipboardContext;
#[cfg(target_os = "android")]
use self::channel_clipboard::ChannelClipboardContext;
#[cfg(all(feature = "clipboard", not(target_os = "android")))]
use self::delayed_clipboard::DelayedClipboardContext;

#[cfg(target_os = "android")]
pub type Clipboard = ChannelClipboardContext;
#[cfg(all(feature = "clipboard", not(target_os = "android")))]
pub type Clipboard = DelayedClipboardContext;
#[cfg(all(not(feature = "clipboard"), not(target_os = "android")))]
pub type Clipboard = EmptyClipboardContext;
