use std::fmt;
use std::collections::HashMap;
use std::path::PathBuf;

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

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum ClipboardType
{
    Text,

    Files,
    Plain,

    PlainUtf8,
    SimpleText,
    SimpleString,

    GnomeFiles,
    MateFiles,
    KdeFiles,
    KdeFilesCut,
    UriList
}

impl fmt::Display for ClipboardType
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        match self {
            Self::Text => write!(f, "UTF8_STRING"),
            Self::SimpleText => write!(f, "TEXT"),
            Self::Plain => write!(f, "text/plain"),
            Self::PlainUtf8 => write!(f, "text/plain;charset=utf-8"),
            Self::SimpleString => write!(f, "STRING"),
            Self::GnomeFiles => write!(f, "x-special/gnome-copied-files"),
            Self::KdeFiles => write!(f, "application/x-kde4-urilist"),
            Self::KdeFilesCut => write!(f, "application/x-kde-cutselections"),
            Self::MateFiles => write!(f, "x-special/mate-copied-files"),
            Self::UriList | Self::Files => write!(f, "text/uri-list"),
        }
    }
}

pub fn create_text_targets(contents: &[u8]) -> HashMap<ClipboardType, &[u8]> {
    let mut clipboard_list = HashMap::new();
    clipboard_list.insert(ClipboardType::Text, contents);
    #[cfg(target_os = "linux")]
    {
        clipboard_list.insert(ClipboardType::Plain, contents);
        clipboard_list.insert(ClipboardType::PlainUtf8, contents);
        clipboard_list.insert(ClipboardType::SimpleText, contents);
    }
    return clipboard_list;
}

pub fn create_targets_for_cut_files(files: Vec<PathBuf>) -> (HashMap<ClipboardType, String>, String)
{
    let file_content = files
        .iter()
        .map(|p| format!("file://{}", p.to_str().unwrap()))
        .collect::<Vec<String>>()
        .join("\n");
    let cut_content = [String::from("cut"), file_content.clone()].join("\n");

    let mut clipboard_list = HashMap::new();
    #[cfg(target_os = "linux")]
    {
        clipboard_list.insert(ClipboardType::GnomeFiles, cut_content.clone());
        clipboard_list.insert(ClipboardType::KdeFiles, file_content.clone());
        clipboard_list.insert(ClipboardType::KdeFilesCut, "1".into());
        clipboard_list.insert(ClipboardType::MateFiles, cut_content);
        clipboard_list.insert(ClipboardType::UriList, file_content.clone());
    }
    clipboard_list.insert(ClipboardType::Text, file_content.clone());

    return (clipboard_list, file_content);
}
