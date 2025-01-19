use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[cfg(all(feature = "clipboard", not(target_os = "android")))]
pub mod delayed_clipboard;
#[cfg(any(not(feature = "clipboard"), target_os = "android"))]
pub mod empty_clipboard;

use bytes::Bytes;
#[cfg(all(feature = "clipboard", not(target_os = "android")))]
use clipboard::TargetMimeType;

#[cfg(all(feature = "clipboard", not(target_os = "android")))]
use self::delayed_clipboard::DelayedClipboardContext;
#[cfg(any(not(feature = "clipboard"), target_os = "android"))]
use self::empty_clipboard::EmptyClipboardContext;

#[cfg(all(feature = "clipboard", not(target_os = "android")))]
pub type Clipboard = DelayedClipboardContext;
#[cfg(any(not(feature = "clipboard"), target_os = "android"))]
pub type Clipboard = EmptyClipboardContext;

pub type ClipboardHash = Arc<Mutex<Option<String>>>;

use indexmap::IndexSet;

use crate::message::GroupName;
use crate::{defaults::CLIPBOARD_NAME, message::MessageType};

pub type ModifiedFiles = Arc<Mutex<HashSet<PathBuf>>>;
pub type Paths = HashMap<PathBuf, IndexSet<GroupName>>;
pub type ClipboardTargets = Vec<(ClipboardType, Vec<u8>)>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Copy)]
pub enum ClipboardSystem {
    Clipboard,
    Filesystem,
}

impl From<&str> for ClipboardSystem {
    fn from(value: &str) -> Self {
        if value == CLIPBOARD_NAME {
            Self::Clipboard
        } else {
            Self::Filesystem
        }
    }
}

pub struct ClipboardWriteMessage {
    pub destination: String,
    pub message_type: MessageType,
    pub from: String,
    pub data: Bytes,
}

pub struct ClipboardReadMessage {
    pub groups: IndexSet<String>,
    pub message_type: MessageType,
    pub data: Bytes,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum ClipboardType {
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
    UriList,

    ClipboardSent,
}

#[cfg(all(feature = "clipboard", not(target_os = "android")))]
impl From<ClipboardType> for TargetMimeType {
    fn from(value: ClipboardType) -> Self {
        match value {
            ClipboardType::Text => TargetMimeType::Text,
            ClipboardType::Files => TargetMimeType::Files,
            e => TargetMimeType::Specific(e.to_string()),
        }
    }
}

impl fmt::Display for ClipboardType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
            Self::ClipboardSent => write!(f, "x-special/clipboard-sent"),
        }
    }
}

pub fn create_text_targets(contents: Bytes) -> ClipboardTargets {
    let mut clipboard_list = Vec::new();
    clipboard_list.push((ClipboardType::Text, contents.to_vec()));
    #[cfg(target_os = "linux")]
    {
        clipboard_list.push((ClipboardType::Plain, contents.to_vec()));
        clipboard_list.push((ClipboardType::PlainUtf8, contents.to_vec()));
        clipboard_list.push((ClipboardType::SimpleText, contents.to_vec()));
    }
    clipboard_list
}

#[cfg(target_os = "linux")]
pub fn create_targets_for_cut_files(files: Vec<PathBuf>) -> (ClipboardTargets, String) {
    use crate::encryption::hash;

    let file_content = files
        .iter()
        .filter_map(|pb| {
            crate::filesystem::encode_path(pb.as_path()).map(|s| format!("file://{}", s))
        })
        .collect::<Vec<String>>()
        .join("\n");
    let cut_content = [String::from("cut"), file_content.clone()].join("\n");

    let hash_str = hash(file_content.as_bytes());

    let cut_content = cut_content.into_bytes();
    let file_content = file_content.into_bytes();
    (
        vec![
            (ClipboardType::GnomeFiles, cut_content.clone()),
            (ClipboardType::KdeFiles, file_content.clone()),
            (ClipboardType::KdeFilesCut, "1".as_bytes().to_vec()),
            (ClipboardType::MateFiles, cut_content),
            (ClipboardType::UriList, file_content.clone()),
            (ClipboardType::Text, file_content),
        ],
        hash_str,
    )
}

#[cfg(not(target_os = "linux"))]
pub fn create_targets_for_cut_files(files: Vec<PathBuf>) -> (ClipboardTargets, String) {
    use crate::encryption::hash;
    #[cfg(target_os = "macos")]
    let contents_for_hash = files
        .iter()
        .filter_map(|pb| {
            crate::filesystem::encode_path(pb.as_path()).map(|s| format!("file://{}", s))
        })
        .collect::<Vec<String>>()
        .join("\n");
    let file_content = files
        .into_iter()
        .map(|f| f.to_string_lossy().to_string())
        .collect::<Vec<String>>()
        .join("\n");

    #[cfg(target_os = "macos")]
    let hash_str = hash(contents_for_hash.as_bytes());
    #[cfg(not(target_os = "macos"))]
    let hash_str = hash(file_content.as_bytes());

    (
        vec![(ClipboardType::Files, file_content.into_bytes())],
        hash_str,
    )
}
