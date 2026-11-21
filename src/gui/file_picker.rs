use super::workflows::Field;
use super::{
    Job, Message, SecretString, Task,
    backend::{Failure, Reply},
};
use std::{path::Path, sync::Arc};

type Picker = std::pin::Pin<Box<dyn std::future::Future<Output = Option<rfd::FileHandle>> + Send>>;

pub fn pick_workflow_file(serial: u64, field: Field, save: bool) -> Task<Message> {
    iced::window::latest()
        .then(move |window| match window {
            Some(id) => iced::window::run(id, move |window| {
                let dialog = rfd::AsyncFileDialog::new()
                    .set_parent(window)
                    .set_title(if save {
                        "Choose a destination file"
                    } else {
                        "Select a file"
                    });
                let picker: Picker = if save {
                    Box::pin(dialog.save_file())
                } else {
                    Box::pin(dialog.pick_file())
                };
                Some(picker)
            }),
            None => Task::done(None),
        })
        .then(move |picker| {
            Task::perform(
                async move {
                    let picker = picker.ok_or_else(|| {
                        Failure::from("The file chooser needs an open window.".to_owned())
                    })?;
                    let path = picker
                        .await
                        .map(|file| selected_path(file.path()))
                        .transpose()
                        .map_err(Failure::from)?;
                    Ok(Reply::PickedFile(field, path))
                },
                move |result| Message::Finished(serial, Job::PickFile(field), Arc::new(result)),
            )
        })
}

/// Choose a file to attach, or (with `save`) where to save an attachment.
pub fn pick_attachment(serial: u64, id: usize, save: Option<(usize, String)>) -> Task<Message> {
    let index = save.as_ref().map(|(index, _)| *index);
    iced::window::latest()
        .then(move |window| {
            let suggested = save.as_ref().map(|(_, name)| name.clone());
            match window {
                Some(id) => iced::window::run(id, move |window| {
                    let dialog = rfd::AsyncFileDialog::new().set_parent(window);
                    let picker: Picker = match &suggested {
                        Some(name) => Box::pin(
                            dialog
                                .set_title("Save attachment as")
                                .set_file_name(name)
                                .save_file(),
                        ),
                        None => Box::pin(dialog.set_title("Attach a file").pick_file()),
                    };
                    Some(picker)
                }),
                None => Task::done(None),
            }
        })
        .then(move |picker| {
            Task::perform(
                async move {
                    let picker = picker.ok_or_else(|| {
                        Failure::from("The file chooser needs an open window.".to_owned())
                    })?;
                    let path = picker
                        .await
                        .map(|file| selected_path(file.path()))
                        .transpose()
                        .map_err(Failure::from)?;
                    Ok(Reply::AttachmentPath(path.map(|p| p.expose().to_owned())))
                },
                move |result| {
                    Message::Finished(
                        serial,
                        Job::PickAttachment { id, save: index },
                        Arc::new(result),
                    )
                },
            )
        })
}

/// Create the parented chooser on Iced's window thread (required by AppKit),
/// then await it asynchronously. Picking only fills the path.
pub fn pick_key_file(serial: u64) -> Task<Message> {
    iced::window::latest()
        .then(|window| match window {
            Some(id) => iced::window::run(id, |window| {
                Some(
                    rfd::AsyncFileDialog::new()
                        .set_parent(window)
                        .set_title("Select a vault key file")
                        .pick_file(),
                )
            }),
            None => Task::done(None),
        })
        .then(move |picker| {
            Task::perform(
                async move {
                    let picker = picker.ok_or_else(|| {
                        Failure::from("The key-file chooser needs an open window.".to_owned())
                    })?;
                    let selected = picker.await;
                    selected
                        .map(|file| selected_path(file.path()))
                        .transpose()
                        .map(Reply::KeyFile)
                        .map_err(Failure::from)
                },
                move |result| Message::Finished(serial, Job::PickKey, Arc::new(result)),
            )
        })
}

fn selected_path(path: &Path) -> Result<SecretString, String> {
    if !path.is_absolute() {
        return Err("Select a file using an absolute path.".into());
    }
    path.to_str().map(SecretString::from).ok_or_else(|| {
        "The selected path is not valid UTF-8. Choose a file with a UTF-8 filename.".into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_keeps_the_exact_path_and_rejects_lossy_conversion() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("my key — external");
        assert_eq!(
            selected_path(&path).unwrap().expose(),
            path.to_str().unwrap()
        );
        assert!(selected_path(Path::new("relative.key")).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let invalid = root.path().join(std::ffi::OsString::from_vec(vec![0xff]));
            assert!(selected_path(&invalid).is_err());
        }
    }
}
