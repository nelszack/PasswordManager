use crate::{
    types::ItemKind,
    vault::{EntryView, TrashView},
};
use zeroize::Zeroizing;

fn kind(view: &EntryView<'_>) -> ItemKind {
    view.metadata
        .map_or(ItemKind::Login, |metadata| metadata.kind)
}

pub(super) fn entry_details(view: &EntryView<'_>) -> Zeroizing<String> {
    let fields = Zeroizing::new(
        view.metadata
            .map_or(&[][..], |metadata| metadata.custom_fields.as_slice())
            .iter()
            .map(|field| format!("{}={}", field.name, field.value))
            .collect::<Vec<_>>(),
    );
    let fields = Zeroizing::new(fields.join("\n"));
    Zeroizing::new(format!(
        "Type: {}\nURLs: {:?}\n{:?}{}{}\n",
        kind(view),
        view.urls,
        view.entry,
        if fields.is_empty() {
            ""
        } else {
            "\nCustom fields:\n"
        },
        *fields
    ))
}

pub(super) fn entries(views: &[EntryView<'_>]) -> String {
    if views.is_empty() {
        return "No entries.".into();
    }
    views
        .iter()
        .map(|view| {
            let entry = view.entry;
            let urls = view.urls.join(", ");
            let fields = view
                .metadata
                .map_or(&[][..], |metadata| metadata.custom_fields.as_slice())
                .iter()
                .map(|field| {
                    if field.secret {
                        format!("{} [secret]", field.name)
                    } else {
                        format!("{}={}", field.name, field.value)
                    }
                })
                .collect::<Vec<_>>();
            format!(
                "{}. {} [{}] {:?} {:?} {:?} {:?}{}\n",
                entry.id,
                entry.name,
                kind(view),
                entry.username,
                (!urls.is_empty()).then_some(urls),
                entry.notes,
                fields,
                if view.has_totp { " [TOTP]" } else { "" }
            )
        })
        .collect()
}

pub(super) fn history(changed: &[&str]) -> String {
    if changed.is_empty() {
        return "No password history.".into();
    }
    changed
        .iter()
        .enumerate()
        .map(|(index, changed)| format!("{}. changed {}\n", index + 1, changed))
        .collect()
}

pub(super) fn trash(items: &[TrashView<'_>]) -> String {
    if items.is_empty() {
        return "Trash is empty.".into();
    }
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            format!(
                "{}. {} [{}] {:?} deleted {}{}\n",
                index + 1,
                item.entry.entry.name,
                kind(&item.entry),
                item.entry.entry.username,
                item.deleted,
                if item.entry.has_totp { " [TOTP]" } else { "" }
            )
        })
        .collect()
}
