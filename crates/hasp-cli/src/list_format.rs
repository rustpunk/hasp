//! List-output formatting for `hasp-cli`.
//!
//! The library returns `Vec<Entry>`; this module turns it into
//! human- or machine-readable text.  All formatting lives in the
//! CLI — the library never pays for presentation logic.

use hasp::Entry;

/// Output style for `hasp list`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    /// Two-space separated columns (default).
    #[default]
    Plain,
    /// Human-readable aligned columns.
    Table,
    /// JSON array of objects.
    Json,
}

/// Render a slice of `Entry` values into the requested format.
pub fn format_list(entries: &[Entry], format: Format) -> Result<String, String> {
    match format {
        Format::Plain => Ok(format_plain(entries)),
        Format::Table => Ok(format_table(entries)),
        Format::Json => format_json(entries),
    }
}

fn format_plain(entries: &[Entry]) -> String {
    entries
        .iter()
        .map(|e| format!("{}  {}", e.name, e.url))
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_table(entries: &[Entry]) -> String {
    let max_name = entries.iter().map(|e| e.name.len()).max().unwrap_or(0);
    entries
        .iter()
        .map(|e| format!("{:<width$}  {}", e.name, e.url, width = max_name))
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_json(entries: &[Entry]) -> Result<String, String> {
    #[derive(serde::Serialize)]
    struct ListEntry<'a> {
        name: &'a str,
        url: &'a str,
    }

    let json_entries: Vec<_> = entries
        .iter()
        .map(|e| ListEntry {
            name: &e.name,
            url: e.url.as_str(),
        })
        .collect();

    serde_json::to_string(&json_entries)
        .map_err(|e| format!("failed to serialize list output: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn sample_entries() -> Vec<Entry> {
        vec![
            Entry {
                name: "short".into(),
                url: Url::parse("env://SHORT").unwrap(),
            },
            Entry {
                name: "a-very-long-name".into(),
                url: Url::parse("file:///etc/secrets/long.txt").unwrap(),
            },
        ]
    }

    #[test]
    fn plain_format() {
        let out = format_plain(&sample_entries());
        assert_eq!(
            out,
            "short  env://SHORT\na-very-long-name  file:///etc/secrets/long.txt"
        );
    }

    #[test]
    fn table_format_aligns_names() {
        let out = format_table(&sample_entries());
        let lines: Vec<_> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        // First line name is padded to the longest name width (16).
        assert!(lines[0].starts_with("short             "));
        assert!(lines[0].ends_with("  env://SHORT"));
        // Second line is already max width.
        assert!(lines[1].starts_with("a-very-long-name  "));
    }

    #[test]
    fn json_format_roundtrips() {
        let entries = sample_entries();
        let out = format_json(&entries).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["name"], "short");
        assert_eq!(arr[0]["url"], "env://SHORT");
        assert_eq!(arr[1]["name"], "a-very-long-name");
        assert_eq!(arr[1]["url"], "file:///etc/secrets/long.txt");
    }

    #[test]
    fn empty_list_all_formats() {
        let empty: Vec<Entry> = vec![];
        assert_eq!(format_plain(&empty), "");
        assert_eq!(format_table(&empty), "");
        assert_eq!(format_json(&empty).unwrap(), "[]");
    }
}
