use std::path::{Path, PathBuf};
use toml_edit::{DocumentMut, Item, Value};

#[derive(Clone, Debug)]
pub struct Block {
    source: String,
    start: usize,
    end: usize,
    indent: String,
    newline: &'static str,
    pub text: String,
}

impl Block {
    pub fn parse(source: String) -> Result<Self, String> {
        let newline = if source.contains("\r\n") {
            "\r\n"
        } else {
            "\n"
        };
        let lines: Vec<&str> = source.split_inclusive('\n').collect();
        let mut offset = 0;
        let mut found = None;
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if matches!(trimmed, "manifest: |" | "manifest: |-" | "manifest: |+") {
                if found.is_some() {
                    return Err(
                        "More than one manifest block. Choose a file with one block.".into(),
                    );
                }
                let key_indent = line.len() - line.trim_start().len();
                let start = offset + line.len();
                let mut end = start;
                let mut indentation = None;
                for body in &lines[index + 1..] {
                    if !body.trim().is_empty() {
                        let spaces = body.len() - body.trim_start_matches(' ').len();
                        if spaces <= key_indent {
                            break;
                        }
                        indentation.get_or_insert(spaces);
                        if spaces < indentation.unwrap_or(0) {
                            return Err("Inconsistent manifest indentation".into());
                        }
                    }
                    end += body.len();
                }
                found = Some((
                    start,
                    end,
                    " ".repeat(indentation.ok_or("Empty manifest block")?),
                ));
            }
            offset += line.len();
        }
        let (start, end, indent) = found.ok_or("No manifest: | block found")?;
        let mut text = String::new();
        for line in source[start..end].split_inclusive('\n') {
            text.push_str(
                line.trim_end_matches(['\r', '\n'])
                    .strip_prefix(&indent)
                    .unwrap_or(""),
            );
            text.push('\n');
        }
        Ok(Self {
            source,
            start,
            end,
            indent,
            newline,
            text,
        })
    }

    pub fn replace(&self, text: &str) -> Result<String, String> {
        text.parse::<DocumentMut>().map_err(|e| e.to_string())?;
        let mut output = self.source[..self.start].to_owned();
        for line in text.lines() {
            output.push_str(&self.indent);
            output.push_str(line);
            output.push_str(self.newline);
        }
        output.push_str(&self.source[self.end..]);
        Ok(output)
    }

    pub fn unchanged(&self, path: &Path) -> Result<(), String> {
        let current = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        if current == self.source {
            Ok(())
        } else {
            Err("The deployment file changed. Reload it before applying.".into())
        }
    }
}

pub fn discover(repo: &Path) -> Result<PathBuf, String> {
    fn scan(dir: &Path, matches: &mut Vec<PathBuf>) -> Result<(), String> {
        for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_symlink() {
                continue;
            }
            let path = entry.path();
            if kind.is_dir() {
                if !matches!(
                    entry.file_name().to_str(),
                    Some(".git" | "target" | "node_modules")
                ) {
                    scan(&path, matches)?;
                }
            } else if matches!(
                path.extension().and_then(|s| s.to_str()),
                Some("yaml" | "yml")
            ) {
                let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
                if text.contains("open-pact")
                    && text.contains("helm:")
                    && Block::parse(text).is_ok()
                {
                    matches.push(path);
                }
            }
        }
        Ok(())
    }
    let mut matches = Vec::new();
    scan(repo, &mut matches)?;
    if matches.len() == 1 {
        Ok(matches.remove(0))
    } else {
        Err(format!(
            "Found {} deployment files. Enter the manifest file path.",
            matches.len()
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Part {
    Key(String),
    Index(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Bool,
    Number,
    Text,
    List,
}

#[derive(Clone, Debug)]
pub struct Field {
    pub path: Vec<Part>,
    pub label: String,
    pub kind: Kind,
    pub value: String,
}

pub fn fields(text: &str) -> Result<Vec<Field>, String> {
    let document = text.parse::<DocumentMut>().map_err(|e| e.to_string())?;
    fn visit(item: &Item, path: Vec<Part>, output: &mut Vec<Field>) {
        match item {
            Item::Table(table) => {
                for (key, value) in table.iter() {
                    let mut path = path.clone();
                    path.push(Part::Key(key.into()));
                    visit(value, path, output);
                }
            }
            Item::ArrayOfTables(array) => {
                for (i, table) in array.iter().enumerate() {
                    let mut path = path.clone();
                    path.push(Part::Index(i));
                    visit(&Item::Table(table.clone()), path, output);
                }
            }
            Item::Value(value) => visit_value(value, path, output),
            Item::None => (),
        }
    }
    fn visit_value(value: &Value, path: Vec<Part>, output: &mut Vec<Field>) {
        if let Value::InlineTable(table) = value {
            for (key, value) in table.iter() {
                let mut path = path.clone();
                path.push(Part::Key(key.into()));
                visit_value(value, path, output);
            }
            return;
        }
        let kind = match value {
            Value::Boolean(_) => Kind::Bool,
            Value::Integer(_) | Value::Float(_) => Kind::Number,
            Value::Array(_) => Kind::List,
            _ => Kind::Text,
        };
        let label = path
            .iter()
            .map(|p| match p {
                Part::Key(k) => k.clone(),
                Part::Index(i) => format!("[{}]", i + 1),
            })
            .collect::<Vec<_>>()
            .join(" / ");
        let value = value
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| value.to_string().trim().into());
        output.push(Field {
            path,
            label,
            kind,
            value,
        });
    }
    let mut output = Vec::new();
    visit(
        &Item::Table(document.as_table().clone()),
        Vec::new(),
        &mut output,
    );
    Ok(output)
}

pub fn set_field(text: &str, field: &Field, input: &str) -> Result<String, String> {
    let mut document = text.parse::<DocumentMut>().map_err(|e| e.to_string())?;
    let replacement = match field.kind {
        Kind::Text => Value::from(input),
        _ => input.parse::<Value>().map_err(|e| e.to_string())?,
    };
    let valid = match field.kind {
        Kind::Bool => replacement.is_bool(),
        Kind::Number => replacement.is_integer() || replacement.is_float(),
        Kind::List => replacement.is_array(),
        Kind::Text => true,
    };
    if !valid {
        return Err("Value has the wrong type".into());
    }
    fn value_at(value: &mut Value, path: &[Part], replacement: Value) -> Result<(), String> {
        let Some((first, rest)) = path.split_first() else {
            *value = replacement;
            return Ok(());
        };
        let next = match first {
            Part::Key(key) => value.as_inline_table_mut().and_then(|t| t.get_mut(key)),
            Part::Index(i) => value.as_array_mut().and_then(|a| a.get_mut(*i)),
        }
        .ok_or("Field does not exist")?;
        value_at(next, rest, replacement)
    }
    fn item_at(item: &mut Item, path: &[Part], replacement: Value) -> Result<(), String> {
        if let Item::Value(value) = item {
            return value_at(value, path, replacement);
        }
        let Some((first, rest)) = path.split_first() else {
            return Err("Cannot replace a table".into());
        };
        match first {
            Part::Key(key) => item_at(
                item.as_table_mut()
                    .and_then(|t| t.get_mut(key))
                    .ok_or("Missing table key")?,
                rest,
                replacement,
            ),
            Part::Index(i) => {
                let table = item
                    .as_array_of_tables_mut()
                    .and_then(|a| a.get_mut(*i))
                    .ok_or("Missing array table")?;
                let Some((Part::Key(key), tail)) = rest.split_first() else {
                    return Err("Missing table key".into());
                };
                item_at(
                    table.get_mut(key).ok_or("Missing table key")?,
                    tail,
                    replacement,
                )
            }
        }
    }
    item_at(document.as_item_mut(), &field.path, replacement)?;
    Ok(document.to_string())
}

pub fn diff(before: &str, after: &str) -> String {
    if before == after {
        return "No changes".into();
    }
    before
        .lines()
        .map(|s| format!("- {s}\n"))
        .chain(after.lines().map(|s| format!("+ {s}\n")))
        .collect()
}
