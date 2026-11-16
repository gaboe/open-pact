use crate::text::humanize;
use toml_edit::{DocumentMut, Item, Value};

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
    pub section: String,
    pub label: String,
    pub kind: Kind,
    pub value: String,
}

fn field_names(path: &[Part]) -> (String, String) {
    let Some(Part::Key(first)) = path.first() else {
        return ("Manifest".into(), String::new());
    };
    if path.len() == 1 {
        return ("Manifest".into(), humanize(first));
    }
    let section = match first.as_str() {
        "company" => "Company".into(),
        "schedule" => "Automatic sending".into(),
        "controls" => "Checks".into(),
        other => humanize(other),
    };
    let noun = if first == "controls" { "Check" } else { "Item" };
    let label = path[1..]
        .iter()
        .map(|part| match part {
            Part::Key(key) => humanize(key),
            Part::Index(index) => format!("{noun} {}", index + 1),
        })
        .collect::<Vec<_>>()
        .join(" · ");
    (section, label)
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
        let (section, label) = field_names(&path);
        let value = value
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| value.to_string().trim().into());
        output.push(Field {
            path,
            section,
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
    similar::TextDiff::from_lines(before, after)
        .unified_diff()
        .context_radius(2)
        .header("Active manifest", "Proposed manifest")
        .to_string()
}

pub enum ListEdit<'a> {
    Set(usize, &'a str),
    Add,
    Remove(usize),
}

pub fn edit_list(text: &str, field: &Field, edit: ListEdit<'_>) -> Result<String, String> {
    let current = fields(text)?
        .into_iter()
        .find(|current| current.path == field.path)
        .ok_or("List no longer exists")?;
    let mut value = current.value.parse::<Value>().map_err(|e| e.to_string())?;
    let array = value.as_array_mut().ok_or("Field is not a list")?;
    match edit {
        ListEdit::Add => {
            array.push("");
        }
        ListEdit::Remove(index) => {
            if index >= array.len() {
                return Err("List item no longer exists".into());
            }
            array.remove(index);
        }
        ListEdit::Set(index, input) => {
            let original = array.get(index).ok_or("List item no longer exists")?;
            let replacement = if original.is_str() {
                Value::from(input)
            } else {
                input.parse::<Value>().map_err(|e| e.to_string())?
            };
            array.replace(index, replacement);
        }
    }
    set_field(text, field, &value.to_string())
}

pub fn list_items(field: &Field) -> Result<Vec<String>, String> {
    let value = field.value.parse::<Value>().map_err(|e| e.to_string())?;
    Ok(value
        .as_array()
        .ok_or("Field is not a list")?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| item.to_string())
        })
        .collect())
}
