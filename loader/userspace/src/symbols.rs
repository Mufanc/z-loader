use std::fs;
use std::path::Path;
use anyhow::{bail, Context, Result};
use object::{File, Object, ObjectKind, ObjectSection, ObjectSymbol};

pub fn resolve<P : AsRef<Path>>(library: P, name: &str) -> Result<usize> {
    let data = fs::read(library)?;
    let object = File::parse(data.as_slice())?;

    object.dynamic_symbols().chain(object.symbols())
        .find_map(|sym| {
            if sym.name() == Ok(name) {
                Some(sym.address() as usize)
            } else {
                None
            }
        })
        .context(format!("failed to resolve symbol {name}"))
}

pub fn resolve_for_uprobe<P : AsRef<Path>>(library: P, name: &str) -> Result<u64> {
    let data = fs::read(library)?;

    fn internal(data: &[u8], name: &str, mirror: Option<&File>) -> Result<u64> {
        let object = File::parse(data)?;
        let mut symbols = object.dynamic_symbols().chain(object.symbols());

        if let Some(symbol) = symbols.find(|sym| sym.name() == Ok(name)) {
            return Ok(match object.kind() {
                ObjectKind::Dynamic | ObjectKind::Executable => {
                    let index = symbol.section_index()
                        .context(format!("symbol `{name}` does not appear in section"))?;

                    let section = if let Some(mirror) = mirror {
                        let name = object.section_by_index(index)?.name()?;
                        mirror
                            .section_by_name(name)
                            .context(format!("can't find section `{name}` in mirror"))?
                    } else {
                        object.section_by_index(index)?
                    };

                    let (offset, _length) = section.file_range()
                        .context(format!("symbol `{name}` in section `{:?}` which has no offset", section.name()?))?;

                    symbol.address() - section.address() + offset
                }
                _ => symbol.address()
            })
        }

        if let Some(section) = object.section_by_name(".gnu_debugdata") {
            let mut buffer: &[u8] = section.data()?;
            let mut inner = Vec::new();

            lzma_rs::xz_decompress(&mut buffer, &mut inner)?;

            return internal(&inner, name, Some(&object));
        }

        bail!("failed to resolve symbol `{name}`")
    }

    internal(&data, name, None)
}
