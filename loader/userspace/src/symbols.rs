use std::{fmt, fs};
use std::path::Path;
use anyhow::{bail, Context, Result};
use cpp_demangle::{DemangleOptions, DemangleWrite, Symbol};
use object::{File, Object, ObjectKind, ObjectSection, ObjectSymbol};

pub struct ArgCounter {
    count: usize
}

impl DemangleWrite for ArgCounter {
    fn write_string(&mut self, s: &str) -> fmt::Result {
        match s.trim() {
            "(" => self.count = 0,
            "," => self.count += 1,
            _ => ()
        }

        Ok(())
    }
}

impl ArgCounter {
    fn new() -> Self {
        Self { count: 0 }
    }

    pub fn count(sym: &str) -> Result<usize> {
        let sym = Symbol::new(sym)?;
        let mut counter = Self::new();

        sym.structured_demangle(&mut counter, &DemangleOptions::default())?;

        Ok(counter.count + 1)
    }
}

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

pub fn resolve_for_uprobe<P : AsRef<Path>>(library: P, prefix: &str) -> Result<(String, u64)> {
    let data = fs::read(library)?;

    fn internal(data: &[u8], prefix: &str, mirror: Option<&File>) -> Result<(String, u64)> {
        let object = File::parse(data)?;

        let mut symbols = object.dynamic_symbols().chain(object.symbols());
        let symbol = symbols.find(|sym| sym.name().is_ok_and(|name| name.starts_with(prefix)));

        if let Some(symbol) = symbol {
            let name: String = symbol.name()?.into();
            let addr = match object.kind() {
                ObjectKind::Dynamic | ObjectKind::Executable => {
                    let index = symbol.section_index()
                        .context(format!("symbol `{prefix}` does not appear in section"))?;

                    let section = if let Some(mirror) = mirror {
                        let name = object.section_by_index(index)?.name()?;
                        mirror
                            .section_by_name(name)
                            .context(format!("can't find section `{name}` in mirror"))?
                    } else {
                        object.section_by_index(index)?
                    };

                    let (offset, _length) = section.file_range()
                        .context(format!("symbol `{prefix}` in section `{:?}` which has no offset", section.name()?))?;

                    symbol.address() - section.address() + offset
                }
                _ => symbol.address()
            };
            
            return Ok((name, addr))
        }

        if let Some(section) = object.section_by_name(".gnu_debugdata") {
            let mut buffer: &[u8] = section.data()?;
            let mut inner = Vec::new();

            lzma_rs::xz_decompress(&mut buffer, &mut inner)?;

            return internal(&inner, prefix, Some(&object));
        }

        bail!("failed to resolve symbol `{prefix}`")
    }

    internal(&data, prefix, None)
}
