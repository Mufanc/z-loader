use std::collections::HashSet;
use std::ffi::CStr;
use std::path::PathBuf;
use std::sync::{mpsc, Mutex};
use std::thread;
use std::thread::{Builder};
use std::time::Duration;

use anyhow::{bail, Result};
use libc::c_char;
use log::{debug, error, info, LevelFilter, warn};
use notify::{Config, Event, EventKind, INotifyWatcher, RecursiveMode, Watcher};
use notify::event::ModifyKind;
use rusqlite::{Connection, OpenFlags};

use common::debug_select;
use common::lazy::Lazy;

const SYSTEM_UID: libc::uid_t = 1000;
const PARASITIC_PACKAGE: &str = "com.android.shell";
const MANAGER_PACKAGE: &str = "org.lsposed.manager"; 

const PER_USER_RANGE: libc::uid_t = 100000;

const DATABASE: &str = "/data/adb/lspd/config/modules_config.db";

const SQL: &str = "
SELECT DISTINCT s.app_pkg_name, s.user_id
FROM scope s
INNER JOIN modules m ON s.mid = m.mid
WHERE m.enabled = 1
";

#[derive(Debug, Eq, PartialEq, Hash)]
struct ScopeInfo {
    pkg: String,
    user: libc::uid_t
}

struct ScopeMonitor {
    database: String,
    conn: Option<Connection>
}

impl ScopeMonitor {
    fn new(database: &str) -> Self {
        Self {
            database: database.into(),
            conn: None
        }
    }

    fn setup(&mut self, callback: impl Fn(Vec<ScopeInfo>)) -> Result<()> {
        if let Ok(scope) = self.read_scope() {
            callback(scope)
        }

        let (tx, rx) = mpsc::channel();

        let database = PathBuf::from(&self.database);
        let database_wal = PathBuf::from(format!("{}-wal", &self.database));
        let dir: PathBuf = database.parent().unwrap().into();

        let tx_clone = tx.clone();
        let mut watcher =  INotifyWatcher::new(
            move |ev: notify::Result<Event>| {
                debug!("inotify event: {ev:?}");
                
                match ev {
                    Ok(Event { kind: EventKind::Modify(ModifyKind::Data(_)), paths, .. }) => {
                        if paths.contains(&database) || paths.contains(&database_wal) {
                            tx_clone.send(false).unwrap()
                        }
                    }
                    Err(err) => warn!("inotify error: {err}"),
                    _ => ()
                }
            },
            Config::default()
        )?;

        watcher.watch(dir.as_ref(), RecursiveMode::NonRecursive)?;

        let mut debounce = false;
        while let Ok(delayed) = rx.recv() {
            if delayed {
                debounce = false;
                if let Ok(scope) = self.read_scope() {
                    callback(scope)
                }
            } else if !debounce {
                thread::sleep(Duration::from_secs(1));
                debounce = true;
                tx.send(true).unwrap();
            }
        }

        bail!("closed channel");
    }

    fn read_scope(&mut self) -> Result<Vec<ScopeInfo>> {
        let res = try {
            if self.conn.is_none() {
                let conn = Connection::open_with_flags(
                    &self.database,
                    OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX
                )?;
                let _ = conn.prepare("SELECT name FROM sqlite_master WHERE type='table'")?;
                self.conn.replace(conn);
            }

            let conn = self.conn.as_ref().unwrap();

            let mut cursor = conn.prepare(SQL)?;
            let scope = cursor.query_map([], |row| {
                Ok(ScopeInfo { pkg: row.get(0)?, user: row.get(1)? })
            })?;

            scope.flatten().collect()
        };

        #[cfg(debug_assertions)]
        if let Err(err) = &res {
            warn!("failed to load database: {err}");
        }

        res
    }
}

static INIT_LOGGER: Lazy<()> = Lazy::new(|| {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(debug_select!(LevelFilter::Trace, LevelFilter::Info))
            .with_tag("ZLoader-LSPosed")
    );
}) ;

static G_SCOPE: Lazy<Mutex<HashSet<ScopeInfo>>> = Lazy::new(|| {
    let _ = Builder::new()
        .name("scope monitor".into())
        .spawn(|| {
            info!("scope monitor thread spawned: {}", unsafe { libc::gettid() });

            let mut monitor = ScopeMonitor::new(DATABASE);
            let res = monitor.setup(|scope| {
                info!("scope updated: {scope:?}");
                let mut lock = G_SCOPE.lock().unwrap();
                scope.into_iter().for_each(|info| { lock.insert(info); });
            });

            if let Err(err) = res {
                error!("database monitor exited unexpectedly: {err}");
            }
        });

    Mutex::new(HashSet::new())
});

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn check_process(uid: libc::uid_t, pkg: *const c_char, _name: *const c_char) -> bool {
    let _ = &*INIT_LOGGER;
    let _ = &*G_SCOPE;

    if uid == SYSTEM_UID {
        return true
    }

    if !pkg.is_null() {
        let user = uid / PER_USER_RANGE;
        let pkg = unsafe { CStr::from_ptr(pkg).to_str().unwrap() };
        
        if pkg == PARASITIC_PACKAGE || pkg == MANAGER_PACKAGE {
            return true
        }
        
        let lock = G_SCOPE.lock().unwrap();
        if lock.contains(&ScopeInfo { pkg: pkg.into(), user }) {
            return true
        }
    }

    false
}
