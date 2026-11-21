use std::io;
use std::path::Path;
use std::time::UNIX_EPOCH;

use anyhow::Result;
use fs_err as fs;
use tempfile::tempdir;

use uv_cache::Cache;
use uv_cache_info::Timestamp;
use uv_trampoline_builder::{WindowMode, windows_python_launcher, windows_script_launcher};

use super::{mocked_interpreter_response, unexpected_probe};
use crate::Interpreter;
use crate::interpreter::{
    CacheTarget, Error, ExecutableTarget, InterpreterInfo, LinkSnapshot, canonicalize_executable,
};

#[cfg(target_pointer_width = "64")]
fn wow64_executable(windows: &Path) -> io::Result<Option<std::path::PathBuf>> {
    use uv_fs::wow64::FileSystemView;

    let exe = windows.join(r"SysWOW64\cmd.exe");
    if !exe.try_exists()? {
        // WOW64 is an optional component on Windows Server.
        return Ok(None);
    }
    let view = FileSystemView::for_executable(&exe);
    assert!(matches!(view, FileSystemView::Bit32), "{view:?}");
    Ok(Some(exe))
}

#[test]
fn link_snapshot_requires_reaching_the_canonical_path() -> Result<()> {
    let dir = tempdir()?;
    let base = dir.path().join("python.exe");
    fs::write(&base, [])?;
    let canonical = dunce::canonicalize(&base)?;
    // An alternate name can identify the same file without exposing any
    // link whose timestamps would track the mapping (e.g., a subst drive).
    let alias = dir.path().join("alias.exe");
    fs::hard_link(&base, &alias)?;
    assert!(LinkSnapshot::capture(&alias, &canonical).is_none());
    Ok(())
}

#[tokio::test]
async fn launcher_junction_restored_after_probe() -> Result<()> {
    use fs_err::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_WRITE_ATTRIBUTES};

    let dir = tempdir()?;
    let proxy = dir.path().join("python.exe");
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    let current = dir.path().join("current");
    let managed = dir.path().join("managed");
    fs::create_dir(&managed)?;
    let minor = managed.join("minor");
    for installation in [&first, &second] {
        fs::create_dir(installation)?;
        fs::write(installation.join("python.exe"), [])?;
    }
    uv_fs::replace_symlink(&first, &minor)?;
    uv_fs::replace_symlink(&minor, &current)?;
    let target = current.join("python.exe");
    fs::write(
        &proxy,
        windows_python_launcher(&target, WindowMode::Console)?,
    )?;
    let cache = Cache::temp()?.init().await?;
    let identified = ExecutableTarget::identify(&proxy).expect("executable target");
    let resolved = identified.for_cache(&proxy)?.expect("cache target");
    let entry = resolved.cache_entry(&cache);
    // Ensure the directory update is observable even within a single clock tick.
    fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES.0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(&managed)?
        .set_modified(UNIX_EPOCH)?;
    let probe = || {
        let mut response = mocked_interpreter_response(&proxy).expect("Valid mocked metadata");
        response.metadata.sys_base_executable = Some(target.clone());
        response.metadata.sys_base_prefix = dunce::canonicalize(&current)?;
        Ok::<_, Error>((response, None))
    };
    let info = InterpreterInfo::query_cached(&proxy, &cache, || {
        // Move the original junction back with its own timestamps intact.
        let saved = managed.join("saved");
        fs::rename(&minor, &saved)?;
        uv_fs::create_symlink(&second, &minor)?;
        let result = probe()?;
        uv_fs::remove_symlink(&minor)?;
        fs::rename(&saved, &minor)?;
        Ok(result)
    })?;
    assert_eq!(info.metadata.sys_base_prefix, dunce::canonicalize(&second)?);
    assert_eq!(canonicalize_executable(&proxy)?, resolved.canonical);
    assert!(!entry.path().exists());

    InterpreterInfo::query_cached(&proxy, &cache, probe)?;
    let info = InterpreterInfo::query_cached(&proxy, &cache, unexpected_probe)?;
    assert_eq!(info.metadata.sys_base_prefix, dunce::canonicalize(&first)?);
    Ok(())
}

#[tokio::test]
async fn launcher_junction_moves_during_probe() -> Result<()> {
    let dir = tempdir()?;
    let proxy = dir.path().join("python.exe");
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    let link = dir.path().join("current");
    fs::create_dir(&first)?;
    fs::create_dir(&second)?;
    fs::write(first.join("python.exe"), [])?;
    fs::write(second.join("python.exe"), [])?;
    uv_fs::replace_symlink(&first, &link)?;
    fs::write(
        &proxy,
        windows_python_launcher(link.join("python.exe"), WindowMode::Console)?,
    )?;
    let cache = Cache::temp()?.init().await?;
    let identified = ExecutableTarget::identify(&proxy).expect("executable target");
    let resolved = identified.for_cache(&proxy)?.expect("cache target");
    assert_eq!(
        resolved.canonical,
        dunce::canonicalize(first.join("python.exe"))?
    );
    let mut response = mocked_interpreter_response(&proxy)?;
    response.metadata.sys_base_executable = Some(resolved.canonical.clone());
    InterpreterInfo::query_cached(&proxy, &cache, || {
        // A minor-version update can move the junction while both the
        // proxy and the interpreter that answered the probe stay intact.
        uv_fs::replace_symlink(&second, &link)?;
        Ok((response, None))
    })?;

    assert_eq!(
        canonicalize_executable(&proxy)?,
        dunce::canonicalize(second.join("python.exe"))?
    );
    let entry = resolved.cache_entry(&cache);
    assert!(!entry.path().exists());
    Ok(())
}

#[cfg(target_pointer_width = "64")]
#[test]
fn redirected_config_with_native_python_and_wow64_launcher() -> Result<()> {
    let windows = std::env::var_os("SystemRoot").expect("Windows directory");
    let windows = Path::new(&windows);
    let Some(launcher) = wow64_executable(windows)? else {
        return Ok(());
    };
    let metadata = mocked_interpreter_response(&launcher)?.metadata;
    assert!(metadata.pointer_size.is_64());
    // Model a proxy checking for a config under System32 before it sets
    // __PYVENV_LAUNCHER__ for the native Python process.
    let inputs = std::collections::HashMap::from([(windows.join(r"System32\pyvenv.cfg"), None)]);
    assert!(!metadata.shares_cache_inputs(&launcher, &inputs));
    Ok(())
}

#[cfg(target_pointer_width = "64")]
#[tokio::test]
async fn redirected_inputs_bypass_interpreter_cache() -> Result<()> {
    use crate::PointerSize::_32 as Bits32;

    // A native launcher can start a 32-bit process. Use an existing
    // executable as its target so the test needs no writes to System32.
    let windows = std::env::var_os("SystemRoot").expect("Windows directory");
    let target = Path::new(&windows).join(r"System32\cmd.exe");
    let dir = tempdir()?;
    let executable = dir.path().join("proxy.exe");
    fs::write(
        &executable,
        windows_python_launcher(&target, WindowMode::Console)?,
    )?;
    let cache = Cache::temp()?.init().await?;
    let entry = ExecutableTarget::identify(&executable)
        .expect("executable target")
        .for_cache(&executable)?
        .expect("cache target")
        .cache_entry(&cache);
    let mut response = mocked_interpreter_response(&executable)?;
    response.metadata.sys_base_executable = Some(target.clone());
    response.metadata.pointer_size = Bits32;
    let info = InterpreterInfo::query_cached(&executable, &cache, || Ok((response, None)))?;
    assert!(!entry.path().exists());

    // Seed the incompatible response directly to check that cache reads reject it.
    fs::create_dir_all(entry.dir())?;
    fs::write(entry.path(), rmp_serde::to_vec(&info)?)?;
    let mut native = mocked_interpreter_response(&executable)?;
    native.metadata.sys_base_executable = Some(target);
    let info = InterpreterInfo::query_cached(&executable, &cache, || Ok((native, None)))?;
    assert!(info.metadata.pointer_size.is_64());
    InterpreterInfo::query_cached(&executable, &cache, unexpected_probe)?;
    Ok(())
}

#[tokio::test]
async fn launcher_probe_reports_a_separate_junction() -> Result<()> {
    let dir = tempdir()?;
    let proxy = dir.path().join("python.exe");
    let shim = dir.path().join("shim");
    let installation = dir.path().join("installation");
    for home in [&shim, &installation] {
        fs::create_dir(home)?;
        fs::write(home.join("python.exe"), [])?;
    }
    fs::write(
        &proxy,
        windows_python_launcher(r"shim\python.exe", WindowMode::Console)?,
    )?;
    let alias = dir.path().join("alias");
    uv_fs::create_symlink(&installation, &alias)?;
    let reported = alias.join("python.exe");
    let identified = ExecutableTarget::identify(&proxy).expect("executable target");
    let resolved = identified.for_cache(&proxy)?.expect("cache target");
    assert_ne!(dunce::canonicalize(&reported)?, resolved.canonical);
    let cache = Cache::temp()?.init().await?;
    let mut response = mocked_interpreter_response(&proxy)?;
    response.metadata.sys_base_executable = Some(reported.clone());
    InterpreterInfo::query_cached(&proxy, &cache, || {
        // The shim runs Python through its own junction. By the time the
        // probe returns, that path can identify the shim itself.
        uv_fs::replace_symlink(&shim, &alias)?;
        Ok((response, None))
    })?;
    assert_eq!(dunce::canonicalize(&reported)?, resolved.canonical);
    assert!(!resolved.cache_entry(&cache).path().exists());
    Ok(())
}

#[tokio::test]
async fn nested_launcher_bypasses_cache() -> Result<()> {
    use std::env;
    use std::path::PathBuf;

    use uv_cache_key::cache_digest;
    use uv_static::EnvVars;

    let dir = tempdir()?;
    let proxy = dir.path().join("python.exe");
    let target = dir.path().join("inner.exe");
    let base = dir.path().join("base.exe");
    fs::write(&base, [])?;
    fs::write(
        &proxy,
        windows_python_launcher(&target, WindowMode::Console)?,
    )?;
    fs::write(
        &target,
        windows_python_launcher("base.exe", WindowMode::Console)?,
    )?;
    let cache = Cache::temp()?.init().await?;
    let identified = ExecutableTarget::identify(&proxy).expect("executable target");
    let resolved = identified.for_cache(&proxy)?.expect("cache target");
    let entry = resolved.cache_entry(&cache);
    let mut response = mocked_interpreter_response(&proxy)?;
    response.metadata.sys_base_executable = Some(base.clone());
    let info = InterpreterInfo::query_cached(&proxy, &cache, || Ok((response, None)))?;
    assert!(!entry.path().exists());

    // Older entries for an absolute target track both proxies. Their timestamps
    // can remain fresh after the final interpreter changes.
    let digest = cache_digest(&(
        proxy.as_path(),
        resolved.canonical.as_path(),
        env::var_os(EnvVars::PYTHONEXECUTABLE).map(PathBuf::from),
        env::var_os(EnvVars::PYVENV_LAUNCHER).map(PathBuf::from),
    ));
    let legacy = entry.with_file(format!("{digest}.msgpack"));
    assert_bypasses_fresh_entry(&cache, &legacy, &proxy, &info)?;

    // A third-party shim can redirect Python without any uv resources.
    fs::write(&target, [])?;
    for reported_base in [None, Some(base)] {
        let mut response = mocked_interpreter_response(&proxy)?;
        response.metadata.sys_base_executable = reported_base;
        InterpreterInfo::query_cached(&proxy, &cache, || Ok((response, None)))?;
        assert!(!entry.path().exists());
    }

    Ok(())
}

#[tokio::test]
async fn retargeted_launcher_does_not_reuse_a_removed_alias() -> Result<()> {
    let dir = tempdir()?;
    let proxy = dir.path().join("python.exe");
    let home = dir.path().join("home");
    let link = dir.path().join("link");
    fs::create_dir(&home)?;
    let base = home.join("python.exe");
    fs::write(&base, [])?;
    uv_fs::create_symlink(&home, &link)?;
    let cache = Cache::temp()?.init().await?;

    // Both relative targets resolve to the same file. Replacing a launcher
    // from an archive can also give both versions the same modification time.
    let retarget = |relative: &str| -> Result<_> {
        fs::write(
            &proxy,
            windows_python_launcher(relative, WindowMode::Console)?,
        )?;
        fs::OpenOptions::new()
            .write(true)
            .open(&proxy)?
            .set_modified(UNIX_EPOCH)?;
        let mut response = mocked_interpreter_response(&proxy)?;
        response.metadata.sys_base_executable = Some(dir.path().join(relative));
        InterpreterInfo::query_cached(&proxy, &cache, || Ok((response, None)))?;
        let info = InterpreterInfo::query_cached(&proxy, &cache, unexpected_probe)?;
        Ok(info.metadata.sys_base_executable)
    };
    assert_eq!(retarget(r"link\python.exe")?, Some(link.join("python.exe")));
    uv_fs::remove_symlink(&link)?;
    assert_eq!(retarget(r"home\python.exe")?, Some(base));
    Ok(())
}

#[tokio::test]
async fn junction_selects_venvs_with_a_shared_proxy() -> Result<()> {
    let cache = Cache::temp()?.init().await?;
    let dir = tempdir()?;
    let active = dir.path().join("active");
    let proxy = active.join(r"Scripts\python.exe");
    let base = dir.path().join("python.exe");
    fs::write(&base, [])?;
    let scripts = dir.path().join("scripts");
    fs::create_dir(&scripts)?;
    fs::write(
        scripts.join("python.exe"),
        windows_python_launcher(r"..\..\python.exe", WindowMode::Console)?,
    )?;
    // Both venvs reach the same launcher and interpreter, but each has
    // its own configuration despite identical modification times.
    for include_site in [false, true] {
        let venv = dir.path().join(include_site.to_string());
        fs::create_dir(&venv)?;
        uv_fs::create_symlink(&scripts, venv.join("Scripts"))?;
        let config = venv.join("pyvenv.cfg");
        fs::write(
            &config,
            format!("include-system-site-packages = {include_site}\n"),
        )?;
        fs::OpenOptions::new()
            .write(true)
            .open(&config)?
            .set_modified(UNIX_EPOCH)?;
        uv_fs::replace_symlink(&venv, &active)?;
        let mut response = mocked_interpreter_response(&proxy)?;
        response.metadata.sys_base_executable = Some(base.clone());
        if !include_site {
            response.metadata.sys_path.clear();
        }
        let expected = response.metadata.sys_path.clone();
        InterpreterInfo::query_cached(&proxy, &cache, || Ok((response, None)))?;
        let info = InterpreterInfo::query_cached(&proxy, &cache, unexpected_probe)?;
        assert_eq!(info.metadata.sys_path, expected);
    }
    Ok(())
}

#[tokio::test]
async fn script_replacing_proxy_bypasses_cache() -> Result<()> {
    let dir = tempdir()?;
    let executable = dir.path().join("python.exe");
    let target = dir.path().join("base.exe");
    fs::write(&target, [])?;
    let replace = |bytes| -> io::Result<()> {
        fs::write(&executable, bytes)?;
        fs::OpenOptions::new()
            .write(true)
            .open(&executable)?
            .set_modified(UNIX_EPOCH)
    };
    let cache = Cache::temp()?.init().await?;
    let mut probes = 0;
    let mut probe = || {
        probes += 1;
        let mut response = mocked_interpreter_response(&executable).expect("Valid mocked metadata");
        response.metadata.sys_base_executable = Some(target.clone());
        Ok((response, None))
    };

    replace(windows_python_launcher("base.exe", WindowMode::Console)?)?;
    InterpreterInfo::query_cached(&executable, &cache, &mut probe)?;
    InterpreterInfo::query_cached(&executable, &cache, unexpected_probe)?;

    // The script runs its own entry point even with the same interpreter
    // path and modification time as the cached proxy.
    replace(windows_script_launcher(
        "print('script')",
        false,
        "base.exe",
    )?)?;
    InterpreterInfo::query_cached(&executable, &cache, &mut probe)?;
    InterpreterInfo::query_cached(&executable, &cache, probe)?;
    assert_eq!(probes, 3);

    // Eviction has no entry to remove even after the interpreter disappears.
    fs::remove_file(&target)?;
    Interpreter::clear_cache(&executable, &cache)?;
    let Err(Error::BrokenLink(link)) = Interpreter::query(&executable, &cache) else {
        anyhow::bail!("expected a broken script launcher");
    };
    assert_eq!(link.target(), Some(target.as_path()));
    Ok(())
}

#[tokio::test]
async fn venv_proxy_caches_a_real_interpreter_probe() -> Result<()> {
    let cache = Cache::temp()?.init().await?;
    let python = Interpreter::query(which::which("python")?, &cache)?;
    let base = dunce::canonicalize(python.to_base_python()?)?;
    let home = base.parent().expect("base interpreter directory");
    let dir = tempdir()?;
    let scripts = dir.path().join("Scripts");
    fs::create_dir(&scripts)?;
    fs::write(
        dir.path().join("pyvenv.cfg"),
        format!(
            "home = {}\ninclude-system-site-packages = false\n",
            home.display()
        ),
    )?;
    let proxy = scripts.join("python.exe");
    fs::write(&proxy, windows_python_launcher(&base, WindowMode::Console)?)?;
    assert_eq!(canonicalize_executable(&proxy)?, base);

    let interpreter = Interpreter::query(&proxy, &cache)?;
    assert!(interpreter.is_virtualenv());
    assert!(same_file::is_same_file(
        interpreter.sys_executable(),
        &proxy
    )?);
    assert_eq!(dunce::canonicalize(interpreter.to_base_python()?)?, base);
    InterpreterInfo::query_cached(&proxy, &cache, unexpected_probe)?;
    Ok(())
}

#[tokio::test]
async fn direct_launcher_cache_tracks_target() -> Result<()> {
    let dir = tempdir()?;
    let proxy = dir.path().join("python.exe");
    let target = dir.path().join("base.exe");
    fs::write(&target, [])?;
    fs::write(
        &proxy,
        windows_python_launcher(&target, WindowMode::Console)?,
    )?;
    let cache = Cache::temp()?.init().await?;
    let mut probes = 0;
    let mut probe = || {
        probes += 1;
        let mut response = mocked_interpreter_response(&proxy).expect("Valid mocked metadata");
        response.metadata.sys_base_executable = Some(target.clone());
        Ok((response, None))
    };
    InterpreterInfo::query_cached(&proxy, &cache, &mut probe)?;
    InterpreterInfo::query_cached(&proxy, &cache, unexpected_probe)?;

    fs::OpenOptions::new()
        .write(true)
        .open(&target)?
        .set_modified(UNIX_EPOCH)?;
    InterpreterInfo::query_cached(&proxy, &cache, &mut probe)?;
    InterpreterInfo::query_cached(&proxy, &cache, unexpected_probe)?;

    Interpreter::clear_cache(&proxy, &cache)?;
    InterpreterInfo::query_cached(&proxy, &cache, probe)?;
    assert_eq!(probes, 3);
    Ok(())
}

#[test]
fn existing_target_can_be_probed_when_normalized_path_is_unavailable() -> Result<()> {
    let dir = tempdir()?;
    let proxy = dir.path().join("python.exe");
    fs::write(dir.path().join("base.exe"), [])?;
    fs::write(
        &proxy,
        windows_python_launcher("base.exe", WindowMode::Console)?,
    )?;
    let target = ExecutableTarget::identify(&proxy).expect("valid proxy");
    for error in [io::ErrorKind::PermissionDenied, io::ErrorKind::NotFound] {
        let input = target.cache_input::<()>(&proxy, Err(error.into()))?;
        assert!(input.is_none());
    }
    Ok(())
}

#[test]
fn missing_target_diagnostic_checks_current_launcher() -> Result<()> {
    let dir = tempdir()?;
    let proxy = dir.path().join("python.exe");
    let first = dir.path().join("first.exe");
    let second = dir.path().join("second.exe");
    fs::write(&first, [])?;
    fs::write(&second, [])?;
    fs::write(
        &proxy,
        windows_python_launcher(&first, WindowMode::Console)?,
    )?;
    let target = ExecutableTarget::identify(&proxy).expect("valid proxy");
    let resolve = || target.cache_input(&proxy, target.canonicalize());

    fs::remove_file(&first)?;
    let Err(Error::BrokenLink(link)) = resolve() else {
        anyhow::bail!("expected a broken trampoline");
    };
    assert_eq!(link.path, proxy);
    assert_eq!(link.target(), Some(first.as_path()));

    // The target read before the lookup can belong to a replaced launcher.
    fs::write(
        &proxy,
        windows_python_launcher(&second, WindowMode::Console)?,
    )?;
    assert!(resolve()?.is_none());
    Ok(())
}

#[tokio::test]
async fn proxy_target_removed_during_probe() -> Result<()> {
    let dir = tempdir()?;
    let proxy = dir.path().join("python.exe");
    let target = dir.path().join("base.exe");
    fs::write(&target, [])?;
    fs::write(
        &proxy,
        windows_python_launcher("base.exe", WindowMode::Console)?,
    )?;
    let cache = Cache::temp()?.init().await?;
    let err = InterpreterInfo::query_cached(&proxy, &cache, || {
        // The cache inputs exist when checked, but the proxy can no longer start Python.
        fs::remove_file(&target)?;
        InterpreterInfo::query(&proxy, &cache)
    })
    .unwrap_err();
    let Error::BrokenLink(link) = err else {
        anyhow::bail!("expected a broken proxy, got {err}");
    };
    assert_eq!(link.path, proxy);
    assert_eq!(link.target(), Some(target.as_path()));
    assert!(!target.try_exists()?);
    Ok(())
}

#[tokio::test]
async fn failed_proxy_probe_with_stale_home() -> Result<()> {
    let dir = tempdir()?;
    let scripts = dir.path().join("Scripts");
    fs::create_dir(&scripts)?;
    let proxy = scripts.join("python.exe");
    fs::write(
        &proxy,
        windows_python_launcher("target.exe", WindowMode::Console)?,
    )?;
    // The target exists but cannot answer a Python probe.
    fs::write(scripts.join("target.exe"), [])?;
    fs::write(
        dir.path().join("pyvenv.cfg"),
        format!("home = {}\n", dir.path().join("missing").display()),
    )?;
    let cache = Cache::temp()?.init().await?;
    let err = Interpreter::query(&proxy, &cache).unwrap_err();
    assert!(matches!(err, Error::StatusCode(_)), "{err}");
    Ok(())
}

#[tokio::test]
async fn junction_loop_bypasses_cache() -> Result<()> {
    let dir = tempdir()?;
    let scripts = dir.path().join("Scripts");
    fs::create_dir(&scripts)?;
    let proxy = scripts.join("python.exe");
    let home = dir.path().join("home");
    let target = home.join("python.exe");
    fs::create_dir(&home)?;
    fs::write(&target, [])?;
    fs::write(
        dir.path().join("pyvenv.cfg"),
        format!("home = {}\n", home.display()),
    )?;
    fs::write(
        &proxy,
        windows_python_launcher(r"..\home\python.exe", WindowMode::Console)?,
    )?;
    let cache = Cache::temp()?.init().await?;
    let mut response = mocked_interpreter_response(&proxy)?;
    response.metadata.sys_base_executable = Some(target.clone());
    let cached = InterpreterInfo::query_cached(&proxy, &cache, || Ok((response, None)))?;
    InterpreterInfo::query_cached(&proxy, &cache, unexpected_probe)?;

    // Move a junction onto its own destination, leaving the proxy intact.
    let redirect = dir.path().join("redirect");
    let saved = dir.path().join("saved");
    uv_fs::create_symlink(&home, &redirect)?;
    fs::rename(&home, &saved)?;
    fs::rename(&redirect, &home)?;
    let err = canonicalize_executable(&proxy).unwrap_err();
    assert_ne!(err.kind(), io::ErrorKind::NotFound, "{err}");

    // Project discovery would replace the environment on a broken-link error.
    assert!(home.try_exists().is_err());
    let err = Interpreter::query(&proxy, &cache).unwrap_err();
    assert!(matches!(err, Error::StatusCode(_)), "{err}");

    let prefix = dir.path().join("fresh-probe");
    let mut response = mocked_interpreter_response(&proxy)?;
    response.metadata.sys_prefix = prefix.clone();
    response.metadata.sys_base_executable = Some(target);
    let info = InterpreterInfo::query_cached(&proxy, &cache, || Ok((response, None)))?;
    assert_eq!(info.metadata.sys_prefix, prefix);
    let proxy_entry = proxy_only_entry(&proxy, &cache);
    assert!(!proxy_entry.path().exists());
    Interpreter::clear_cache(&proxy, &cache)?;

    uv_fs::remove_symlink(&home)?;
    fs::rename(&saved, &home)?;
    let after = InterpreterInfo::query_cached(&proxy, &cache, unexpected_probe)?;
    assert_eq!(after.metadata.sys_prefix, cached.metadata.sys_prefix);
    Ok(())
}

#[tokio::test]
async fn unresolved_launcher_bypasses_cache() -> Result<()> {
    let dir = tempdir()?;
    let proxy = dir.path().join("python.exe");
    // The target depends on the current directory for the drive. A venv probe reports
    // the proxy as `sys.executable` regardless of which interpreter actually ran.
    fs::write(
        &proxy,
        windows_python_launcher("C:python.exe", WindowMode::Console)?,
    )?;
    let cache = Cache::temp()?.init().await?;
    let entry = proxy_only_entry(&proxy, &cache);
    let response = mocked_interpreter_response(&proxy)?;
    let mut info = InterpreterInfo::query_cached(&proxy, &cache, || Ok((response, None)))?;
    assert!(!entry.path().exists());

    // Seed an entry keyed on the proxy alone, with a fresh timestamp.
    info.file_timestamps
        .insert(proxy.clone(), Some(Timestamp::from_path(&proxy)?));
    assert_bypasses_fresh_entry(&cache, &entry, &proxy, &info)?;
    Interpreter::clear_cache(&proxy, &cache)?;
    assert!(entry.path().exists());
    Ok(())
}

fn proxy_only_entry(proxy: &Path, cache: &Cache) -> uv_cache::CacheEntry {
    CacheTarget {
        target: &ExecutableTarget {
            absolute: proxy,
            launcher: None,
        },
        canonical: proxy.to_path_buf(),
        launcher: None,
    }
    .cache_entry(cache)
}

fn assert_bypasses_fresh_entry(
    cache: &Cache,
    entry: &uv_cache::CacheEntry,
    proxy: &Path,
    info: &InterpreterInfo,
) -> Result<()> {
    fs::create_dir_all(entry.dir())?;
    fs::write(entry.path(), rmp_serde::to_vec(info)?)?;
    assert!(InterpreterInfo::read_cached(cache, entry, proxy).is_some());
    let mut probed = false;
    let response = mocked_interpreter_response(proxy)?;
    InterpreterInfo::query_cached(proxy, cache, || {
        probed = true;
        Ok((response, None))
    })?;
    assert!(probed);
    Ok(())
}
