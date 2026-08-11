//! 入出力分離検証（規範 §5.4）。
//!
//! 出力 path は入力 file・入力 directory 配下・入力と同一 file identity の hard link
//! であってはならない（規範 §5.4）。該当する場合は解析開始前に Exit Code 4 で停止する。
//!
//! 既存出力の上書きは既定で禁止する。`--overwrite` 指定時だけ通常 file への置換を
//! 許可し、出力先 symlink は常に拒否する。

use std::fs;
use std::path::{Path, PathBuf};

/// 入出力分離検証の失敗（規範 §5.4 違反、Exit Code 4）。
#[derive(Debug, Clone, thiserror::Error)]
pub enum IoSafetyError {
    /// 出力 path が入力 directory 配下にある（規範 §5.4）。
    #[error("出力 path が入力 directory 配下にある: output={output}, input_root={input_root}")]
    OutputInsideInput {
        output: PathBuf,
        input_root: PathBuf,
    },
    /// 出力 path が入力 file と同一である（規範 §5.4）。
    #[error("出力 path が入力 file と同一である: {0}")]
    OutputSameAsInput(PathBuf),
    /// 出力 path が入力と同一 file identity（hard link）である（規範 §5.4）。
    #[error(
        "出力 path が入力と同一 file identity である（hard link）: output={output}, input={input}"
    )]
    OutputHardLinkedToInput { output: PathBuf, input: PathBuf },
    /// 出力先が symlink である（規範 §5.4: symlink 常時拒否）。
    #[error("出力先が symlink である: {0}")]
    OutputIsSymlink(PathBuf),
    /// 出力先が既存だが overwrite が許可されていない（規範 §5.4）。
    #[error("出力先が既存だが overwrite 未許可: {0}")]
    OutputExistsNoOverwrite(PathBuf),
}

/// 出力 path と入力 root の重複を検査する（規範 §5.4）。
///
/// - `input_root`: 入力 directory または入力 file の path
/// - `output_path`: 出力先 path
/// - `overwrite`: `--overwrite` 指定の有無
///
/// 次の場合に [`IoSafetyError`] を返す:
/// 1. 出力が入力 directory 配下にある
/// 2. 出力が入力 file と同一 path
/// 3. 出力が入力と同一 file identity（hard link）
/// 4. 出力先が symlink（`overwrite` に関わらず常時拒否）
/// 5. 出力先が既存の通常 file で、`overwrite` が未指定
pub fn verify_io_separation(
    input_root: &Path,
    output_path: &Path,
    overwrite: bool,
) -> Result<(), IoSafetyError> {
    // 1. 出力が入力配下または同一かを正規化して判定する。
    let input_canonical = canonicalize(input_root).unwrap_or_else(|_| input_root.to_path_buf());
    let output_canonical = canonicalize(output_path).unwrap_or_else(|_| output_path.to_path_buf());

    // 出力 == 入力の完全一致。
    if output_canonical == input_canonical {
        return Err(IoSafetyError::OutputSameAsInput(output_path.to_path_buf()));
    }

    // 出力が入力 directory 配下にあるか。
    if output_canonical.starts_with(&input_canonical) {
        return Err(IoSafetyError::OutputInsideInput {
            output: output_path.to_path_buf(),
            input_root: input_root.to_path_buf(),
        });
    }

    // 2. 出力先が symlink なら常時拒否（規範 §5.4）。
    if let Ok(meta) = fs::symlink_metadata(output_path)
        && meta.is_symlink()
    {
        return Err(IoSafetyError::OutputIsSymlink(output_path.to_path_buf()));
    }

    // 3. 出力先が既存で overwrite 未許可の場合は拒否（規範 §5.4）。
    if !overwrite && output_path.exists() {
        return Err(IoSafetyError::OutputExistsNoOverwrite(
            output_path.to_path_buf(),
        ));
    }

    // 4. hard link 検出: 入力と出力が同一 file identity を持つか（規範 §5.4）。
    if let Some(input_id) = file_identity(input_root)
        && let Some(output_id) = file_identity(output_path)
        && input_id == output_id
    {
        return Err(IoSafetyError::OutputHardLinkedToInput {
            output: output_path.to_path_buf(),
            input: input_root.to_path_buf(),
        });
    }

    Ok(())
}

/// path を canonical 化する（symlink を解決しない best effort）。
fn canonicalize(path: &Path) -> Result<PathBuf, ()> {
    // symlink_metadata で symlink か確認し、symlink でなければ canonicalize。
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_symlink() => {
            // symlink の場合は canonicalize で解決先を得る。
            fs::canonicalize(path).map_err(|_| ())
        }
        Ok(_) => fs::canonicalize(path).map_err(|_| ()),
        Err(_) => {
            // 存在しない path は親 directory の canonical + 残り path で近似する。
            if let Some(parent) = path.parent()
                && let Ok(parent_canon) = fs::canonicalize(parent)
                && let Some(file_name) = path.file_name()
            {
                return Ok(parent_canon.join(file_name));
            }
            Err(())
        }
    }
}

/// file identity（Unix: (dev, ino)、Windows: size + mtime の近似）を取得する。
#[cfg(unix)]
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::metadata(path).ok()?;
    Some((meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    // Windows では (size, mtime_nanos) の組で近似する。
    let meta = fs::metadata(path).ok()?;
    let mtime_nanos = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    Some((meta.len(), mtime_nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_output_inside_input() {
        // 規範 §5.4・§21-9: input directory 内 output を拒否する。
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path();
        let output = input.join("results.json");

        let result = verify_io_separation(input, &output, false);
        assert!(matches!(
            result,
            Err(IoSafetyError::OutputInsideInput { .. })
        ));
    }

    #[test]
    fn rejects_output_same_as_input() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("file.evtx");
        fs::write(&input, b"data").unwrap();

        let result = verify_io_separation(&input, &input, false);
        assert!(matches!(result, Err(IoSafetyError::OutputSameAsInput(_))));
    }

    #[test]
    fn rejects_output_symlink_always() {
        // 規範 §5.4: 出力先 symlink は overwrite に関わらず常時拒否。
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let dir = tempfile::tempdir().unwrap();
            let input = dir.path().join("input");
            fs::create_dir(&input).unwrap();
            let target = dir.path().join("result.json");
            fs::write(&target, b"").unwrap();
            let link = dir.path().join("output.json");
            symlink(&target, &link).unwrap();

            let result = verify_io_separation(&input, &link, true);
            assert!(matches!(result, Err(IoSafetyError::OutputIsSymlink(_))));
        }
    }

    #[test]
    fn rejects_existing_output_without_overwrite() {
        // 規範 §5.4: 既定で上書き禁止。
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        fs::create_dir(&input).unwrap();
        let output = dir.path().join("output.json");
        fs::write(&output, b"existing").unwrap();

        let result = verify_io_separation(&input, &output, false);
        assert!(matches!(
            result,
            Err(IoSafetyError::OutputExistsNoOverwrite(_))
        ));
    }

    #[test]
    fn allows_existing_output_with_overwrite() {
        // 規範 §5.4: --overwrite 指定時は通常 file の置換を許可。
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        fs::create_dir(&input).unwrap();
        let output = dir.path().join("output.json");
        fs::write(&output, b"existing").unwrap();

        let result = verify_io_separation(&input, &output, true);
        assert!(result.is_ok());
    }

    #[test]
    fn allows_non_overlapping_output() {
        // 入力と出力が完全に分離している場合は OK。
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        fs::create_dir(&input).unwrap();
        let output = dir.path().join("output.json");

        let result = verify_io_separation(&input, &output, false);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_hard_link_to_input() {
        // 規範 §5.4: 入力と同一 file identity の hard link を拒否。
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let input = dir.path().join("input.evtx");
            fs::write(&input, b"data").unwrap();
            let hard_link = dir.path().join("output.json");
            fs::hard_link(&input, &hard_link).unwrap();

            let result = verify_io_separation(&input, &hard_link, true);
            assert!(matches!(
                result,
                Err(IoSafetyError::OutputHardLinkedToInput { .. })
            ));
        }
    }

    #[test]
    fn allows_nested_output_outside_input() {
        // 入力の外にある directory 配下の出力は OK。
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        fs::create_dir(&input).unwrap();
        let output_dir = dir.path().join("output");
        fs::create_dir(&output_dir).unwrap();
        let output = output_dir.join("result.json");

        let result = verify_io_separation(&input, &output, false);
        assert!(result.is_ok());
    }
}
