// criterion benchmark 雏形（T0-011、F-026）
//
// Phase 1 以降で core の各関数（決定的 ID 生成・canonical JSON・
// Windows path 正規化など）の benchmark を追加する。
// Phase 0 では、benchmark がビルド・実行できることのみ確認する。

use criterion::{Criterion, black_box, criterion_group, criterion_main};

fn smoke_benchmark(c: &mut Criterion) {
    // Phase 1 で実装する関数の benchmark を追加する。
    // black_box で最適化を抑止する典型的な criterion の使い方を示す雏形。
    c.bench_function("smoke", |b| b.iter(|| black_box(1u32 + 1u32)));
}

criterion_group!(benches, smoke_benchmark);
criterion_main!(benches);
