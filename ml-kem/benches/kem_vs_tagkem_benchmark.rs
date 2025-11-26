use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand_core::CryptoRng;

use ::kem::{Decapsulate, Encapsulate};
// 引入你的 crate（假设叫 ml_kem）
use ml_kem::*;

// 定义要测试的标签大小（字节）
const TAG_SIZES: &[usize] = &[ 32, 64];

/// 对比标准 KEM 与 Tag-KEM 在指定参数集下的性能
fn kem_vs_tagkem_benchmark(c: &mut Criterion) {
    let mut rng = rand::rng();

    // 测试所有三种参数集
    // bench_kem_vs_tagkem::<MlKem512, TagMlKem512>(c, &mut rng, "ML-KEM-512");
    bench_kem_vs_tagkem::<MlKem768, TagMlKem768>(c, &mut rng, "KEM768");
    // bench_kem_vs_tagkem::<MlKem1024, TagMlKem1024>(c, &mut rng, "ML-KEM-1024");
}

/// 通用函数：对指定 KEM 类型进行性能对比
fn bench_kem_vs_tagkem<K, TK>(c: &mut Criterion, rng: &mut impl CryptoRng, name: &str)
where
    K: KemCore,
    TK: TagBasedKemCore,
    K::EncapsulationKey: Encapsulate<Ciphertext<K>, SharedKey<K>>,
    K::DecapsulationKey: Decapsulate<Ciphertext<K>, SharedKey<K>>,
    TK::TagEncapsulationKey: TagBasedEncapsulate<TagCiphertext<TK>, TagSharedKey<TK>>,
    TK::TagDecapsulationKey: TagBasedDecapsulate<TagCiphertext<TK>, TagSharedKey<TK>>,
{
    let group_name = format!("{}", name);
    let mut group = c.benchmark_group(group_name);

    // === 1. 密钥生成对比 ===
    group.bench_function("kg-std", |b| {
        b.iter_with_large_drop(|| {
            let (dk, ek) = K::generate(rng);
            (dk, ek)
        });
    });

    group.bench_function("kg-tb", |b| {
        b.iter_with_large_drop(|| {
            let (dk, ek) = TK::generate(rng);
            (dk, ek)
        });
    });

    // === 2. 封装性能对比（标准 vs 不同 tag 长度）===
    let (dk_std, ek_std) = K::generate(rng);
    let (dk_tag, ek_tag) = TK::generate(rng);

    // 标准封装
    group.bench_function("enc-std", |b| {
        b.iter_with_large_drop(|| {
            ek_std.encapsulate(rng).unwrap()
        });
    });

    // Tag 封装 —— 测试不同 tag 长度
    for &tag_size in TAG_SIZES {
        let tag: Vec<u8> = vec![0u8; tag_size]; // 使用零填充 tag，实际应用中可以是任意内容
        group.bench_with_input(
            BenchmarkId::new("enc-tb", tag_size),
            &tag,
            |b, tag| {
                b.iter_with_large_drop(|| {
                    ek_tag.encapsulate_with_tag(rng, tag).unwrap()
                });
            },
        );
    }

    // === 3. 解封装性能对比 ===
    // 生成一个标准密文用于测试
    let (ct_std, _) = ek_std.encapsulate(rng).unwrap();
    // 生成一个带空 tag 的密文用于测试 Tag-KEM 解封装
    let (ct_tag, _) = ek_tag.encapsulate_with_tag(rng, b"").unwrap();

    group.bench_function("dec-std", |b| {
        b.iter(|| {
            dk_std.decapsulate(&ct_std).unwrap()
        });
    });

    // 测试不同 tag 长度下的解封装性能
    for &tag_size in TAG_SIZES {
        let tag: Vec<u8> = vec![0u8; tag_size];
        group.bench_with_input(
            BenchmarkId::new("dec-tb", tag_size),
            &tag,
            |b, tag| {
                b.iter(|| {
                    dk_tag.decapsulate_with_tag(&ct_tag, tag).unwrap()
                });
            },
        );
    }

    // === 4. 端到端 round-trip 性能对比 ===
    group.bench_function("round-trip-std", |b| {
        b.iter_with_large_drop(|| {
            let (dk, ek) = K::generate(rng);
            let (ct, _) = ek.encapsulate(rng).unwrap();
            dk.decapsulate(&ct).unwrap()
        });
    });

    for &tag_size in TAG_SIZES {
        let tag: Vec<u8> = vec![0u8; tag_size];
        group.bench_with_input(
            BenchmarkId::new("round-trip-tb", tag_size),
            &tag,
            |b, tag| {
                b.iter_with_large_drop(|| {
                    let (dk, ek) = TK::generate(rng);
                    let (ct, _) = ek.encapsulate_with_tag(rng, tag).unwrap();
                    dk.decapsulate_with_tag(&ct, tag).unwrap()
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, kem_vs_tagkem_benchmark);
criterion_main!(benches);