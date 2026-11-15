//! Multi-pattern scanner for phantom tokens and their base64 variants.
//!
//! Matching uses Aho-Corasick over the raw bytes of the URL, headers, and
//! body. Base64 runs are also decoded (standard and URL-safe) and scanned, so
//! a phantom hidden inside `base64(json)` still trips the firewall.

use aho_corasick::{AhoCorasick, MatchKind};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub struct Pair {
    pub from: String,
    pub to: String,
    /// Index into the supervisor secret table.
    pub id: usize,
}

#[derive(Clone)]
pub struct Rewriter {
    pub(crate) patterns: Vec<String>,
    replacements: Vec<Vec<u8>>,
    ids: Vec<usize>,
    pub(crate) ac: Option<AhoCorasick>,
    pairs: Vec<Pair>,
}

impl Rewriter {
    pub fn from_pairs(pairs: &[Pair]) -> Self {
        let mut patterns = Vec::new();
        let mut replacements = Vec::new();
        let mut ids = Vec::new();
        for pair in pairs {
            if pair.from.is_empty() {
                continue;
            }
            push_unique(
                &mut patterns,
                &mut replacements,
                &mut ids,
                pair.from.clone(),
                pair.to.as_bytes().to_vec(),
                pair.id,
            );
            for (encoded, replacement) in base64_variants(&pair.from, &pair.to) {
                push_unique(
                    &mut patterns,
                    &mut replacements,
                    &mut ids,
                    encoded,
                    replacement.into_bytes(),
                    pair.id,
                );
            }
        }
        let ac = build_automaton(&patterns);
        Self {
            patterns,
            replacements,
            ids,
            ac,
            pairs: pairs.to_vec(),
        }
    }

    pub fn rewrite(&self, input: &[u8]) -> Vec<u8> {
        let direct = self.replace_direct(input);
        self.rewrite_encoded_blobs(&direct)
    }

    pub fn matching_ids(&self, input: &[u8]) -> Vec<usize> {
        let mut found = Vec::new();
        self.collect_ids(input, &mut found);
        for_each_b64_run(input, |run| {
            for decoded in decode_both(run) {
                self.collect_ids(&decoded, &mut found);
                for pair in &self.pairs {
                    if pair.from.len() >= 8
                        && decoded
                            .windows(pair.from.len())
                            .any(|window| window == pair.from.as_bytes())
                    {
                        push_id(&mut found, pair.id);
                    }
                }
            }
        });
        found.sort_unstable();
        found.dedup();
        found
    }

    fn collect_ids(&self, input: &[u8], found: &mut Vec<usize>) {
        let Some(ac) = &self.ac else {
            return;
        };
        for mat in ac.find_iter(input) {
            if let Some(id) = self.ids.get(mat.pattern().as_usize()) {
                push_id(found, *id);
            }
        }
    }

    fn replace_direct(&self, input: &[u8]) -> Vec<u8> {
        let Some(ac) = &self.ac else {
            return input.to_vec();
        };
        let mut out = Vec::with_capacity(input.len());
        let mut cursor = 0;
        for mat in ac.find_iter(input) {
            if mat.start() < cursor {
                continue;
            }
            out.extend_from_slice(&input[cursor..mat.start()]);
            if let Some(rep) = self.replacements.get(mat.pattern().as_usize()) {
                out.extend_from_slice(rep);
            }
            cursor = mat.end();
        }
        out.extend_from_slice(&input[cursor..]);
        out
    }

    fn rewrite_encoded_blobs(&self, input: &[u8]) -> Vec<u8> {
        if self.pairs.is_empty() {
            return input.to_vec();
        }
        let mut out = Vec::with_capacity(input.len());
        let mut last = 0;
        let runs = b64_runs(input);
        for (start, end) in runs {
            let run = &input[start..end];
            if let Some(replaced) = rewrite_run(run, &self.pairs) {
                out.extend_from_slice(&input[last..start]);
                out.extend_from_slice(&replaced);
                last = end;
            }
        }
        out.extend_from_slice(&input[last..]);
        out
    }
}

impl Drop for Rewriter {
    fn drop(&mut self) {
        for pattern in &mut self.patterns {
            pattern.zeroize();
        }
        for replacement in &mut self.replacements {
            replacement.zeroize();
        }
        for pair in &mut self.pairs {
            pair.from.zeroize();
            pair.to.zeroize();
        }
    }
}

fn build_automaton(patterns: &[String]) -> Option<AhoCorasick> {
    if patterns.is_empty() {
        return None;
    }
    AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(patterns)
        .ok()
}

fn push_id(found: &mut Vec<usize>, id: usize) {
    if !found.contains(&id) {
        found.push(id);
    }
}

fn push_unique(
    patterns: &mut Vec<String>,
    replacements: &mut Vec<Vec<u8>>,
    ids: &mut Vec<usize>,
    pattern: String,
    replacement: Vec<u8>,
    id: usize,
) {
    if pattern.len() < 8 {
        return;
    }
    if patterns.iter().any(|p| p == &pattern) {
        return;
    }
    patterns.push(pattern);
    replacements.push(replacement);
    ids.push(id);
}

fn base64_variants(from: &str, to: &str) -> Vec<(String, String)> {
    let raw_from = from.as_bytes();
    let raw_to = to.as_bytes();
    vec![
        (STANDARD.encode(raw_from), STANDARD.encode(raw_to)),
        (
            STANDARD_NO_PAD.encode(raw_from),
            STANDARD_NO_PAD.encode(raw_to),
        ),
        (URL_SAFE.encode(raw_from), URL_SAFE.encode(raw_to)),
        (
            URL_SAFE_NO_PAD.encode(raw_from),
            URL_SAFE_NO_PAD.encode(raw_to),
        ),
    ]
}

fn rewrite_run(run: &[u8], pairs: &[Pair]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(run).ok()?;
    let padded = text.contains('=');
    let url = text.contains('-') || text.contains('_');
    let decoded = if url {
        if padded {
            URL_SAFE.decode(text).ok()?
        } else {
            URL_SAFE_NO_PAD.decode(text).ok()?
        }
    } else if padded {
        STANDARD.decode(text).ok()?
    } else {
        STANDARD_NO_PAD.decode(text).ok()?
    };
    let mut changed = false;
    let mut current = decoded;
    for pair in pairs {
        let needle = pair.from.as_bytes();
        if needle.is_empty() || !contains_slice(&current, needle) {
            continue;
        }
        current = replace_slice(&current, needle, pair.to.as_bytes());
        changed = true;
    }
    if !changed {
        return None;
    }
    let encoded = if url {
        if padded {
            URL_SAFE.encode(&current)
        } else {
            URL_SAFE_NO_PAD.encode(&current)
        }
    } else if padded {
        STANDARD.encode(&current)
    } else {
        STANDARD_NO_PAD.encode(&current)
    };
    Some(encoded.into_bytes())
}

fn contains_slice(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn replace_slice(hay: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        if &hay[i..i + needle.len()] == needle {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out.extend_from_slice(&hay[i..]);
    out
}

fn decode_both(run: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = std::str::from_utf8(run) else {
        return Vec::new();
    };
    [
        STANDARD.decode(text),
        STANDARD_NO_PAD.decode(text),
        URL_SAFE.decode(text),
        URL_SAFE_NO_PAD.decode(text),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn for_each_b64_run(data: &[u8], mut f: impl FnMut(&[u8])) {
    for (start, end) in b64_runs(data) {
        f(&data[start..end]);
    }
}

fn b64_runs(data: &[u8]) -> Vec<(usize, usize)> {
    let mut runs = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        if is_b64_byte(b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= 16 {
                runs.push((s, i));
            }
        }
    }
    if let Some(s) = start {
        if data.len() - s >= 16 {
            runs.push((s, data.len()));
        }
    }
    runs
}

fn is_b64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'=')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_and_base64_match_the_same_secret() {
        let pairs = [Pair {
            from: "ghp_phantomvalue".into(),
            to: "ghp_realsecret1".into(),
            id: 3,
        }];
        let rewriter = Rewriter::from_pairs(&pairs);
        let raw = b"Bearer ghp_phantomvalue";
        assert_eq!(rewriter.matching_ids(raw), vec![3]);
        let swapped = rewriter.rewrite(raw);
        assert_eq!(
            String::from_utf8(swapped).unwrap(),
            "Bearer ghp_realsecret1"
        );
        let encoded = STANDARD.encode("ghp_phantomvalue");
        let ids = rewriter.matching_ids(encoded.as_bytes());
        assert_eq!(ids, vec![3]);
        let swapped_b64 = rewriter.rewrite(encoded.as_bytes());
        assert_eq!(
            String::from_utf8(swapped_b64).unwrap(),
            STANDARD.encode("ghp_realsecret1")
        );
    }
}
