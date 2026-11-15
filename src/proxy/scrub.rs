//! Streaming replacement with a hold-back window.
//!
//! A secret (or phantom) may be split across chunked or SSE frames. The
//! scrubber keeps the last `longest_pattern - 1` bytes, plus any partial
//! match that crosses the emit boundary, and only emits bytes that cannot
//! still grow into a match.

use crate::proxy::tripwire::Rewriter;
use aho_corasick::AhoCorasick;

pub struct StreamScrubber {
    rewriter: Rewriter,
    hold: usize,
    buf: Vec<u8>,
}

impl StreamScrubber {
    pub fn new(rewriter: Rewriter) -> Self {
        let hold = rewriter.max_pattern_len().saturating_sub(1);
        Self {
            rewriter,
            hold,
            buf: Vec::new(),
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        self.emit(false)
    }

    pub fn finish(&mut self) -> Vec<u8> {
        let tail = self.emit(true);
        self.buf.clear();
        tail
    }

    fn emit(&mut self, finish: bool) -> Vec<u8> {
        if self.buf.is_empty() {
            return Vec::new();
        }
        if !finish && self.buf.len() <= self.hold {
            return Vec::new();
        }
        let mut limit = if finish {
            self.buf.len()
        } else {
            self.buf.len() - self.hold
        };
        if let Some(ac) = self.rewriter.automaton() {
            for mat in ac.find_iter(&self.buf) {
                if mat.start() < limit && mat.end() > limit {
                    limit = mat.start();
                }
            }
        }
        let head = self.buf[..limit].to_vec();
        let rewritten = self.rewriter.rewrite(&head);
        self.buf.drain(..limit);
        rewritten
    }
}

impl Rewriter {
    pub fn max_pattern_len(&self) -> usize {
        self.patterns.iter().map(|p| p.len()).max().unwrap_or(0)
    }

    pub fn automaton(&self) -> Option<&AhoCorasick> {
        self.ac.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::tripwire::Pair;

    #[test]
    fn split_secret_is_replaced() {
        let rewriter = Rewriter::from_pairs(&[Pair {
            from: "SECRETKEY".into(),
            to: "PHANTOM".into(),
            id: 0,
        }]);
        let mut scrubber = StreamScrubber::new(rewriter);
        let mut out = Vec::new();
        for chunk in ["abcSECRE", "TKEYxyz"].iter() {
            out.extend(scrubber.push(chunk.as_bytes()));
        }
        out.extend(scrubber.finish());
        assert_eq!(String::from_utf8(out).unwrap(), "abcPHANTOMxyz");
    }

    #[test]
    fn one_byte_chunks() {
        let rewriter = Rewriter::from_pairs(&[Pair {
            from: "REALKEYVALUE".into(),
            to: "FAKE".into(),
            id: 0,
        }]);
        let mut scrubber = StreamScrubber::new(rewriter);
        let input = b"xxREALKEYVALUEyy";
        let mut out = Vec::new();
        for byte in input {
            out.extend(scrubber.push(&[*byte]));
        }
        out.extend(scrubber.finish());
        assert_eq!(String::from_utf8(out).unwrap(), "xxFAKEyy");
    }
}
