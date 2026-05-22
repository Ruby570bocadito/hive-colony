// Pure Rust RandomForest evaluator.
// Replaces ONNX Runtime dependency with zero-cost tree traversal.
// Model format: custom binary (exported from sklearn via train_classifier.py).
//
// No C/C++ deps. No OpenSSL. Compiles on all platforms.

use tracing::{info, warn};

/// RandomForest classifier loaded from binary model data.
pub struct RandomForest {
    n_estimators: u32,
    n_classes: u32,
    n_features: u32,
    trees: Vec<DecisionTree>,
}

struct DecisionTree {
    n_nodes: u32,
    children_left: Vec<i32>,
    children_right: Vec<i32>,
    feature: Vec<i32>,
    threshold: Vec<f32>,
    value: Vec<f32>, // n_nodes * n_classes
}

impl RandomForest {
    /// Load from compact binary format.
    /// Format: n_estimators(u32) n_classes(u32) n_features(u32) [tree_data...]
    /// Each tree: n_nodes(u32) children_left[n_nodes](i32) children_right[n_nodes](i32)
    ///            feature[n_nodes](i32) threshold[n_nodes](f32) value[n_nodes*n_classes](f32)
    pub fn from_binary(data: &[u8]) -> Option<Self> {
        if data.len() < 12 { return None; }

        let n_estimators = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let n_classes = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let n_features = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);

        let mut offset = 12usize;
        let mut trees = Vec::with_capacity(n_estimators as usize);

        for _ in 0..n_estimators {
            if offset + 4 > data.len() { return None; }
            let n_nodes = u32::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3]
            ]) as usize;
            offset += 4;

            let nn = n_nodes;
            let sz_i32 = nn * 4;
            let sz_f32 = nn * 4;
            let sz_val = nn * n_classes as usize * 4;

            if offset + sz_i32 * 3 + sz_f32 + sz_val > data.len() { return None; }

            let children_left = read_i32_slice(&data[offset..], nn); offset += sz_i32;
            let children_right = read_i32_slice(&data[offset..], nn); offset += sz_i32;
            let feature = read_i32_slice(&data[offset..], nn); offset += sz_i32;
            let threshold = read_f32_slice(&data[offset..], nn); offset += sz_f32;
            let value = read_f32_slice(&data[offset..], nn * n_classes as usize); offset += sz_val;

            trees.push(DecisionTree {
                n_nodes: nn as u32,
                children_left, children_right, feature, threshold, value,
            });
        }

        info!("RF loaded: {} trees, {} classes, {} features ({} KB)",
            n_estimators, n_classes, n_features, data.len() / 1024);

        Some(Self { n_estimators, n_classes, n_features, trees })
    }

    /// Predict class for a single sample.
    /// Returns the predicted class index (0-based).
    pub fn predict(&self, features: &[f32]) -> Option<u32> {
        if features.len() != self.n_features as usize {
            warn!("RF: feature count mismatch: got {}, expected {}", features.len(), self.n_features);
            return None;
        }

        let mut votes = vec![0u32; self.n_classes as usize];

        for tree in &self.trees {
            let leaf = tree.predict_leaf(features);
            // Leaf value contains class probabilities [n_classes]
            let val_offset = leaf * self.n_classes as usize;
            if val_offset + self.n_classes as usize <= tree.value.len() {
                let mut best_class = 0usize;
                let mut best_val = f32::NEG_INFINITY;
                for c in 0..self.n_classes as usize {
                    let v = tree.value[val_offset + c];
                    if v > best_val {
                        best_val = v;
                        best_class = c;
                    }
                }
                votes[best_class] += 1;
            }
        }

        // Majority vote
        votes.iter()
            .enumerate()
            .max_by_key(|(_, &v)| v)
            .map(|(i, _)| i as u32)
    }

    /// Predict class with confidence score.
    pub fn predict_proba(&self, features: &[f32]) -> Option<(u32, f32)> {
        if features.len() != self.n_features as usize { return None; }

        let mut proba_sum = vec![0.0f32; self.n_classes as usize];
        for tree in &self.trees {
            let leaf = tree.predict_leaf(features);
            let val_offset = leaf * self.n_classes as usize;
            if val_offset + self.n_classes as usize <= tree.value.len() {
                for c in 0..self.n_classes as usize {
                    proba_sum[c] += tree.value[val_offset + c];
                }
            }
        }

        let total: f32 = proba_sum.iter().sum();
        if total == 0.0 { return Some((0, 0.0)); }

        proba_sum.iter_mut().for_each(|v| *v /= total);
        proba_sum.iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .map(|(i, v)| (i as u32, *v))
    }
}

impl DecisionTree {
    /// Traverse tree from root to leaf. Returns leaf node index.
    fn predict_leaf(&self, features: &[f32]) -> usize {
        let mut node: i32 = 0;
        loop {
            let idx = node as usize;
            let left = self.children_left[idx];
            let right = self.children_right[idx];

            // Leaf node: both children = -1
            if left == -1 && right == -1 {
                return idx;
            }

            let feat = self.feature[idx] as usize;
            if feat < features.len() && features[feat] <= self.threshold[idx] {
                node = left;
            } else {
                node = right;
            }
        }
    }
}

fn read_i32_slice(data: &[u8], count: usize) -> Vec<i32> {
    let mut v = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * 4;
        v.push(i32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]));
    }
    v
}

fn read_f32_slice(data: &[u8], count: usize) -> Vec<f32> {
    let mut v = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * 4;
        v.push(f32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_i32() {
        let data = [1u8,0,0,0, 255,255,255,255];
        let v = read_i32_slice(&data, 2);
        assert_eq!(v, vec![1, -1]);
    }

    #[test]
    fn test_rf_from_empty() {
        assert!(RandomForest::from_binary(&[]).is_none());
        assert!(RandomForest::from_binary(&[0;4]).is_none());
    }

    #[test]
    fn test_rf_header_parse() {
        // Minimal valid header: 1 tree, 2 classes, 3 features
        let mut data = vec![];
        data.extend_from_slice(&1u32.to_le_bytes()); // n_estimators
        data.extend_from_slice(&2u32.to_le_bytes()); // n_classes
        data.extend_from_slice(&3u32.to_le_bytes()); // n_features
        // 1 tree with 1 node (leaf)
        data.extend_from_slice(&1u32.to_le_bytes()); // n_nodes
        // children_left[1], children_right[1], feature[1], threshold[1], value[2]
        data.extend_from_slice(&(-1i32).to_le_bytes());
        data.extend_from_slice(&(-1i32).to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&1.0f32.to_le_bytes());
        data.extend_from_slice(&0.5f32.to_le_bytes());
        data.extend_from_slice(&0.5f32.to_le_bytes());

        let rf = RandomForest::from_binary(&data);
        assert!(rf.is_some());
        let rf = rf.unwrap();
        assert_eq!(rf.n_estimators, 1);
        assert_eq!(rf.n_classes, 2);
        assert_eq!(rf.n_features, 3);
    }
}
