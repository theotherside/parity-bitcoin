
use db;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use linked_hash_map::LinkedHashMap;
use primitives::hash::H256;
use super::{Chain, Verify, ContinueVerify, Error as VerificationError, TransactionError, BlockStatus};
use chain::{self, RepresentH256};
use futures::{Future, Poll, Async};
use std::collections::{HashMap, HashSet};

const BLOCK_STATE_PENDING: usize = 0;
const BLOCK_STATE_PROCESSING: usize = 1;
const BLOCK_STATE_INCONCLUSIVE: usize = 2;
const BLOCK_STATE_GOOD: usize = 3;
const BLOCK_STATE_BAD: usize = 4;

struct Queue {
	verifier: Box<ContinueVerify<State=usize>>,
	line: LinkedHashMap<H256, AtomicUsize>,
	blocks: HashMap<H256, chain::Block>,
	known_bad: HashSet<H256>,
}

struct VerificationArtefacts;

enum VerificationResult {
	Valid(VerificationArtefacts),
	Inconclusive(VerificationArtefacts),
	Bad,
}

struct BlockVerification<'a> {
	queue: &'a Queue,
	hash: H256,
}

enum Error {
	BlockVanished,
	BlockVanishedFromLine,
	ScheduledTwice,
}

impl<'a> Future for BlockVerification<'a> {
	type Item = VerificationResult;
	type Error = Error;

	fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
		let block = match self.queue.blocks.get(&self.hash) {
			Some(block) => block,
			None => { return Err(Error::BlockVanished); }
		};

		let line_atomic = match self.queue.line.get(&self.hash) {
			Some(atomic) => atomic,
			None => { return Err(Error::BlockVanishedFromLine); }
		};

		let current_state = line_atomic.swap(BLOCK_STATE_PROCESSING, Ordering::SeqCst);

		if current_state == BLOCK_STATE_PROCESSING {
			return Err(Error::ScheduledTwice);
		}

		match current_state {
			BLOCK_STATE_PENDING => {
				match self.queue.verifier.verify(block) {
					Ok(result) => {
						line_atomic.store(BLOCK_STATE_GOOD, Ordering::SeqCst);
						Ok(Async::Ready(VerificationResult::Valid(VerificationArtefacts)))
					},
					Err(VerificationError::Transaction(num, TransactionError::Inconclusive(_))) => {
						line_atomic.store(BLOCK_STATE_INCONCLUSIVE, Ordering::SeqCst);
						Ok(Async::Ready(VerificationResult::Inconclusive(VerificationArtefacts)))
					},
					Err(e) => {
						println!("Verification failed: {:?}", e);
						line_atomic.store(BLOCK_STATE_BAD, Ordering::SeqCst);
						Ok(Async::Ready(VerificationResult::Bad))
					}
				}
			},
			_ => Ok(Async::NotReady)
		}
	}

}

impl Queue {

	fn new(verifier: Box<ContinueVerify<State=usize>>) -> Self {
		Queue {
			verifier: verifier,
			line: LinkedHashMap::new(),
			blocks: HashMap::new(),
			known_bad: HashSet::new(),
		}
	}

	fn push(&mut self, block: chain::Block) {
		let hash = block.hash();
		self.blocks.insert(hash.clone(), block);
		self.line.insert(hash.clone(), AtomicUsize::new(BLOCK_STATE_PENDING));
	}

	fn verify(&self, hash: &H256) -> BlockVerification {
		BlockVerification { queue: self, hash: hash.clone() }
	}

	fn insert(&mut self, store: &db::Store) -> Result<(), ()> {
		Ok(())
	}

	fn status(&self, hash: &H256) -> BlockStatus {
		match self.line.get(hash) {
			None => { return BlockStatus::Absent; },
			Some(atomic) => {
				match atomic.load(Ordering::Relaxed) {
					BLOCK_STATE_PENDING => BlockStatus::Pending,
					BLOCK_STATE_PROCESSING => BlockStatus::Verifying,
					BLOCK_STATE_INCONCLUSIVE => BlockStatus::Verifying,
					BLOCK_STATE_GOOD => BlockStatus::Valid,
					BLOCK_STATE_BAD => BlockStatus::Invalid,
					_ => BlockStatus::Absent,
				}
			},
		}
	}
}


#[cfg(test)]
mod tests {
	use super::Queue;
	use super::super::{BlockStatus, VerificationResult, Verify, ContinueVerify, Chain, Error as VerificationError, TransactionError};
	use chain::{Block, RepresentH256};
	use primitives::hash::H256;
	use test_data;
	use std::collections::HashMap;
	use futures::Future;

	struct FacileVerifier;
	impl Verify for FacileVerifier {
		fn verify(&self, _block: &Block) -> VerificationResult { Ok(Chain::Main) }
	}

	impl ContinueVerify for FacileVerifier {
		type State = usize;
		fn continue_verify(&self, _block: &Block, _state: usize) -> VerificationResult { Ok(Chain::Main) }
	}

	struct EvilVerifier;
	impl Verify for EvilVerifier {
		fn verify(&self, _block: &Block) -> VerificationResult { Err(VerificationError::Empty) }
	}

	impl ContinueVerify for EvilVerifier {
		type State = usize;
		fn continue_verify(&self, _block: &Block, _state: usize) -> VerificationResult { Ok(Chain::Main) }
	}

	struct HupVerifier {
		hups: HashMap<H256, usize>,
	}

	impl Verify for HupVerifier {
		fn verify(&self, block: &Block) -> VerificationResult {
			if let Some(hup) = self.hups.get(&block.hash()) {
				Err(VerificationError::Transaction(*hup, TransactionError::Inconclusive(H256::from(0))))
			}
			else {
				Ok(Chain::Main)
			}
		}
	}

	impl ContinueVerify for HupVerifier {
		type State = usize;
		fn continue_verify(&self, _block: &Block, _state: usize) -> VerificationResult { Ok(Chain::Main) }
	}

	#[test]
	fn test_verify() {
		let mut queue = Queue::new(Box::new(FacileVerifier));
		let block = test_data::genesis();
		let hash = block.hash();
		queue.push(block);

		assert_eq!(queue.status(&hash), BlockStatus::Pending);

		let result = queue.verify(&hash).wait();

		assert_eq!(queue.status(&hash), BlockStatus::Valid);
		assert!(result.is_ok());
	}
}
