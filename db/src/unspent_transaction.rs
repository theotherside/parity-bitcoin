use primitives::H256;
use std::collections::HashSet;
use chain;
use bitcrypto;

#[derive(Hash, PartialEq, Eq)]
pub struct UnspentTransaction {
	script: H256,
	transaction: H256,
}

impl UnspentTransaction {
	pub fn new(script: H256, transaction: H256) -> Self {
		UnspentTransaction { script: script, transaction: transaction }
	}

	pub fn into_key(self) -> Vec<u8> {
		let mut result = Vec::with_capacity(512);
		result[0..32].copy_from_slice(&*self.script);
		result[32..64].copy_from_slice(&*self.transaction);
		result
	}
}

impl From<Vec<u8>> for UnspentTransaction {
	fn from(val: Vec<u8>) -> Self {
		UnspentTransaction {
			script: val[0..32].into(),
			transaction: val[32..64].into(),
		}
	}
}

pub struct UnspentUpdate {
	new: HashSet<UnspentTransaction>,
	removes: HashSet<UnspentTransaction>,
}

impl UnspentUpdate {
	pub fn new() -> Self {
		UnspentUpdate { new: HashSet::new(), removes: HashSet::new() }
	}

	pub fn push_new(&mut self, hash: &H256, transaction: &chain::Transaction) {
		for output in transaction.outputs.iter() {
			let script_hash = bitcrypto::dhash256(&output.script_pubkey);
			let unspent = UnspentTransaction::new(script_hash, hash.clone());
			self.removes.remove(&unspent);
			self.new.insert(unspent);
		}
	}

	pub fn push_spent(&mut self, hash: &H256, transaction: &chain::Transaction) {
		for output in transaction.outputs.iter() {
			let script_hash = bitcrypto::dhash256(&output.script_pubkey);
			let unspent = UnspentTransaction::new(script_hash, hash.clone());
			self.new.remove(&unspent);
			self.removes.insert(unspent);
		}
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use primitives::H256;
	use chain;

	#[test]
	fn from_into() {
		let key = UnspentTransaction::new(
			"75c7985c5dc0ca8cc56ac3618c57f0060b0c2cf9ad840ed31b7e835807fcb2fb".into(),
			"d6a0dd90afb9540bc0b8e59c861c3fd1f2313eb617663a07688e37717a51a367".into());
		let output: UnspentTransaction = key.into();

		assert_eq!(output.script, H256::from("75c7985c5dc0ca8cc56ac3618c57f0060b0c2cf9ad840ed31b7e835807fcb2fb"));
		assert_eq!(output.transaction, H256::from("d6a0dd90afb9540bc0b8e59c861c3fd1f2313eb617663a07688e37717a51a367"));
	}

	#[test]
	fn update() {
		let t: chain::Transaction = "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000".into();

		let mut update = UnspentUpdate::new();
		update.push_new(&t.hash(), &t);

		assert_eq!(1, update.new.len(), "There should be one unspent transaction to add");
	}

	#[test]
	fn update_remove() {
		let t: chain::Transaction = "0100000001a6b97044d03da79c005b20ea9c0e1a6d9dc12d9f7b91a5911c9030a439eed8f5000000004948304502206e21798a42fae0e854281abd38bacd1aeed3ee3738d9e1446618c4571d1090db022100e2ac980643b0b82c0e88ffdfec6b64e3e6ba35e7ba5fdd7d5d6cc8d25c6b241501ffffffff0100f2052a010000001976a914404371705fa9bd789a2fcd52d2c580b65d35549d88ac00000000".into();

		let mut update = UnspentUpdate::new();
		update.push_new(&t.hash(), &t);
		update.push_spent(&t.hash(), &t);

		assert_eq!(0, update.new.len(), "There should be no unspent transaction to add");
		assert_eq!(1, update.removes.len(), "There should be one unspent transaction to remove");
	}

}
