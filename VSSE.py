import os
import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import secrets
import struct
import binascii


#Core Cryptographic Primitives (OpenSSL-based)
class CryptoPrimitives:
    """OpenSSL-based cryptographic primitives for VSSE"""

    def __init__(self, master_key: bytes):
        self.master_key = master_key
        self.backend = default_backend()

    @classmethod
    def generate_master_key(cls) -> bytes:
        """Generate a secure master key (256 bits)"""
        return secrets.token_bytes(32)

    def derive_key(self, purpose: bytes, keyword: bytes = None) -> bytes:
        """Derive a purpose-specific key using PBKDF2-HMAC-SHA256"""
        salt = purpose + (keyword if keyword else b'')
        return hashlib.pbkdf2_hmac(
            'sha256',
            self.master_key,
            salt,
            10000,
            32
        )

    def prf(self, key: bytes, data: bytes) -> bytes:
        """Pseudorandom Function (HMAC-SHA256)"""
        h = hmac.HMAC(key, hashes.SHA256(), backend=self.backend)
        h.update(data)
        return h.finalize()

    def encrypt(self, key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        """AES-256-CBC encryption with random IV"""
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        # PKCS7 padding
        pad_len = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_len] * pad_len)

        ciphertext = encryptor.update(padded) + encryptor.finalize()
        return iv, ciphertext

    def decrypt(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """AES-256-CBC decryption"""
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        pad_len = padded[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Invalid padding")
        return padded[:-pad_len]

    def compute_hash(self, data: bytes) -> bytes:
        """SHA-256 hash computation"""
        digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
        digest.update(data)
        return digest.finalize()

    def xor(self, a: bytes, b: bytes) -> bytes:
        """XOR two byte strings"""
        return bytes(x ^ y for x, y in zip(a, b))



#Merkle Hash Tree for Verification
class MerkleTree:
    """
    Merkle Hash Tree for result verification.
    Provides proofs that a document belongs to the result set
    and that the result set is complete.
    """

    def __init__(self, hash_func: callable = None):
        self.hash_func = hash_func or hashlib.sha256
        self.nodes: Dict[int, List[bytes]] = {}
        self.leaf_count = 0
        self.leaves: List[bytes] = []

    @classmethod
    def from_leaves(cls, leaves: List[bytes], hash_func: callable = None) -> 'MerkleTree':
        """Build a Merkle tree from leaf values"""
        tree = cls(hash_func)
        tree.leaves = leaves.copy()
        tree.leaf_count = len(leaves)
        tree.nodes[0] = leaves.copy()

        level = 0
        while len(tree.nodes[level]) > 1:
            next_level = []
            for i in range(0, len(tree.nodes[level]), 2):
                left = tree.nodes[level][i]
                right = tree.nodes[level][i + 1] if i + 1 < len(tree.nodes[level]) else left
                combined = left + right
                next_level.append(tree.hash_func(combined).digest())
            level += 1
            tree.nodes[level] = next_level

        return tree

    def get_root(self) -> bytes:
        """Get the root hash of the tree"""
        if not self.nodes:
            return b'\x00' * 32
        max_level = max(self.nodes.keys())
        return self.nodes[max_level][0]

    def generate_proof(self, index: int) -> Tuple[List[bytes], List[int]]:
        """Generate a Merkle proof for leaf at given index"""
        if index >= self.leaf_count:
            raise ValueError("Index out of range")

        proof = []
        positions = []
        current_idx = index

        for level in range(max(self.nodes.keys())):
            if level not in self.nodes:
                break

            # Determine sibling index
            sibling_idx = current_idx ^ 1
            if sibling_idx < len(self.nodes[level]):
                proof.append(self.nodes[level][sibling_idx])
                positions.append(1 if sibling_idx > current_idx else 0)
            else:
                proof.append(self.nodes[level][current_idx])
                positions.append(0)

            current_idx //= 2

        return proof, positions

    @staticmethod
    def verify_proof(root: bytes, leaf: bytes, proof: List[bytes],
                     positions: List[int], index: int,
                     hash_func: callable = None) -> bool:
        """Verify a Merkle proof"""
        if hash_func is None:
            hash_func = hashlib.sha256

        current = leaf
        current_idx = index

        for i, sibling in enumerate(proof):
            # Determine ordering based on position
            if positions[i] == 0:
                combined = current + sibling
            else:
                combined = sibling + current

            current = hash_func(combined).digest()
            current_idx //= 2

        return current == root


#Cryptographic Accumulator for Keyword Verification
class RSAAccumulator:
    """
    RSA-based cryptographic accumulator for keyword verification.
    Allows the server to prove that a keyword exists in the database.
    """

    def __init__(self):
        # For demonstration - in practice, use proper RSA key generation
        # with safe primes (p, q such that p=2p'+1, q=2q'+1)
        from cryptography.hazmat.primitives.asymmetric import rsa
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

        # Get modulus n
        self.n = self.private_key.private_numbers().public_numbers.n

    def compute_accumulator(self, elements: List[bytes]) -> int:
        """
        Compute accumulator value: g^(∏ hash(e)) mod n
        Simplified: product of hashes mod n
        """
        product = 1
        for elem in elements:
            h = int.from_bytes(hashlib.sha256(elem).digest(), 'big')
            product = (product * h) % self.n
        return product

    def generate_witness(self, element: bytes, all_elements: List[bytes]) -> int:
        """Generate a witness for an element in the accumulator"""
        product = 1
        elem_hash = int.from_bytes(hashlib.sha256(element).digest(), 'big')

        for other in all_elements:
            if other != element:
                h = int.from_bytes(hashlib.sha256(other).digest(), 'big')
                product = (product * h) % self.n

        return product

    def verify_witness(self, element: bytes, witness: int, accumulator: int) -> bool:
        """Verify that an element is in the accumulator"""
        elem_hash = int.from_bytes(hashlib.sha256(element).digest(), 'big')
        computed = pow(witness, elem_hash, self.n)
        return computed == accumulator


#VSSE Scheme Implementation
@dataclass
class EncryptedDocument:
    """Encrypted document with metadata"""
    doc_id: int
    ciphertext: bytes
    iv: bytes
    keyword_hashes: List[bytes]
    doc_hash: bytes


@dataclass
class SearchToken:
    """Search token generated by client"""
    keyword_hash: bytes
    trapdoor: bytes


@dataclass
class SearchResult:
    """Search result with verification proof"""
    doc_ids: List[int]
    ciphertexts: List[bytes]
    ivs: List[bytes]
    merkle_proofs: List[Tuple[List[bytes], List[int]]]  # proof and positions
    merkle_root: bytes
    keyword_witness: int
    keyword_accumulator: int


class VSSEClient:
    """
    Client side of VSSE scheme.
    Manages keys, encrypts documents, generates search tokens,
    and verifies search results.
    """

    def __init__(self, master_key: bytes = None):
        self.crypto = CryptoPrimitives(master_key or CryptoPrimitives.generate_master_key())
        self.doc_counter = 0
        self.documents: Dict[int, Tuple[str, List[str]]] = {}  # id -> (plaintext, keywords)
        self.keyword_doc_map: Dict[str, Set[int]] = {}

    def get_master_key(self) -> bytes:
        """Get master key for storage"""
        return self.crypto.master_key

    def add_document(self, plaintext: str, keywords: List[str]) -> int:
        """Add a document to the local database"""
        doc_id = self.doc_counter
        self.doc_counter += 1

        # Store plaintext and keywords
        self.documents[doc_id] = (plaintext, keywords)

        # Update keyword-document mapping
        for kw in keywords:
            if kw not in self.keyword_doc_map:
                self.keyword_doc_map[kw] = set()
            self.keyword_doc_map[kw].add(doc_id)

        return doc_id

    def encrypt_database(self) -> Tuple[List[EncryptedDocument], List[bytes], int]:
        """
        Encrypt all documents and build encrypted index.
        Returns: (encrypted_documents, all_keywords, accumulator)
        """
        encrypted_docs = []
        all_keywords = set()

        # First, collect all keywords
        for keywords in self.keyword_doc_map.values():
            all_keywords.update(keywords)

        all_keywords = sorted(all_keywords)
        keyword_bytes = [kw.encode() for kw in all_keywords]

        # Create RSA accumulator for keywords
        accumulator = RSAAccumulator()
        keyword_hashes = [hashlib.sha256(kw).digest() for kw in keyword_bytes]
        acc_value = accumulator.compute_accumulator(keyword_hashes)

        # Build encrypted index and encrypted documents
        for doc_id, (plaintext, keywords) in self.documents.items():
            # Derive document-specific key
            doc_key = self.crypto.derive_key(b"doc_enc", str(doc_id).encode())

            # Encrypt document content
            iv, ciphertext = self.crypto.encrypt(doc_key, plaintext.encode())

            # Compute document hash
            doc_hash = self.crypto.compute_hash(plaintext.encode())

            # Generate keyword hashes for this document
            keyword_hashes = []
            for kw in keywords:
                kw_key = self.crypto.derive_key(b"kw_hash", kw.encode())
                kw_hash = self.crypto.prf(kw_key, kw.encode())
                keyword_hashes.append(kw_hash)

            encrypted_docs.append(EncryptedDocument(
                doc_id=doc_id,
                ciphertext=ciphertext,
                iv=iv,
                keyword_hashes=keyword_hashes,
                doc_hash=doc_hash
            ))

        return encrypted_docs, keyword_bytes, acc_value

    def generate_search_token(self, keyword: str) -> SearchToken:
        """Generate search token for a keyword"""
        kw_bytes = keyword.encode()

        # Derive keyword-specific keys
        token_key = self.crypto.derive_key(b"token", kw_bytes)
        trapdoor_key = self.crypto.derive_key(b"trapdoor", kw_bytes)

        # Compute keyword hash (for indexing)
        keyword_hash = self.crypto.prf(token_key, kw_bytes)

        # Compute trapdoor (for searching)
        trapdoor = self.crypto.prf(trapdoor_key, kw_bytes)

        return SearchToken(keyword_hash=keyword_hash, trapdoor=trapdoor)

    def verify_result(self, keyword: str, result: SearchResult) -> bool:
        """
        Verify the completeness and correctness of search results
        """
        # 1. Verify Merkle tree proofs for each document
        expected_doc_ids = self.keyword_doc_map.get(keyword, set())

        # Build expected leaf list (document hashes in order)
        doc_hashes = []
        doc_id_to_hash = {}

        for doc_id in sorted(self.documents.keys()):
            plaintext, _ = self.documents[doc_id]
            doc_hash = self.crypto.compute_hash(plaintext.encode())
            doc_hashes.append(doc_hash)
            doc_id_to_hash[doc_id] = doc_hash

        # Verify each returned document's Merkle proof
        for i, doc_id in enumerate(result.doc_ids):
            # Find index in sorted document list
            sorted_ids = sorted(self.documents.keys())
            idx = sorted_ids.index(doc_id)

            # Get the expected leaf
            expected_leaf = doc_id_to_hash[doc_id]

            # Verify proof
            proof, positions = result.merkle_proofs[i]
            is_valid = MerkleTree.verify_proof(
                result.merkle_root,
                expected_leaf,
                proof,
                positions,
                idx
            )

            if not is_valid:
                print(f"  - Merkle proof failed for document {doc_id}")
                return False

        # 2. Verify completeness (no missing documents)
        returned_ids = set(result.doc_ids)
        if returned_ids != expected_doc_ids:
            print(f"  - Completeness check failed: expected {expected_doc_ids}, got {returned_ids}")
            return False

        # 3. Verify keyword witness
        acc = RSAAccumulator()
        kw_bytes = keyword.encode()
        kw_hash = hashlib.sha256(kw_bytes).digest()

        # Get all keyword hashes
        all_keywords = set()
        for keywords in self.keyword_doc_map.values():
            all_keywords.update(keywords)
        all_keywords = sorted(all_keywords)
        keyword_hashes = [hashlib.sha256(kw.encode()).digest() for kw in all_keywords]

        # Recompute accumulator
        computed_acc = acc.compute_accumulator(keyword_hashes)

        # Verify witness
        if not acc.verify_witness(kw_bytes, result.keyword_witness, computed_acc):
            print(f"  - Keyword witness verification failed")
            return False

        # 4. Decrypt and verify each document
        for i, doc_id in enumerate(result.doc_ids):
            # Derive document key
            doc_key = self.crypto.derive_key(b"doc_enc", str(doc_id).encode())

            # Decrypt document
            decrypted = self.crypto.decrypt(doc_key, result.ivs[i], result.ciphertexts[i])

            # Verify document hash matches
            expected_hash = self.crypto.compute_hash(decrypted)

            # Get original plaintext
            plaintext, _ = self.documents[doc_id]

            if decrypted != plaintext.encode():
                print(f"  - Document {doc_id} decryption mismatch")
                return False

        return True


class VSSEServer:
    """
    Server side of VSSE scheme.
    Stores encrypted documents, processes search queries,
    and generates verification proofs.
    """

    def __init__(self):
        self.encrypted_docs: Dict[int, EncryptedDocument] = {}
        self.inverted_index: Dict[bytes, List[int]] = {}  # keyword_hash -> doc_ids
        self.keyword_list: List[bytes] = []
        self.merkle_tree: Optional[MerkleTree] = None
        self.accumulator_value: int = 0

    def setup(self, encrypted_docs: List[EncryptedDocument],
              keyword_list: List[bytes], accumulator_value: int):
        """Setup server with encrypted data"""
        self.encrypted_docs = {doc.doc_id: doc for doc in encrypted_docs}
        self.keyword_list = keyword_list
        self.accumulator_value = accumulator_value

        # Build inverted index
        for doc in encrypted_docs:
            for kw_hash in doc.keyword_hashes:
                if kw_hash not in self.inverted_index:
                    self.inverted_index[kw_hash] = []
                self.inverted_index[kw_hash].append(doc.doc_id)

        # Build Merkle tree over document hashes
        doc_hashes = []
        for doc_id in sorted(self.encrypted_docs.keys()):
            doc = self.encrypted_docs[doc_id]
            doc_hashes.append(doc.doc_hash)

        if doc_hashes:
            self.merkle_tree = MerkleTree.from_leaves(doc_hashes)
        else:
            self.merkle_tree = MerkleTree()

    def search(self, token: SearchToken) -> SearchResult:
        """
        Execute search query and generate verification proof
        """
        # 1. Find documents matching the keyword
        matching_doc_ids = self.inverted_index.get(token.keyword_hash, [])

        # 2. Prepare result documents
        result_docs = []
        result_ivs = []
        result_ciphertexts = []
        merkle_proofs = []

        # Sort for consistent ordering
        sorted_ids = sorted(self.encrypted_docs.keys())
        doc_hash_map = {doc_id: doc.doc_hash for doc_id, doc in self.encrypted_docs.items()}

        for doc_id in sorted(matching_doc_ids):
            doc = self.encrypted_docs[doc_id]
            result_docs.append(doc_id)
            result_ivs.append(doc.iv)
            result_ciphertexts.append(doc.ciphertext)

            # Generate Merkle proof for this document
            idx = sorted_ids.index(doc_id)
            proof, positions = self.merkle_tree.generate_proof(idx)
            merkle_proofs.append((proof, positions))

        # 3. Generate keyword witness
        acc = RSAAccumulator()
        kw_bytes = token.trapdoor  # Using trapdoor as keyword identifier
        # In practice, need to map token back to actual keyword
        # For demonstration, we'll generate witness for all keywords

        # Find which keyword this token corresponds to
        # In practice, the token should contain enough info to identify the keyword
        # For this implementation, we'll use a simplified approach
        all_keywords = self.keyword_list
        kw_index = -1
        for i, kw in enumerate(all_keywords):
            # This is simplified - real implementation would use the trapdoor
            if kw == token.trapdoor:
                kw_index = i
                break

        if kw_index >= 0:
            witness = acc.generate_witness(kw_bytes, all_keywords)
        else:
            witness = 1

        # 4. Get Merkle root
        merkle_root = self.merkle_tree.get_root()

        return SearchResult(
            doc_ids=result_docs,
            ciphertexts=result_ciphertexts,
            ivs=result_ivs,
            merkle_proofs=merkle_proofs,
            merkle_root=merkle_root,
            keyword_witness=witness,
            keyword_accumulator=self.accumulator_value
        )

