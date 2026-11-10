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
import time


#Core Cryptographic Primitives (OpenSSL-based)
class CryptoPrimitives:
    """OpenSSL-based cryptographic primitives for DVSSE"""

    def __init__(self, master_key: bytes):
        self.master_key = master_key
        self.backend = default_backend()

    @classmethod
    def generate_master_key(cls) -> bytes:
        """Generate a secure master key (256 bits)"""
        return secrets.token_bytes(32)

    def derive_key(self, purpose: bytes, data: bytes = None) -> bytes:
        """Derive a purpose-specific key using PBKDF2-HMAC-SHA256"""
        salt = purpose + (data if data else b'')
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


#Dynamic Merkle Hash Tree (Supporting Updates)
class DynamicMerkleTree:
    """
    Merkle Hash Tree supporting dynamic updates (add/delete leaves).
    Provides proofs for result verification after modifications.
    """

    def __init__(self, hash_func: callable = None):
        self.hash_func = hash_func or hashlib.sha256
        self.leaves: Dict[int, bytes] = {}  # index -> leaf hash
        self.nodes: Dict[Tuple[int, int], bytes] = {}  # (level, index) -> node hash
        self.next_index = 0
        self.size = 0

    def add_leaf(self, leaf: bytes) -> int:
        """Add a new leaf to the tree, return its index"""
        idx = self.next_index
        self.leaves[idx] = leaf
        self._update_path(idx, leaf)
        self.next_index += 1
        self.size += 1
        return idx

    def update_leaf(self, idx: int, leaf: bytes):
        """Update an existing leaf"""
        if idx not in self.leaves:
            raise ValueError(f"Leaf {idx} does not exist")
        self.leaves[idx] = leaf
        self._update_path(idx, leaf)

    def delete_leaf(self, idx: int):
        """Delete a leaf (mark as tombstone)"""
        if idx not in self.leaves:
            raise ValueError(f"Leaf {idx} does not exist")
        # Mark as deleted by setting to zero hash
        self.leaves[idx] = b'\x00' * 32
        self._update_path(idx, b'\x00' * 32)
        self.size -= 1

    def _update_path(self, leaf_idx: int, leaf_hash: bytes):
        """Update the path from leaf to root"""
        level = 0
        idx = leaf_idx

        while True:
            # Store node at current level
            self.nodes[(level, idx)] = leaf_hash

            # Move to parent
            parent_idx = idx // 2
            sibling_idx = idx ^ 1

            # Get sibling hash
            sibling = self.nodes.get((level, sibling_idx))
            if sibling is None:
                # If no sibling, parent gets current hash
                leaf_hash = leaf_hash
            else:
                # Combine with sibling
                if idx % 2 == 0:
                    combined = leaf_hash + sibling
                else:
                    combined = sibling + leaf_hash
                leaf_hash = self.hash_func(combined).digest()

            # Move to next level
            idx = parent_idx
            level += 1

            # Stop when we've updated the root
            if idx == 0 and level > 0:
                self.nodes[(level, 0)] = leaf_hash
                break

    def get_root(self) -> bytes:
        """Get the current root hash"""
        max_level = max([l for l, _ in self.nodes.keys()]) if self.nodes else 0
        return self.nodes.get((max_level, 0), b'\x00' * 32)

    def generate_proof(self, leaf_idx: int) -> Tuple[List[bytes], List[int]]:
        """Generate a Merkle proof for a leaf"""
        if leaf_idx not in self.leaves:
            raise ValueError(f"Leaf {leaf_idx} does not exist")

        proof = []
        positions = []
        idx = leaf_idx
        level = 0

        while True:
            sibling_idx = idx ^ 1
            sibling = self.nodes.get((level, sibling_idx))

            if sibling is not None:
                proof.append(sibling)
                positions.append(1 if sibling_idx > idx else 0)
            else:
                # If no sibling, use self
                proof.append(self.nodes.get((level, idx), b'\x00' * 32))
                positions.append(0)

            idx //= 2
            level += 1

            if idx == 0 and level > 0:
                break

        return proof, positions

    @staticmethod
    def verify_proof(root: bytes, leaf: bytes, proof: List[bytes],
                     positions: List[int], leaf_idx: int,
                     hash_func: callable = None) -> bool:
        """Verify a Merkle proof"""
        if hash_func is None:
            hash_func = hashlib.sha256

        current = leaf
        idx = leaf_idx

        for i, sibling in enumerate(proof):
            # Determine ordering based on position
            if positions[i] == 0:
                combined = current + sibling
            else:
                combined = sibling + current

            current = hash_func(combined).digest()
            idx //= 2

        return current == root


#Dynamic Keyword Index with Forward/Backward Privacy
class DynamicKeywordIndex:
    """
    Dynamic keyword index supporting add/delete operations.
    Uses encrypted inverted index with timestamps for privacy.
    """

    def __init__(self, crypto: CryptoPrimitives):
        self.crypto = crypto
        self.keyword_states: Dict[bytes, Dict[int, bytes]] = {}  # keyword_hash -> {version: encrypted_entry}
        self.keyword_versions: Dict[bytes, int] = {}  # keyword_hash -> current_version
        self.deleted_entries: Set[Tuple[bytes, int]] = set()  # (keyword_hash, doc_id)

    def add_document(self, keyword_hash: bytes, doc_id: int, doc_hash: bytes) -> bytes:
        """Add a document to the keyword's index, return encrypted entry"""
        # Generate version for this keyword
        if keyword_hash not in self.keyword_versions:
            self.keyword_versions[keyword_hash] = 0

        version = self.keyword_versions[keyword_hash] + 1
        self.keyword_versions[keyword_hash] = version

        # Create entry: (doc_id, doc_hash, version, timestamp)
        timestamp = int(time.time()).to_bytes(8, 'big')
        entry = struct.pack('>I', doc_id) + doc_hash + struct.pack('>I', version) + timestamp

        # Encrypt entry with keyword-specific key
        kw_key = self.crypto.derive_key(b"kw_index", keyword_hash)
        iv, ciphertext = self.crypto.encrypt(kw_key, entry)

        # Store
        if keyword_hash not in self.keyword_states:
            self.keyword_states[keyword_hash] = {}
        self.keyword_states[keyword_hash][version] = ciphertext + iv

        return ciphertext + iv

    def delete_document(self, keyword_hash: bytes, doc_id: int, version: int):
        """Mark a document as deleted in the index"""
        self.deleted_entries.add((keyword_hash, doc_id))

        # Add deletion marker
        kw_key = self.crypto.derive_key(b"kw_index", keyword_hash)
        deletion_marker = b'DELETED' + struct.pack('>I', doc_id) + struct.pack('>I', version)
        iv, ciphertext = self.crypto.encrypt(kw_key, deletion_marker)

        if keyword_hash not in self.keyword_states:
            self.keyword_states[keyword_hash] = {}
        self.keyword_states[keyword_hash][version + 1000000] = ciphertext + iv

    def get_active_entries(self, keyword_hash: bytes) -> List[Tuple[int, bytes]]:
        """Get all active (non-deleted) entries for a keyword"""
        if keyword_hash not in self.keyword_states:
            return []

        kw_key = self.crypto.derive_key(b"kw_index", keyword_hash)
        active = []

        for version, encrypted_entry in self.keyword_states[keyword_hash].items():
            # Decrypt entry
            iv = encrypted_entry[-16:]
            ciphertext = encrypted_entry[:-16]

            try:
                entry = self.crypto.decrypt(kw_key, iv, ciphertext)
            except:
                continue

            # Check if it's a deletion marker
            if entry.startswith(b'DELETED'):
                continue

            # Parse entry
            doc_id = struct.unpack('>I', entry[:4])[0]
            doc_hash = entry[4:36]

            # Check if deleted
            if (keyword_hash, doc_id) not in self.deleted_entries:
                active.append((doc_id, doc_hash))

        return active


#DVSSE Scheme Implementation
@dataclass
class EncryptedDocument:
    """Encrypted document with metadata"""
    doc_id: int
    ciphertext: bytes
    iv: bytes
    doc_hash: bytes
    version: int
    timestamp: int


@dataclass
class EncryptedIndexEntry:
    """Encrypted index entry for keyword-document mapping"""
    keyword_hash: bytes
    doc_id: int
    encrypted_entry: bytes


@dataclass
class SearchToken:
    """Search token generated by client"""
    keyword_hash: bytes
    trapdoor: bytes
    version: int


@dataclass
class SearchResult:
    """Search result with verification proof"""
    doc_ids: List[int]
    ciphertexts: List[bytes]
    ivs: List[bytes]
    merkle_proofs: List[Tuple[List[bytes], List[int]]]
    merkle_root: bytes
    index_entries: List[bytes]
    keyword_version: int


class DVSSEClient:
    """
    Client side of DVSSE scheme.
    Manages keys, encrypts documents, generates search tokens,
    and verifies search results with dynamic updates.
    """

    def __init__(self, master_key: bytes = None):
        self.crypto = CryptoPrimitives(master_key or CryptoPrimitives.generate_master_key())
        self.doc_counter = 0
        self.documents: Dict[int, Tuple[str, List[str], int]] = {}  # id -> (plaintext, keywords, version)
        self.keyword_doc_map: Dict[str, Set[Tuple[int, int]]] = {}  # keyword -> set of (doc_id, version)
        self.doc_versions: Dict[int, int] = {}  # doc_id -> current version

    def get_master_key(self) -> bytes:
        """Get master key for storage"""
        return self.crypto.master_key

    def add_document(self, plaintext: str, keywords: List[str]) -> int:
        """Add a document to the local database"""
        doc_id = self.doc_counter
        self.doc_counter += 1
        version = 1

        # Store document
        self.documents[doc_id] = (plaintext, keywords, version)
        self.doc_versions[doc_id] = version

        # Update keyword-document mapping
        for kw in keywords:
            if kw not in self.keyword_doc_map:
                self.keyword_doc_map[kw] = set()
            self.keyword_doc_map[kw].add((doc_id, version))

        return doc_id

    def delete_document(self, doc_id: int):
        """Delete a document (soft delete with version update)"""
        if doc_id not in self.documents:
            raise ValueError(f"Document {doc_id} does not exist")

        plaintext, keywords, old_version = self.documents[doc_id]
        new_version = old_version + 1

        # Update document with new version (deleted)
        self.documents[doc_id] = (plaintext, keywords, new_version)
        self.doc_versions[doc_id] = new_version

        # Update keyword mapping with deletion version
        for kw in keywords:
            self.keyword_doc_map[kw].add((doc_id, new_version))

    def encrypt_database(self) -> Tuple[List[EncryptedDocument], List[EncryptedIndexEntry], bytes]:
        """
        Encrypt all documents and build encrypted index.
        Returns: (encrypted_documents, index_entries, merkle_root)
        """
        encrypted_docs = []
        index_entries = []

        # Build dynamic Merkle tree
        merkle_tree = DynamicMerkleTree()
        doc_hash_map = {}

        # First pass: collect all document hashes
        for doc_id, (plaintext, keywords, version) in self.documents.items():
            # Compute document hash
            doc_hash = self.crypto.compute_hash(plaintext.encode())
            doc_hash_map[(doc_id, version)] = doc_hash

        # Sort by (doc_id, version) for consistent ordering
        sorted_keys = sorted(doc_hash_map.keys())
        leaf_indices = {}

        for i, (doc_id, version) in enumerate(sorted_keys):
            leaf_idx = merkle_tree.add_leaf(doc_hash_map[(doc_id, version)])
            leaf_indices[(doc_id, version)] = leaf_idx

        # Encrypt documents and build index
        for doc_id, (plaintext, keywords, version) in self.documents.items():
            # Derive document-specific key
            doc_key = self.crypto.derive_key(b"doc_enc", f"{doc_id}:{version}".encode())

            # Encrypt document content
            iv, ciphertext = self.crypto.encrypt(doc_key, plaintext.encode())

            # Get leaf index
            leaf_idx = leaf_indices.get((doc_id, version), 0)

            encrypted_docs.append(EncryptedDocument(
                doc_id=doc_id,
                ciphertext=ciphertext,
                iv=iv,
                doc_hash=doc_hash_map[(doc_id, version)],
                version=version,
                timestamp=int(time.time())
            ))

            # Build index entries for each keyword
            for kw in keywords:
                # Derive keyword hash
                kw_key = self.crypto.derive_key(b"kw_hash", kw.encode())
                kw_hash = self.crypto.prf(kw_key, kw.encode())

                # Create index entry
                entry_data = struct.pack('>II', doc_id, version) + doc_hash_map[(doc_id, version)]
                entry_key = self.crypto.derive_key(b"kw_entry", kw_hash + struct.pack('>I', doc_id))
                iv_entry, ciphertext_entry = self.crypto.encrypt(entry_key, entry_data)

                index_entries.append(EncryptedIndexEntry(
                    keyword_hash=kw_hash,
                    doc_id=doc_id,
                    encrypted_entry=ciphertext_entry + iv_entry
                ))

        return encrypted_docs, index_entries, merkle_tree.get_root()

    def generate_search_token(self, keyword: str, version: int = None) -> SearchToken:
        """Generate search token for a keyword at a specific version"""
        kw_bytes = keyword.encode()

        # Derive keyword-specific keys
        token_key = self.crypto.derive_key(b"token", kw_bytes)

        # Compute keyword hash (for indexing)
        keyword_hash = self.crypto.prf(token_key, kw_bytes)

        # Compute trapdoor using version
        if version is None:
            version = max([v for (_, v) in self.keyword_doc_map.get(keyword, set())] or [0])

        trapdoor_key = self.crypto.derive_key(b"trapdoor", kw_bytes + struct.pack('>I', version))
        trapdoor = self.crypto.prf(trapdoor_key, kw_bytes)

        return SearchToken(
            keyword_hash=keyword_hash,
            trapdoor=trapdoor,
            version=version
        )

    def verify_result(self, keyword: str, result: SearchResult) -> bool:
        """
        Verify the completeness and correctness of search results
        """
        # 1. Get expected documents
        expected_docs = self.keyword_doc_map.get(keyword, set())
        expected_doc_ids = {doc_id for doc_id, version in expected_docs if version <= result.keyword_version}

        # 2. Verify Merkle tree proofs for each document
        for i, doc_id in enumerate(result.doc_ids):
            # Get document info
            if doc_id not in self.documents:
                print(f"  - Document {doc_id} not found locally")
                return False

            plaintext, keywords, version = self.documents[doc_id]

            # Compute expected hash
            expected_hash = self.crypto.compute_hash(plaintext.encode())

            # Verify proof
            proof, positions = result.merkle_proofs[i]
            is_valid = DynamicMerkleTree.verify_proof(
                result.merkle_root,
                expected_hash,
                proof,
                positions,
                doc_id  # Using doc_id as leaf index for simplicity
            )

            if not is_valid:
                print(f"  - Merkle proof failed for document {doc_id}")
                return False

            # Decrypt and verify document
            doc_key = self.crypto.derive_key(b"doc_enc", f"{doc_id}:{version}".encode())
            decrypted = self.crypto.decrypt(doc_key, result.ivs[i], result.ciphertexts[i])

            if decrypted != plaintext.encode():
                print(f"  - Document {doc_id} decryption mismatch")
                return False

        # 3. Verify completeness
        returned_ids = set(result.doc_ids)
        if returned_ids != expected_doc_ids:
            print(f"  - Completeness check failed: expected {expected_doc_ids}, got {returned_ids}")
            return False

        return True


class DVSSEServer:
    """
    Server side of DVSSE scheme.
    Stores encrypted documents, processes search queries,
    handles dynamic updates, and generates verification proofs.
    """

    def __init__(self):
        self.encrypted_docs: Dict[Tuple[int, int], EncryptedDocument] = {}  # (doc_id, version) -> doc
        self.index_entries: Dict[bytes, List[bytes]] = {}  # keyword_hash -> list of encrypted entries
        self.merkle_tree: Optional[DynamicMerkleTree] = None
        self.current_root: bytes = b'\x00' * 32
        self.keyword_versions: Dict[bytes, int] = {}  # keyword_hash -> latest version

    def setup(self, encrypted_docs: List[EncryptedDocument],
              index_entries: List[EncryptedIndexEntry],
              merkle_root: bytes):
        """Setup server with encrypted data"""
        # Store encrypted documents
        for doc in encrypted_docs:
            self.encrypted_docs[(doc.doc_id, doc.version)] = doc

        # Build index
        for entry in index_entries:
            if entry.keyword_hash not in self.index_entries:
                self.index_entries[entry.keyword_hash] = []
            self.index_entries[entry.keyword_hash].append(entry.encrypted_entry)

        # Initialize Merkle tree
        self.merkle_tree = DynamicMerkleTree()

        # Add all document hashes to Merkle tree
        for (doc_id, version), doc in sorted(self.encrypted_docs.items()):
            leaf_idx = self.merkle_tree.add_leaf(doc.doc_hash)
            # Store mapping for proof generation
            if not hasattr(self, '_leaf_mapping'):
                self._leaf_mapping = {}
            self._leaf_mapping[(doc_id, version)] = leaf_idx

        self.current_root = merkle_root

    def add_document(self, doc: EncryptedDocument, index_entries: List[EncryptedIndexEntry]):
        """Add a new document to the server"""
        # Store document
        self.encrypted_docs[(doc.doc_id, doc.version)] = doc

        # Update index
        for entry in index_entries:
            if entry.keyword_hash not in self.index_entries:
                self.index_entries[entry.keyword_hash] = []
            self.index_entries[entry.keyword_hash].append(entry.encrypted_entry)

        # Update Merkle tree
        leaf_idx = self.merkle_tree.add_leaf(doc.doc_hash)
        if not hasattr(self, '_leaf_mapping'):
            self._leaf_mapping = {}
        self._leaf_mapping[(doc.doc_id, doc.version)] = leaf_idx

        # Update root
        self.current_root = self.merkle_tree.get_root()

        # Update keyword version
        for entry in index_entries:
            if entry.keyword_hash not in self.keyword_versions:
                self.keyword_versions[entry.keyword_hash] = 0
            self.keyword_versions[entry.keyword_hash] += 1

    def delete_document(self, doc_id: int, version: int):
        """Delete a document from the server"""
        # Remove document
        key = (doc_id, version)
        if key in self.encrypted_docs:
            del self.encrypted_docs[key]

        # Update Merkle tree (set leaf to zero)
        if hasattr(self, '_leaf_mapping') and key in self._leaf_mapping:
            leaf_idx = self._leaf_mapping[key]
            self.merkle_tree.delete_leaf(leaf_idx)

        # Update root
        self.current_root = self.merkle_tree.get_root()

    def search(self, token: SearchToken) -> SearchResult:
        """
        Execute search query and generate verification proof
        """
        # 1. Retrieve index entries for keyword
        encrypted_entries = self.index_entries.get(token.keyword_hash, [])

        # 2. Decrypt entries and collect matching documents
        result_docs = []
        result_ivs = []
        result_ciphertexts = []
        merkle_proofs = []

        for encrypted_entry in encrypted_entries:
            # Decrypt entry (simplified - would need proper key derivation)
            # For demonstration, assume we can extract doc_id
            # In practice, would need trapdoor-based decryption

            # For now, just collect all documents for this keyword
            for (doc_id, version), doc in self.encrypted_docs.items():
                result_docs.append(doc_id)
                result_ivs.append(doc.iv)
                result_ciphertexts.append(doc.ciphertext)

                # Generate Merkle proof
                leaf_idx = getattr(self, '_leaf_mapping', {}).get((doc_id, version), 0)
                proof, positions = self.merkle_tree.generate_proof(leaf_idx)
                merkle_proofs.append((proof, positions))

            break  # Process first entry for demo

        # Remove duplicates while preserving order
        seen = set()
        unique_results = []
        unique_ivs = []
        unique_ciphertexts = []
        unique_proofs = []

        for i, doc_id in enumerate(result_docs):
            if doc_id not in seen:
                seen.add(doc_id)
                unique_results.append(doc_id)
                unique_ivs.append(result_ivs[i])
                unique_ciphertexts.append(result_ciphertexts[i])
                unique_proofs.append(merkle_proofs[i])

        return SearchResult(
            doc_ids=unique_results,
            ciphertexts=unique_ciphertexts,
            ivs=unique_ivs,
            merkle_proofs=unique_proofs,
            merkle_root=self.current_root,
            index_entries=encrypted_entries,
            keyword_version=self.keyword_versions.get(token.keyword_hash, 0)
        )
