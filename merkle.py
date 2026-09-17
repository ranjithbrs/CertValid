"""
merkle.py - Cryptographic Merkle Tree Batch Verification Engine for CertValid.
Constructs binary Merkle trees over issued certificates, generates inclusion proofs,
and verifies audit paths to prove certificate existence in the global registry batch root.
"""

import hashlib
from typing import List, Dict, Optional, Tuple


def compute_leaf_hash(cert: dict) -> str:
    """
    Compute cryptographic leaf hash for a certificate record.
    Binds cert_id, file_hash, signature, and status into an immutable hash digest.
    """
    raw_payload = f"{cert.get('cert_id')}|{cert.get('file_hash')}|{cert.get('signature') or ''}|{cert.get('status', 'active')}"
    return hashlib.sha256(raw_payload.encode('utf-8')).hexdigest()


def hash_pair(left: str, right: str) -> str:
    """Compute parent hash from left and right child hashes."""
    return hashlib.sha256((left + right).encode('utf-8')).hexdigest()


def build_merkle_tree(certificates: List[dict]) -> dict:
    """
    Build a complete binary Merkle Tree over a list of certificate records.
    Returns the root hash, all tree levels, leaf mapping, and tree depth.
    """
    if not certificates:
        empty_root = hashlib.sha256(b'CertValid_Empty_Tree').hexdigest()
        return {
            'root': empty_root,
            'levels': [[empty_root]],
            'leaf_count': 0,
            'leaf_hashes': {},
            'depth': 1
        }

    # Deterministic sort by cert_id
    sorted_certs = sorted(certificates, key=lambda c: str(c.get('cert_id', '')))

    # Level 0: Leaf Hashes
    leaf_hashes = {}
    current_level = []
    for cert in sorted_certs:
        c_id = cert.get('cert_id')
        l_hash = compute_leaf_hash(cert)
        leaf_hashes[c_id] = l_hash
        current_level.append(l_hash)

    levels = [list(current_level)]

    # Build levels up to Root
    while len(current_level) > 1:
        next_level = []
        # If odd number of nodes, duplicate the last node
        if len(current_level) % 2 != 0:
            current_level.append(current_level[-1])

        for i in range(0, len(current_level), 2):
            parent = hash_pair(current_level[i], current_level[i + 1])
            next_level.append(parent)

        levels.append(list(next_level))
        current_level = next_level

    root = levels[-1][0] if levels and levels[-1] else ''

    return {
        'root': root,
        'levels': levels,
        'leaf_count': len(sorted_certs),
        'leaf_hashes': leaf_hashes,
        'depth': len(levels)
    }


def get_merkle_proof(cert_id: str, certificates: List[dict]) -> Optional[dict]:
    """
    Generate the cryptographic audit trail (Merkle inclusion proof) for a certificate.
    Returns the leaf hash, list of sibling hashes with positions, and expected root.
    """
    sorted_certs = sorted(certificates, key=lambda c: str(c.get('cert_id', '')))
    cert_ids = [c.get('cert_id') for c in sorted_certs]

    if cert_id not in cert_ids:
        return None

    index = cert_ids.index(cert_id)
    tree_meta = build_merkle_tree(certificates)
    levels = tree_meta['levels']
    root = tree_meta['root']
    leaf_hash = tree_meta['leaf_hashes'].get(cert_id)

    proof = []
    current_idx = index

    for level in levels[:-1]:  # Exclude root level
        # Duplicate last element if odd
        level_copy = list(level)
        if len(level_copy) % 2 != 0:
            level_copy.append(level_copy[-1])

        if current_idx % 2 == 0:
            # Sibling is to the right
            sibling_idx = current_idx + 1
            if sibling_idx < len(level_copy):
                proof.append({'position': 'right', 'hash': level_copy[sibling_idx]})
        else:
            # Sibling is to the left
            sibling_idx = current_idx - 1
            proof.append({'position': 'left', 'hash': level_copy[sibling_idx]})

        current_idx = current_idx // 2

    return {
        'cert_id': cert_id,
        'leaf_hash': leaf_hash,
        'merkle_root': root,
        'proof': proof,
        'proof_length': len(proof)
    }


def verify_merkle_proof(leaf_hash: str, proof: List[dict], expected_root: str) -> bool:
    """
    Verify that a leaf hash belongs to a Merkle root using its inclusion proof path.
    """
    current_hash = leaf_hash
    for step in proof:
        sibling = step.get('hash', '')
        pos = step.get('position', 'right')
        if pos == 'left':
            current_hash = hash_pair(sibling, current_hash)
        else:
            current_hash = hash_pair(current_hash, sibling)

    return current_hash.lower() == expected_root.lower()
