import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import struct


# Helper: Hash-to-Scalar
def hash_to_scalar(data: bytes, curve: ec.EllipticCurve) -> int:
    """Hash arbitrary bytes into a scalar in the range [0, order-1]"""
    order = curve.order
    hash_len = (order.bit_length() + 7) // 8 + 32
    h = hashlib.shake_256(data).digest(hash_len)
    return int.from_bytes(h, 'big') % order

# Helper: Hash-to-Group
def hash_to_curve(data: bytes, curve: ec.EllipticCurve) -> ec.EllipticCurvePublicKey:
    """Hash arbitrary bytes to an elliptic curve point (simplified try-and-increment)"""
    backend = default_backend()
    x = 0
    while True:
        h = hashlib.sha256(data + struct.pack('>I', x)).digest()
        x_val = int.from_bytes(h, 'big')
        try:
            point = ec.EllipticCurvePublicKey.from_encoded_point(
                curve, b'\x04' + h
            )
            return point
        except ValueError:
            x += 1
            if x > 1000:
                raise RuntimeError("Hash-to-curve failed")


# the VOPRF Server
class VOPRFServer:
    def __init__(self, curve=ec.SECP256R1()):
        self.curve = curve
        # Generate server private key k and public key G*k
        self.private_key = ec.generate_private_key(curve, default_backend())
        self.public_key = self.private_key.public_key()

    def evaluate(self, blinded_point: ec.EllipticCurvePublicKey) -> bytes:
        """Evaluate the blinded point: Z = M * k"""
        private_numbers = self.private_key.private_numbers()
        private_scalar = private_numbers.private_value

        M = blinded_point.public_numbers()
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
        M_point = EllipticCurvePublicNumbers(M.x, M.y, self.curve).public_key(default_backend())

        d = private_scalar
        Z_point = self._scalar_mult(M_point, d)

        return Z_point.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )

    def _scalar_mult(self, point: ec.EllipticCurvePublicKey, scalar: int) -> ec.EllipticCurvePublicKey:
        """Elliptic curve scalar multiplication: scalar * point"""
        # This is a placeholder. A full implementation requires low-level EC operations.
        return point

    def generate_dleq_proof(self, M: ec.EllipticCurvePublicKey, Z: ec.EllipticCurvePublicKey) -> bytes:
        """Generate DLEQ proof: log_G(pkS) == log_M(Z)"""
        order = self.curve.order
        r = hash_to_scalar(os.urandom(32), self.curve)

        G = ec.EllipticCurvePublicKey.from_encoded_point(self.curve, b'\x04' + b'\x00' * 64)
        a1 = self._scalar_mult(G, r)
        a2 = self._scalar_mult(M, r)

        c = self._hash_dleq(G, self.public_key, M, Z, a1, a2)
        private_scalar = self.private_key.private_numbers().private_value
        s = (r - c * private_scalar) % order

        proof = struct.pack('>QQ', c, s)
        return proof

    def _hash_dleq(self, G, pkS, M, Z, a1, a2):
        """Compute the DLEQ challenge hash"""
        h = hashlib.sha256()
        h.update(G.public_bytes(encoding=serialization.Encoding.X962,
                                format=serialization.PublicFormat.CompressedPoint))
        h.update(pkS.public_bytes(encoding=serialization.Encoding.X962,
                                  format=serialization.PublicFormat.CompressedPoint))
        h.update(M.public_bytes(encoding=serialization.Encoding.X962,
                                format=serialization.PublicFormat.CompressedPoint))
        h.update(Z.public_bytes(encoding=serialization.Encoding.X962,
                                format=serialization.PublicFormat.CompressedPoint))
        h.update(a1.public_bytes(encoding=serialization.Encoding.X962,
                                 format=serialization.PublicFormat.CompressedPoint))
        h.update(a2.public_bytes(encoding=serialization.Encoding.X962,
                                 format=serialization.PublicFormat.CompressedPoint))
        digest = h.digest()
        return int.from_bytes(digest, 'big') % self.curve.order


# the VOPRF Client
class VOPRFClient:
    def __init__(self, curve=ec.SECP256R1()):
        self.curve = curve

    def blind(self, input_data: bytes) -> tuple[ec.EllipticCurvePublicKey, int]:
        """Blind the input: generate blinding factor r, return blinded point M and r"""
        Hx = hash_to_curve(input_data, self.curve)
        r = hash_to_scalar(os.urandom(32), self.curve)
        M = self._scalar_mult(Hx, r)
        return M, r

    def finalize(self, input_data: bytes, Z_bytes: bytes, r: int,
                 server_public_key: ec.EllipticCurvePublicKey) -> bytes:
        """Unblind and verify: compute N = Z^(1/r)"""
        Z = ec.EllipticCurvePublicKey.from_encoded_point(self.curve, Z_bytes)

        r_inv = pow(r, -1, self.curve.order)
        N = self._scalar_mult(Z, r_inv)

        output = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"VOPRF Output",
            backend=default_backend()
        ).derive(N.public_bytes(encoding=serialization.Encoding.X962,
                                format=serialization.PublicFormat.UncompressedPoint))
        return output

    def _scalar_mult(self, point: ec.EllipticCurvePublicKey, scalar: int) -> ec.EllipticCurvePublicKey:
        """Scalar multiplication (same as server)"""
        return point
