#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple


# ============================================================
# Conversoes basicas
# ============================================================

def i2osp(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("Inteiro negativo nao pode ser convertido para bytes.")
    if x >= 256 ** length:
        raise ValueError("Inteiro grande demais para o tamanho solicitado.")
    return x.to_bytes(length, "big")


def os2ip(data: bytes) -> int:
    return int.from_bytes(data, "big")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


def int_to_b64(x: int) -> str:
    if x == 0:
        return b64e(b"\x00")
    return b64e(x.to_bytes((x.bit_length() + 7) // 8, "big"))


def b64_to_int(s: str) -> int:
    return os2ip(b64d(s))


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Entradas do XOR precisam ter o mesmo tamanho.")
    return bytes(x ^ y for x, y in zip(a, b))


# ============================================================
# Miller-Rabin e geracao dos primos
# ============================================================

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
]


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False

    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0

    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        passou = False

        for _ in range(s - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                passou = True
                break

        if not passou:
            return False

    return True


def generate_prime(bits: int, rounds: int = 40) -> int:
    if bits < 16:
        raise ValueError("Use pelo menos 16 bits.")

    while True:
        candidate = secrets.randbits(bits)

        candidate |= (1 << (bits - 1))
        candidate |= 1

        if is_probable_prime(candidate, rounds=rounds):
            return candidate


# ============================================================
# RSA
# ============================================================

@dataclass
class PublicKey:
    n: int
    e: int

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


@dataclass
class PrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def public_key(self) -> PublicKey:
        return PublicKey(n=self.n, e=self.e)


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return a, 1, 0

    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)

    if g != 1:
        raise ValueError("Inverso modular nao existe.")

    return x % m


def generate_rsa_keypair(prime_bits: int = 1024, e: int = 65537) -> PrivateKey:
    if prime_bits < 1024:
        raise ValueError("Para cumprir o trabalho, p e q devem ter pelo menos 1024 bits.")

    while True:
        p = generate_prime(prime_bits)
        q = generate_prime(prime_bits)

        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        if math.gcd(e, phi) == 1:
            d = modinv(e, phi)
            return PrivateKey(n=n, e=e, d=d, p=p, q=q)


def rsa_encrypt_int(m: int, public_key: PublicKey) -> int:
    if not (0 <= m < public_key.n):
        raise ValueError("Mensagem fora do intervalo RSA.")

    return pow(m, public_key.e, public_key.n)


def rsa_decrypt_int(c: int, private_key: PrivateKey) -> int:
    if not (0 <= c < private_key.n):
        raise ValueError("Criptograma fora do intervalo RSA.")

    return pow(c, private_key.d, private_key.n)


# ============================================================
# OAEP
# ============================================================

HASH_NAME = "SHA3-256"
HASH_LEN = hashlib.sha3_256().digest_size


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def mgf1(seed: bytes, mask_len: int, hash_func=sha3_256) -> bytes:
    if mask_len < 0:
        raise ValueError("mask_len invalido.")

    output = b""
    counter = 0

    while len(output) < mask_len:
        c = counter.to_bytes(4, "big")
        output += hash_func(seed + c)
        counter += 1

    return output[:mask_len]


def oaep_encode(message: bytes, k: int, label: bytes = b"") -> bytes:
    h_len = HASH_LEN
    max_len = k - 2 * h_len - 2

    if len(message) > max_len:
        raise ValueError(f"Mensagem grande demais para um bloco OAEP. Maximo: {max_len} bytes.")

    l_hash = sha3_256(label)

    ps = b"\x00" * (k - len(message) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + message

    seed = secrets.token_bytes(h_len)

    db_mask = mgf1(seed, k - h_len - 1)
    masked_db = xor_bytes(db, db_mask)

    seed_mask = mgf1(masked_db, h_len)
    masked_seed = xor_bytes(seed, seed_mask)

    return b"\x00" + masked_seed + masked_db


def oaep_decode(encoded: bytes, k: int, label: bytes = b"") -> bytes:
    h_len = HASH_LEN

    if len(encoded) != k:
        raise ValueError("Bloco OAEP com tamanho incorreto.")

    if k < 2 * h_len + 2:
        raise ValueError("Modulo RSA pequeno demais para OAEP com SHA3-256.")

    y = encoded[0]
    masked_seed = encoded[1:1 + h_len]
    masked_db = encoded[1 + h_len:]

    seed_mask = mgf1(masked_db, h_len)
    seed = xor_bytes(masked_seed, seed_mask)

    db_mask = mgf1(seed, k - h_len - 1)
    db = xor_bytes(masked_db, db_mask)

    l_hash = sha3_256(label)
    received_l_hash = db[:h_len]
    rest = db[h_len:]

    if y != 0 or received_l_hash != l_hash:
        raise ValueError("Falha na decodificacao OAEP.")

    index = None

    for i, byte in enumerate(rest):
        if byte == 0x01:
            index = i
            break

        if byte != 0x00:
            raise ValueError("Padding OAEP invalido.")

    if index is None:
        raise ValueError("Separador 0x01 nao encontrado no OAEP.")

    return rest[index + 1:]


def rsa_oaep_encrypt_block(message_block: bytes, public_key: PublicKey) -> bytes:
    k = public_key.size_bytes

    encoded = oaep_encode(message_block, k)
    m = os2ip(encoded)

    c = rsa_encrypt_int(m, public_key)

    return i2osp(c, k)


def rsa_oaep_decrypt_block(cipher_block: bytes, private_key: PrivateKey) -> bytes:
    k = private_key.size_bytes

    if len(cipher_block) != k:
        raise ValueError("Bloco cifrado com tamanho incorreto.")

    c = os2ip(cipher_block)
    m = rsa_decrypt_int(c, private_key)

    encoded = i2osp(m, k)

    return oaep_decode(encoded, k)


# ============================================================
# Cifracao e decifracao de arquivos
# ============================================================

def rsa_oaep_encrypt_file(input_path: Path, output_path: Path, public_key: PublicKey) -> None:
    k = public_key.size_bytes
    max_block = k - 2 * HASH_LEN - 2

    if max_block <= 0:
        raise ValueError("Chave RSA pequena demais para OAEP com SHA3-256.")

    plaintext = input_path.read_bytes()
    ciphertext_blocks = []

    for start in range(0, len(plaintext), max_block):
        block = plaintext[start:start + max_block]
        encrypted_block = rsa_oaep_encrypt_block(block, public_key)
        ciphertext_blocks.append(encrypted_block)

    output_path.write_bytes(b"".join(ciphertext_blocks))


def rsa_oaep_decrypt_file(input_path: Path, output_path: Path, private_key: PrivateKey) -> None:
    k = private_key.size_bytes
    ciphertext = input_path.read_bytes()

    if len(ciphertext) == 0:
        output_path.write_bytes(b"")
        return

    if len(ciphertext) % k != 0:
        raise ValueError("Arquivo cifrado invalido.")

    plaintext_blocks = []

    for start in range(0, len(ciphertext), k):
        block = ciphertext[start:start + k]
        decrypted_block = rsa_oaep_decrypt_block(block, private_key)
        plaintext_blocks.append(decrypted_block)

    output_path.write_bytes(b"".join(plaintext_blocks))


# ============================================================
# Assinatura
# ============================================================

def sign_hash_raw_rsa(message: bytes, private_key: PrivateKey) -> bytes:
    digest = sha3_256(message)

    h = os2ip(digest)

    s = rsa_decrypt_int(h, private_key)

    return i2osp(s, private_key.size_bytes)


def create_signed_document(input_path: Path, output_path: Path, private_key: PrivateKey) -> None:
    message = input_path.read_bytes()

    digest = sha3_256(message)
    signature = sign_hash_raw_rsa(message, private_key)

    pub = private_key.public_key()

    signed_doc: Dict[str, object] = {
        "format": "CIC0201-RSA-SIGN-V1",
        "hash_algorithm": HASH_NAME,
        "signature_algorithm": "RSA-RAW-SHA3-256",
        "encoding": "BASE64",
        "public_key": {
            "n_base64": int_to_b64(pub.n),
            "e_base64": int_to_b64(pub.e),
        },
        "message_base64": b64e(message),
        "hash_base64": b64e(digest),
        "signature_base64": b64e(signature),
    }

    output_path.write_text(json.dumps(signed_doc, indent=2), encoding="utf-8")


def verify_signed_document(input_path: Path) -> None:
    data = json.loads(input_path.read_text(encoding="utf-8"))

    if data.get("format") != "CIC0201-RSA-SIGN-V1":
        raise ValueError("Formato de documento nao reconhecido.")

    n = b64_to_int(data["public_key"]["n_base64"])
    e = b64_to_int(data["public_key"]["e_base64"])
    public_key = PublicKey(n=n, e=e)

    message = b64d(data["message_base64"])
    signature = b64d(data["signature_base64"])
    declared_hash = b64d(data["hash_base64"])

    if len(signature) != public_key.size_bytes:
        raise ValueError("Assinatura com tamanho invalido.")

    s_int = os2ip(signature)
    h_int = rsa_encrypt_int(s_int, public_key)

    recovered_full = i2osp(h_int, public_key.size_bytes)
    recovered_hash = recovered_full[-HASH_LEN:]

    calculated_hash = sha3_256(message)

    if declared_hash != calculated_hash:
        print("[-] Hash armazenado no documento nao confere com a mensagem.")
        return

    if recovered_hash == calculated_hash:
        print("[+] SUCESSO: A assinatura e VALIDA. A integridade e autenticidade foram confirmadas.")
    else:
        print("[-] ERRO: A assinatura e INVALIDA. O documento foi alterado ou a chave esta incorreta.")


# ============================================================
# Leitura e escrita das chaves
# ============================================================

def save_private_key(path: Path, private_key: PrivateKey) -> None:
    data = {
        "type": "RSA_PRIVATE_KEY",
        "n_base64": int_to_b64(private_key.n),
        "e_base64": int_to_b64(private_key.e),
        "d_base64": int_to_b64(private_key.d),
        "p_base64": int_to_b64(private_key.p),
        "q_base64": int_to_b64(private_key.q),
    }

    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def save_public_key(path: Path, public_key: PublicKey) -> None:
    data = {
        "type": "RSA_PUBLIC_KEY",
        "n_base64": int_to_b64(public_key.n),
        "e_base64": int_to_b64(public_key.e),
    }

    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_private_key(path: Path) -> PrivateKey:
    data = json.loads(path.read_text(encoding="utf-8"))

    if data.get("type") != "RSA_PRIVATE_KEY":
        raise ValueError("Arquivo nao parece ser uma chave privada RSA deste programa.")

    return PrivateKey(
        n=b64_to_int(data["n_base64"]),
        e=b64_to_int(data["e_base64"]),
        d=b64_to_int(data["d_base64"]),
        p=b64_to_int(data["p_base64"]),
        q=b64_to_int(data["q_base64"]),
    )


def load_public_key(path: Path) -> PublicKey:
    data = json.loads(path.read_text(encoding="utf-8"))

    if data.get("type") != "RSA_PUBLIC_KEY":
        raise ValueError("Arquivo nao parece ser uma chave publica RSA deste programa.")

    return PublicKey(
        n=b64_to_int(data["n_base64"]),
        e=b64_to_int(data["e_base64"]),
    )

# ============================================================
# Comandos do terminal
# ============================================================

def cmd_genkeys(args: argparse.Namespace) -> None:
    private_key = generate_rsa_keypair(
        prime_bits=args.prime_bits,
        e=args.e
    )

    save_private_key(Path(args.private), private_key)
    save_public_key(Path(args.public), private_key.public_key())

    print("Chaves geradas com sucesso.")
    print(f"p e q: {args.prime_bits} bits cada")
    print(f"n: {private_key.n.bit_length()} bits")
    print(f"Chave privada: {args.private}")
    print(f"Chave publica: {args.public}")


def cmd_encrypt(args: argparse.Namespace) -> None:
    public_key = load_public_key(Path(args.public))

    rsa_oaep_encrypt_file(
        input_path=Path(args.input),
        output_path=Path(args.output),
        public_key=public_key
    )

    print(f"Arquivo cifrado salvo em: {args.output}")


def cmd_decrypt(args: argparse.Namespace) -> None:
    private_key = load_private_key(Path(args.private))

    rsa_oaep_decrypt_file(
        input_path=Path(args.input),
        output_path=Path(args.output),
        private_key=private_key
    )

    print(f"Arquivo decifrado salvo em: {args.output}")


def cmd_sign(args: argparse.Namespace) -> None:
    private_key = load_private_key(Path(args.private))

    create_signed_document(
        input_path=Path(args.input),
        output_path=Path(args.output),
        private_key=private_key
    )

    print(f"Documento assinado salvo em: {args.output}")


def cmd_verify(args: argparse.Namespace) -> None:
    verify_signed_document(Path(args.input))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Trabalho 2: RSA, OAEP e assinatura."
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True
    )

    p_gen = sub.add_parser(
        "genkeys",
        help="Gera chaves RSA."
    )
    p_gen.add_argument(
        "--prime-bits",
        type=int,
        default=1024,
        help="Bits de cada primo p e q."
    )
    p_gen.add_argument(
        "--e",
        type=int,
        default=65537,
        help="Expoente publico."
    )
    p_gen.add_argument(
        "--private",
        required=True,
        help="Arquivo da chave privada."
    )
    p_gen.add_argument(
        "--public",
        required=True,
        help="Arquivo da chave publica."
    )
    p_gen.set_defaults(func=cmd_genkeys)

    p_enc = sub.add_parser(
        "encrypt",
        help="Cifra arquivo com RSA-OAEP."
    )
    p_enc.add_argument(
        "--public",
        required=True,
        help="Chave publica JSON."
    )
    p_enc.add_argument(
        "--in",
        dest="input",
        required=True,
        help="Arquivo de entrada."
    )
    p_enc.add_argument(
        "--out",
        dest="output",
        required=True,
        help="Arquivo cifrado de saida."
    )
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser(
        "decrypt",
        help="Decifra arquivo com RSA-OAEP."
    )
    p_dec.add_argument(
        "--private",
        required=True,
        help="Chave privada JSON."
    )
    p_dec.add_argument(
        "--in",
        dest="input",
        required=True,
        help="Arquivo cifrado."
    )
    p_dec.add_argument(
        "--out",
        dest="output",
        required=True,
        help="Arquivo decifrado."
    )
    p_dec.set_defaults(func=cmd_decrypt)

    p_sign = sub.add_parser(
        "sign",
        help="Assina arquivo com SHA3-256 e RSA."
    )
    p_sign.add_argument(
        "--private",
        required=True,
        help="Chave privada JSON."
    )
    p_sign.add_argument(
        "--in",
        dest="input",
        required=True,
        help="Arquivo a ser assinado."
    )
    p_sign.add_argument(
        "--out",
        dest="output",
        required=True,
        help="Documento assinado JSON."
    )
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser(
        "verify",
        help="Verifica a assinatura de um documento JSON."
    )
    p_verify.add_argument(
        "--in",
        dest="input",
        required=True,
        help="Documento assinado JSON a ser verificado."
    )
    p_verify.set_defaults(func=cmd_verify)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    args.func(args)


if __name__ == "__main__":
    main()

