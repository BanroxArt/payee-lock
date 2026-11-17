import hashlib

from hypothesis import given
from hypothesis import strategies as st

from payeelock.keccak import keccak256, sponge256


def test_known_vectors() -> None:
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    # ERC-20 Transfer and Approval event topics.
    assert (
        keccak256(b"Transfer(address,address,uint256)").hex()
        == "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    )
    assert (
        keccak256(b"Approval(address,address,uint256)").hex()
        == "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
    )


@given(st.binary(max_size=600))
def test_sponge_matches_nist_sha3_with_its_pad(data: bytes) -> None:
    assert sponge256(data, 0x06) == hashlib.sha3_256(data).digest()


def test_block_boundaries() -> None:
    for n in (135, 136, 137, 271, 272, 273):
        assert sponge256(b"\x00" * n, 0x06) == hashlib.sha3_256(b"\x00" * n).digest()
