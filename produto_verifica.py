"""Independent verifier of the Fiel proof archive. Read only.

Python 3.9+ standard library only: it does not import the product code, so a third party (a
client, an auditor, an expert) can check an archive without trusting that code. The format, all
it relies on:

- ``<raiz>/ledger.jsonl``: one JSON object per line, in append order. Each one has, among other
  fields, ``url``, ``source``, ``sha256`` (of the raw bytes fetched), ``bytes`` (their length),
  ``seen_at`` (ISO 8601 with offset, the fetch clock), ``prev`` and ``sha``.
- hash chain: ``sha`` = SHA-256 (hex) of the line's object without ``sha``, written as
  ``json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False)`` in UTF-8 (ASCII
  escapes; floats as Python writes them, the shortest round trip). ``prev`` is the ``sha`` of the
  previous line; the first line's is 64 zeros. The head is the last line's ``sha``.
- ``<raiz>/blobs/<sha256>``: the raw bytes, gzip-compressed; SHA-256 of the decompressed bytes =
  the file name = the record's ``sha256``, and their length = ``bytes``.
- ``seen_at`` never goes back for one url (any source), in ledger order; equal is allowed.

``--sem-blobs``: the quick check. Everything above but the blobs' content: a blob must exist,
none is decompressed (the report says ``"blobs": "presença só"``; the full check, the default,
says ``"conferidos"``). The tree and the anchors need the ledger only. Anchors are appended
after the full check only.

Checks, each failure with its line (1-based): ``chain`` (prev is not the previous sha),
``hash`` (sha does not match the line), ``json`` (not a JSON object), ``seen_at`` (missing,
without offset, or before the url's previous one), ``blob_missing``, ``blob`` (does not
decompress, or SHA-256 / length differ). Not failures, only listed: ``orphans`` (blobs no
line names: a crash between storing and appending leaves one) and ``tmp`` (unfinished writes).
A deleted last line keeps the chain whole: give ``--anchor`` a head published earlier (it must
be some line's sha), or ``--ancoras ops/ancoras.tsv``, the heads published with the repository
(each commit and push stamps them): tab-separated ``data_utc`` (when the head was recorded),
``head`` (64 hex) and ``n_linhas`` (the ledger's lines then); a header line and lines starting
with ``#`` are skipped. Each head must be the ``sha`` of exactly line ``n_linhas``. The cache/
folder (materialized copies) is not part of the proof.

``--append-ancora`` (with ``--ancoras``): only when the whole check is OK (the anchors already
listed included), append one line (now in UTC, head, lines); earlier lines are never rewritten,
and a head already listed with the same lines is not appended again.

Merkle tree (RFC 6962 §2.1, SHA-256): one
leaf per ledger line, in order; the leaf's input is the 32 bytes of the line's ``sha``, so leaf =
SHA-256(0x00 || sha), node = SHA-256(0x01 || left || right), the empty tree's root = SHA-256 of
nothing, split at the largest power of 2 smaller than n. The report's ``merkle_root`` is the root
of the whole ledger. ``--prova-inclusao N [--tamanho T]`` prints the inclusion proof of line N in
the tree of the first T lines (default: all); ``--verificar-inclusao ARQ --raiz-publicada HEX``
checks such a proof with no ledger at all (RFC 9162 §2.1.3.2): the record must hash to its
``sha``, the path must lead to the proof's root, and that root must be the published one
(``--raiz-publicada``, or the ``raiz`` of the anchor of ``tree_size`` lines in ``--ancoras``).
Since the Merkle tree, an anchor row may carry a 4th column ``raiz``: the root of the tree of
its first ``n_linhas`` lines (``--append-ancora`` writes it, after one ``#`` line naming the
column; the three-column rows stay as they were). The full check fails a row whose root is not
that tree's, a row with fewer lines than the row before it, and lists in ``consistencia`` the
proof (RFC 6962 §2.1.2) between each consecutive pair of anchors. ``--prova-consistencia M N``
prints the proof from the first M lines to the first N; ``--verificar-consistencia ARQ
--ancoras TSV`` checks it with no ledger (RFC 9162 §2.1.4.2) and requires both roots to be the
anchors' roots of those sizes.

    python3 scripts/produto_verifica.py [--raiz out/produto/arquivo] [--anchor SHA]
                                        [--ancoras ops/ancoras.tsv [--append-ancora]]
    python3 scripts/produto_verifica.py [--raiz ...] --prova-inclusao N [--tamanho T]
    python3 scripts/produto_verifica.py --verificar-inclusao prova.json --raiz-publicada HEX
    python3 scripts/produto_verifica.py --verificar-inclusao prova.json --ancoras ancoras.tsv
    python3 scripts/produto_verifica.py [--raiz ...] --prova-consistencia M N
    python3 scripts/produto_verifica.py --verificar-consistencia prova.json --ancoras ancoras.tsv
Prints a JSON report; exit 0 = OK, 1 = FALHA (``first_break`` is the first failure).
"""

from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import sys
import time
from pathlib import Path

GENESIS = "0" * 64
CHUNK = 1 << 20


def line_sha(obj: dict) -> str:
    body = {k: v for k, v in obj.items() if k != "sha"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def blob_check(path: Path) -> tuple[str, int]:
    """(SHA-256, length) of the decompressed bytes of a blob, read in chunks."""
    h, n = hashlib.sha256(), 0
    with gzip.open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


ALGO = ("RFC 6962 SHA-256; folha = SHA-256(0x00 || sha da linha, 32 bytes); "
        "nó = SHA-256(0x01 || esquerda || direita)")  # fmt: skip


class ProofError(ValueError):
    """A Merkle proof that does not verify."""


def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _is_hex64(s: object) -> bool:
    return isinstance(s, str) and len(s) == 64 and set(s) <= set("0123456789abcdef")


def leaf_of(obj: dict) -> bytes:
    """The leaf hash of a ledger line: its ``sha`` (64 hex) as the leaf input."""
    sha = obj["sha"]
    if not _is_hex64(sha):
        raise ValueError("sha is not 64 lowercase hex")
    return leaf_hash(bytes.fromhex(sha))


def _split(n: int) -> int:
    """The largest power of 2 smaller than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def mth(leaves: list[bytes]) -> bytes:
    """MTH(D[n]) of RFC 6962 §2.1, from the leaf hashes."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def inclusion_proof(leaves: list[bytes], m: int) -> list[bytes]:
    """PATH(m, D[n]) of RFC 6962 §2.1.1: the audit path of leaf m (0-based)."""
    n = len(leaves)
    if not 0 <= m < n:
        raise ValueError(f"leaf {m} is outside a tree of {n}")
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return inclusion_proof(leaves[:k], m) + [mth(leaves[k:])]
    return inclusion_proof(leaves[k:], m - k) + [mth(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], root_hash: bytes
                     ) -> None:  # fmt: skip
    """RFC 9162 §2.1.3.2; raises ProofError unless ``proof`` leads ``leaf`` to ``root_hash``."""
    if not 0 <= index < size:
        raise ProofError(f"leaf {index} is outside a tree of {size}")
    if len(leaf) != 32:
        raise ProofError("the leaf hash is not 32 bytes")
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            raise ProofError("the proof is longer than the path")
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not fn & 1 and fn:
                fn, sn = fn >> 1, sn >> 1
        else:
            r = node_hash(r, p)
        fn, sn = fn >> 1, sn >> 1
    if sn != 0:
        raise ProofError("the proof is shorter than the path")
    if r != root_hash:
        raise ProofError("the proof leads to another root")


def consistency_proof(leaves: list[bytes], m: int) -> list[bytes]:
    """PROOF(m, D[n]) of RFC 6962 §2.1.2: the tree of the first m leaves is a prefix of this one
    (0 < m <= n; empty when m = n)."""
    if not 0 < m <= len(leaves):
        raise ValueError(f"no consistency proof from {m} to {len(leaves)} leaves")
    return _subproof(leaves, m, True)


def _subproof(leaves: list[bytes], m: int, whole: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if whole else [mth(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(leaves[:k], m, whole) + [mth(leaves[k:])]
    return _subproof(leaves[k:], m - k, False) + [mth(leaves[:k])]


def verify_consistency(m: int, n: int, root_m: bytes, root_n: bytes, proof: list[bytes]) -> None:
    """RFC 9162 §2.1.4.2; raises ProofError unless the tree of n leaves with root ``root_n``
    extends the tree of m leaves with root ``root_m``."""
    if m > n:
        raise ProofError(f"the first tree ({m}) is bigger than the second ({n})")
    if m == 0:
        raise ProofError("a consistency check from the empty tree proves nothing")
    if m == n:
        if proof:
            raise ProofError("equal sizes take an empty proof")
        if root_m != root_n:
            raise ProofError("equal sizes, different roots")
        return
    if not proof:
        raise ProofError("the proof is empty")
    path = [root_m, *proof] if m & (m - 1) == 0 else list(proof)
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn, sn = fn >> 1, sn >> 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            raise ProofError("the proof is longer than the path")
        if fn & 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            while not fn & 1 and fn:
                fn, sn = fn >> 1, sn >> 1
        else:
            sr = node_hash(sr, c)
        fn, sn = fn >> 1, sn >> 1
    if sn != 0:
        raise ProofError("the proof is shorter than the path")
    if fr != root_m:
        raise ProofError("the proof does not lead to the first root")
    if sr != root_n:
        raise ProofError("the proof does not lead to the second root")


def published_roots(tsv: Path) -> dict[int, bytes]:
    """n_linhas -> raiz of the anchors' rows that publish a root; ValueError when two rows give
    one size two roots."""
    out: dict[int, bytes] = {}
    for row in tsv.read_text().splitlines():
        f = row.split("\t")
        if row.startswith(("#", "data_utc")) or len(f) != 4 or not f[2].isdigit():
            continue
        if not _is_hex64(f[3]) or out.setdefault(int(f[2]), bytes.fromhex(f[3])).hex() != f[3]:
            raise ValueError(f"{tsv}: the root of {f[2]} lines is not one 64-hex value")
    return out


def check_consistency(doc: dict, roots: dict[int, bytes] | None) -> dict:
    """The report of a consistency proof file, read with no ledger."""
    out = {"status": "FALHA", "size1": doc.get("size1"), "size2": doc.get("size2")}
    try:
        m, n = int(doc["size1"]), int(doc["size2"])
        r1, r2 = bytes.fromhex(doc["root1"]), bytes.fromhex(doc["root2"])
        verify_consistency(m, n, r1, r2, [bytes.fromhex(h) for h in doc["caminho"]])
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        return out | {"detail": f"{type(e).__name__}: {e}"}
    if roots is None or m not in roots or n not in roots:
        return out | {"detail": "prova coerente, raiz não ancorada: passe --ancoras com as "
                                "raízes dos dois tamanhos"}  # fmt: skip
    if (roots[m], roots[n]) != (r1, r2):
        return out | {"detail": "as raízes da prova não são as publicadas"}
    return out | {"status": "OK", "detail": f"a árvore de {n} linhas estende a de {m}"}


def check_inclusion(doc: dict, published: bytes | None) -> dict:
    """The report of an inclusion proof file, read with no ledger."""
    out = {"status": "FALHA", "leaf_index": doc.get("leaf_index"),
           "tree_size": doc.get("tree_size"), "raiz": doc.get("raiz")}  # fmt: skip
    try:
        line = doc["linha"]
        if line.get("sha") != line_sha(line):
            raise ProofError("the record does not hash to its sha")
        path = [bytes.fromhex(h) for h in doc["caminho"]]
        verify_inclusion(leaf_of(line), int(doc["leaf_index"]), int(doc["tree_size"]), path,
                         bytes.fromhex(doc["raiz"]))  # fmt: skip
    except (KeyError, TypeError, ValueError, AttributeError) as e:  # ProofError is a ValueError
        return out | {"detail": f"{type(e).__name__}: {e}"}
    if published is None:
        return out | {"detail": "prova coerente, raiz não ancorada: passe --raiz-publicada"}
    if bytes.fromhex(doc["raiz"]) != published:
        return out | {"detail": "a raiz da prova não é a raiz publicada"}
    return out | {"status": "OK", "detail": "a linha está na árvore da raiz publicada"}


def ledger_leaves(root_dir: Path) -> tuple[list[dict], list[bytes]]:
    """The ledger's lines and their leaf hashes; ValueError on a line that is not a JSON object
    hashing to its own ``sha`` (run the full check for the details)."""
    objs = []
    for n, text in enumerate((root_dir / "ledger.jsonl").read_text().splitlines(), start=1):
        obj = json.loads(text)
        if not isinstance(obj, dict) or obj.get("sha") != line_sha(obj):
            raise ValueError(f"line {n} is not a JSON object hashing to its sha")
        objs.append(obj)
    return objs, [leaf_of(o) for o in objs]


def verify(root: Path, anchor: str | None = None, ancoras: Path | None = None,
           sem_blobs: bool = False) -> dict:  # fmt: skip
    t0 = time.monotonic()
    fails: list[dict] = []
    head, shas, last_seen, named = GENESIS, {}, {}, {}  # shas: line sha -> line number
    leaves: list[bytes] | None = []  # None once a line has no leaf

    def fail(line: int | None, kind: str, detail: str) -> None:
        fails.append({"line": line, "kind": kind, "detail": detail})

    ledger = root / "ledger.jsonl"
    lines = ledger.read_text().splitlines() if ledger.exists() else []
    if not ledger.exists():
        fail(None, "ledger_missing", str(ledger))
    for n, text in enumerate(lines, start=1):
        try:
            obj = json.loads(text)
        except ValueError:
            obj = None
        if not isinstance(obj, dict):
            fail(n, "json", "not a JSON object")
            leaves = None
            continue
        if obj.get("prev") != head:
            fail(n, "chain", f"prev {str(obj.get('prev'))[:16]} is not line {n - 1}'s sha "
                             f"{head[:16]}")  # fmt: skip
        if obj.get("sha") != line_sha(obj):
            fail(n, "hash", "sha does not match the line")
        head = str(obj.get("sha"))
        shas[head] = n
        try:
            if leaves is not None:
                leaves.append(leaf_of(obj))
        except (KeyError, ValueError):
            leaves = None  # the hash check above already failed this line
        url = obj.get("url")
        try:
            t = dt.datetime.fromisoformat(obj["seen_at"])
            if t.tzinfo is None:
                raise ValueError("no offset")
        except (KeyError, TypeError, ValueError) as e:
            fail(n, "seen_at", f"unreadable seen_at: {e}")
        else:
            if url in last_seen and t < last_seen[url][0]:
                fail(n, "seen_at", f"{obj['seen_at']} is before line {last_seen[url][1]} of "
                                   f"the same url ({last_seen[url][0].isoformat()})")  # fmt: skip
            else:
                last_seen[url] = (t, n)
        named.setdefault(str(obj.get("sha256")), []).append((n, obj.get("bytes")))
    blobs = root / "blobs"
    present = {p.name for p in blobs.iterdir()} if blobs.is_dir() else set()
    raw_bytes = 0
    for sha, uses in named.items():
        n = uses[0][0]
        if sha not in present:
            fail(n, "blob_missing", f"blobs/{sha} named by line {n}")
            continue
        if sem_blobs:
            continue
        try:
            got, size = blob_check(blobs / sha)
        except (OSError, EOFError, gzip.BadGzipFile) as e:
            fail(n, "blob", f"blobs/{sha} does not decompress: {type(e).__name__}")
            continue
        raw_bytes += size
        if got != sha:
            fail(n, "blob", f"blobs/{sha} decompresses to sha256 {got[:16]}")
        for m, b in uses:
            if b != size:
                fail(m, "blob", f"line {m} says {b} bytes, blobs/{sha} has {size}")
    if anchor is not None and anchor not in shas:
        fail(None, "anchor", f"anchored head {anchor[:16]} is no line's sha (truncated?)")
    if ancoras is not None and not ancoras.exists():
        fail(None, "anchor", f"{ancoras} does not exist")
    rows = ancoras.read_text().splitlines() if ancoras is not None and ancoras.exists() else []
    good: list[tuple[int, int]] = []  # (TSV line, n_linhas) of the rows that check
    for k, row in enumerate(rows, start=1):
        if not row.strip() or row.startswith(("#", "data_utc")):
            continue
        f = row.split("\t")
        if len(f) not in (3, 4) or not f[2].isdigit() or (len(f) == 4 and not _is_hex64(f[3])):
            fail(None, "anchor", f"{ancoras} line {k}: not data_utc, head, n_linhas[, raiz]")
        elif shas.get(f[1]) != int(f[2]):
            where = f"is line {shas[f[1]]}" if f[1] in shas else "is no line's sha (truncated?)"
            fail(None, "anchor", f"{ancoras} line {k}: head {f[1][:16]} of {f[2]} lines {where}")
        elif len(f) == 4 and (leaves is None or mth(leaves[: int(f[2])]).hex() != f[3]):
            fail(None, "anchor", f"{ancoras} line {k}: root {f[3][:16]} is not the tree of the "
                                 f"first {f[2]} lines")  # fmt: skip
        else:
            good.append((k, int(f[2])))
    consist = []  # each consecutive pair of anchors, in the file's (publication) order
    # ponytail: every root is recomputed from the leaves, O(anchors x lines) hashes (~0.3 s at
    # 5k lines and 30 anchors); memoize subtree hashes by range when this nears the 5 s budget
    for i in range(1, len(good)):  # not zip(strict=): the macOS python3 is 3.9
        (k1, m), (k2, n) = good[i - 1], good[i]
        if n < m:
            fail(None, "anchor", f"{ancoras} line {k2}: {n} lines, fewer than line {k1}'s {m}")
        elif leaves is not None:
            proof = consistency_proof(leaves[:n], m)
            verify_consistency(m, n, mth(leaves[:m]), mth(leaves[:n]), proof)
            consist.append({"de": m, "para": n, "caminho": [h.hex() for h in proof]})
    fails.sort(key=lambda f: (f["line"] is None, f["line"] or 0))
    return {"status": "FALHA" if fails else "OK", "raiz": str(root), "head": head,
            "lines": len(lines), "merkle_root": None if leaves is None else mth(leaves).hex(),
            "consistencia": consist, "blobs": "presença só" if sem_blobs else "conferidos",
            "blobs_named": len(named), "blobs_present": len(present),
            "raw_bytes_checked": raw_bytes, "first_break": fails[0] if fails else None,
            "failures": fails, "orphans": sorted(present - set(named) - {
                p for p in present if p.endswith(".tmp")}),
            "tmp": sorted(p for p in present if p.endswith(".tmp")),
            "seconds": round(time.monotonic() - t0, 2)}  # fmt: skip


def append_anchor(path: Path, doc: dict, now: dt.datetime) -> str | None:
    """Append (data_utc, head, n_linhas, raiz) of an OK report to ``path``; the row, or None
    when the report is not OK, the ledger is empty, or that head and count are already listed.
    Before the first row with a root, one comment line names the new column; the rows already
    there (three columns) are never rewritten."""
    if doc["status"] != "OK" or doc["lines"] == 0:
        return None
    old = path.read_text()  # verify() already failed if it does not exist
    rows = [r.split("\t") for r in old.splitlines()
            if r.strip() and not r.startswith(("#", "data_utc"))]  # fmt: skip
    if any(f[1:3] == [doc["head"], str(doc["lines"])] for f in rows):
        return None
    stamp = f"{now.astimezone(dt.timezone.utc):%Y-%m-%dT%H:%M:%SZ}"  # noqa: UP017 (system python3 3.9 has no datetime.UTC)
    row = f"{stamp}\t{doc['head']}\t{doc['lines']}\t{doc['merkle_root']}"
    note = "" if any(len(f) == 4 for f in rows) else (
        f"# desde {stamp}: data_utc\thead\tn_linhas\traiz\n")  # fmt: skip
    with path.open("a") as f:  # append only
        f.write(("\n" if old and not old.endswith("\n") else "") + note + row + "\n")
    return row


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    root = Path(__file__).resolve().parents[1] / "out/produto/arquivo"
    ap.add_argument("--raiz", type=Path, default=root)
    ap.add_argument("--anchor", help="a head published earlier: it must be in the ledger")
    ap.add_argument("--ancoras", type=Path, help="TSV of heads published earlier (ops/)")
    ap.add_argument("--append-ancora", action="store_true", help="if OK, append the head")
    ap.add_argument("--sem-blobs", action="store_true",
                    help="quick check: the blobs' presence only, none decompressed")  # fmt: skip
    ap.add_argument("--prova-inclusao", type=int, metavar="N",
                    help="print the inclusion proof of line N (1-based)")  # fmt: skip
    ap.add_argument("--tamanho", type=int, metavar="T",
                    help="the proof's tree: the first T lines (default: all)")  # fmt: skip
    ap.add_argument("--verificar-inclusao", type=Path, metavar="ARQ",
                    help="check an inclusion proof file; no ledger needed")  # fmt: skip
    ap.add_argument("--raiz-publicada", metavar="HEX", help="the root the proof must reach")
    ap.add_argument("--prova-consistencia", type=int, nargs=2, metavar=("M", "N"),
                    help="print the consistency proof from M lines to N")  # fmt: skip
    ap.add_argument("--verificar-consistencia", type=Path, metavar="ARQ",
                    help="check a consistency proof file; no ledger needed")  # fmt: skip
    a = ap.parse_args(argv)
    if a.append_ancora and a.ancoras is None:
        ap.error("--append-ancora needs --ancoras")
    if a.append_ancora and a.sem_blobs:
        ap.error("--append-ancora needs the full check, not --sem-blobs")
    if a.raiz_publicada is not None and not _is_hex64(a.raiz_publicada):
        ap.error("--raiz-publicada is not 64 hex")
    if a.verificar_inclusao is not None or a.verificar_consistencia is not None:
        try:
            roots = published_roots(a.ancoras) if a.ancoras is not None else None
        except (OSError, ValueError) as e:
            print(json.dumps({"status": "FALHA", "detail": f"{type(e).__name__}: {e}"}))
            return 1
        if a.verificar_consistencia is not None:
            doc = check_consistency(json.loads(a.verificar_consistencia.read_text()), roots)
        else:
            proof = json.loads(a.verificar_inclusao.read_text())
            pub = bytes.fromhex(a.raiz_publicada) if a.raiz_publicada else None
            if pub is None and roots is not None:
                pub = roots.get(proof.get("tree_size"))
            doc = check_inclusion(proof, pub)
        print(json.dumps(doc, indent=1, ensure_ascii=False))
        return 0 if doc["status"] == "OK" else 1
    if a.prova_inclusao is not None or a.prova_consistencia is not None:
        try:
            objs, leaves = ledger_leaves(a.raiz)
        except (OSError, ValueError) as e:
            print(json.dumps({"status": "FALHA", "detail": f"{type(e).__name__}: {e}"}))
            return 1
    if a.prova_consistencia is not None:
        m, n = a.prova_consistencia
        if not 1 <= m <= n <= len(objs):
            ap.error(f"need 1 <= M <= N <= {len(objs)} (the ledger's lines)")
        path = [h.hex() for h in consistency_proof(leaves[:n], m)]
        doc = {"algoritmo": ALGO, "size1": m, "size2": n, "root1": mth(leaves[:m]).hex(),
               "root2": mth(leaves[:n]).hex(), "caminho": path}  # fmt: skip
        print(json.dumps(doc, indent=1, ensure_ascii=False))
        return 0
    if a.prova_inclusao is not None:
        size = len(objs) if a.tamanho is None else a.tamanho
        if not 1 <= a.prova_inclusao <= size <= len(objs):
            ap.error(f"need 1 <= N <= T <= {len(objs)} (the ledger's lines)")
        i, tree = a.prova_inclusao - 1, leaves[:size]
        path = [h.hex() for h in inclusion_proof(tree, i)]
        doc = {"algoritmo": ALGO, "leaf_index": i, "tree_size": size, "raiz": mth(tree).hex(),
               "caminho": path, "linha": objs[i]}  # fmt: skip
        print(json.dumps(doc, indent=1, ensure_ascii=False))
        return 0
    doc = verify(a.raiz, a.anchor, a.ancoras, a.sem_blobs)
    if a.append_ancora:
        doc["ancora_appended"] = append_anchor(a.ancoras, doc, dt.datetime.now(dt.timezone.utc))  # noqa: UP017 (system python3 3.9 has no datetime.UTC)
    print(json.dumps(doc, indent=1, ensure_ascii=False))
    return 0 if doc["status"] == "OK" else 1


if __name__ == "__main__":
    sys.exit(main())
