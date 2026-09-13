"""P4c: eigene geschlossene Cipherverträge; unveränderliche Versionen und CAS-Kopf."""

from ohpipe.domain import manual_context

from contextlib import contextmanager, suppress
import base64
import fcntl
import hmac
import json
import os
from pathlib import Path
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .protected_store import (
    ProtectionError,
    ProtectionConfig,
    ProtectionBusy,
    ProtectedStore,
    canonical,
    digest,
    directory,
    read_at,
    read_private,
    disjoint,
    _mode,
)
from .journal import load_key
from .domain.manual_pseudonymisation import OPAQUE
from .domain.decision import SHA256_RE

REGISTRY = "pseudonymisation.registry"
RESOLUTION = "pseudonymisation.resolution"
FINAL = "transcript.pseudonymised.final"
REPORT = "replacement.report"
GATE = "transcript.pseudonymised.confirmed"
ROLES = {REGISTRY, RESOLUTION, FINAL, REPORT}


def need(ok):
    if not ok:
        raise ProtectionError("Geschlossener P4c-Schutzvertrag verletzt")


def validate_ref(ref):
    try:
        need(set(ref) == {"v", "role", "sha256", "cipher_sha256", "aad"})
        need(type(ref["v"]) is int and ref["v"] == 1 and ref["role"] in ROLES)
        for k in ("sha256", "cipher_sha256"):
            need(isinstance(ref[k], str) and SHA256_RE.fullmatch(ref[k]))
        a = ref["aad"]
        need(
            set(a)
            == set(
                [
                    "domain",
                    "v",
                    "workspace",
                    "profile",
                    "graph",
                    "registry_id",
                    "key_id",
                    "role",
                    "record",
                    "version",
                    "parent",
                    "operation",
                ]
            )
        )
        need(a["domain"] == "ohpipe:p4c:protected" and type(a["v"]) is int and a["v"] == 1)
        need(manual_context.known(a["profile"]) and a["role"] == ref["role"])
        for k in ("workspace", "graph"):
            need(isinstance(a[k], str) and SHA256_RE.fullmatch(a[k]))
        for k in ("registry_id", "key_id", "operation"):
            need(isinstance(a[k], str) and OPAQUE.fullmatch(a[k]))
        need(type(a["version"]) is int and a["version"] > 0)
        need(
            a["parent"] is None or isinstance(a["parent"], str) and SHA256_RE.fullmatch(a["parent"])
        )
        if ref["role"] == REGISTRY:
            need(a["record"] is None)
        else:
            need(manual_context.record(a["record"], a["profile"]))
        need(ref["role"] == FINAL or ref["sha256"] == ref["cipher_sha256"])
    except (KeyError, ValueError, TypeError):
        raise ProtectionError("Ungültiger P4c-Schutzverweis") from None


class RegistryStore:
    def __init__(self, ws, journal_key=None):
        self.ws = ws
        selected = os.environ.get("OHPIPE_REGISTRY_CONFIG")
        if not selected:
            raise ProtectionConfig("OHPIPE_REGISTRY_CONFIG fehlt; Register ausdrücklich einrichten")
        try:
            p = Path(selected)
            c = json.loads(read_private(p))
            need(
                set(c)
                == set(
                    [
                        "v",
                        "root",
                        "registry_id",
                        "workspace",
                        "profile",
                        "scope",
                        "key_file",
                        "key_id",
                        "candidate_key_file",
                        "candidate_key_id",
                    ]
                )
            )
            need(type(c["v"]) is int and c["v"] == 1)
            if not c["key_file"] or not c["candidate_key_file"]:
                raise ProtectionConfig("P4c-Schlüsselverweis fehlt")
            self.config = c
            self.root = Path(c["root"])
            self.workspace = digest(os.fsencode(ws.root.resolve()))
            need(
                c["workspace"] == self.workspace
                and c["profile"] == ws.profile.id
                and manual_context.enabled(ws.profile)
            )
            need(c["scope"] == manual_context.PROFILES[ws.profile.id][2])
            for k in ("key_id", "candidate_key_id", "registry_id"):
                need(isinstance(c[k], str) and OPAQUE.fullmatch(c[k]))
            repo = Path(__file__).resolve().parents[2]
            protection = ProtectedStore(ws, journal_key)
            disjoint(self.root, protection.root, Path(c["key_file"]), Path(c["candidate_key_file"]))
            for path in (
                self.root,
                p.parent,
                Path(c["key_file"]).parent,
                Path(c["candidate_key_file"]).parent,
            ):
                for forbidden in (
                    ws.root.resolve(),
                    repo,
                    repo.parent / "ohpipe",
                    repo.parent / "ohpipe-bau-16-09",
                ):
                    disjoint(path, forbidden)
            self.key = read_private(Path(c["key_file"]))
            self.candidate_key = read_private(Path(c["candidate_key_file"]))
            keys = [self.key, self.candidate_key, protection.key, journal_key or load_key(ws.root)]
            need(all(isinstance(k, bytes) and len(k) == 32 for k in keys[:3]))
            keys = [k for k in keys if k is not None]
            need(len(set(keys)) == len(keys))
            for path in (self.root, self.root / "objects"):
                with directory(path):
                    pass
        except ProtectionError:
            raise
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            raise ProtectionError(
                "P4c-Konfiguration oder deklarierte Ablage nicht prüfbar"
            ) from None

    def ensure_current(self, journal_key):
        current = RegistryStore(self.ws, journal_key)
        need(
            current.config == self.config
            and hmac.compare_digest(current.key, self.key)
            and hmac.compare_digest(current.candidate_key, self.candidate_key)
        )

    def seal(self, raw, role, record, operation, *, version=1, parent=None):
        aad = dict(
            domain="ohpipe:p4c:protected",
            v=1,
            workspace=self.workspace,
            profile=self.ws.profile.id,
            graph=self.ws.running_graph_sha256(),
            registry_id=self.config["registry_id"],
            key_id=self.config["key_id"],
            role=role,
            record=record,
            version=version,
            parent=parent,
            operation=operation,
        )
        nonce = secrets.token_bytes(12)
        blob = canonical(
            dict(
                aad=aad,
                nonce=base64.b64encode(nonce).decode(),
                ciphertext=base64.b64encode(
                    AESGCM(self.key).encrypt(nonce, raw, canonical(aad))
                ).decode(),
            )
        )
        sha = digest(blob)
        ref = dict(
            v=1, role=role, sha256=digest(raw) if role == FINAL else sha, cipher_sha256=sha, aad=aad
        )
        validate_ref(ref)
        return ref, blob

    def put(self, ref, blob):
        validate_ref(ref)
        need(digest(blob) == ref["cipher_sha256"])
        with directory(self.root / "objects") as fd:
            try:
                old = read_at(fd, ref["cipher_sha256"])
            except FileNotFoundError:
                self._write(fd, ref["cipher_sha256"], blob, immutable=True)
            else:
                need(old == blob)

    @staticmethod
    def _write(fd, name, raw, *, immutable=False):
        temporary = "." + secrets.token_hex(16)
        opened = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
        )
        try:
            data = memoryview(raw)
            while data:
                n = os.write(opened, data)
                need(n > 0)
                data = data[n:]
            os.fsync(opened)
        finally:
            os.close(opened)
        if immutable:
            os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.unlink(temporary, dir_fd=fd)
        else:
            os.rename(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)

    def check(self, ref, record):
        validate_ref(ref)
        a = ref["aad"]
        need(
            a["workspace"] == self.workspace
            and a["profile"] == self.ws.profile.id
            and a["graph"] == self.ws.running_graph_sha256()
            and a["key_id"] == self.config["key_id"]
            and a["registry_id"] == self.config["registry_id"]
            and a["record"] == record
        )
        try:
            with directory(self.root / "objects") as fd:
                raw = read_at(fd, ref["cipher_sha256"])
            need(digest(raw) == ref["cipher_sha256"])
            blob = json.loads(raw)
            need(set(blob) == {"aad", "nonce", "ciphertext"} and blob["aad"] == a)
            nonce, cipher = (
                base64.b64decode(blob[k], validate=True) for k in ("nonce", "ciphertext")
            )
            need(len(nonce) == 12 and len(cipher) >= 16)
            return nonce, cipher
        except (OSError, ValueError, KeyError, TypeError):
            raise ProtectionError("P4c-Cipherobjekt nicht prüfbar") from None

    def open(self, ref, record):
        nonce, cipher = self.check(ref, record)
        try:
            raw = AESGCM(self.key).decrypt(nonce, cipher, canonical(ref["aad"]))
        except InvalidTag:
            raise ProtectionError("P4c-Cipherobjekt nicht authentisch") from None
        need(ref["role"] != FINAL or digest(raw) == ref["sha256"])
        return raw

    def head(self):
        try:
            with directory(self.root) as fd:
                try:
                    raw = read_at(fd, "head")
                except FileNotFoundError:
                    return None
            ref = json.loads(raw)
            validate_ref(ref)
            need(ref["role"] == REGISTRY and raw == canonical(ref))
            self.check(ref, None)
            return ref
        except (OSError, ValueError, KeyError, TypeError):
            raise ProtectionError("Registerkopf nicht prüfbar") from None

    def set_head(self, ref):
        self.check(ref, None)
        with directory(self.root) as fd:
            with suppress(FileNotFoundError):
                read_at(fd, "head")
            self._write(fd, "head", canonical(ref))

    @contextmanager
    def lock(self):
        with directory(self.root) as fd:
            opened = os.open(
                "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd
            )
            try:
                _mode(opened)
                try:
                    fcntl.flock(opened, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ProtectionBusy("Register wird gerade geschrieben") from None
                yield
            finally:
                os.close(opened)
