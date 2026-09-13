"""Descriptorbezogene P4b-Ablage. Klartext lebt nur in expliziten Aufrufern.

check() prüft Cipherbytes und öffentliche Kontextbindung, entschlüsselt nicht.
open() prüft zusätzlich AEAD und gibt erst nach erfolgreicher Authentifizierung
vollständige Bytes zurück. Es gibt keinen Klartext- oder Ersatzstore.
"""

from ohpipe.domain import manual_context

from contextlib import contextmanager, suppress
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .domain.manual_pseudonymisation import OPAQUE


class ProtectionError(RuntimeError):
    code = 1


class ProtectionConfig(ProtectionError):
    code = 2


class ProtectionBusy(ProtectionError):
    code = 3


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _safe(message="Schutzablage oder Schutzvertrag nicht prüfbar"):
    return ProtectionError(message)


def _mode(fd, directory=False):
    s = os.fstat(fd)
    valid = stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink == 1
    if (
        not valid
        or s.st_uid != os.getuid()
        or stat.S_IMODE(s.st_mode) != (0o700 if directory else 0o600)
    ):
        raise _safe()


@contextmanager
def directory(path, *, private=True):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise _safe()
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            other = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = other
        if private:
            _mode(fd, True)
        yield fd
    except OSError:
        raise _safe() from None
    finally:
        os.close(fd)


def read_at(fd, name):
    opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        _mode(opened)
        chunks = []
        while chunk := os.read(opened, 65536):
            chunks.append(chunk)
            if sum(map(len, chunks)) > 128 * 1024 * 1024:
                raise _safe()
        return b"".join(chunks)
    finally:
        os.close(opened)


def read_private(path):
    with directory(Path(path).parent) as fd:
        return read_at(fd, Path(path).name)


def disjoint(*paths):
    for i, a in enumerate(paths):
        for b in paths[i + 1 :]:
            if a == b or a in b.parents or b in a.parents:
                raise _safe("Schutzwurzeln sind nicht disjunkt")


def context(ws, *, phase, object_id, session_id, revision, key_id, store_id):
    return {
        "domain": "ohpipe:p4b:protected",
        "v": 1,
        "workspace": digest(os.fsencode(ws.root.resolve())),
        "profile": ws.profile.id,
        "graph": ws.running_graph_sha256(),
        "phase": phase,
        "object_id": object_id,
        "session_id": session_id,
        "revision": revision,
        "key_id": key_id,
        "store_id": store_id,
    }


def validate_ref(ref):
    from .domain.decision import SHA256_RE

    try:
        if (
            set(ref) != {"v", "role", "sha256", "cipher_sha256", "aad"}
            or type(ref["v"]) is not int
            or ref["v"] != 1
        ):
            raise _safe()
        if ref["role"] not in (
            "pii.spans",
            "pseudonymisation.cases",
            "transcript.pseudonymised.draft",
            "editor",
            "plan",
        ):
            raise _safe()
        for name in ("sha256", "cipher_sha256"):
            if not isinstance(ref[name], str) or not SHA256_RE.fullmatch(ref[name]):
                raise _safe()
        a = ref["aad"]
        if set(a) != set(
            [
                "domain",
                "v",
                "workspace",
                "profile",
                "graph",
                "record",
                "phase",
                "object_id",
                "session_id",
                "revision",
                "key_id",
                "store_id",
            ]
        ):
            raise _safe()
        if a["domain"] != "ohpipe:p4b:protected" or type(a["v"]) is not int or a["v"] != 1:
            raise _safe()
        if not manual_context.known(a["profile"]) or a["phase"] not in (
            "pii.mark",
            "pseudonymise",
            "pseudonymisation.cases",
        ):
            raise _safe()
        if not manual_context.record(a["record"], a["profile"]):
            raise _safe()
        for n in ("workspace", "graph"):
            if not isinstance(a[n], str) or not SHA256_RE.fullmatch(a[n]):
                raise _safe()
        for n in ("object_id", "session_id", "key_id", "store_id"):
            if not isinstance(a[n], str) or not OPAQUE.fullmatch(a[n]):
                raise _safe()
        if type(a["revision"]) is not int or a["revision"] < 1:
            raise _safe()
        if (
            ref["role"] != "transcript.pseudonymised.draft"
            and ref["sha256"] != ref["cipher_sha256"]
        ):
            raise _safe()
    except (KeyError, TypeError, ValueError):
        raise _safe() from None


class ProtectedStore:
    def __init__(self, ws, journal_key=None):
        self.ws = ws
        selected = os.environ.get("OHPIPE_PROTECTION_CONFIG")
        if not selected:
            raise ProtectionConfig("OHPIPE_PROTECTION_CONFIG fehlt")
        try:
            config_path = Path(selected)
            config = json.loads(read_private(config_path))
            if (
                set(config) != {"v", "root", "key_file", "key_id", "store_id"}
                or type(config["v"]) is not int
                or config["v"] != 1
            ):
                raise _safe()
            if not config["key_file"]:
                raise ProtectionConfig("Schlüsselverweis fehlt")
            self.root, self.key_file = Path(config["root"]), Path(config["key_file"])
            for name in ("key_id", "store_id"):
                if not OPAQUE.fullmatch(config[name]):
                    raise _safe()
            self.key_id, self.store_id = config["key_id"], config["store_id"]
            repo = Path(__file__).resolve().parents[2]
            forbidden = (
                ws.root.resolve(),
                repo,
                repo.parent / "ohpipe",
                repo.parent / "ohpipe-bau-16-09",
            )
            disjoint(self.root, self.key_file.parent)
            for p in (self.root, config_path.parent, self.key_file.parent):
                for q in forbidden:
                    disjoint(p, q)
            self.key = read_private(self.key_file)
            if len(self.key) != 32 or self.key == journal_key:
                raise _safe("Ungültiger oder nicht getrennter Schutzschlüssel")
            for p in (self.root, self.root / "objects", self.root / "sessions"):
                with directory(p):
                    pass
        except ProtectionError:
            raise
        except (OSError, ValueError, TypeError, KeyError):
            raise _safe() from None

    def ensure_current(self, journal_key):
        """Ein offener Dialog darf keinen inzwischen ersetzten Schutzstand nutzen."""
        import hmac

        current = ProtectedStore(self.ws, journal_key)
        if (
            current.root != self.root
            or current.key_file != self.key_file
            or current.key_id != self.key_id
            or current.store_id != self.store_id
            or not hmac.compare_digest(current.key, self.key)
        ):
            raise ProtectionError("Schutzstand seit Öffnung geändert; erneut öffnen")

    def seal(self, raw, *, role, record, phase, session_id, revision):
        aad = context(
            self.ws,
            phase=phase,
            object_id=secrets.token_hex(16),
            session_id=session_id,
            revision=revision,
            key_id=self.key_id,
            store_id=self.store_id,
        )
        aad["record"] = record
        nonce = secrets.token_bytes(12)
        encrypted = AESGCM(self.key).encrypt(nonce, raw, canonical(aad))
        envelope = canonical(
            {
                "aad": aad,
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(encrypted).decode(),
            }
        )
        sha = digest(envelope)
        ref = {
            "v": 1,
            "role": role,
            "sha256": digest(raw) if role == "transcript.pseudonymised.draft" else sha,
            "cipher_sha256": sha,
            "aad": aad,
        }
        validate_ref(ref)
        return ref, envelope

    def put(self, ref, envelope):
        validate_ref(ref)
        if digest(envelope) != ref["cipher_sha256"]:
            raise _safe()
        # Ein temporärer CIPHER-Inode wird erst nach fsync sichtbar. Abgebrochene
        # Cipherreste sind keine adressierbaren Objekte und keine Evidenz.
        with directory(self.root / "objects") as fd:
            temporary = "." + secrets.token_hex(16)
            opened = os.open(
                temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
            )
            try:
                remaining = memoryview(envelope)
                while remaining:
                    n = os.write(opened, remaining)
                    if n <= 0:
                        raise _safe()
                    remaining = remaining[n:]
                os.fsync(opened)
            finally:
                os.close(opened)
            try:
                os.link(
                    temporary,
                    ref["cipher_sha256"],
                    src_dir_fd=fd,
                    dst_dir_fd=fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                if read_at(fd, ref["cipher_sha256"]) != envelope:
                    raise _safe() from None
            finally:
                os.unlink(temporary, dir_fd=fd)
            os.fsync(fd)

    def check(self, ref, record):
        validate_ref(ref)
        a = ref["aad"]
        expected = context(
            self.ws,
            phase=a["phase"],
            object_id=a["object_id"],
            session_id=a["session_id"],
            revision=a["revision"],
            key_id=self.key_id,
            store_id=self.store_id,
        )
        expected["record"] = record
        if a != expected:
            raise _safe("Schutzkontext stimmt nicht")
        try:
            with directory(self.root / "objects") as fd:
                envelope = read_at(fd, ref["cipher_sha256"])
            if digest(envelope) != ref["cipher_sha256"]:
                raise _safe()
            value = json.loads(envelope)
            if set(value) != {"aad", "nonce", "ciphertext"} or value["aad"] != a:
                raise _safe()
            nonce = base64.b64decode(value["nonce"], validate=True)
            cipher = base64.b64decode(value["ciphertext"], validate=True)
            if len(nonce) != 12 or len(cipher) < 16:
                raise _safe()
            return nonce, cipher
        except (OSError, ValueError, KeyError, TypeError):
            raise _safe() from None

    def open(self, ref, record):
        nonce, cipher = self.check(ref, record)
        try:
            raw = AESGCM(self.key).decrypt(nonce, cipher, canonical(ref["aad"]))
        except InvalidTag:
            raise _safe("Schutzobjekt nicht authentisch") from None
        if ref["role"] == "transcript.pseudonymised.draft" and digest(raw) != ref["sha256"]:
            raise _safe()
        return raw

    @contextmanager
    def lock(self):
        name = digest(os.fsencode(self.ws.root.resolve()))
        with directory(self.root) as fd:
            opened = os.open(
                name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd
            )
            try:
                _mode(opened)
                try:
                    fcntl.flock(opened, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ProtectionBusy("Schutzablage wird gerade geschrieben") from None
                yield
            finally:
                os.close(opened)

    def pointer(self, ref):
        # Der Komfortzeiger enthält ausschließlich dieselben verschlüsselten
        # Umschlagbytes; Wiederaufnahme wählt IMMER zunächst den Journalcheckpoint.
        with directory(self.root / "objects") as source:
            blob = read_at(source, ref["cipher_sha256"])
        with directory(self.root / "sessions") as target:
            with suppress(FileNotFoundError):
                # Einen gefährlichen Komfortzeiger nicht still überschreiben.
                read_at(target, ref["aad"]["session_id"])
            temporary = "." + secrets.token_hex(16)
            opened = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=target)
            try:
                with os.fdopen(opened, "wb", closefd=False) as stream:
                    stream.write(blob)
                    stream.flush()
                    os.fsync(opened)
            finally:
                os.close(opened)
            os.rename(temporary, ref["aad"]["session_id"], src_dir_fd=target, dst_dir_fd=target)
            os.fsync(target)
