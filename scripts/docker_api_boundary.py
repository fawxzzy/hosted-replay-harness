#!/usr/bin/env python3
"""Transparent Unix-socket relay with a closed, sanitized Docker API receipt."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import signal
from collections import Counter, deque
from pathlib import Path
from typing import Final


SCHEMA: Final = "fawxzzy.hosted-replay-harness.docker-api-boundary.v1"
PHASES: Final = (
    "API_NEGOTIATION",
    "IMAGE_INSPECT",
    "IMAGE_PULL",
    "NETWORK_INSPECT_REUSE",
    "VOLUME_INSPECT",
    "VOLUME_CREATE",
    "CONTAINER_INSPECT",
    "CONTAINER_LIST",
    "CONTAINER_CREATE",
    "CONTAINER_START",
    "CLEANUP_API_PHASE",
    "UNKNOWN_API_PHASE",
)
METHOD_CLASSES: Final = ("READ", "WRITE", "DELETE", "OTHER")
STATUS_CLASSES: Final = ("1XX", "2XX", "3XX", "4XX", "5XX", "OTHER")
STATUS_CODES: Final = (200, 201, 204, 304, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503)
CLASSIFICATIONS: Final = (
    "NO_DOCKER_API_REQUEST_OBSERVED",
    "DOCKER_API_REQUESTS_OBSERVED",
    "DOCKER_API_ERROR_RESPONSE_OBSERVED",
    "DOCKER_API_RESPONSE_INCOMPLETE",
    "DOCKER_API_WRITE_ATTEMPT_OBSERVED",
    "OBSERVER_FORWARDING_FAILED",
)
API_PREFIX = re.compile(br"^/v[0-9]+(?:\.[0-9]+)?(?=/|$)")
MAX_LINE: Final = 16384


class WriteAttemptError(Exception):
    """Stop a prohibited non-read-only request before it reaches Docker."""


def method_class(method: bytes) -> str:
    if method in (b"GET", b"HEAD"):
        return "READ"
    if method in (b"POST", b"PUT", b"PATCH"):
        return "WRITE"
    if method == b"DELETE":
        return "DELETE"
    return "OTHER"


def normalize_path(target: bytes) -> bytes:
    path = target.split(b"?", 1)[0]
    return API_PREFIX.sub(b"", path, count=1) or b"/"


def classify_path(method: bytes, target: bytes) -> str:
    path = normalize_path(target)
    if path in (b"/_ping", b"/version", b"/info"):
        return "API_NEGOTIATION"
    if path == b"/images/create":
        return "IMAGE_PULL"
    if path.startswith(b"/images/") and path.endswith(b"/json"):
        return "IMAGE_INSPECT"
    if path == b"/networks/create" or path.startswith(b"/networks/"):
        return "NETWORK_INSPECT_REUSE"
    if path == b"/volumes/create":
        return "VOLUME_CREATE"
    if path.startswith(b"/volumes/"):
        return "VOLUME_INSPECT"
    if path == b"/containers/create":
        return "CONTAINER_CREATE"
    if path == b"/containers/json":
        return "CONTAINER_LIST"
    if path.startswith(b"/containers/") and path.endswith(b"/start"):
        return "CONTAINER_START"
    if path.startswith(b"/containers/") and path.endswith(b"/json"):
        return "CONTAINER_INSPECT"
    if path in (b"/containers/prune", b"/volumes/prune", b"/networks/prune"):
        return "CLEANUP_API_PHASE"
    return "UNKNOWN_API_PHASE"


class Receipt:
    def __init__(self) -> None:
        self.connection_count = 0
        self.request_count = 0
        self.response_count = 0
        self.error_response_count = 0
        self.write_attempt_count = 0
        self.forwarding_error_count = 0
        self.parser_error_count = 0
        self.phase_counts: Counter[str] = Counter()
        self.method_counts: Counter[str] = Counter()
        self.status_class_counts: Counter[str] = Counter()
        self.status_code_counts: Counter[str] = Counter()
        self.first_phase = "NONE"
        self.last_phase = "NONE"
        self.first_error_phase = "NONE"
        self.first_error_status_code = 0

    def connect(self) -> None:
        self.connection_count += 1

    def request(self, phase: str, method: str) -> None:
        self.request_count += 1
        self.phase_counts[phase] += 1
        self.method_counts[method] += 1
        if self.first_phase == "NONE":
            self.first_phase = phase
        self.last_phase = phase

    def response(self, phase: str, code: int) -> None:
        self.response_count += 1
        status_class = f"{code // 100}XX" if 100 <= code <= 599 else "OTHER"
        self.status_class_counts[status_class] += 1
        key = f"CODE_{code}" if code in STATUS_CODES else "CODE_OTHER"
        self.status_code_counts[key] += 1
        if code >= 400 or code < 100:
            self.error_response_count += 1
            if self.first_error_phase == "NONE":
                self.first_error_phase = phase
                self.first_error_status_code = code if code in STATUS_CODES else 0

    def write_attempt(self) -> None:
        self.write_attempt_count += 1

    def forwarding_error(self) -> None:
        self.forwarding_error_count += 1

    def parser_error(self) -> None:
        self.parser_error_count += 1

    def classification(self) -> str:
        if self.write_attempt_count:
            return "DOCKER_API_WRITE_ATTEMPT_OBSERVED"
        if self.forwarding_error_count or self.parser_error_count:
            return "OBSERVER_FORWARDING_FAILED"
        if self.request_count == 0:
            return "NO_DOCKER_API_REQUEST_OBSERVED"
        if self.response_count < self.request_count:
            return "DOCKER_API_RESPONSE_INCOMPLETE"
        if self.error_response_count:
            return "DOCKER_API_ERROR_RESPONSE_OBSERVED"
        return "DOCKER_API_REQUESTS_OBSERVED"

    def sanitized(self) -> dict[str, object]:
        result: dict[str, object] = {
            "schema": SCHEMA,
            "classification": self.classification(),
            "connection_count": self.connection_count,
            "request_count": self.request_count,
            "response_count": self.response_count,
            "error_response_count": self.error_response_count,
            "write_attempt_count": self.write_attempt_count,
            "forwarding_error_count": self.forwarding_error_count,
            "parser_error_count": self.parser_error_count,
            "first_phase": self.first_phase,
            "last_phase": self.last_phase,
            "first_error_phase": self.first_error_phase,
            "first_error_status_code": self.first_error_status_code,
            "phase_counts": {phase: self.phase_counts[phase] for phase in PHASES},
            "method_class_counts": {name: self.method_counts[name] for name in METHOD_CLASSES},
            "status_class_counts": {name: self.status_class_counts[name] for name in STATUS_CLASSES},
            "status_code_counts": {
                **{f"CODE_{code}": self.status_code_counts[f"CODE_{code}"] for code in STATUS_CODES},
                "CODE_OTHER": self.status_code_counts["CODE_OTHER"],
            },
        }
        canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
        result["canonical_sha256"] = hashlib.sha256(canonical).hexdigest()
        validate_result(result)
        return result


class HTTPFramingParser:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.state = "line"
        self.content_remaining = 0
        self.chunk_remaining = 0
        self.chunked = False
        self.content_length = 0

    def pop_line(self) -> bytes | None:
        marker = self.buffer.find(b"\r\n")
        if marker < 0:
            if len(self.buffer) > MAX_LINE:
                raise ValueError("HTTP line exceeds bound")
            return None
        line = bytes(self.buffer[:marker])
        del self.buffer[: marker + 2]
        return line

    def consume_body(self) -> bool:
        if self.state == "body":
            consumed = min(len(self.buffer), self.content_remaining)
            del self.buffer[:consumed]
            self.content_remaining -= consumed
            if self.content_remaining == 0:
                self.state = "line"
            return consumed > 0
        if self.state == "chunk_data":
            consumed = min(len(self.buffer), self.chunk_remaining)
            del self.buffer[:consumed]
            self.chunk_remaining -= consumed
            if self.chunk_remaining == 0:
                self.state = "chunk_crlf"
            return consumed > 0
        if self.state == "chunk_crlf":
            if len(self.buffer) < 2:
                return False
            if self.buffer[:2] != b"\r\n":
                raise ValueError("invalid chunk framing")
            del self.buffer[:2]
            self.state = "chunk_size"
            return True
        return False

    def parse_header(self, line: bytes) -> None:
        name, separator, value = line.partition(b":")
        if not separator:
            raise ValueError("invalid HTTP header framing")
        name = name.strip().lower()
        value = value.strip().lower()
        if name == b"content-length":
            if not value.isdigit():
                raise ValueError("invalid content length")
            self.content_length = int(value)
        elif name == b"transfer-encoding" and b"chunked" in value:
            self.chunked = True

    def finish_headers(self) -> None:
        if self.chunked:
            self.state = "chunk_size"
        elif self.content_length:
            self.content_remaining = self.content_length
            self.state = "body"
        else:
            self.state = "line"
        self.chunked = False
        self.content_length = 0


class RequestParser(HTTPFramingParser):
    def __init__(self, receipt: Receipt, pending: deque[tuple[str, bytes]]) -> None:
        super().__init__()
        self.receipt = receipt
        self.pending = pending

    def feed(self, data: bytes) -> None:
        self.buffer.extend(data)
        while self.buffer:
            if self.consume_body():
                continue
            if self.state == "chunk_size":
                line = self.pop_line()
                if line is None:
                    return
                size_token = line.split(b";", 1)[0]
                try:
                    size = int(size_token, 16)
                except ValueError as exc:
                    raise ValueError("invalid chunk size") from exc
                if size == 0:
                    self.state = "chunk_trailer"
                else:
                    self.chunk_remaining = size
                    self.state = "chunk_data"
                continue
            if self.state == "chunk_trailer":
                line = self.pop_line()
                if line is None:
                    return
                if not line:
                    self.state = "line"
                continue
            line = self.pop_line()
            if line is None:
                return
            if self.state == "line":
                parts = line.split(b" ", 2)
                if len(parts) != 3 or not parts[2].startswith(b"HTTP/1."):
                    raise ValueError("invalid HTTP request line")
                method, target = parts[0], parts[1]
                phase = classify_path(method, target)
                method_kind = method_class(method)
                self.receipt.request(phase, method_kind)
                if method_kind != "READ":
                    self.receipt.write_attempt()
                    raise WriteAttemptError
                self.pending.append((phase, method))
                self.state = "headers"
            elif self.state == "headers":
                if line:
                    self.parse_header(line)
                else:
                    self.finish_headers()


class ResponseParser(HTTPFramingParser):
    def __init__(self, receipt: Receipt, pending: deque[tuple[str, bytes]]) -> None:
        super().__init__()
        self.receipt = receipt
        self.pending = pending
        self.no_body = False

    def feed(self, data: bytes) -> None:
        self.buffer.extend(data)
        while self.buffer:
            if self.consume_body():
                continue
            if self.state == "chunk_size":
                line = self.pop_line()
                if line is None:
                    return
                try:
                    size = int(line.split(b";", 1)[0], 16)
                except ValueError as exc:
                    raise ValueError("invalid response chunk size") from exc
                if size == 0:
                    self.state = "chunk_trailer"
                else:
                    self.chunk_remaining = size
                    self.state = "chunk_data"
                continue
            if self.state == "chunk_trailer":
                line = self.pop_line()
                if line is None:
                    return
                if not line:
                    self.state = "line"
                continue
            line = self.pop_line()
            if line is None:
                return
            if self.state == "line":
                parts = line.split(b" ", 2)
                if len(parts) < 2 or not parts[0].startswith(b"HTTP/1.") or not parts[1].isdigit():
                    raise ValueError("invalid HTTP response line")
                code = int(parts[1])
                phase, method = self.pending.popleft() if self.pending else ("UNKNOWN_API_PHASE", b"")
                self.receipt.response(phase, code)
                self.no_body = method == b"HEAD" or code in (204, 304) or 100 <= code < 200
                self.state = "headers"
            elif self.state == "headers":
                if line:
                    self.parse_header(line)
                else:
                    if self.no_body:
                        self.state = "line"
                        self.chunked = False
                        self.content_length = 0
                    else:
                        self.finish_headers()
                    self.no_body = False


def validate_result(result: dict[str, object]) -> None:
    expected_keys = {
        "schema",
        "classification",
        "connection_count",
        "request_count",
        "response_count",
        "error_response_count",
        "write_attempt_count",
        "forwarding_error_count",
        "parser_error_count",
        "first_phase",
        "last_phase",
        "first_error_phase",
        "first_error_status_code",
        "phase_counts",
        "method_class_counts",
        "status_class_counts",
        "status_code_counts",
        "canonical_sha256",
    }
    if set(result) != expected_keys:
        raise ValueError("observer result schema is invalid")
    if result.get("schema") != SCHEMA or result.get("classification") not in CLASSIFICATIONS:
        raise ValueError("observer result enum is invalid")
    for key in (
        "connection_count",
        "request_count",
        "response_count",
        "error_response_count",
        "write_attempt_count",
        "forwarding_error_count",
        "parser_error_count",
        "first_error_status_code",
    ):
        if type(result.get(key)) is not int or int(result[key]) < 0:
            raise ValueError("observer result count is invalid")
    for key in ("first_phase", "last_phase", "first_error_phase"):
        if result.get(key) not in (*PHASES, "NONE"):
            raise ValueError("observer phase is invalid")
    expected_maps = {
        "phase_counts": set(PHASES),
        "method_class_counts": set(METHOD_CLASSES),
        "status_class_counts": set(STATUS_CLASSES),
        "status_code_counts": {*(f"CODE_{code}" for code in STATUS_CODES), "CODE_OTHER"},
    }
    for key, expected in expected_maps.items():
        values = result.get(key)
        if not isinstance(values, dict) or set(values) != expected:
            raise ValueError("observer count map is invalid")
        if any(type(value) is not int or value < 0 for value in values.values()):
            raise ValueError("observer map count is invalid")
    digest = result.get("canonical_sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("observer digest is invalid")
    canonical = json.dumps(
        {key: value for key, value in result.items() if key != "canonical_sha256"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    if digest != hashlib.sha256(canonical).hexdigest():
        raise ValueError("observer digest does not match sanitized state")


def format_state_lines(result: dict[str, object]) -> str:
    validate_result(result)
    fields: list[tuple[str, str, object]] = []
    for key in (
        "schema",
        "classification",
        "connection_count",
        "request_count",
        "response_count",
        "error_response_count",
        "write_attempt_count",
        "forwarding_error_count",
        "parser_error_count",
        "first_phase",
        "last_phase",
        "first_error_phase",
        "first_error_status_code",
        "canonical_sha256",
    ):
        kind = "int" if key.endswith("_count") or key == "first_error_status_code" else "str"
        fields.append((f"docker_api_boundary.{key}", kind, result[key]))
    for map_key in ("phase_counts", "method_class_counts", "status_class_counts", "status_code_counts"):
        for key, value in sorted(result[map_key].items()):
            fields.append((f"docker_api_boundary.{map_key}.{key}", "int", value))
    rendered = "".join(f"{key}\t{kind}\t{value}\n" for key, kind, value in fields)
    if not all(re.fullmatch(r"[A-Za-z0-9_.]+\t(?:str|int)\t[A-Za-z0-9_.-]+", line) for line in rendered.splitlines()):
        raise ValueError("observer state output is not closed-schema")
    return rendered


class BoundaryServer:
    def __init__(self, listen: Path, upstream: Path, receipt: Receipt) -> None:
        self.listen = listen
        self.upstream = upstream
        self.receipt = receipt
        self.tasks: set[asyncio.Task[None]] = set()

    async def relay(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, parser: object) -> None:
        while True:
            data = await reader.read(65536)
            if not data:
                try:
                    writer.write_eof()
                except (AttributeError, OSError):
                    pass
                return
            try:
                parser.feed(data)
            except WriteAttemptError:
                writer.close()
                await asyncio.gather(writer.wait_closed(), return_exceptions=True)
                return
            except ValueError:
                self.receipt.parser_error()
            writer.write(data)
            await writer.drain()

    async def handle(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self.tasks.add(task)
        self.receipt.connect()
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            upstream_reader, upstream_writer = await asyncio.open_unix_connection(str(self.upstream))
            pending: deque[tuple[str, bytes]] = deque()
            request_parser = RequestParser(self.receipt, pending)
            response_parser = ResponseParser(self.receipt, pending)
            await asyncio.gather(
                self.relay(client_reader, upstream_writer, request_parser),
                self.relay(upstream_reader, client_writer, response_parser),
            )
        except (OSError, asyncio.IncompleteReadError):
            self.receipt.forwarding_error()
        finally:
            client_writer.close()
            if upstream_writer is not None:
                upstream_writer.close()
            await asyncio.gather(
                client_writer.wait_closed(),
                *(
                    [upstream_writer.wait_closed()]
                    if upstream_writer is not None
                    else []
                ),
                return_exceptions=True,
            )
            if task is not None:
                self.tasks.discard(task)

    async def run(self, stop: asyncio.Event, ready: Path) -> None:
        if self.listen.exists():
            raise FileExistsError("observer listen socket already exists")
        server = await asyncio.start_unix_server(self.handle, path=str(self.listen))
        os.chmod(self.listen, 0o600)
        ready.touch(mode=0o600, exist_ok=False)
        async with server:
            await stop.wait()
        if self.tasks:
            done, pending = await asyncio.wait(self.tasks, timeout=5)
            if pending:
                self.receipt.forwarding_error()
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)


def write_state(path: Path, result: dict[str, object]) -> None:
    rendered = format_state_lines(result).encode()
    temporary = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(rendered)
    os.replace(temporary, path)


async def async_main(args: argparse.Namespace) -> int:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for name in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(name, stop.set)
    receipt = Receipt()
    server = BoundaryServer(args.listen, args.upstream, receipt)
    try:
        await server.run(stop, args.ready)
    except (OSError, ValueError):
        receipt.forwarding_error()
    finally:
        for path in (args.listen, args.ready):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        write_state(args.state, receipt.sanitized())
    if receipt.write_attempt_count:
        return 2
    return 1 if receipt.forwarding_error_count or receipt.parser_error_count else 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True, type=Path)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--ready", required=True, type=Path)
    args = parser.parse_args()
    raise SystemExit(asyncio.run(async_main(args)))


if __name__ == "__main__":
    main()
