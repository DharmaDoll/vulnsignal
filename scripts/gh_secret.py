#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable

import secretstorage

DEFAULT_SERVICE = "gh"
DEFAULT_HOST = "github.com"
DEFAULT_USER = "DharmaDoll"
DEFAULT_CONTROL_DIR = os.path.expanduser("~/.local/keyring")


@dataclass(frozen=True)
class SecretSpec:
    service: str
    host: str
    user: str

    @property
    def label(self) -> str:
        return f"{self.service}/{self.host}/{self.user}"

    @property
    def attributes(self) -> dict[str, str]:
        return {
            "service": self.service,
            "host": self.host,
            "user": self.user,
        }


def _connection() -> secretstorage.DBusConnection:
    try:
        return secretstorage.dbus_init()
    except secretstorage.SecretServiceNotAvailableException as exc:
        raise RuntimeError(
            "Secret Service is unavailable; run inside a desktop session or with DBUS_SESSION_BUS_ADDRESS set."
        ) from exc


def _collection() -> secretstorage.Collection:
    connection = _connection()
    collection = secretstorage.get_default_collection(connection)
    if collection.is_locked():
        password = os.environ.get("GH_KEYRING_PASSWORD")
        if password:
            subprocess.run(
                [
                    "gnome-keyring-daemon",
                    "--unlock",
                    "--components=secrets",
                    "--daemonize",
                    "--control-directory",
                    DEFAULT_CONTROL_DIR,
                ],
                input=f"{password}\n".encode("utf-8"),
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            collection = secretstorage.get_default_collection(connection)
        if collection.is_locked():
            raise RuntimeError("Secret Service collection is locked; unlock it first and retry.")
    return collection


def _spec_from_args(args: argparse.Namespace) -> SecretSpec:
    return SecretSpec(
        service=args.service,
        host=args.host,
        user=args.user,
    )


def _find_item(collection: secretstorage.Collection, spec: SecretSpec) -> secretstorage.Item | None:
    for item in collection.search_items(spec.attributes):
        return item
    return None


def store_secret(spec: SecretSpec, token: str, replace: bool = True) -> None:
    collection = _collection()
    collection.create_item(spec.label, spec.attributes, token.encode("utf-8"), replace=replace)


def read_secret(spec: SecretSpec) -> str:
    collection = _collection()
    item = _find_item(collection, spec)
    if item is None:
        raise RuntimeError(f"secret not found for {spec.label}")
    return item.get_secret().decode("utf-8")


def list_secrets(service: str | None = None) -> list[dict[str, str]]:
    collection = _collection()
    rows: list[dict[str, str]] = []
    for item in collection.get_all_items():
        attrs = item.get_attributes()
        if service is not None and attrs.get("service") != service:
            continue
        rows.append(
            {
                "label": item.get_label(),
                "service": attrs.get("service", ""),
                "host": attrs.get("host", ""),
                "user": attrs.get("user", ""),
            }
        )
    return rows


def run_with_secret(spec: SecretSpec, command: Iterable[str]) -> int:
    token = read_secret(spec)
    env = os.environ.copy()
    env["GH_TOKEN"] = token
    env["GITHUB_TOKEN"] = token
    result = subprocess.run(list(command), env=env, check=False)
    return result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Store and use GitHub CLI tokens from Secret Service.")
    parser.add_argument("--service", default=DEFAULT_SERVICE, help="Secret Service service attribute.")
    parser.add_argument("--host", default=DEFAULT_HOST, help="GitHub host attribute.")
    parser.add_argument("--user", default=DEFAULT_USER, help="GitHub user attribute.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    store = subparsers.add_parser("store", help="Store a token from stdin in Secret Service.")
    store.add_argument("--keep-existing", action="store_true", help="Keep existing item if present.")

    get = subparsers.add_parser("get", help="Print the stored token to stdout.")

    run = subparsers.add_parser("run", help="Run a command with GH_TOKEN sourced from Secret Service.")
    run.add_argument("argv", nargs=argparse.REMAINDER, help="Command to execute after '--'.")

    subparsers.add_parser("list", help="List stored GitHub-related secrets.")

    return parser


def main() -> int:
    if not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        os.makedirs(DEFAULT_CONTROL_DIR, exist_ok=True)
        os.chmod(DEFAULT_CONTROL_DIR, 0o700)
        bootstrap = (
            f'printf "%s\\n" "$GH_KEYRING_PASSWORD" | '
            f'gnome-keyring-daemon --unlock --components=secrets --daemonize '
            f'--control-directory "{DEFAULT_CONTROL_DIR}" >/dev/null 2>&1; '
        )
        if "GH_KEYRING_PASSWORD" not in os.environ:
            bootstrap = (
                f'printf "\\n" | gnome-keyring-daemon --login --components=secrets '
                f'--daemonize --control-directory "{DEFAULT_CONTROL_DIR}" >/dev/null 2>&1; '
            )
        os.execvp(
            "dbus-run-session",
            [
                "dbus-run-session",
                "--",
                "bash",
                "-lc",
                bootstrap + 'exec "$0" "$@"',
                sys.executable,
                os.path.abspath(__file__),
                *sys.argv[1:],
            ],
        )
    parser = build_parser()
    args = parser.parse_args()
    spec = _spec_from_args(args)

    if args.command == "store":
        token = sys.stdin.read().strip()
        if not token:
            raise SystemExit("error: no token read from stdin")
        store_secret(spec, token, replace=not args.keep_existing)
        return 0

    if args.command == "get":
        sys.stdout.write(read_secret(spec))
        sys.stdout.write("\n")
        return 0

    if args.command == "run":
        argv = args.argv
        if argv and argv[0] == "--":
            argv = argv[1:]
        if not argv:
            raise SystemExit("error: missing command after 'run --'")
        return run_with_secret(spec, argv)

    if args.command == "list":
        for row in list_secrets(service=args.service):
            print(f"{row['label']}\t{row['service']}\t{row['host']}\t{row['user']}")
        return 0

    raise SystemExit("error: unknown command")


if __name__ == "__main__":
    raise SystemExit(main())
