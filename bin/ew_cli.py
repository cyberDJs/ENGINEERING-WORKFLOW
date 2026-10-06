"""Argument parsing for hardened EW CLI."""
from __future__ import annotations

import argparse
from pathlib import Path

from ew_runtime import *
from ew_ops import adopt, doctor, init, rollback, selftest

def main(argv: list[str] | None=None) -> int:
    parser = argparse.ArgumentParser(prog='ew')
    parser.add_argument('--version', action='version', version=f'%(prog)s {CLI_VERSION}')
    commands = parser.add_subparsers(dest='command', required=True)
    init_parser = commands.add_parser('init')
    init_parser.add_argument('project_dir', type=Path)
    init_parser.add_argument('--name', required=True)
    init_parser.add_argument('--profile', choices=sorted(PROFILES), default='standard-product')
    init_parser.add_argument('--risk', choices=RISKS, default='R2')
    init_parser.add_argument('--reversibility', choices=REV_MIN, default='REV-2')
    init_parser.add_argument('--dry-run', action='store_true')
    init_parser.add_argument('--json', action='store_true')
    adopt_parser = commands.add_parser('adopt')
    adopt_parser.add_argument('project_dir', type=Path)
    adopt_parser.add_argument('--name', required=True)
    adopt_parser.add_argument('--profile', choices=sorted(PROFILES), default='standard-product')
    adopt_parser.add_argument('--risk', choices=RISKS, default='R2')
    adopt_parser.add_argument('--reversibility', choices=REV_MIN, default='REV-2')
    adopt_parser.add_argument('--apply', action='store_true')
    adopt_parser.add_argument('--acknowledge-sensitive-paths', action='store_true')
    adopt_parser.add_argument('--acknowledge-symlinks', action='store_true')
    adopt_parser.add_argument('--symlink-rationale')
    adopt_parser.add_argument('--json', action='store_true')
    doctor_parser = commands.add_parser('doctor')
    doctor_parser.add_argument('project_dir', type=Path, nargs='?', default=Path('.'))
    doctor_parser.add_argument('--json', action='store_true')
    rollback_parser = commands.add_parser('rollback')
    rollback_parser.add_argument('project_dir', type=Path, nargs='?', default=Path('.'))
    rollback_parser.add_argument('--apply', action='store_true')
    rollback_parser.add_argument('--json', action='store_true')
    selftest_parser = commands.add_parser('self-test')
    selftest_parser.add_argument('--json', action='store_true')
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == 'init':
            output = init(arguments.project_dir, arguments.name, arguments.profile, arguments.risk, arguments.reversibility, arguments.dry_run)
        elif arguments.command == 'adopt':
            output = adopt(arguments.project_dir, arguments.name, arguments.profile, arguments.risk, arguments.reversibility, apply=arguments.apply, acknowledge_sensitive_paths=arguments.acknowledge_sensitive_paths, acknowledge_symlinks=arguments.acknowledge_symlinks, symlink_rationale=arguments.symlink_rationale)
        elif arguments.command == 'doctor':
            output = doctor(arguments.project_dir)
        elif arguments.command == 'rollback':
            output = rollback(arguments.project_dir, apply=arguments.apply)
        else:
            output = selftest()
        emit(output, arguments.json)
        return 0 if output['status'] in SUCCESS else 1
    except Blocked as exc:
        emit({'status': 'BLOCKED', 'operation': arguments.command, 'project_dir': str(getattr(arguments, 'project_dir', '')), 'details': {'error': str(exc)}}, getattr(arguments, 'json', False))
        return 2
    except Exception as exc:
        emit({'status': 'FAILED', 'operation': arguments.command, 'project_dir': str(getattr(arguments, 'project_dir', '')), 'details': {'error': str(exc)}}, getattr(arguments, 'json', False))
        return 1
