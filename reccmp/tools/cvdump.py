#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path
import subprocess

import reccmp
from reccmp.cvdump.runner import DumpOpt, Cvdump
from reccmp.project.logging import argparse_add_logging_args, argparse_parse_logging

logger = logging.getLogger(__name__)

# cvdump.exe arguments:
# Usage: cvdump [-?] [-asmin] [-coffsymrva] [-fixup] [-fpo] [-ftm] [-g]
#         [-h] [-headers] [-id] [-inll] [-illines] [-l] [-m] [-MXXX] [-omapf]
#         [-omapt] [-p] [-pdata] [-pdbpath] [-s] [-seccontrib] [-sf] [-S]
#         [-t] [-tmap] [-tmw] [-ttm] [-x] [-xdata] [-xme] [-xmi] file


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Wrapper for cvdump.exe (Code View Dump)"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {reccmp.VERSION}"
    )
    parser.add_argument(
        "pdb_path",
        type=Path,
    )
    # It should be okay to use "-o" because it doesn't collide with any
    # of the cvdump arguments.
    parser.add_argument(
        "-o",
        "--out",
        dest="out_file",
        type=Path,
        help="Write to file",
    )
    parser.add_argument(
        "-p",
        dest="options",
        action="append_const",
        const=DumpOpt.PUBLICS,
        help="PUBLICS",
    )
    parser.add_argument(
        "-l",
        dest="options",
        action="append_const",
        const=DumpOpt.LINES,
        help="LINES",
    )
    parser.add_argument(
        "-s",
        dest="options",
        action="append_const",
        const=DumpOpt.SYMBOLS,
        help="SYMBOLS",
    )
    parser.add_argument(
        "-g",
        dest="options",
        action="append_const",
        const=DumpOpt.GLOBALS,
        help="GLOBALS",
    )
    parser.add_argument(
        "-seccontrib",
        dest="options",
        action="append_const",
        const=DumpOpt.SECTION_CONTRIB,
        help="SECTION CONTRIBUTIONS",
    )
    parser.add_argument(
        "-m",
        dest="options",
        action="append_const",
        const=DumpOpt.MODULES,
        help="MODULES",
    )
    parser.add_argument(
        "-t",
        dest="options",
        action="append_const",
        const=DumpOpt.TYPES,
        help="TYPES",
    )
    argparse_add_logging_args(parser)
    args = parser.parse_args()
    argparse_parse_logging(args=args)

    if not args.pdb_path.is_file():
        parser.error(f"File not found: {args.pdb_path}")

    return args


def main():
    args = parse_args()

    cv = Cvdump(args.pdb_path)
    if args.options:
        cv.options.update(args.options)

    cmd_line = cv.cmd_line()
    logger.debug("Command: %r", cmd_line)
    if args.out_file:
        with open(args.out_file, "w+", encoding="utf-8") as f:
            with subprocess.Popen(cmd_line, stdout=f):
                pass
    else:
        with subprocess.Popen(cmd_line):
            pass


if __name__ == "__main__":
    raise SystemExit(main())
