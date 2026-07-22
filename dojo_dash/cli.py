"""`dojo-dash` command entrypoint.

    dojo-dash serve            # run the live report server (the container default)
    dojo-dash render [...]     # render reports to HTML/Markdown (see --help)
    dojo-dash seed [...]       # populate a demo DefectDojo with sample findings

Each subcommand delegates to a module; run `dojo-dash <cmd> --help` for its options.
"""
import sys

USAGE = __doc__


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "serve"
    rest = argv[1:]

    if cmd in ("serve", "server"):
        from .server import main as serve_main
        serve_main()
    elif cmd == "render":
        from . import render
        sys.argv = ["dojo-dash render", *rest]
        render.main()
    elif cmd == "seed":
        from . import seed
        sys.argv = ["dojo-dash seed", *rest]
        seed.main()
    elif cmd in ("-h", "--help", "help"):
        print(USAGE)
    else:
        sys.stderr.write(f"dojo-dash: unknown command '{cmd}'\n\n{USAGE}")
        sys.exit(2)


if __name__ == "__main__":
    main()
