# Contributing

Thanks for helping improve php2shell-scanner.

## Ground rules
- Keep the tool **non-destructive**. Pull requests that add exploitation,
  OOM-triggering, or any payload designed to crash or alter a remote host will
  be declined. This project is an exposure mapper, not an exploit.
- Standard library only — no third-party runtime dependencies.
- Never commit real scan data or anything identifying a third-party host.

## Good contributions
- New passive fingerprint sources (more CMS/framework cookie names, headers).
- Better version parsing, fewer false `INDETERMINATE`s.
- Performance, output formats, packaging.
- Tests.

## Dev
```bash
python3 php2shell_exposure_scanner.py --help
# quick offline logic check
python3 -c "import ast; ast.parse(open('php2shell_exposure_scanner.py').read()); print('ok')"
```

Open an issue first for anything substantial so we can agree on the approach.
