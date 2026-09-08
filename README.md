<p align="center">
  <img src="bloodbober.jpg" alt="BloodBober" width="280">
</p>

# BloodBober - BloodHound Attack Path Analyzer

`BloodBober` is a small local Flask web application for reviewing BloodHound ZIP exports, highlighting interesting ACLs, delegation findings, roasting opportunities, and attack paths.

## Credits

Project creator: [MRXH4X](https://github.com/MRXH4X)

Special thanks for the Bober Edition version.

## Install

### Linux

```bash
pipx install "$(printf '%s\n' dist/blood_bober-*.whl | sort -V | tail -n 1)"
```

### Windows / PowerShell

```powershell
pipx install (Get-ChildItem dist/blood_bober-*.whl | Sort-Object { [version](($_.BaseName -replace '^blood_bober-', '' -replace '-py3-none-any$', '')) } | Select-Object -Last 1).FullName
```

For the optional production WSGI server dependency:

```bash
pipx inject blood-bober waitress
```

## Usage

Start the app:

```bash
bloodbober
```

By default it listens on `127.0.0.1:5000` and opens the browser automatically.

Useful options:

```bash
bloodbober --host 127.0.0.1 --port 5000
bloodbober --no-browser
bloodbober --debug
```

Then load a BloodHound ZIP file in the web UI and mark owned principals in the sidebar.

## Build

### Linux

Generic wheel build:

```bash
python -m build --wheel
```

### Windows / PowerShell

Use the helper script. It keeps Python temporary files inside the project
directory and builds without an isolated temp environment:

```powershell
.\scripts\build-wheel.ps1
```

If the build tooling is missing from the virtual environment:

```powershell
.\scripts\build-wheel.ps1 -InstallDeps
```

The project also includes a prebuilt wheel under `dist/` for direct `pipx` installation.

## License

MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files, to deal in the Software
without restriction, including without limitation the rights to use, copy,
modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
