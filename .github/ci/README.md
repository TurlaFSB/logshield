# CI tool pins

`requirements.txt` pins every Python tool CI uses, with the hash of every
published file, and CI installs it with `pip install --require-hashes`. To update:

```sh
python3 -m venv /tmp/ci && /tmp/ci/bin/pip install -r requirements.in
/tmp/ci/bin/pip freeze   # then write each name==version with its PyPI file hashes
```

(`pip-compile --generate-hashes` from pip-tools does the same in one step.)
actionlint is not installed through pip: the workflow downloads the release
archive and checks it against a pinned SHA-256 taken from the publisher's
checksum file.
