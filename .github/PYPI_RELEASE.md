# PyPI Release Setup

This project uses PyPI Trusted Publishing through GitHub Actions. No `PYPI_API_TOKEN` secret is required.

## PyPI Trusted Publisher values

Configure these values in PyPI project settings:

- PyPI project name: `libcrypto`
- Owner: `Pymmdrza`
- Repository: `libcrypto`
- Workflow filename: `deploy-pypi-release.yaml`
- Environment name: `pypi`

## Recommended release flow

1. Update the version locally:

   ```bash
   python scripts/set_version.py 1.6.0
   ```

2. Commit and tag:

   ```bash
   git add src/libcrypto/_version.py
   git commit -m "chore: release v1.6.0"
   git tag v1.6.0
   git push origin main v1.6.0
   ```

3. GitHub Actions will build, verify, publish to PyPI, and create a GitHub Release.

You may also run the `Publish libcrypto to PyPI` workflow manually and provide the version input.
