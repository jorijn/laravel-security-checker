# Releasing

Releases are automated with [release-please](https://github.com/googleapis/release-please).
Packagist reads the version from the git tag (`vX.Y.Z`), so a release is nothing more than a
tag plus a GitHub release; there is no `version` field in `composer.json` to bump.

## Day to day

1. Every pull request title follows [Conventional Commits](https://www.conventionalcommits.org/)
   (checked by `.github/workflows/pr-title.yaml`). Pull requests are squash-merged, so the
   title becomes the commit message on `master`.
2. After each merge, release-please updates a single open release pull request
   (`chore(master): release X.Y.Z`) with the next version and the CHANGELOG entry.
3. Merging that release pull request tags `vX.Y.Z` and publishes the GitHub release.
   Packagist picks the tag up through its webhook.

Nothing is released until you merge the release pull request, so several changes can be
collected into one release.

| PR title starts with                       | Version bump | In CHANGELOG |
|--------------------------------------------|--------------|--------------|
| `feat!:`, `fix!:` or a `BREAKING CHANGE:` footer | major  | yes          |
| `feat:`                                    | minor        | yes          |
| `fix:`, `perf:`, `deps:`, `revert:`        | patch        | yes          |
| `docs:`, `chore:`, `ci:`, `test:`, `refactor:`, `style:`, `build:` | none | no |

`deps:` is for changes to runtime constraints in `require`, which affect users. Dependabot
uses it automatically; `require-dev` bumps get `chore:` instead.

To force a specific version, put a `Release-As: X.Y.Z` footer in a commit message on the
branch, for example:

```sh
git commit --allow-empty -m "chore: release 4.0.0" -m "Release-As: 4.0.0"
```

## Maintaining 3.x next to 4.x

3.x receives security fixes only, until February 2027. While 4.0 is not on `master` yet,
`master` is the 3.x line and nothing special is needed.

When the first 4.0 change is about to be merged:

1. Create the maintenance branch from the latest 3.x release: `git push origin v3.Y.Z:refs/heads/3.x`.
   Its copy of `.release-please-manifest.json` keeps tracking 3.x versions.
2. Push the empty `Release-As: 4.0.0` commit above to `master`. Without it, a plain `fix:` on
   `master` would propose `3.Y.Z+1`, the same tag the `3.x` branch may want.
3. Protect `3.x` like `master`.

From then on, release-please runs on both branches (see `.github/workflows/release-please.yaml`)
and keeps one release pull request per branch: `chore(3.x): release 3.Y.Z` and
`chore(master): release 4.Y.Z`. A security fix goes to `master` first and is cherry-picked
to `3.x` with the same `fix:` message. Never use a breaking (`!`) type on `3.x`: it would
propose `4.0.0` there.

GitHub marks the most recently published release as "Latest", so after a 3.x release run
`gh release edit <newest 4.x tag> --latest` to point it back to 4.x. Composer and Packagist
are not affected by this; they compare version numbers.
