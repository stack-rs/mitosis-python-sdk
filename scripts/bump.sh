#!/bin/bash
TAG="$1"
git-cliff --bump -t "$TAG" -o CHANGELOG.md
uv version "$TAG"
git add .
git commit -m "chore(release): bump version to $TAG"
git tag "$TAG"
git push --atomic origin main "$TAG"
