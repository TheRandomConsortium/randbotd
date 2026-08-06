#!/bin/bash
set -e

# Always enforce project tidiness before building
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

./scripts/sh/check_cleanliness.sh

BUMP_TYPE=${1:-patch}
TARGET_INPUT=${2:-amd64}

# Map architecture inputs to Debian arch & Rust target triple
case "$TARGET_INPUT" in
    amd64|x86_64)
        DEB_ARCH="amd64"
        RUST_TARGET="x86_64-unknown-linux-gnu"
        ;;
    arm64|aarch64)
        DEB_ARCH="arm64"
        RUST_TARGET="aarch64-unknown-linux-gnu"
        ;;
    armhf|armv7*)
        DEB_ARCH="armhf"
        RUST_TARGET="armv7-unknown-linux-gnueabihf"
        ;;
    *)
        DEB_ARCH="$TARGET_INPUT"
        RUST_TARGET=""
        ;;
esac

CURRENT_VERSION=$(grep -E '^version = ' Cargo.toml | head -n 1 | awk -F '"' '{print $2}')
IFS='.' read -r major minor patch <<< "$CURRENT_VERSION"

if [ "$BUMP_TYPE" == "major" ]; then
    major=$((major + 1))
    minor=0
    patch=0
elif [ "$BUMP_TYPE" == "minor" ]; then
    minor=$((minor + 1))
    patch=0
elif [ "$BUMP_TYPE" == "patch" ]; then
    patch=$((patch + 1))
fi

if [ "$BUMP_TYPE" != "none" ]; then
    NEW_VERSION="$major.$minor.$patch"
    echo "Bumping version from $CURRENT_VERSION to $NEW_VERSION..."
    sed -i "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
else
    NEW_VERSION=$CURRENT_VERSION
    echo "Keeping version at $NEW_VERSION..."
fi

# Determine incremental release number for this version
REPO_DIR="$HOME/randbotd-repo"
mkdir -p "$REPO_DIR"

RELEASE=1
EXISTING_DEBS=$(find "$REPO_DIR" -name "randbotd_${NEW_VERSION}-*_${DEB_ARCH}.deb" 2>/dev/null || true)
if [ -n "$EXISTING_DEBS" ]; then
    MAX_RELEASE=0
    for deb in $EXISTING_DEBS; do
        fname=$(basename "$deb")
        rel_part="${fname#randbotd_${NEW_VERSION}-}"
        rel_num="${rel_part%%_*}"
        if [[ "$rel_num" =~ ^[0-9]+$ ]]; then
            if [ "$rel_num" -gt "$MAX_RELEASE" ]; then
                MAX_RELEASE=$rel_num
            fi
        fi
    done
    if [ "$MAX_RELEASE" -gt 0 ]; then
        RELEASE=$((MAX_RELEASE + 1))
    fi
fi
FULL_VERSION="${NEW_VERSION}-${RELEASE}"
echo "Using Full Version: $FULL_VERSION"

echo "Building release binary for architecture: $DEB_ARCH..."
HOST_ARCH=$(uname -m)
if [ -n "$RUST_TARGET" ] && [[ ("$DEB_ARCH" == "amd64" && "$HOST_ARCH" != "x86_64") || ("$DEB_ARCH" == "arm64" && "$HOST_ARCH" != "aarch64") ]]; then
    echo "Cross-compiling for $RUST_TARGET..."
    cargo build --release --target "$RUST_TARGET"
    BINARY_PATH="target/$RUST_TARGET/release/randbotd"
else
    echo "Building natively..."
    cargo build --release
    BINARY_PATH="target/release/randbotd"
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Binary not found at $BINARY_PATH"
    exit 1
fi

STAGING_DIR="build_temp/deb_staging"
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR/usr/bin"
mkdir -p "$STAGING_DIR/lib/systemd/system"
mkdir -p "$STAGING_DIR/DEBIAN"

cp "$BINARY_PATH" "$STAGING_DIR/usr/bin/randbotd"
chmod 755 "$STAGING_DIR/usr/bin/randbotd"

cp debian/randbotd.service "$STAGING_DIR/lib/systemd/system/randbotd.service"
chmod 644 "$STAGING_DIR/lib/systemd/system/randbotd.service"

cp debian/postinst "$STAGING_DIR/DEBIAN/postinst"
chmod 755 "$STAGING_DIR/DEBIAN/postinst"

cp debian/postrm "$STAGING_DIR/DEBIAN/postrm"
chmod 755 "$STAGING_DIR/DEBIAN/postrm"

cat > "$STAGING_DIR/DEBIAN/control" << EOF
Package: randbotd
Version: $FULL_VERSION
Section: net
Priority: optional
Architecture: $DEB_ARCH
Maintainer: The Random Consortium
Description: Random Consortium's Certificate Bot Daemon (randbotd)
 Decentralized Trust & Multi-Network SSL Authority Daemon
EOF

OUTPUT_DEB="randbotd_${FULL_VERSION}_${DEB_ARCH}.deb"

if command -v dpkg-deb >/dev/null 2>&1; then
    echo "Building deb package using dpkg-deb..."
    dpkg-deb --build "$STAGING_DIR" "$OUTPUT_DEB"
else
    echo "dpkg-deb not found. Assembling deb package using ar & tar..."
    DEB_BUILD_DIR="build_temp/deb_build"
    rm -rf "$DEB_BUILD_DIR"
    mkdir -p "$DEB_BUILD_DIR"
    
    echo "2.0" > "$DEB_BUILD_DIR/debian-binary"
    (cd "$STAGING_DIR/DEBIAN" && tar --owner=0 --group=0 -czf "$PROJECT_ROOT/$DEB_BUILD_DIR/control.tar.gz" .)
    (cd "$STAGING_DIR" && tar --owner=0 --group=0 --exclude='DEBIAN' -czf "$PROJECT_ROOT/$DEB_BUILD_DIR/data.tar.gz" .)
    (cd "$DEB_BUILD_DIR" && ar rcs "$PROJECT_ROOT/$OUTPUT_DEB" debian-binary control.tar.gz data.tar.gz)
    rm -rf "$DEB_BUILD_DIR"
fi

rm -rf "$STAGING_DIR"
echo "Successfully created package: $OUTPUT_DEB"

echo "Copying package to repository directory at $REPO_DIR..."
cp "$OUTPUT_DEB" "$REPO_DIR/"

echo "Cleaning up older package versions in repository (keeping latest 3)..."
pushd "$REPO_DIR" > /dev/null
ls -t randbotd_*.deb 2>/dev/null | tail -n +4 | xargs -I {} rm -f {}
popd > /dev/null

echo "Updating APT repository metadata..."
pushd "$REPO_DIR" > /dev/null
rm -f Packages Packages.gz
if command -v dpkg-scanpackages >/dev/null 2>&1; then
    dpkg-scanpackages . /dev/null > Packages 2>/dev/null
elif command -v apt-ftparchive >/dev/null 2>&1; then
    apt-ftparchive packages . > Packages 2>/dev/null
else
    echo "Generating Packages index using pure shell parser..."
    for deb in *.deb; do
        [ -f "$deb" ] || continue
        if command -v dpkg-deb >/dev/null 2>&1; then
            dpkg-deb -f "$deb" >> Packages
        else
            ar p "$deb" control.tar.gz | tar -xzO ./control >> Packages
        fi
        echo "Filename: ./$deb" >> Packages
        echo "Size: $(stat -c%s "$deb")" >> Packages
        echo "SHA256: $(sha256sum "$deb" | awk '{print $1}')" >> Packages
        echo "" >> Packages
    done
fi
gzip -9c Packages > Packages.gz
popd > /dev/null

cat > randbotd.list << EOF
deb [trusted=yes] file://$REPO_DIR ./
EOF

echo "Done! Package is available in local repository at $REPO_DIR"
echo ""
echo "To use/sync this repository with a remote server (e.g., homeserver):"
echo "  1. Sync repository files to remote server:"
echo "     rsync -avz $REPO_DIR/ user@homeserver:~/randbotd-repo/"
echo "  2. On remote server, add repo source:"
echo "     echo 'deb [trusted=yes] file:///home/user/randbotd-repo ./' | sudo tee /etc/apt/sources.list.d/randbotd.list"
echo "  3. Update and install on remote server:"
echo "     sudo apt update && sudo apt install randbotd"
