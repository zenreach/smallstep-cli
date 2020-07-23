#/bin/sh
set -ex;

OUTPUT_DIR=$1
RELEASE_DIR=$2

STEP_VERSION=$3
STEP_PLATFORM=$4
STEP_ARCH=$5
STEP_EXEC_NAME=$6

BUNDLE_DIR=${OUTPUT_DIR}/bundle

mkdir -p "$BUNDLE_DIR" "$RELEASE_DIR"
TMP=$(mktemp -d "$BUNDLE_DIR/tmp.XXXX")
trap "rm -rf $TMP" EXIT INT QUIT TERM

stepName=step_${STEP_VERSION}
newdir="$TMP/${stepName}"
mkdir -p "$newdir/bin"

cp "$OUTPUT_DIR/bin/step" "$newdir/bin/${STEP_EXEC_NAME}"

cp README.md "$newdir"
NEW_BUNDLE="${RELEASE_DIR}/step_${STEP_PLATFORM}_${STEP_VERSION}_${STEP_ARCH}.tar.gz"

rm -f "$NEW_BUNDLE"
tar -zcvf "$NEW_BUNDLE" -C "$TMP" "${stepName}"