#!/usr/bin/env bash
set -e
SCRIPTPATH=$(dirname "$(realpath "$0")")
TESTDIR=$(mktemp -d)

cleanup () {
    cd "$SCRIPTPATH" || true
    fusermount -u "$TESTDIR" -q || true
    wait
    rm -rf "$TESTDIR"
}

read_dir_contents () {
    find "$TESTDIR" \
         -type d -exec stat --format "%N %A %u:%g" {} \; \
         -or \
         -type f -exec stat --format "%N %A %u:%g %s" {} \; |
        sort
}

run () {
    echo "========================"
    echo "$@"
    echo "------------------------"
    output=$("$@" 2>&1)
    res=$?
    if [[ -n "$output" ]]
    then
        echo "------------------------"
        echo "$output"
    fi
    echo "========================"
    echo
    if [ $res -ne 0 ]
    then
        exit $res
    fi
}

mkdir "$TESTDIR"/dir0
echo "CONTENT" > "$TESTDIR"/dir0/file0
mkdir "$TESTDIR"/dir1
mkdir "$TESTDIR"/dir5
mkdir "$TESTDIR"/dir1/dir2
touch "$TESTDIR"/file1
touch "$TESTDIR"/file5
touch "$TESTDIR"/file4
ln -s linktarget "$TESTDIR"/link0

ORIG_CONTENTS=$(read_dir_contents)

./ramcachefs -d -f "$TESTDIR" -o noautopersist -o size=1M -o maxinodes=2000 2>&1 &

while ! findmnt --mountpoint "$TESTDIR" >/dev/null
do
    sleep 0.1
done

trap cleanup EXIT

echo "========================"
echo "Reading tree"
echo "------------------------"
READ_CONTENTS=$(read_dir_contents)
echo "========================"
echo

if [[ "$ORIG_CONTENTS" != "$READ_CONTENTS" ]]
then
    echo "Failed correctly reading original directory:"
    if command -v icdiff >/dev/null 2>/dev/null
    then
        icdiff <(echo "$ORIG_CONTENTS") <(echo "$READ_CONTENTS")
    else
        echo "Original directory:"
        echo "$ORIG_CONTENTS"
        echo ""
        echo "Read directory:"
        echo "$READ_CONTENTS"
    fi
    exit 1
fi

pushd "$TESTDIR" >/dev/null

run sh -c 'echo OUT1 > file2'
run sh -c 'echo OUT1LONG > file2'
run sh -c 'echo OUT2LONG > file3'
run sh -c 'echo CONTENTLONG > dir0/file0'
run mkdir -p dir0/dir3
run mv ./dir5 dir4
run mkdir -p dir6
run ln -s newtarget dir0/link1
run rm file1
run mv file2 file2renamed
run mv file3 dir0/file2
run mv dir1/dir2 dir0
run mv dir0 dir4/dir5
run mv dir4 dir6
run ls -al
run rm file5
run mv file4 file5
run chmod 705 .

run df --output .

if [[ "$1" == "-i" ]]
then
    echo "========================"
    echo "Mounted in $TESTDIR"
    read -r -p "Press enter key..."
    echo "========================"
    echo
fi

popd >/dev/null

echo "========================"
echo "Reading tree"
echo "------------------------"
NEW_CONTENTS=$(read_dir_contents)
echo "========================"
echo

echo "========================"
echo "Sending persist ioctl"
echo "------------------------"
./ramcachefs -p "$TESTDIR"
echo "========================"
echo

df --output "$TESTDIR"

fusermount -u "$TESTDIR" -q

PERSISTED_CONTENTS=$(read_dir_contents)

if [[ "$NEW_CONTENTS" != "$PERSISTED_CONTENTS" ]]
then
    echo "Failed correctly persisting new directory:"
    if command -v icdiff >/dev/null 2>/dev/null
    then
        icdiff <(echo "$NEW_CONTENTS") <(echo "$PERSISTED_CONTENTS")
    else
        echo "New directory:"
        echo "$NEW_CONTENTS"
        echo ""
        echo "Persisted directory:"
        echo "$PERSISTED_CONTENTS"
        echo
    fi
    exit 1
fi
