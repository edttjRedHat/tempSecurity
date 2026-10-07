#!/bin/bash
typeset _scrName="${BASH_SOURCE[0]##*/}"
typeset _scrPath="$(CDPATH= \command cd -L "${BASH_SOURCE[0]%/*}" 2> /dev/null;\command pwd)"

set -ex
set -o pipefail


typeset oslMnfstDir="${1%%/}"; [ $# != 0 ] && shift; : "${projWS:=/}"
typeset badBaseOSList="${1}"; [ $# != 0 ] && shift

typeset -a badBaseOSs=(); IFS=, read -ra badBaseOSs <<< "${badBaseOSList}"

exec 9<> __baseOS; rm -f __baseOS
find "${oslMnfstDir}/" -type f -name 'oslScan--*--report-*.manifest' \( \
    -exec bash -ec '
        oFN="{}"
        echo "oslMnfst: ${oFN##*/}"; cat "{}"
    ' \; -o \( -exec false '{}' + -quit \) \
\) | awk '
    BEGIN {
        img=""
    }
    /^oslMnfst:/ {
        # oslScan--REPO#P1#...#PN@sha256%HASH--report-...
        split($(0), f, ": ")
        split(f[2], f, "--")
        img=f[2]
        gsub("#", "/", img)
        gsub("%", ":", img)
    }
    /^ *baseos-osname:/ {
        split($(0), f, ": ")
        baseOS[f[2]][img]=0
    }
    END {
        for (k1 in baseOS) {
            print(k1":")
            for (k2 in baseOS[k1]) print("  - "k2)
        }
    }
' 1>&9

echo "Detected Base OSs:
$({ cat /dev/stdin; } 0<&9 | yq eval '.[] | "  - " + key')
"

foundBadBaseOSs="$(
    { cat /dev/stdin; } 0<&9 |
        yq eval '.[] | key' |
        xargs -d\\n -I'{}' bash -exc '
            _fail_xargs() { exit 255; }; trap _fail_xargs ERR
            badBaseOS="$('"
                echo ',${badBaseOSList},' | sed -nE 's/.*,({}),.*/\\1/p'
            "')"
            if [ -n "${badBaseOS}" ]; then
                echo "  - ${badBaseOS}:"
                { cat /dev/stdin; } 0<&9 |
                    yq eval "\"      - \" + .${badBaseOS}[]"
            fi
        '
)"
[ -n "${foundBadBaseOSs}" ] && echo "Found disallowed Base OSs:
${foundBadBaseOSs}
" && false

true
