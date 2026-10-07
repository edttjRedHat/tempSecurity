#!/bin/bash
typeset _scrName="${BASH_SOURCE[0]##*/}"
typeset _scrPath="$(CDPATH= \command cd -L "${BASH_SOURCE[0]%/*}" 2> /dev/null;\command pwd)"

set -ex
set -o pipefail


typeset projWS="${1%%/}"; [ $# != 0 ] && shift; : "${projWS:=/}"
typeset -i mode="${1}"; [ $# != 0 ] && shift

typeset oslDir="${projWS}/__oslMnfst"
typeset sumDir="${projWS}/__summary"

if ((mode)); then   # Reconcile Mode.
    typeset unsplitScript="$(
        cat - 0<<'unsplitScript-EOF'
: Unsplitting - Processing: '{}'
typeset sumDir="$1"; [ $# != 0 ] && shift

typeset mFN="$(
    echo '{}' |
    sed -E \
        `# ...--report-SCAN_TYPE[-OS][--00000].manifest` \
        -e 's/(--[0-9]+)?\.manifest$//'
)";
typeset cFP="${sumDir}/__tmp/${mFN##*/}.manifest"

[ ! -f "${cFP}" ] && {
    find -L "${mFN%/*}" -type f \( \
        -path "${mFN}.manifest" -o \
        -path "${mFN}--*.manifest" \
    \) | sort | xargs -d\\n -I{''} bash -exc "
        cFP='${cFP}'"'
        cat "{''}" 1>> "${cFP}" || exit 255
    '
}
true
unsplitScript-EOF
    )"
    typeset mergeScript="$(
        cat - 0<<'mergeScript-EOF'
: Merging - Processing: '{}'
typeset sumDir="$1"; [ $# != 0 ] && shift

typeset mFN="$(
    echo '{}' |
    sed -E \
        `# ...--report-SCAN_TYPE[-OS].manifest` \
        -e 's/(.*--report)(-.+)?\.manifest$/\1/'
)"
typeset cFP="${sumDir}/combinedMnfst/${mFN##*/}-combined.manifest"

[ ! -f "${cFP}" ] && {
    ls -U "${mFN}"-*.manifest 2> /dev/null |
        xargs -d\\n -I{''} bash -exc "
            cFP='${cFP}'
            mFN='${mFN}'
            sType='{""}'"'
            sType="${sType#${mFN}-}"; sType="${sType%%.*}"; sType="${sType%%-*}"
            cat <(echo "--- # ${sType}") "{''}" 1>> "${cFP}"
        '
}
true
mergeScript-EOF
    )"
    typeset reportScript="$(
        cat - 0<<'reportScript-EOF'
: Report - Processing: '{}'
typeset sumDir="$1"; [ $# != 0 ] && shift
typeset repScr="$1"; [ $# != 0 ] && shift

typeset cFP='{}'
typeset cFN="${cFP%-*}"
typeset rFP="${sumDir}/${cFN##*/}-summary.txt"

"${repScr}" <(grep -E '^(\w|---)' "${cFP}") 1> "${rFP}"
reportScript-EOF
    )"

    # Prepare target directory.
    rm -rf "${sumDir}"; mkdir -p "${sumDir}/"{__tmp,combinedMnfst}
    # Unsplit manifest files.
    find -L "${oslDir}/" -type f -name 'oslScan--*.manifest' \( \
        -exec bash -exc "${unsplitScript}" '' "${sumDir}" \; -o \
        \( -exec false '{}' + -quit \) \
    \)
    # Merge manifest files.
    find -L "${sumDir}/__tmp/" -type f -name 'oslScan--*.manifest' \( \
        -exec bash -exc "${mergeScript}" '' "${sumDir}" \; -o \
        \( -exec false '{}' + -quit \) \
    \); rm -rf "${sumDir}/__tmp/"
    # Create summary report.
    find -L "${sumDir}/combinedMnfst/" -type f -name 'oslScan--*.manifest' \( \
        -exec bash -exc "${reportScript}" '' "${sumDir}" \
            "${_scrPath}/osl_reconcile_manifest.py" \; -o \
        \( -exec false '{}' + -quit \) \
    \)
else                # Disperse Mode.
    typeset breakScript="$(
        cat - 0<<'breakScript-EOF'
: Breaking - Processing: '{}'
typeset oslDir="$1"; [ $# != 0 ] && shift

typeset cFP='{}'
typeset mFN="${cFP%-*}"

awk -v mFN="${oslDir}/${mFN##*/}" '
    /^--- # / {sType=$(3);next}   # `--- # SCAN_TYPE`
        {print > mFN"-"sType".manifest"}
' "${cFP}"
rm "${cFP}"
breakScript-EOF
    )"

    # Prepare target directory.
    rm -rf "${oslDir}"; mkdir -p "${oslDir}"
    # Break manifest files.
    find -L "${sumDir}/combinedMnfst/" -type f -name 'oslScan--*.manifest' \( \
        -exec bash -exc "${breakScript}" '' "${oslDir}" \; -o \
        \( -exec false '{}' + -quit \) \
    \); rm -rf "${sumDir}/"
fi
