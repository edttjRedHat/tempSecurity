#!/bin/bash
typeset _scrName="${BASH_SOURCE[0]##*/}"
typeset _scrPath="$(CDPATH= \command cd -L "${BASH_SOURCE[0]%/*}" 2> /dev/null;\command pwd)"
set -o pipefail
shopt -s extglob

function ParseURI() {
    ########
    # Usage:
    #   eval "(
    #       ParseURI <uriStr> [<uriSch>][,[<uriUsr>][,[<uriPwd>][,[<uriHost>][,[<uriPort>][,[<uriPath>][,[<uriQry>][,[<uriFrg>]]]]]]]]
    #   )"
    #
    # Args:
    #   uriStr:     URI string.
    #                   SCHEME:[//USR[:PWD]@HOST[:PORT]][PATH][?QRY][#FRG]
    #   uriVars:    List (comma-delimited) for parent context variables to
    #               store URI components, in the following order (skip if a
    #               particular component is not needed):
    #                   uriSch,uriNetCrd,uriNetLoc,uriNetPath,uriUsr,uriPwd,
    #                   uriHost,uriPort,uriPath,uriQry,uriFrg
    #               Where:
    #                   uriNetCrd    := <uriUsr>[:<uriPwd>]
    #                   uriNetLoc    := <uriHost>[:<uriPort>]
    #                   uriNetPath   := <uriNetLoc>/<uriPath>
    #
    # Example:
    #   eval "$(ParseURI 'https://host.com/path/fo/file' uriSch,,uriNetPath)"
    #   #   Will set:
    #   #       uriSch=https
    #   #       uriNetPath=host.com/path/fo/file
    ########
    typeset uriStr="${1}"; [ $# != 0 ] && shift
    typeset uriVars="${1}"; [ $# != 0 ] && shift

    typeset uriSch= uriUsr= uriPwd= uriHost= uriPort= uriPath= uriQry= uriFrg=
    typeset uriNetCrd= uriNetLoc= uriNetPath=
    typeset -i wUsr=1 wPwd=1 wHost=1 wPort=1 wQry=0 wFrg=0
    typeset -a uriArr=()

    [[ "${uriStr}" =~ [[:alnum:]]+: ]] || {
        [ "${uriStr:0:1}" != / ] && uriStr="./${uriStr}" ||
            uriStr="/${uriStr}"
        uriNetPath="${uriStr%/*}"
        uriStr="$(
            cd -L "${uriNetPath}" 2> /dev/null && pwd || {
                echo "$([ "${uriStr:0:1}" = . ] && echo "${PWD}/")$(
                    sed -E \
                        -e 's#/+#/#g                            # Remove repeated `/`.' \
                        -e ':a;s#/\.(/|$)#\1#;ta                # Remove `.`.' \
                        -e ':b;s#(^/|/[^/]+/)\.\.(/|$)#\2#;tb   # Remove `..`.' \
                        -e 's#$^#/#                             # Make sure does not go beyond root of FS.' \
                        0<<<"${uriNetPath}"
                )"
            }
        )/${uriStr##*/}"
        [ "${uriStr:0:2}" = // ] && uriStr="file:/${uriStr}" ||
            uriStr="file://${uriStr}"
    }

    uriSch="${uriStr%%:*}"; uriStr="${uriStr#*:}"
    case ${uriSch} in
      (http?(s))    wQry=1 wFrg=1;;
      (@(r|t)ar|?(g|l)zip)  wHost=0 wPort=0 wQry=1;;
      (file)    wUsr=0 wPwd=0 wPort=0;;
    esac

    if { ((wHost)) && [ "${uriStr:0:2}" = // ]; }; then
        uriStr="${uriStr:2}" uriNetLoc="${uriStr%%/*}"
        [ "${uriNetLoc}" = "${uriStr}" ] && uriStr= ||
            uriStr="${uriStr#*/}"
        if { ((wUsr)) && [ -n "${uriStr}" ]; }; then
            uriNetCrd="${uriNetLoc%@*}"
            [ "${uriNetCrd}" = "${uriNetLoc}" ] && uriNetCrd= ||
                uriNetLoc="${uriNetLoc##*@}"
            if ((wPwd)); then
                uriUsr="${uriNetCrd%%:*}"
                [ "${uriUsr}" = "${uriNetCrd}" ] || uriPwd="${uriNetCrd#*:}"
            else
                uriUsr="${uriNetCrd}"
            fi
        fi

        if [ -n "${uriNetLoc}" ]; then
            uriHost="${uriNetLoc}"
            if ((wPort)); then
                uriHost="${uriNetLoc%:*}"
                [ "${uriHost}" = "${uriNetLoc}" ] || uriPort="${uriNetLoc##*:}"
            fi
        fi
    fi

    if [ -n "${uriStr}" ]; then
        if ((wQry)); then
            uriPath="${uriStr%%\?*}"
        else
            uriPath="${uriStr}"
        fi
        [ "${uriPath}" = "${uriStr}" ] && {
            ((wFrg)) && [[ "${uriStr}" =~ \# ]] &&
                uriPath="${uriStr%%#*}" uriStr="#${uriStr#*#}" || uriStr=
        } || uriStr="${uriStr#*\?}"
    fi

    if { ((wQry)) && [ -n "${uriStr}" ]; }; then
        if ((wFrg)); then
            uriQry="${uriStr%%#*}"
        else
            uriQry="${uriStr}"
        fi
        [ "${uriQry}" = "${uriStr}" ] || { ((wFrg)) && uriFrg="${uriStr#*#}"; }
    fi

    uriNetPath="${uriNetLoc}/${uriPath}"

    IFS=, read -ra uriArr 0<<<"${uriVars}"

    echo "
        ${uriArr[0]:+${uriArr[0]}='${uriSch}'}
        ${uriArr[1]:+${uriArr[1]}='${uriNetCrd}'}
        ${uriArr[2]:+${uriArr[2]}='${uriNetLoc}'}
        ${uriArr[3]:+${uriArr[3]}='${uriNetPath}'}
        ${uriArr[4]:+${uriArr[4]}='${uriUsr}'}
        ${uriArr[5]:+${uriArr[5]}='${uriPwd}'}
        ${uriArr[6]:+${uriArr[6]}='${uriHost}'}
        ${uriArr[7]:+${uriArr[7]}='${uriPort}'}
        ${uriArr[8]:+${uriArr[8]}='${uriPath}'}
        ${uriArr[9]:+${uriArr[9]}='${uriQry}'}
        ${uriArr[10]:+${uriArr[10]}='${uriFrg}'}
    "
}


function TruncFN() {
    ########
    # Usage:
    #   echo "$(TruncFN <filePath> [<extraLen>])"
    #
    # Truncate File Name portion of the path to the max. limit of the File
    # System. If the File Name portion exceeds the the max. limit, it will be
    # truncated to `<60%multipleOf10Down>^...^<35%multipleOf10Up>`.
    #
    # Args:
    #   filePath    File Path to be processed. May contain directory, only the
    #               File Name portion will be processed.
    #   extraRed    Extra no. of characters to be reduced from system max. as
    #               reservation for File Name addition by application (def: 0).
    #               Note:   Final max. File Name length will be floored at 30
    #                       characters.
    #   extraLen    Extra no. of characters want to be reserved as extra
    #               safeguard in multiple of 10 (def: 1).
    #
    # Example (on a system with max. File Name is 255 characters):
    #   echo "$(TruncFN '<pfx150Chars><middlePart16+Chars><sfx90Chars>')"
    #   # Will yield:   <pfx150Chars>^...^<sfx90Chars>
    ########
    typeset filePath="${1}"; [ $# != 0 ] && shift
    typeset -i xtRed="${1:-0}"; [ $# != 0 ] && shift
    typeset -i xtLen="${1:-1}"; [ $# != 0 ] && shift

    typeset fnTruncStr='...'

    typeset fD="${filePath%/*}"
    typeset fN="${filePath##*/}"
    typeset -i fnMaxLen="$(($(getconf NAME_MAX .)-${xtRed}))"; ((
        fnMaxLen < 30
    )) && fnMaxLen=30
    typeset -i fnPfxLen="$((10*(fnMaxLen*6/100)))"
    typeset -i fnSfxLen="$((10*(((fnMaxLen*35)+999)/1000)))"

    (((fnMaxLen-=(xtLen=10*xtLen)) < (fnPfxLen+fnSfxLen))) && ((fnPfxLen-=10))

    [ "${fN}" = "${fD}" ] && unset fD
    ((${#fN} > fnMaxLen)) &&
        fN="${fN::${fnPfxLen}}${fnTruncStr}${fN: -${fnSfxLen}}"
    echo "${fD+${fD}/}${fN}"
}


function AutoLogFile() {
    ########
    # Usage:
    #   echo "$(AutoLogFile <logName> <logDir> [<numLen>])"
    #
    # Create a circular increment numbered log file with the following pattern:
    #   `<%Y%m%d>-Log--<numLenDigit>--<logName>.txt`
    #   With:
    #       %Y%m%d      Current date.
    #       numLenDigit Decimal digit character with 0-prefixed upto `numLen`
    #                   width, starting from 0 and incremented by 1 from the
    #                   max. found value. Floored at 1 digit width.
    #
    # Args:
    #   logName Name of the log file.
    #   logDir  Log file directory (def: `CWD`).
    #   numLen  Max. decimal digit width (def: 3; i.e. 000 - 999).
    ########
    typeset logName="${1}"; [ $# != 0 ] && shift
    typeset logDir="${1:-.}"; [ $# != 0 ] && shift
    typeset -i numLen="${1:-3}"; [ $# != 0 ] && shift

    typeset -i i=0 iMax=0

    typeset qmChars="$(eval "printf '?%.0s' {1..${numLen}}")"
    typeset zrChars="$(eval "printf '0%.0s' {1..${numLen}}")"

    ((numLen < 1)) && numLen=1
    logFile="$(printf "%(%Y%m%d)T-Log--${qmChars}--${logName}.txt" -1)"
    mkdir -p "${logDir}"; cd "${logDir}"
    for e in ${logFile}; do
        if [ "${e}" = "${logFile}" ]; then
            iMax=0  # No log file with the pattern found, starts from 0.
            break
        else
            i="$((10#$(
                echo "${e}" | sed -E \
                    -e 's/^.{14}([[:digit:]]{'"${numLen}"'})-.+/\1/;t' \
                    -e 's/^.+/-2/'
            ) + 1))"    # Make sure the `??...?` captures decimal digits only.
            ((iMax < i)) && iMax=${i}
        fi
    done
    cd - 1> /dev/null
    logFile="$(
        echo "${logFile}" | sed -E \
            's/^(.{14})\?{'"${numLen}"'}(.+)/\1'"$(
                printf "%0${numLen}d" $((iMax % 1${zrChars}))
            )"'\2/'
    )"

    echo "${logDir}/${logFile}"
}
