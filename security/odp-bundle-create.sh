#!/bin/bash
typeset _scrName="${BASH_SOURCE[0]##*/}"
typeset _scrPath="$(CDPATH= \command cd -L "${BASH_SOURCE[0]%/*}" 2> /dev/null;\command pwd)"
typeset _useMsg=;
while read -rd '' _useMsg; do :; done 0<<'_useMsg-EOF'
Create ODP Bundle.

Usage:
    odp-bundle create.sh [-i VERSION] [-s PHASES] ODP_ROOT OSM_PARS

Where:
    -i  Install required tools.
        VERSION Version of `odpctl` to install (default (empty string): `bin-`,
                use the `odpctl` install script default).
                Format:
                    bin-BIN_BRANCH  Install the executable version
                    git-GIT_BR_TAG  Install the python source version.
                Where:
                    BIN_BRANCH  Branch of the executable version in the
                                artifactory.
                    GIT_BR_TAG  The `git` branch (`refs/heads/GIT_BR_TAG) or
                                tag (`refs/tags/GIT_BR_TAG`).
                For details, see:
                https://packages.vcfd.broadcom.net/odpcli-generic-local/
                https://gitlab.eng.vmware.com/core-build/odpclients/
    -s  Skip certain phases.
        This option may be given multiple times.
        PHASES  List (comma delimited) of phases to be skipped.
                Format:
                    X,Y-Z...
                        X    -> Skip phase X.
                        Y-Z  -> Skip phases Y to Z (inclusively).
                Phases:
                  1  -> Generate project skeleton.
                  2  -> Generate BaseOS packages.
                  3  -> Finalize packages.
    ODP_ROOT    Root path of ODP Bundle.
    OSM_PARS    Parameter to `osstp-load` utility (`|` delimited).
                Format:
                    KEY|[SERVER]|REL_INFO
                Where:
                    KEY         Key string (`USER@DOMAIN:KEY`).
                    SERVER      Name of OSM Server.
                        production   -> Alias to official OSM Server
                                        (default).
                        beta         -> Alias to beta OSM Server.
                        URL          -> URL of the OSM Server.
                    REL_INFO    OSM Release name and version.
                        Format:
                            NAME:VERSION
                                NAME    OSM Release name.
                                VERSION OSM Release version.
_useMsg-EOF

set -o pipefail
shopt -s extglob


typeset gCLIdir=__bin


function GenSkel() {
    ########
    # Generate project skeleton.
    #
    # Args:
    #   odpRoot:    See `OSP_ROOT` in `_useMsg`.
    #   osmRelInfo: See `REL_INFO` under ``OSM_PARS in `_useMsg`.
    ########
    typeset odpRoot="${1%%/}"; [ $# != 0 ] && shift; : "${odpRoot:=/}"
    typeset osmRelInfo="${1}"; [ $# != 0 ] && shift

    "${gCLIdir}/odpctl/odpctl" skeleton \
        -d "${odpRoot}/" -gen_readme -pull_src -name "${osmRelInfo}"
}

function GenCtTrk() {
    ########
    # Generate `ct-tracker` packages.
    #
    # Args:
    #   odpRoot:    See `OSP_ROOT` in `_useMsg`.
    #   osmRelInfo: See `REL_INFO` under ``OSM_PARS in `_useMsg`.
    ########
    typeset odpRoot="${1%%/}"; [ $# != 0 ] && shift; : "${odpRoot:=/}"
    typeset osmRelInfo="${1}"; [ $# != 0 ] && shift

    typeset -Ai ctTrk=()

    eval "$(
        "${gCLIdir}/odpctl/odpctl" get_usetickets -name "${osmRelInfo}" |
            sed -nE "
                /\s${osmRelInfo/:/-} ct-tracker-/\
                s/^([0-9]+)\s.*\sct-tracker-(.*)\s([^\s]+)/ctTrk['\2-\3']=\1/p
            "
    )"
    find -L "${odpRoot}/" -mindepth 2 -type d -name 'ct-tracker-*' \( \
        -exec bash -exc "
            : Processing: '{}'
            _scrPath='${_scrPath}'
            gCLIdir='${gCLIdir}'
            odpRoot='${odpRoot}'
            osmRelInfo='${osmRelInfo}'
            $(typeset -p ctTrk)"'
            odpDir="{}"
            odpETCdir="${odpRoot}/__etc_${odpDir#${odpRoot}/}"
            osID="${odpDir##*/ct-tracker-}"
            osName="${osID%%-*}"
            find -L "${odpDir}/" -mindepth 1 -maxdepth 1 \( \
                -exec bash -exc "
                    mkdir -p \"${odpETCdir}\"
                    mv -f \"{""}\" \"${odpETCdir}/\"
                " \; -o \
                \( -exec false {""} + -quit \) \
            \)  # Move any retrieved files, if any, to ETC directory.
            "${gCLIdir}/odpctl/odpctl" ct_tracker \
                -d "${odpDir}/" ${ctTrk["${osID}"]}
            [ -f "{}/README.txt" ] || eval "
                cat - 0<<ReadMe-EOF 1> \"{}/README.txt\"
$(cat "${_scrPath}/odp-template/${osName}-README.txt")
ReadMe-EOF
            "
        ' \; -o \
        \( -exec false '{}' + -quit \) \
    \)
}

function FinPkgs() {
    ########
    # Finalize packages.
    #
    # Args:
    #   odpRoot:    See `OSP_ROOT` in `_useMsg`.
    ########
    typeset odpRoot="${1%%/}"; [ $# != 0 ] && shift; : "${odpRoot:=/}"

    # Copy `(BUILD|INSTALL).txt` from template in each package directory, if
    #   missing.
    find -L "${odpRoot}/" -mindepth 2 -type d ! -name 'ct-tracker-*' \( \
        -exec bash -exc "
            : Processing: '{}'
            _scrPath='${_scrPath}'"'
            files="BUILD INSTALL"
            for f in ${files}; do
                [ -e "{}/${f}.txt" ] ||
                    cp "${_scrPath}/odp-template/${f}.txt" "{}/"
            done
        ' \; -o \
        \( -exec false '{}' + -quit \) \
    \)
}

function Main() {
    typeset opts= iArg= sArg=
    while getopts 'hi:s:' opts; do
        case ${opts} in
          (h)
            echo "${_useMsg}"; return 0
            ;;
          (i)
            : Install required tools.
            case ${OPTARG} in
              (''|bin-*)
                [ -z "${OPTARG}" ] && iArg= || iArg="${OPTARG#bin-}"
                mkdir -p "${gCLIdir}"
                [ "${iArg}" = main ] && iArg=
                BRANCH="${iArg}" ODP_HOME="${gCLIdir}" bash -c "$(
                    curl -fsSL 'https://packages.vcfd.broadcom.net/odpcli-generic-local/install.sh'
                )"
                mkdir -p "${gCLIdir}/odpctl/bin"    # Workaround for missing directory when installing ODP CLI.
                rm -rf __odp
                ;;
              (git-*)
                iArg="${OPTARG#git-}"
                rm -rf "${gCLIdir}"; mkdir -p "${gCLIdir}"
                DEP_GIT_URL='git@gitlab.eng.vmware.com:core-build/odpclients.git' \
                    DEP_GIT_BRANCH="${iArg}" \
                    DEP_GIT_WORKTREE="${gCLIdir}/odpctl" \
                    DEP_GIT_SPARSE_CO_PATTERNS="/bin/ /etc/ /lib/ /odpctl.py" \
                    "${_scrPath}/../jenkins/dev/checkout-dependencies.sh"
                ln -s ./odpctl.py "${gCLIdir}/odpctl/odpctl"
                python -m venv __odp
                source __odp/bin/activate
                pip install -r "${gCLIdir}/odpctl/etc/build-requirements.txt"
                pip install -r "${gCLIdir}/odpctl/etc/requirements.txt"
                ;;
            esac
            ;;
          (s)
            : Skip phases.
            OPTARG="$(
                eval "
                    echo $(
                        echo "${OPTARG}" |
                        sed -E -e 's/([0-9]+)-([0-9]+)/{\1..\2}/g' -e 's/,/ /g'
                    )
                " | sed -E 's/ /,/g'
            )"
            sArg+="${sArg:+,}${OPTARG}"
            ;;
          (*)
            echo "${_useMsg}"; return 255
            ;;
        esac
    done
    shift $((OPTIND-1))

    typeset odpRoot="${1%%/}"; [ $# != 0 ] && shift; : "${topLvlTar:=/}"
    typeset osmPars="${1}|"; [ $# != 0 ] && shift

    typeset imgPath=
    typeset -i i=0 exitStat=0 phase=1 skipPhaseBM=0
    typeset -a osmArgs=()
    typeset -ai skipPhases=()

    typeset odpCfg="${gCLIdir}/odpctl/etc/config.txt"

    IFS=\| read -ra osmArgs <<< "${osmPars}"
    set -- "${osmArgs[@]}"
    typeset osmKey="${1}"; [ $# != 0 ] && shift
    typeset osmServer="${1:-production}"; [ $# != 0 ] && shift
    typeset osmRelInfo="${1}"; [ $# != 0 ] && shift
    unset osmPars osmArgs

    IFS=, read -ra skipPhases <<< "${sArg}"
    for i in "${skipPhases[@]}"; do
        ((i > 0)) && ((skipPhaseBM |= (1 << (i-1))))
    done

    case ${osmServer} in
      (''|production)
        osmServer='https://osm.eng.vmware.com/'
        ;;
      (beta)
        osmServer='https://osm-beta.eng.vmware.com/'
        ;;
    esac
    # Create temporary config file.
    exec 9<> credFile; rm -f credFile
    jq -r "
        .workspace = \"${odpRoot}\" |
        .osm_server = \"${osmServer}\" |
        .APIKey = \"${osmKey}\"
    " "${odpCfg}" 1>&9
    { cat /dev/stdin 1> "${odpCfg}"; } 0<&9
    exec 9<&- 9>&-

    [ -d __odp ] && source __odp/bin/activate

    # The `set -e` is ignored if the function call is part of conditional
    #   expression, such as `if FUNC; then ... fi` or `FUNC || ...`.
    set -ex
    while ((phase)); do
        case ${phase} in
          (1)
            : Phase ${phase} - Generate project skeleton.
            ((skipPhaseBM & (1 << (phase++ - 1)))) && continue
            GenSkel "${odpRoot}" "${osmRelInfo}"
            ;;
          (2)
            : Phase ${phase} - Generate BaseOS packages.
            ((skipPhaseBM & (1 << (phase++ - 1)))) && continue
            GenCtTrk "${odpRoot}" "${osmRelInfo}"
            ;;
          (3)
            : Phase ${phase} - Finalize packages.
            ((skipPhaseBM & (1 << (phase++ - 1)))) && continue
            FinPkgs "${odpRoot}" "${osmRelInfo}"
            ;;
          (*)
            phase=0
            ;;
        esac
    done
}


Main "$@"
