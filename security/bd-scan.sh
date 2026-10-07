#!/bin/bash
typeset _scrName="${BASH_SOURCE[0]##*/}"
typeset _scrPath="$(CDPATH= \command cd -L "${BASH_SOURCE[0]%/*}" 2> /dev/null;\command pwd)"
typeset _useMsg=; read -rd '' _useMsg 0<<'_useMsg-EOF'
BlackDuck Scan for SCA.

Usage:
  bd-scan.sh -h [-d]
  bd-scan.sh -d
  bd-scan.sh -a GRADLE_VER
  bd-scan.sh -s BD_URL API_TOKEN P_PRJ_NAME P_PRJ_VER PRJ_NAME PRJ_VER
    SCAN_TYPE SCAN_PAR SCAN_URL [CFG_FILE] [XTRA_PAR]

Where:
  -h        Display help.
    -d          Display Synopsis Detect help instead.
  -d        Only download Synopsis Detect tooling.
  -a        Create Synopsis Detect tooling for AirGap env.
    GRADLE_VER  Gradle Version to be used.
  -s        Initiate scan using Synopsis Detect tooling.
    BD_URL      BlackDuck Server URL.
    API_TOKEN   BlackDuck API Token.
    P_PRJ_NAME  BlackDuck Parent Project Name.
    P_PRJ_VER   BlackDuck Parent Project Version.
    PRJ_NAME    BlackDuck Project Name.
    PRJ_VER     BlackDuck Project Version.
    SCAN_TYPE   Scan Type. Supported value:
                  bin    -> Scan SCAN_URL as binary.
                  ctr    -> Scan SCAN_URL as container.
                  dkr    -> Scan SCAN_URL using Docker Inspector.
                  src    -> Scan SCAN_URL as Source Code.
    SCAN_PARS   [Conditional] Parameters (`|` delimited) specific to Scan Type.
                For Scan Type:
                  dkr:
                    Format:
                      IMG_INS_SHR_DIR
                    Where:
                      IMG_INS_SHR_DIR   Host dir. to be shared with Image
                                        Inspector Container
    SCAN_URL    URL of the artifact to be scanned. Supported scheme:
                  file:///full/path
                        Local file.
                  docker://[HOST[:PORT]]/[NAMESPACE]/REPOSITORY(:TAG|@DIGEST)
                        Container Image Registry location.
    CFG_FILE    [Optional] Config file (YAML) for extra parameters.
                NOTE:
                    Inside this file, you can include another config file via
                    spring boot configuration import mechanism (see
                    https://docs.spring.io/spring-boot/reference/features/
                    external-config.html).
                    Syntax:
                        spring.config.import: [optional:]PATH[\[EXT_HINT\]]
                    Ex:
                        spring.config.import: optional:${PWD}/includeThis[.yml]
                    Explanation:
                        The example above will try to include file
                        `${PWD}/includeThis`, if any, and hinting that the
                        content of the file is YAML.
                    IMPORTANT!!!
                        Please use absolute path only, hence the `${PWD}`, as
                        relative path will be from the parent file directory.
                        Since this file is included via `bash Process
                        Substitution`, hence the parent file directory will be
                        `/dev/fd`.
    XTRA_PAR    [Optional] Extra parameters for Synopsis Detect.
_useMsg-EOF

set -o pipefail
shopt -s extglob


typeset gCLIdir=__bin
typeset xCmd="$(((DRY_RUN)) && echo echo || echo eval)"


function SetToolPars() {
    typeset scanType="${1}"; [ $# != 0 ] && shift
    typeset cfgSection="${1}"; [ $# != 0 ] && shift
    typeset incTools="${1}"; [ $# != 0 ] && shift
    typeset excTools="${1}"; [ $# != 0 ] && shift

    typeset e=
    typeset -a toolsArr=() excArr=()

    IFS=, read -ra excArr 0<<<"${excTools}"
    grep -qE '\bALL,?\b' 0<<<"${incTools}" &&
        incTools=DETECTOR,SIGNATURE_SCAN,BINARY_SCAN,IMPACT_ANALYSIS,DOCKER,\
BAZEL,IAC_SCAN,CONTAINER_SCAN,THREAT_INTEL,COMPONENT_LOCATION_ANALYSIS
    for e in "${excArr[@]}"; do
        incTools="$(sed -E "s/\\b${e},?\\b//" 0<<<"${incTools}")"
    done
    IFS=, read -ra toolsArr 0<<<"${incTools}"

    case ${cfgSection} in
      (detect)
        for e in "${toolsArr[@]}"; do
          case ${e} in
            (BINARY_SCAN)
                cat - 0<<detTool-EOF
    binary.scan.file.path: ${bdScanTgtPath}
detTool-EOF
            ;;
            (CONTAINER_SCAN)
                cat - 0<<detTool-EOF
    container.scan.file.path: ${bdScanTgtPath}
detTool-EOF
            ;;
            (DETECTOR)
                cat - 0<<detTool-EOF
    detector.search:
        continue: true
        depth: 9999
detTool-EOF
            ;;
            (DOCKER)
                cat - 0<<detTool-EOF
    docker.$(
        case ${bdScanTgtSch} in
          (file)    echo tar;;
          (docker)  echo image;;
          (*)       echo "UNSUPPORTED_${bdScanTgtSch}";;
        esac
    ): ${bdScanTgtPath}
    docker.passthrough:
        logging.level.com.synopsys: DEBUG
        imageinspector.service.url: http://host.docker.internal:9002
        shared.dir.path.local: ${bdScanArgs[0]}
#       cleanup.inspector.container: false
#       cleanup.inspector.image: true
    docker.platform.top.layer.id: ${BD_CFG__DETECT_DOCKER_PLATFORM_TOP_LAYER_ID}
detTool-EOF
            ;;
            (SIGNATURE_SCAN)
                cat - 0<<detTool-EOF
    blackduck:
        signature.scanner:
            paths: $(
                grep -qvE '\bDOCKER,?\b' 0<<<"${incTools}" &&
                    echo "${bdScanTgtPath}"
            )
$(
    case ${scanType} in
      (src) cat - 0<<scanType-EOF
            copyright.search: true
            individual.file.matching: ALL
            license.search: true
            snippet.matching: SNIPPET_MATCHING
scanType-EOF
        ;;
    esac
)
detTool-EOF
            ;;
          esac
        done
        ;;
    esac


}
function RunBD() {
    typeset cOpts="${1}"; [ $# != 0 ] && shift

    typeset bdHelp= bdDLonly= bdAirGap=
    typeset -i cOptErr=0
    typeset -a bdScanArgs=()

    typeset bdOutPath=__bd

    case ${cOpts:0:1} in
      (h)
        case ${cOpts:1:1} in
          (d)   bdHelp=-h;;
          (*)   echo "${_useMsg}"; return 0;;
        esac
        ;;
      (d)   bdDLonly=1;;
      (a)
        typeset bdGradleVer="${1:-GRADLE_VER--NotSet}"; [ $# != 0 ] && shift
        bdAirGap="-z FULL --detect.output.path=${bdOutPath}"
        ;;
      (s)
        unset bdAirGap
        typeset bdHubURL="${1:-BD_URL--NotSet}"; [ $# != 0 ] && shift
        typeset bdAPItoken="${1:-API_TOKEN--NotSet}"; [ $# != 0 ] && shift
        typeset bdParPrjName="${1}"; [ $# != 0 ] && shift
        typeset bdParPrjVer="${1:-P_PRJ_VER--NotSet}"; [ $# != 0 ] && shift
        typeset bdPrjName="${1:-PRJ_NAME--NotSet}"; [ $# != 0 ] && shift
        typeset bdPrjVer="${1:-PRJ_VER--NotSet}"; [ $# != 0 ] && shift
        typeset bdScanType="${1}"; [ $# != 0 ] && shift
        typeset bdScanPars="${1}"; [ $# != 0 ] && shift
        typeset bdScanURL="${1:-URL--NotSet}"; [ $# != 0 ] && shift
        typeset bdCfgFile="${1}"; [ $# != 0 ] && shift
        typeset bdXtraPar="${1}"; [ $# != 0 ] && shift

        typeset bdScanTgtSch= bdScanTgtPath=

        [ "${bdParPrjName}" = "${bdPrjName}" ] && {
            bdParPrjName= bdParPrjVer=
        }

        eval "$(
            source "${_scrPath}/sh_libs/utils.sh"
            ParseURI "${bdScanURL}" bdScanTgtSch,,,bdScanTgtPath
        )"
        case ${bdScanTgtSch} in
          (!(file|docker))  cOptErr=1;;
        esac
        [ -z "${bdScanTgtPath}" ] && cOptErr=1
        IFS=\| read -ra bdScanArgs 0<<<"${bdScanPars}"
        ;;
    esac
    [ $# != 0 ] && cOptErr=1

    ((cOptErr)) && echo "${_useMsg}" && return 255

    # The `set -e` is ignored if the function call is part of conditional
    #   expression, such as `if FUNC; then ... fi` or `FUNC || ...`.
    set -ex

    ((DRY_RUN)) || mkdir -p "${gCLIdir}"

    [ -n "${bdAirGap}" ] && {
        wget -O gradle.zip "https://services.gradle.org/distributions/gradle-${bdGradleVer}-bin.zip"
        unzip -od __bin/ gradle.zip && rm gradle.zip
        PATH="__bin/gradle-${bdGradleVer}/bin:${PATH}"
    } ;

    ${xCmd} "
        JAVA_HOME="${JAVA_HOME:-JAVA_HOME--NotSet}" \
            BD_CFG__BLACKDUCK_API_TOKEN="${bdAPItoken}"
            DETECT_JAR_DOWNLOAD_DIR=__bin/synopsys-detect \
            ${bdDLonly:+DETECT_DOWNLOAD_ONLY=1} \
            bash <(curl -fsSL 'https://detect.synopsys.com/detect9.sh') \
            ${bdHelp:-${bdAirGap---spring.config.import=file:<(
                cat - 0<<cfg-EOF
blackduck:
    url: ${bdHubURL}
    api.token: \${BD_CFG__BLACKDUCK_API_TOKEN}
    trust.cert: true
detect:
    output.path: ${bdOutPath}
    project.name: ${bdPrjName}
    project.version.name: ${bdPrjVer}
    project.codelocation.prefix: ${BD_CFG__DETECT_PROJECT_CODELOCATION_PREFIX}
    clone.project.version.name: ${BD_CFG__DETECT_CLONE_PROJECT_VERSION_NAME}
$(
    [ -n "${bdParPrjName}" ] && cat - 0<<pPrj-EOF
    parent.project.name: ${bdParPrjName}
    parent.project.version.name: ${bdParPrjVer}
pPrj-EOF
)
    source.path: ${bdScanTgtPath}
#   cleanup: false
logging:
    # Logging level effect ALL :inspector:s.
#   level.detect: DEBUG                     # Only print failed :inspector:s logging to stdout at the end of :inspector: execution.
    level.com.synopsys.integration: DEBUG   # Print :inspector:s logging to stdout live.
cfg-EOF
            )'[.yml]' \
            --spring.config.import=file:<(
                cat - 0<<cfg-EOF
$(
    if [ -z "${bdScanType}" ]; then
        cat - 0<<scanType-EOF
detect:
    tools.excluded: DETECTOR, SIGNATURE_SCAN, BINARY_SCAN, IMPACT_ANALYSIS, DOCKER, BAZEL, IAC_SCAN, CONTAINER_SCAN, THREAT_INTEL, COMPONENT_LOCATION_ANALYSIS
    excluded.directories: /
scanType-EOF
        elif [ "${bdScanType}" == bin ]; then
            cat - 0<<scanType-EOF
detect:
    tools: ${BD_CFG__DETECT_TOOLS__BIN:=BINARY_SCAN}
$(
    [ -n "${BD_CFG__DETECT_TOOLS_EXCLUDED__BIN}" ] &&
        echo "    tools.excluded: ${BD_CFG__DETECT_TOOLS_EXCLUDED__BIN}"
    SetToolPars "${bdScanType}" detect "${BD_CFG__DETECT_TOOLS__BIN}" \
        "${BD_CFG__DETECT_TOOLS_EXCLUDED__BIN}"
)
scanType-EOF
    elif [ "${bdScanType}" == ctr ]; then
        cat - 0<<scanType-EOF
detect:
    tools: ${BD_CFG__DETECT_TOOLS__CTR:=CONTAINER_SCAN}
$(
    [ -n "${BD_CFG__DETECT_TOOLS_EXCLUDED__CTR}" ] &&
        echo "    tools.excluded: ${BD_CFG__DETECT_TOOLS_EXCLUDED__CTR}"
    SetToolPars "${bdScanType}" detect "${BD_CFG__DETECT_TOOLS__CTR}" \
        "${BD_CFG__DETECT_TOOLS_EXCLUDED__CTR}"
)
scanType-EOF
    elif [ "${bdScanType}" == dkr ]; then
        cat - 0<<scanType-EOF
detect:
    tools: ${BD_CFG__DETECT_TOOLS__DKR:=DOCKER,SIGNATURE_SCAN}
$(
    [ -n "${BD_CFG__DETECT_TOOLS_EXCLUDED__DKR}" ] &&
        echo "    tools.excluded: ${BD_CFG__DETECT_TOOLS_EXCLUDED__DKR}"
    SetToolPars "${bdScanType}" detect "${BD_CFG__DETECT_TOOLS__DKR}" \
        "${BD_CFG__DETECT_TOOLS_EXCLUDED__DKR}"
)
scanType-EOF
    elif [ "${bdScanType}" == src ]; then
        cat - 0<<scanType-EOF
detect:
    tools: ${BD_CFG__DETECT_TOOLS__SRC:=SIGNATURE_SCAN,DETECTOR}
    accuracy.required: NONE
$(
    [ -n "${BD_CFG__DETECT_TOOLS_EXCLUDED__SRC}" ] &&
        echo "    tools.excluded: ${BD_CFG__DETECT_TOOLS_EXCLUDED__SRC}"
    SetToolPars "${bdScanType}" detect "${BD_CFG__DETECT_TOOLS__SRC}" \
        "${BD_CFG__DETECT_TOOLS_EXCLUDED__SRC}"
)
scanType-EOF
    fi
)
cfg-EOF
            )'[.yml]' \
            --spring.config.import=file:<(
                eval "
                    cat - 0<<cfg-EOF
$([ -n "${bdCfgFile}" ] && cat - 0< "${bdCfgFile}")
cfg-EOF
                "
            )'[.yml]' ${bdXtraPar}}}
    " || {
        typeset -i eCode=$?
        if [ "${bdScanType}" == dkr ]; then
            typeset bdImgInsCtrID=
            for bdImgInsCtrID in $(
                docker container ls -a \
                    --filter name='^blackduck-imageinspector-' \
                    --format '{{.ID}}'
              ); do
                docker container stop "${bdImgInsCtrID}"
                docker container rm -v "${bdImgInsCtrID}"
            done
        fi
        return ${eCode}
    }
}

function Main() {
    typeset opt= cOpts=
    while getopts 'hdas' opt; do
        case ${opt} in
          (h)
            [ -n "${cOpts}" ] && cOpts= && break
            cOpts="${opt}"
            ;;
          (d)
            case ${cOpts} in
              ('')  cOpts="${opt}";;
              (h)   cOpts+="${opt}";;
              (*)   cOpts= && break;;
            esac
            ;;
          (a)
            [ -n "${cOpts}" ] && cOpts= && break
            cOpts="${opt}"
            ;;
          (s)
            [ -n "${cOpts}" ] && cOpts= && break
            cOpts="${opt}"
            ;;
          (*)
            cOpts= && break
            ;;
        esac
    done
    [ -z "${cOpts}" ] && echo "${_useMsg}" && return 255
    shift $((OPTIND-1))

    RunBD "${cOpts}" "$@"
}

Main "$@"
