#!/bin/bash
typeset _scrName="${BASH_SOURCE[0]##*/}"
typeset _scrPath="$(CDPATH= \command cd -L "${BASH_SOURCE[0]%/*}" 2> /dev/null;\command pwd)"
set -ex
set -o pipefail
shopt -s extglob

# Core SCA Automation Script.
#
# Prepare all required parameters by `bd-scan.sh`, depending on the scanned
# artifact situation.

typeset -i skipParts="${1:-0}"; [ $# != 0 ] && shift
# Bitmap `skipParts`:
#   0x0001: Prepare fresh workspace.
#   0x0002: Force re-download Synopsis Detect tooling.
#   0x0004: Install dependencies.

typeset bdDir=__bd cliDir=__bin imgDir=__img wrkDir=__wrk
typeset urlSch= urlNetPath=
typeset -i i=0 skipAll=0x07 fnAdd=60

typeset eProduct="${PRODUCT}" eSubProduct="${SUB_PRODUCT}"
typeset eRelease="${RELEASE}" eArtifactBuildID="${ARTIFACT_BUILD_ID}" eExtraQpars="${EXTRA_Q_PARS:-()}"
typeset -i dryRun="${DRY_RUN:-0}"
typeset -i maxScanTry="${MAX_SCAN_TRY:-0}" nextAttempWaitTime="${NEXT_ATTEMPT_WAIT_TIME:-60}"
typeset xCmd="$(((dryRun)) && echo echo || echo eval)"

typeset AUTH="${AUTH}"
export PRD_CFG_INF="${PRD_CFG_INF}"
# The `PRD_CFG_INF` is file path that contain Product Configuration (YAML):
#   mapping:
#       # Mapping to BlackDuck Hub Project Name and Version.
#       products:
#           <prdName>[--<subPrdName>]:
#               bdPrjName:      <bdTopPrjName>
#               bdPrjVerConv:   <bdTopPrjVerConv>
#               bdMainVerSch:   <bdTopMainVerSch>
#               bdRelVerSch:    <bdTopRelVerSch>
#               bdRelVerConv:   <bdTopRelVerConv>
#               execEnvVar:
#                   <envVarName>:   <envVarVal>
#                    ...
#            ...
#       services:
#           <svcName>:
#               bdPrjName:      <bdSubPrjName>
#               bdPrjVerConv:   <bdSubPrjVerConv>
#               bdMainVerSch:   <bdSubMainVerSch>
#               bdRelVerSch:    <bdSubRelVerSch>
#               bdRelVerConv:   <bdSubRelVerConv>
#               execEnvVar:
#                   <envVarName>:   <envVarVal>
#                    ...
#            ...
#       containerImages:
#           <ctrName>:
#               bdPrjName:      <bdSubPrjName>
#               bdPrjVerConv:   <bdSubPrjVerConv>
#               bdMainVerSch:   <bdSubMainVerSch>
#               bdRelVerSch:    <bdSubRelVerSch>
#               bdRelVerConv:   <bdSubRelVerConv>
#               execEnvVar:
#                   <envVarName>:   <envVarVal>
#                    ...
#            ...
#       applications:
#           <appName>:
#               bdPrjName:      <bdSubPrjName>
#               bdPrjVerConv:   <bdSubPrjVerConv>
#               bdMainVerSch:   <bdSubMainVerSch>
#               bdRelVerSch:    <bdSubRelVerSch>
#               bdRelVerConv:   <bdSubRelVerConv>
#               bdScan:
#                   scanner:    <bdScanType>
#                   scnrPar:    <bdScanTypePar>
#               execEnvVar:
#                   <envVarName>:   <envVarVal>
#                    ...
#            ...
#       sourceCodes:
#           <appName>:
#               bdPrjName:      <bdSubPrjName>
#               bdPrjVerConv:   <bdSubPrjVerConv>
#               bdMainVerSch:   <bdSubMainVerSch>
#               bdRelVerSch:    <bdSubRelVerSch>
#               bdRelVerConv:   <bdSubRelVerConv>
#               execEnvVar:
#                   <envVarName>:   <envVarVal>
#                    ...
#            ...
#       # .mapping.{products|containerImages|applications|sourceCodes}.bdPrjName     := {
#       #   null | <bdTopPrjName!!str> | <bdSubPrjName!!str>
#       # }    -> null   :  Use original name.
#       #         ''     :  Set as empty string.
#       #                       For many cases, it means skipping the scan.
#       #                       For `sourceCodes`, empty string means there will
#       #                           not be linked to a BD Hub Parent Project,
#       #                           instead the `products` information will be
#       #                           used as BDHub Project.
#       # .mapping.services.bdPrjName  := {
#       #   null | <bdTopPrjName!!str> | <bdSubPrjName!!str> |
#       #   <containerImages!!map>
#       # }    -> null               :  Use original name.
#       #         ''                 :  Skip the scan.
#       #         containerImages    :  Mapping based on the Container Images
#       #                               inside it.
#       # .mapping.{products|sevices|containerImages|applications|sourceCodes}.bdPrjVerConv  := <prjVerConvScript>
#       #   Project Version converter script.
#       #   The script will be executed as:
#       #     eval "echo '<ver>' | (${verConv})"
#       #   Examples:
#       #     # Forcing the Project Version to `latest`.
#       #     sed -E 's/^.*/latest/'
#       #     # Adding prefix to Project Version.
#       #     sed -E 's/^(.*)/pfx--\1/'
#       # .mapping.{products|sevices|containerImages|applications|sourceCodes}.bdMainVerSch  := <mainVerScheme>
#       #   RegEx pattern to match the mainline version of the product.
#       #   See `main_ver_rgx` from `bd_util.py get-latest-version -h` for
#       #   detail.
#       #   At the `product` level, it will be used to match the Parent Project
#       #   Version. The rest, if will be used to match the Sub Project Version.
#       #   For Sub Project that comes from a different Product, the key should
#       #   be defined, as different Product may have different versioning
#       #   scheme.
#       #   For Sub Project specific to own Product, the key is best undefined,
#       #   so the value from `product` level will be used.
#       # .mapping.{products|sevices|containerImages|applications|sourceCodes}.bdRelVerSch   := <relVerScheme>
#       #   RegEx pattern to match the mainline version of the product.
#       #   See `relVerRgx` on `--rel-ver-info` from
#       #   `bd_util.py get-latest-version -h` for detail.
#       #   For `product` and other level, it follows the same concept like
#       #   `bdMainVerSch` key.
#       # .mapping.{products|sevices|containerImages|applications|sourceCodes}.bdRelVerConv  := <relVerConvScript>
#       #   Bash script to convert Project Version Name to Release Version to
#       #   be used as `relVerVal`. See `--rel-ver-info` from
#       #   `bd_util.py get-latest-version -h` for detail.
#       #   The script will be executed as:
#       #     bash bash -o pipefail -exc '<relVerConvScript>' '' '<prjVerName>'
#       # .mapping.applications.bdScan.scanner
#       #   Scanner Type to be used, instead of using what is set in env. var.
#       #   `SCANNER`. Set to `null` to keep the inherited value from env. var.
#       #   `SCANNER`. See `security/bd-scan.sh -h` for detail.
#       # .mapping.applications.bdScan.scnrPar
#       #   Parameter to the used Scanner Type to be used, instead of using what
#       #   is set in env. var. `SCNR_PAR`. Set to `null` to keep the inherited
#       #   value from env. var. `SCNR_PAR`. See `security/bd-scan.sh -h` for
#       #   detail.
#       # .mapping.{products|sevices|containerImages|applications|sourceCodes}.execEnvVar
#       #   Execution Env. Var. to be defined. Will be defined via:
#       #     eval "<envVarName>=<envVarVal>"
#       #   Examples:
#       #     # Adding Detect Tools for `dkr` scan.
#       #     BD_CFG__DETECT_TOOLS__DKR:    BINARY_SCAN,DOCKER,SIGNATURE_SCAN
#       #     # Adding extra parameter to Synopsis `detect`.
#       #     OPT_XTRA_PAR: "\"--detect.tools.excluded=SIGNATURE_SCAN ${OPT_XTRA_PAR}\""
#       #     # Use extra configuration file for Synopsis `detect`.
#       #     OPT_CFG_FILE: ./__conf/prdCfg.yml
#       #       # Content of `./__conf/prdCfg.yml`:
#       #       #  |detect.npm.dependency.types.excluded:   DEV,PEER
#       #       #  |spring.config.import:                   optional:${PWD}/overridePrdCfg.yml  # MUST use Abs. Path.
#       ########################################################################
#       # Mapping to Product and Sub-Product.
#       includedManifests:
#           <manName>: <prdName> | <prdCfg> [| <subPrd>]
#       # prdName    :  Name of the product the manifest represent.
#       # prdCfg     :  Path to product's config file.
#       # subPrd     :  Name of the sub-product the manifest represent.
#       name:
#           product: |
#               <bashScriptConvertingPrdName>
#           service: |
#               <bashScriptConvertingSvcName>
#           containerImage: |
#               <bashScriptConvertingCtrName>
#           application: |
#               <bashScriptConvertingAppName>
#           manifest: |
#               <bashScriptConvertingManName>
#       # The script will be executed as:
#       #   bash bash -o pipefail -exc '<bashScriptConverting...Name>' \
#       #   '' '<originalName>'
#       # Examples:
#       #   # Given `/path/to/<name>_<debianVer>.tar`, want name without version.
#       #   sed -E 's/_v?[0-9][[:alnum:].:~+-]+\.tar$//' 0<<<"${1##*/}"
export PRJ_MAP_PATH="${PRJ_MAP_PATH}"
export PRD_NAME="${PRD_NAME}" PRD_VER="${PRD_VER}"
export SVC_NAME="${SVC_NAME}" SVC_VER="${SVC_VER}"
export SCANNER="${SCANNER}" SCNR_PAR="${SCNR_PAR}"
export BDHUB_URL="${BDHUB_URL:-BDHUB_URL--NotSet}"
export BDHUB_API_TOKEN="${BDHUB_API_TOKEN:-BDHUB_API_TOKEN--NotSet}"
export OPT_CFG_FILE="${OPT_CFG_FILE}" OPT_XTRA_PAR="${OPT_XTRA_PAR}"

((dryRun)) && skipParts=0x03
[ -n "${ARTIFACT_URL}" ] && eval "$(
    source "${_scrPath}/sh_libs/utils.sh"
    ParseURI "${ARTIFACT_URL}" urlSch,,,urlNetPath
)"

# Prepare fresh workspace.
((skipParts & 0x01)) || rm -rf "${bdDir}/" "${imgDir}/" "${wrkDir}/"

# Force re-download Synopsis Detect tooling.
((skipParts & 0x02)) || rm -rf "${cliDir}/"

# Install dependencies.
((skipParts & 0x04)) || pip3 install --user -r "${_scrPath}/requirements.txt"


function ReadCfg() {
    set -e  # Got turned off if called inside `"$(...)"`.

    typeset cfgFile="${1}"; [ $# != 0 ] && shift
    typeset cfgPath="${1}"; [ $# != 0 ] && shift
    typeset keyVarArrStr="${1}"; [ $# != 0 ] && shift

    typeset e= key= varName= varVal= mapType= retVal=
    typeset -i keyExist=0
    typeset -a keyVarArr=()

    [ -n "${cfgFile}" ] && {
        eval "keyVarArr=${keyVarArrStr}"
        for e in "${keyVarArr[@]}"; do
            key="${e%:*}"
            varName="${e##*:}"
            mapType="$(
                yq eval "explode(.) | ${cfgPath}.${key} | tag" "${cfgFile}"
            )"
            keyExist=0
            case ${mapType} in
              (!('!!null'))
                keyExist=1
                read -rd '' varVal 0<<<"$(
                    yq eval "explode(.) | ${cfgPath}.${key}" "${cfgFile}"
                )" || true
                ;;
            esac
            ((keyExist)) && retVal+="$(
                typeset -p varVal |
                    sed -E '
                        s/^((\S+ ){2})[^=]+(.*)/\1'"${varName}"'\3/
                    '
            )"$'\n'
        done
    }

    echo "${retVal}"
}

function GetMappingInfo() {
    typeset mapFile="${1}"; [ $# != 0 ] && shift
    typeset mapPath="${1}"; [ $# != 0 ] && shift
    typeset mapKey="${1}"; [ $# != 0 ] && shift
    typeset tgtVars="${1}"; [ $# != 0 ] && shift
    typeset valSep="${1}"; [ $# != 0 ] && shift

    typeset -i i=0 eCode=0
    typeset -a varArr=() valArr=()

    typeset mapType="$(
        yq eval "explode(.) | ${mapPath}.${mapKey} | tag " "${mapFile}"
    )"

    case ${mapType} in
      ('!!null')    eCode=255;;
      ('!!str')
        IFS="${valSep}" read -ra valArr 0<<<"$(
            yq eval "explode(.) | ${mapPath}.${mapKey}" "${mapFile}"
        )"
        read -ra varArr 0<<<"${tgtVars}"
        for i in ${!varArr[@]}; do
            typeset ${varArr[${i}]}="${valArr[${i}]%%+([[:space:]])}"
            eval "${varArr[${i}]}=\"\${${varArr[${i}]}##+([[:space:]])}\""
        done
        echo "$(typeset -p ${varArr[@]})"
        ;;
      ('!!map') eCode=254;;
    esac

    return ${eCode}
}

function GetMappedName() {
    set -e  # Got turned off if called inside `"$(...)"`.

    typeset mapFile="${1}"; [ $# != 0 ] && shift
    typeset mapPath="${1}"; [ $# != 0 ] && shift
    typeset srcName="${1}"; [ $# != 0 ] && shift

    typeset tgtName=

    [ -n "${mapFile}" ] && { tgtName="$(
        bash -o pipefail -exc "$(   # Get name convertion script.
            yq eval "explode(.) | ${mapPath} | select(. != null)" "${mapFile}"
        )" '' "${srcName}"  # Supply the original name as `${1}`.
    )" || false; }

    [ -z "${tgtName}" ] && echo "${srcName}" || echo "${tgtName}"
}

function ResolvePrjNameVer() {
    typeset mapFile="${1}"; [ $# != 0 ] && shift

    typeset e= retVal=
    typeset newName= verConv=
    typeset -i eCode1=0 eCode2=0
    typeset -a extVarNamePfx=(mapPath name ver)

    for e in "${extVarNamePfx[@]}"; do
        eval "
            typeset ${e}Var=\"\${1}\"; [ \$# != 0 ] && shift
            typeset ${e}Val=\"\$(eval 'echo \"\${'\"\${${e}Var}\"'}\"')\"
        "
    done

    [ -n "${mapFile}" ] && {
        eval "$(
            GetMappingInfo "${mapFile}" \
                "${mapPathVal}.${nameVal}" bdPrjName \
                newName || echo "(exit $?)"
        )" || eCode1=$?
        case ${eCode1} in
          (0|254|255)
            { ((eCode1)) || [ -n "${newName}" ]; } && {
                eval "$(
                    GetMappingInfo "${mapFile}" \
                        "${mapPathVal}.${nameVal}" bdPrjVerConv \
                        verConv || echo "(exit $?)"
                )" || eCode2=$?
                case ${eCode2} in
                  (0)
                    [ -n "${verConv}" ] && {
                        verVal="$(eval "echo '${verVal}' | (${verConv})")" ||
                            return 1
                    }
                    ;;
                  (!(255))  echo "exit ${eCode2}"; return;;
                esac
            }
            ;;&
          (0)
            mapPathVal=
            [ -z "${newName}" ] && nameVal= || nameVal="${newName}"
            ;;
          (254) mapPathVal+=".${nameVal}.bdPrjName" nameVal=;;
          (255) mapPathVal=;;
          (*)   echo "exit ${eCode1}"; return;;
        esac
    }

    for e in "${extVarNamePfx[@]}"; do
        retVal+="$(
            typeset -p ${e}Val |
                sed -E '
                    s/^((\S+ ){2})[^=]+(.*)/\1'"$(
                        eval "echo \"\${${e}Var}\""
                    )"'\3/
                '
        )"$'\n'
    done
    echo "${retVal}"
}

function SetExecEnv() {
    set -e  # Got turned off if called inside `"$(...)"`.

    typeset mapFile="${1}"; [ $# != 0 ] && shift
    typeset mapPath="${1}"; [ $# != 0 ] && shift

    typeset retVal=

    [ -n "${mapFile}" ] && retVal="$(
        yq eval "
            explode(.) | ${mapPath}.execEnvVar | select(. != null) | .[] |
            key + \"=\" + .
        " "${mapFile}"
    )"

    echo "${retVal}"
}

function GetNameVerFromOCIurl() {
    set -e  # Got turned off if called inside `"$(...)"`.

    typeset ociURL="${1}"; [ $# != 0 ] && shift
    typeset ociName="${1}"; [ $# != 0 ] && shift
    typeset nameVar="${1}"; [ $# != 0 ] && shift
    typeset verVar="${1}"; [ $# != 0 ] && shift

    typeset nameVal= verVal=

    if [[ "${ociURL}" =~ '@sha256:' ]]; then
        nameVal="${ociURL%@sha256:*}"
        if [[ "${ociName}" =~ ':' ]]; then
            verVal="${ociName##*:}"
        else
            verVal="${ociURL##*@sha256:}"
        fi
    else
        nameVal="${ociURL%:*}"
        verVal="${ociURL##*:}"
    fi

    echo "${nameVar}='${nameVal}' ${verVar}='${verVal}'"
}

function BDprjVerNeedDel() {
    set -e  # Got turned off if called inside `"$(...)"`.

    typeset prjName="${1}"; [ $# != 0 ] && shift
    typeset prjVerName="${1}"; [ $# != 0 ] && shift
    typeset topPrjName="${1}"; [ $# != 0 ] && shift
    typeset mainVerSch="${1}"; [ $# != 0 ] && shift
    typeset relVerSch="${1}"; [ $# != 0 ] && shift
    typeset relVerConv="${1}"; [ $# != 0 ] && shift

    typeset relVerVal= retVal=

    relVerVal="$(bash -o pipefail -exc "${relVerConv}" '' "${prjVerName}")"
    retVal="$(
        ${_scrPath}/bd_util.py \
            ${BDHUB_LOG_LEVEL:+--log-level "${BDHUB_LOG_LEVEL}"} \
            project can-version-be-deleted \
            --keep-days 0 --del-non-match \
            ${relVerVal:+--rel-ver-info "${relVerVal}|${relVerSch}"} \
            "${mainVerSch}" "${prjName}" "${prjVerName}" "${topPrjName}"
    )"

    echo "${retVal}"
}

function BDprjVerCreate() {
    typeset prjName="${1}"; [ $# != 0 ] && shift
    typeset prjVerName="${1}"; [ $# != 0 ] && shift
    typeset cloneSrcName="${1}"; [ $# != 0 ] && shift

    typeset cloneSrcURL=

    [ -n "${cloneSrcName}" ] && {
        cloneSrcURL="$(
            ${_scrPath}/bd_api.py \
                ${BDHUB_LOG_LEVEL:+--log-level "${BDHUB_LOG_LEVEL}"} \
                project get-version-url \
                "${prjName}" "${cloneSrcName}"
        )"
        [ -z "${cloneSrcURL}" ] && return 1
    }

    [ -z "$(
        ${_scrPath}/bd_api.py \
            ${BDHUB_LOG_LEVEL:+--log-level "${BDHUB_LOG_LEVEL}"} \
            project create-version \
            ${cloneSrcName:+--clone-url "${cloneSrcURL}"} \
            "${prjName}" "${prjVerName}"
    )" ] && return 1

    return 0
}

function BDprjVerDelete() {
    typeset prjName="${1}"; [ $# != 0 ] && shift
    typeset prjVerName="${1}"; [ $# != 0 ] && shift

    (($(
        ${_scrPath}/bd_api.py \
            ${BDHUB_LOG_LEVEL:+--log-level "${BDHUB_LOG_LEVEL}"} \
            project delete-version \
            "${prjName}" "${prjVerName}"
    ))) || true # BlackDuck is actively update the CVE Records. It is posible
                #   the Project Version being deleted is being updated at the
                #   same time, hence the Delete Request will be rejected with
                #   HTTP 412 with `errorMessage` is set to `Cannot delete
                #   project version because it is in use`.

    return 0
}

function BDprjVerExist() {
    typeset prjName="${1}"; [ $# != 0 ] && shift
    typeset prjVerName="${1}"; [ $# != 0 ] && shift

    [ -z "$(
        ${_scrPath}/bd_api.py \
            ${BDHUB_LOG_LEVEL:+--log-level "${BDHUB_LOG_LEVEL}"} \
            project get-version-url \
            "${prjName}" "${prjVerName}"
    )" ] && return 1

    return 0
}

function BDgetLatestPrjVer() {
    set -e  # Got turned off if called inside `"$(...)"`.

    typeset prjName="${1}"; [ $# != 0 ] && shift
    typeset prjVerName="${1}"; [ $# != 0 ] && shift
    typeset mainVerSch="${1}"; [ $# != 0 ] && shift
    typeset relVerSch="${1}"; [ $# != 0 ] && shift
    typeset relVerConv="${1}"; [ $# != 0 ] && shift

    typeset relVerVal= retVal=

    relVerVal="$(bash -o pipefail -exc "${relVerConv}" '' "${prjVerName}")"
    retVal="$(
        ${_scrPath}/bd_util.py \
            ${BDHUB_LOG_LEVEL:+--log-level "${BDHUB_LOG_LEVEL}"} \
            project get-latest-version \
            ${relVerVal:+--rel-ver-info "${relVerVal}|${relVerSch}"} \
            "${mainVerSch}" "${prjName}"
    )"

    echo "${retVal}"
}

function BDcleanUpPrjVer() {
    typeset prjName="${1}"; [ $# != 0 ] && shift
    typeset prjVerName="${1}"; [ $# != 0 ] && shift
    typeset mainVerSch="${1}"; [ $# != 0 ] && shift
    typeset relVerSch="${1}"; [ $# != 0 ] && shift
    typeset relVerConv="${1}"; [ $# != 0 ] && shift
    typeset topPrjName="${1}"; [ $# != 0 ] && shift
    typeset topMainVerSch="${1}"; [ $# != 0 ] && shift
    typeset topRelVerSch="${1}"; [ $# != 0 ] && shift
    typeset topRelVerConv="${1}"; [ $# != 0 ] && shift

    [ -z "${prjVerName}" ] || {
        # Check if the version is the latest in own Project.
        prjVerName="$(
            BDprjVerNeedDel "${prjName}" "${prjVerName}" '' \
                "${mainVerSch}" \
                "${relVerSch}" \
                "${relVerConv}"
        )"
        [ -z "${prjVerName}" ] || [ -z "${topPrjName}" ] || {
            # Check if the version is not used by other Project that warrant
            #   locking of the version.
            prjVerName="$(
                BDprjVerNeedDel "${prjName}" "${prjVerName}" \
                    "${topPrjName}" \
                    "${topMainVerSch}" \
                    "${topRelVerSch}" \
                    "${topRelVerConv}"
            )"
            [ -z "${prjVerName}" ] || {
                ${xCmd} "
                    BDprjVerDelete '${prjName}' '${prjVerName}'
                "
            }
        }
    }
}


mkdir -p "${bdDir}" "${imgDir}" "${wrkDir}"
case ${ARTIFACT_TYPE:-lclFile} in
  (lclFile)
    : Scanning local file - "${SCANNER}": "${ARTIFACT_URL:=ARTIFACT_URL--NotSet}"
    SVC_NAME="${SVC_NAME:-SVC_NAME--NotSet}"
    SVC_VER="${SVC_VER:-SVC_VER--NotSet}"

    case ${urlSch} in
      (!(file))
        echo "Error - Unsupported scheme: ${urlSch}" 1>&2
        false
        ;;
    esac

    i=0
    while ((maxScanTry && (i++ < maxScanTry) || (! i++))); do
        ((i > 1)) && sleep ${nextAttempWaitTime}
        ((maxScanTry)) && echo "Try no. ${i}."
        ${xCmd} "
$(
    typeset -x | grep -E 'BD_CFG__[^=[:space:]]+=' |
        sed -E 's/^((\S+ ){2})//' | tr '\n' ' '
)   '${_scrPath}/bd-scan.sh' -s '${BDHUB_URL}' \"\${BDHUB_API_TOKEN}\" \
    '${PRD_NAME}' '${PRD_VER}' '${SVC_NAME}' '${SVC_VER}' \
    '${SCANNER}' '${SCNR_PAR}' 'file://${urlNetPath}' \
    '${OPT_CFG_FILE}' '${OPT_XTRA_PAR}'
        " && break
    done
    ((i < (maxScanTry + 2)))  # Fail if max. attempts is reached.
    ;;
  (rmtFile)
    : Scanning remote file - "${SCANNER}": "${ARTIFACT_URL:=ARTIFACT_URL--NotSet}"
    typeset fileType=lclFile
    typeset -i eCode=0

    typeset fileLcl="${urlNetPath////#}"; fileLcl="$(
        source "${_scrPath}/sh_libs/utils.sh"
        TruncFN "${imgDir}/${fileLcl//:/=}" ${fnAdd}
    )"

    ((! dryRun)) && [ -f "${fileLcl}_" ] && exit
    [ -f "${fileLcl}" ] || {
        rm -f "${wrkDir}/f"
        case ${urlSch} in
          (http?(s))
            i=0
            while ((maxScanTry && (i++ < maxScanTry) || (! i++))); do
                ((i > 1)) && sleep ${nextAttempWaitTime}
                ((maxScanTry)) && echo "Try no. ${i}."
                ${xCmd} "
wget \
    ${AUTH:+--user \"\${AUTH%%:*\}\" --password \"\${AUTH#*:\}\"} \
    -O '${wrkDir}/f' '${ARTIFACT_URL}'
                " && break
            done
            ((i < (maxScanTry + 2)))  # Fail if max. attempts is reached.
            ((dryRun)) || [ ! -f "${wrkDir}/f" ] ||
                mv -f "${wrkDir}/f" "${fileLcl}"
            ;;
          (*)
            echo "Error - Unsupported scheme: ${urlSch}" 1>&2
            false
            ;;
        esac
    }
    case ${SCANNER} in (dkr) fileType=ctrImg;; esac
    ${xCmd} "
AUTH=\"\${AUTH}\" $(
    typeset -x | grep -E 'BD_CFG__[^=[:space:]]+=' |
        sed -E 's/^((\S+ ){2})//' | tr '\n' ' '
)   ARTIFACT_TYPE="${fileType}" ARTIFACT_URL='${fileLcl}' \
    PRD_CFG_INF='${PRD_CFG_INF}' PRJ_MAP_PATH= \
    PRD_NAME='${PRD_NAME}' PRD_VER='${PRD_VER}' \
    SVC_NAME='${SVC_NAME}' SVC_VER='${SVC_VER}' \
    SCANNER='${SCANNER}' SCNR_PAR='${SCNR_PAR}' \
    BDHUB_URL='${BDHUB_URL}' BDHUB_API_TOKEN=\"\${BDHUB_API_TOKEN}\" \
    OPT_CFG_FILE='${OPT_CFG_FILE}' OPT_XTRA_PAR='${OPT_XTRA_PAR}' \
    '${_scrPath}/${_scrName}' '$((skipParts | skipAll))' \
    $(
        case ${fileType} in
          (ctrImg)
            sed -E 's/\.t(ar\.)?gz$//' 0<<<"${fileLcl##*/}"
            ;;
        esac
    )
    " || eCode=$?
    ((eCode)) || ((dryRun)) || mv -f "${fileLcl}" "${fileLcl}_"
    ((! eCode))
    ;;
  (pkg:s)
    : Scanning Packages - "${SCANNER}".
    typeset pkgList="${1}"; [ $# != 0 ] && shift
    # List (newline-delimited) `pkgList`:
    #   pkgName|pkgURL
    #     Where:
    #       pkgName:    Name of `pkg` in form of `NAME`.
    #       pkgURL:     URL of `pkg` in form of `SCHEME://HOST[:PORT]/PATH`.
    #                   Special form for `tar`:
    #                     tar://HOST[:PORT]/PATH?QUERY
    #                       QUERY:  SCHEME=PATH[&...]
    #                         SCHEME:   Next level archive scheme.
    #                         PATH:     Path inside prev. level archive.
    #                       Ex.:
    #                         Tar file structure:
    #                           p1/ar1.tar
    #                            |- ./p2/ar12.tar
    #                                |- p3/f123
    #                           p1/ar2.tar
    #                           p1/d1/f1
    #                           p1/d1/f2
    #                           p1/d1/d11/f11
    #                         URL to point to `p3/f123`:
    #                           tar:p1/ar1.tar?tar=./p2/ar12.tar&tar=p3/f123
    #                         URL to point to `p1/ar2.tar`:
    #                           tar:p1/ar1.tar
    #                         URL to point to `p1/d1/*`:
    #                           tar:p1/d1/
    typeset pkgSrc="${1}"; [ $# != 0 ] && shift

    typeset pkgInfo= srcSch= srcNetPath= srcLcl=

    export BD_CFG__DETECT_PROJECT_CODELOCATION_PREFIX

    eval "$(
        source "${_scrPath}/sh_libs/utils.sh"
        ParseURI "${pkgSrc}" srcSch,,,srcNetPath
    )"
    case ${srcSch} in
      (file)        srcLcl="${srcNetPath#${PWD}/${imgDir}/}";;
      (http?(s))    srcLcl="${srcNetPath}";;
      (*)
        echo "Error - Unsupported pkgSrc scheme: ${srcSch}" 1>&2
        false
        ;;
    esac
    srcLcl="${srcLcl////#}"; srcLcl="$(
        source "${_scrPath}/sh_libs/utils.sh"
        TruncFN "${imgDir}/${srcLcl//:/=}" ${fnAdd}
    )"
    [ -f "${srcLcl}" ] || {
        rm -f "${wrkDir}/f"
        case ${srcSch} in
          (http?(s))
            i=0
            while ((maxScanTry && (i++ < maxScanTry) || (! i++))); do
                ((i > 1)) && sleep ${nextAttempWaitTime}
                ((maxScanTry)) && echo "Try no. ${i}."
                ${xCmd} "
wget \
    ${AUTH:+--user \"\${AUTH%%:*\}\" --password \"\${AUTH#*:\}\"} \
    -O '${wrkDir}/f' '${pkgSrc}'
                " && break
            done
            ((i < (maxScanTry + 2)))  # Fail if max. attempts is reached.
            ;;
        esac
        ((dryRun)) || [ ! -f "${wrkDir}/f" ] || mv -f "${wrkDir}/f" "${srcLcl}"
    }
    while read -r pkgInfo; do
        [ -z "${pkgInfo}" ] && continue

        typeset mapPath= svcName= svcVer= pkgName= pkgType= pkgLcl= expDir=
        typeset artURL= urlQry= execEnv= e=
        typeset bdPrjVerNameClone=
        typeset -i eCode=0 noTrack=0

        typeset pkgScanner="${SCANNER}" pkgScnrPar="${SCNR_PAR}"
        typeset bdMainVerSch="${BD_CFG___VAR_bdMainVerSch}"
        typeset bdRelVerSch="${BD_CFG___VAR_bdRelVerSch}"
        typeset bdRelVerConv="${BD_CFG___VAR_bdRelVerConv}"
        typeset bdTopMainVerSch="${bdMainVerSch}"
        typeset bdTopRelVerSch="${bdRelVerSch}"
        typeset bdTopRelVerConv="${bdRelVerConv}"

        ARTIFACT_URL=${pkgInfo#*|}
        pkgName=${pkgInfo%|*}
        eval "$(
            source "${_scrPath}/sh_libs/utils.sh"
            ParseURI "${ARTIFACT_URL}" urlSch,,,urlNetPath,,,,,,urlQry
        )"
        BD_CFG__DETECT_PROJECT_CODELOCATION_PREFIX="${pkgName}"

        [ "${urlNetPath}" = "${srcNetPath}" ] &&
            urlSch=file urlNetPath="${PWD}/${srcLcl}" noTrack=1
        case ${urlSch} in
          (tar)
            expDir="archive=${srcLcl#${imgDir}/}"
            pkgLcl="${urlNetPath:1}"; pkgLcl="${expDir:8}~${pkgLcl#./}"
            pkgLcl="${pkgLcl////#}"; pkgLcl="$(
                source "${_scrPath}/sh_libs/utils.sh"
                TruncFN "${imgDir}/${pkgLcl//:/=}" ${fnAdd}
            )"
            ((! dryRun)) && [ -f "${pkgLcl}_" ] && continue
            ;;
        esac

        mapPath="${PRJ_MAP_PATH}" svcName="${SVC_NAME}" svcVer="${SVC_VER}"
        [ -n "${mapPath}" ] && {
            svcName="$(
                GetMappedName "${PRD_CFG_INF}" .mapping.name.application \
                    "${pkgName}"
            )"
            [[ "${svcName}"]] =~ .:[^:]* ]] && {
                svcVer="${svcName##*:}"
                svcName="${svcName%:*}"
            }
            execEnv="$(echo $(
                SetExecEnv "${PRD_CFG_INF}" ".mapping.applications.${svcName}"
            ))"
            eval "$(
                ReadCfg "${PRD_CFG_INF}" ".mapping.applications.${svcName}" '(
                    bdMainVerSch:bdMainVerSch
                    bdRelVerSch:bdRelVerSch
                    bdRelVerConv:bdRelVerConv
                )'
            )"
            eCode=0
            eval "$(
                GetMappingInfo "${PRD_CFG_INF}" \
                    ".mapping.applications.${svcName}.bdScan" scanner \
                    pkgScanner || echo "(exit $?)"
            )" || eCode=$?;
            case ${eCode} in
              (254)
                echo "Error - ${PRD_CFG_INF}: Invalid" \
                    ".mapping.applications.${svcName}.bdScan.scanner" 1>&2
                false
                ;;
              (!(0|255))    false;;
            esac
            eCode=0
            eval "$(
                GetMappingInfo "${PRD_CFG_INF}" \
                    ".mapping.applications.${svcName}.bdScan" scnrPar \
                    pkgScnrPar || echo "(exit $?)"
            )" || eCode=$?;
            case ${eCode} in
              (254)
                echo "Error - ${PRD_CFG_INF}: Invalid" \
                    ".mapping.applications.${svcName}.bdScan.scnrPar" 1>&2
                false
                ;;
              (!(0|255))    false;;
            esac
            eval "$(
                ResolvePrjNameVer "${PRD_CFG_INF}" mapPath svcName svcVer ||
                    echo "(exit $?)"
            )"
            [ -n "${mapPath}" ] && {
                echo 'Error - Package level can not have sub-mapping:' \
                    "${mapPath}" 1>&2
                false
            }
        }
        [ -z "${svcName}" ] && { echo 'Skipping Scanning Package.'; continue; }

        : Set clone information for Package: "${svcName} - ${svcVer}"
        BDprjVerExist "${svcName}" "${svcVer}" || {
            bdPrjVerNameClone="$(
                BDgetLatestPrjVer "${svcName}" "${svcVer}" \
                    "${bdMainVerSch}" \
                    "${bdRelVerSch}" \
                    "${bdRelVerConv}"
            )"
            export BD_CFG__DETECT_CLONE_PROJECT_VERSION_NAME="${bdPrjVerNameClone}"
#       : Create Project Version for Package: "${svcName} - ${svcVer}"
#           ${xCmd} "
#               BDprjVerCreate '${svcName}' '${svcVer}' '${bdPrjVerNameClone}'
#           "
        }

        case ${urlSch} in
          (file)        pkgType=lclFile;;
          (http?(s))    pkgType=rmtFile;;
          (tar)
            ((dryRun)) || [ -f "${pkgLcl}" ] || {
                [ -d "${imgDir}/${expDir}" ] || {
                    rm -rf "${wrkDir}/d/"
                    mkdir -p "${wrkDir}/d"
                    tar xf "${srcLcl}" -C "${wrkDir}/d/"
                    chmod -R a+r "${wrkDir}/d/"
                    mv -f "${wrkDir}/d" "${imgDir}/${expDir}"
                }
                ln -s "${expDir}/${urlNetPath:1}" "${pkgLcl}"
            }
            if [ -z "${urlQry}" ]; then
                typeset fileType="$(file -bL --mime-type "${pkgLcl}")"
                case ${fileType} in
                  (inode/directory)
                    typeset oPkgLcl="${pkgLcl}"
                    pkgLcl+=.tgz
                    ((dryRun)) || [ -f "${pkgLcl}" ] ||
                        tar zcf "${pkgLcl}" -C "${oPkgLcl}/" .
                    ;;
                esac
                pkgType=lclFile
                urlSch=file urlNetPath="${PWD}/${pkgLcl}" noTrack=1
            else
                pkgType=pkg:s
                urlSch=
            fi
            ;;
          (*)
            echo "Error - Unsupported pkgURL scheme: ${urlSch}" 1>&2
            false
            ;;
        esac
        [ -n "${urlSch}" ] && artURL="${urlSch}://${urlNetPath}"
        case ${pkgType} in
          (lclFile) case ${pkgScanner} in (dkr) pkgType=ctrImg;; esac
        esac
        eCode=0
        ${xCmd} "
AUTH=\"\${AUTH}\" $(
    typeset -x | grep -E 'BD_CFG__[^=[:space:]]+=' |
        sed -E 's/^((\S+ ){2})//' | tr '\n' ' '
)   ARTIFACT_TYPE='${pkgType}' ARTIFACT_URL='${artURL}' \
    PRD_CFG_INF='${PRD_CFG_INF}' PRJ_MAP_PATH= \
    PRD_NAME='${PRD_NAME}' PRD_VER='${PRD_VER}' \
    SVC_NAME='${svcName}' SVC_VER='${svcVer}' \
    SCANNER='${pkgScanner}' SCNR_PAR=\"${pkgScnrPar}\" \
    BDHUB_URL='${BDHUB_URL}' BDHUB_API_TOKEN=\"\${BDHUB_API_TOKEN}\" \
    OPT_CFG_FILE='${OPT_CFG_FILE}' OPT_XTRA_PAR='${OPT_XTRA_PAR}' \
    ${execEnv} \
    '${_scrPath}/${_scrName}' '$((skipParts | skipAll))' \
    $(
        case ${pkgType} in
          (ctrImg)
            sed -E -e 's/^[^~]+~([^~]+).*/\1/' -e 's/\.t(ar\.)?gz$//' \
                -e "s/^([^#]+#)*([^#]+)\$/'\2'/" 0<<<"${urlNetPath##*/}"
            ;;
          (pkg:s)
            echo "'${pkgName}|$(
                typeset -a pkgSrcNext=()
                IFS=\& read -ra pkgSrcNext 0<<<"${urlQry}"
                pkgSrc="${pkgSrcNext[0]%%=*}:${pkgSrcNext[0]#*=}"
                unset pkgSrcNext[0]
                urlQry="$(IFS=\& eval 'echo "${pkgSrcNext[*]}"')"
                echo "${pkgSrc}${urlQry:+?${urlQry}}"
            )' \\"
            echo "'file://${PWD}/${pkgLcl}'"
            ;;
        esac
    )
        " || eCode=$?
        case ${urlSch} in
          (file)
            ((eCode)) || ((dryRun)) || ((noTrack)) ||
                mv -f "${pkgLcl}" "${pkgLcl}_"
            ;;
        esac
        ((! eCode))

        : Clean up Project Version for Package: "${svcName} - ${bdPrjVerNameClone}"
        ((dryRun)) || BDcleanUpPrjVer "${svcName}" "${bdPrjVerNameClone}" \
            "${bdMainVerSch}" "${bdRelVerSch}" "${bdRelVerConv}" \
            "${PRD_NAME:-*}" \
            "${bdTopMainVerSch}" "${bdTopRelVerSch}" "${bdTopRelVerConv}"
    done 0<<<"${pkgList}"
    ;;
  (ctrImg)
    : Scanning Container Image - "${SCANNER}": "${ARTIFACT_URL:=ARTIFACT_URL--NotSet}"
    typeset imgName="${1}"; [ $# != 0 ] && shift
    # imgName: Name of Container Image in form of `NAME[:TAG]`.
    typeset imgPkgName="${1:-ctrImg}"; [ $# != 0 ] && shift
    # imgPkgName: Name of the enclosing package (ex. `imgpkg-bundle`), where the
    #   Container Image is from, in form of `NAME[:TAG]`. Empty string means
    #   this is a stand-alone Container Image.

    typeset ctrImg= baseOS= execEnv=
    typeset bdPrjVerNameClone=
    typeset -i eCode=0 svcPrj=1

    typeset ctrImgArc="${urlNetPath////#}"; ctrImgArc="$(
        source "${_scrPath}/sh_libs/utils.sh"
        TruncFN "${imgDir}/${ctrImgArc//:/=}.tar" ${fnAdd}
    )"
    typeset imgLcl="$(
        source "${_scrPath}/sh_libs/utils.sh"
        TruncFN "${imgDir}/${imgPkgName//:/=}~${ctrImgArc#${imgDir}/}" ${fnAdd}
    )"
    typeset bdMainVerSch="${BD_CFG___VAR_bdMainVerSch}"
    typeset bdRelVerSch="${BD_CFG___VAR_bdRelVerSch}"
    typeset bdRelVerConv="${BD_CFG___VAR_bdRelVerConv}"
    typeset bdTopMainVerSch="${bdMainVerSch}"
    typeset bdTopRelVerSch="${bdRelVerSch}"
    typeset bdTopRelVerConv="${bdRelVerConv}"

    export BD_CFG__DETECT_PROJECT_CODELOCATION_PREFIX="${imgName}"

    ((! dryRun)) && [ -f "${imgLcl}_" ] && exit

    [ -n "${PRJ_MAP_PATH}" ] && {
        svcPrj=0
        [ -z "${SVC_VER}" ] && eval "$(
            GetNameVerFromOCIurl "${urlNetPath}" "${imgName}" SVC_NAME SVC_VER
        )"
        SVC_NAME="$(
            GetMappedName "${PRD_CFG_INF}" .mapping.name.containerImage \
                "${imgName%%:*}"
        )"
        execEnv="$(echo $(
            SetExecEnv "${PRD_CFG_INF}" "${PRJ_MAP_PATH}.${SVC_NAME}"
        ))"
        eval "$(ReadCfg "${PRD_CFG_INF}" "${PRJ_MAP_PATH}.${SVC_NAME}" '(
            bdMainVerSch:bdMainVerSch
            bdRelVerSch:bdRelVerSch
            bdRelVerConv:bdRelVerConv
        )')"
        eval "$(
            ResolvePrjNameVer "${PRD_CFG_INF}" PRJ_MAP_PATH SVC_NAME SVC_VER ||
                echo "(exit $?)"
        )"
        [ -n "${PRJ_MAP_PATH}" ] && {
            echo 'Error - Container Image level can not have sub-mapping:' \
                "${PRJ_MAP_PATH}" 1>&2
            false
        }
    }
    [ -z "${SVC_NAME}" ] && { echo 'Skipping Scanning Container Img.'; exit; }

    : Set clone information for Container Image: "${SVC_NAME} - ${SVC_VER}"
    ((svcPrj)) || BDprjVerExist "${SVC_NAME}" "${SVC_VER}" || {
        bdPrjVerNameClone="$(
            BDgetLatestPrjVer "${SVC_NAME}" "${SVC_VER}" \
                "${bdMainVerSch}" \
                "${bdRelVerSch}" \
                "${bdRelVerConv}"
        )"
        export BD_CFG__DETECT_CLONE_PROJECT_VERSION_NAME="${bdPrjVerNameClone}"
#   : Create Project Version for Container Image: "${SVC_NAME} - ${SVC_VER}"
#       ${xCmd} "
#           BDprjVerCreate '${SVC_NAME}' '${SVC_VER}' '${bdPrjVerNameClone}'
#       "
    }

    [ -f "${imgLcl}" ] || {
        rm -f "${wrkDir}/f"
        case ${urlSch} in
          (docker|oci-reg)
            [ -f "${ctrImgArc}" ] || {
                i=0
                while ((maxScanTry && (i++ < maxScanTry) || (! i++))); do
                    ((i > 1)) && sleep ${nextAttempWaitTime}
                    ((maxScanTry)) && echo "Try no. ${i}."
                    ${xCmd} "
docker image pull '${urlNetPath}' &&
    docker image save -o '${wrkDir}/f' '${urlNetPath}' &&
    chmod a+r '${wrkDir}/f' &&
    docker image rm -f '${urlNetPath}'
                    " && break
                done
                ((i < (maxScanTry + 2)))  # Fail if max. attempts is reached.
                mv -f "${wrkDir}/f" "${ctrImgArc}"
            }
            ln -s "${PWD}/${ctrImgArc}" "${wrkDir}/f"
            ;;
          (file)
            ((dryRun)) || case ${SCANNER} in
              (dkr)
                typeset imgFileType="$(file -bL --mime-type "${urlNetPath}")"
                case ${imgFileType} in
                  (application/@(x-executable|x-tar))
                    ln -s "${urlNetPath}" "${wrkDir}/f"
                    ;;
                  (application/gzip)
                    gunzip -c "${urlNetPath}" 1> "${wrkDir}/f"
                    ;;
                  (*)
                    echo "Unsupported archive type (${imgFileType}): ${imgPath}"
                    false
                    ;;
                esac
((0\$(stat -Lc '%a' "${wrkDir}/f") & 00004)) && chmod a+r "${wrkDir}/f"
                ;;
              (*)
                ln -s "${urlNetPath}" "${wrkDir}/f"
                ;;
            esac
            ;;
          (*)
            echo "Error - Unsupported scheme: ${urlSch}" 1>&2
            false
            ;;
        esac
        ((dryRun)) || [ ! -f "${wrkDir}/f" ] || mv -f "${wrkDir}/f" "${imgLcl}"
    }
    case ${SCANNER} in
      (dkr) ctrImg="${imgDir}/${imgName//:/--}.tar";;
      (*)   ctrImg="${imgDir}/${imgName//:/--}.gz";;
    esac
    ctrImg="$(
        source "${_scrPath}/sh_libs/utils.sh"
        TruncFN "${ctrImg}" ${fnAdd}
    )"
    case ${SCANNER} in
      (dkr)
        # Docker archive have 2 different formats for Image Layers:
        #   Old format: "<64BhexHashVal>/layer.tar"
        #   New format: "blobs/sha256/<64BhexHashVal>"
        ${xCmd} "
baseOS=\"\$(
    '${_scrPath}/id_base_os_layer.py' <(
        tar xf '${imgLcl}' -O manifest.json | jq '.[0].Layers[]' |
            sed -E -e 's|^\"blobs/([^/]+)/(.+)\"$|- \1:\2|;t' \
                -e 's|\"([^/]+)/layer.tar\"|- sha256:\1|'
    ) ./__conf/base-os-layers.yml
)\"
mv -f '${imgLcl}' '${ctrImg}'
        "
        ;;
      (*)   ${xCmd} "gzip -c '${imgLcl}' 1> '${ctrImg}'";;
    esac
    eCode=0
    ${xCmd} "
[ -n '${baseOS}' ] && {
    export BD_CFG__DETECT_DOCKER_PLATFORM_TOP_LAYER_ID='${baseOS#*|}'
    AUTH=\"\${AUTH}\" $(
        typeset -x | grep -E 'BD_CFG__[^=[:space:]]+=' |
            sed -E 's/^((\S+ ){2})//' | tr '\n' ' '
    )   BD_CFG__DETECT_DOCKER_PLATFORM_TOP_LAYER_ID= \
        BD_CFG__DETECT_PROJECT_CODELOCATION_PREFIX= \
        ARTIFACT_TYPE=ctrImg ARTIFACT_URL='docker://${baseOS%|*}' \
        PRD_CFG_INF='${PRD_CFG_INF}' PRJ_MAP_PATH=.mapping.containerImages \
        PRD_NAME='${PRD_NAME}' PRD_VER='${PRD_VER}' \
        SVC_NAME= SVC_VER='${baseOS}' \
        SCANNER='${SCANNER}' SCNR_PAR=\"${SCNR_PAR}\" \
        BDHUB_URL='${BDHUB_URL}' BDHUB_API_TOKEN=\"\${BDHUB_API_TOKEN}\" \
        OPT_CFG_FILE='${OPT_CFG_FILE}' OPT_XTRA_PAR='${OPT_XTRA_PAR}' \
        ${execEnv} \
        '${_scrPath}/${_scrName}' '$((skipParts | skipAll))' \
        '$(echo "${baseOS%|*}" | sed -E 's|^.+/||')' || eCode=\$?
}
if ((eCode)); then
    (exit \$((eCode)))
else
    AUTH=\"\${AUTH}\" $(
        typeset -x | grep -E 'BD_CFG__[^=[:space:]]+=' |
            sed -E 's/^((\S+ ){2})//' | tr '\n' ' '
    )   ARTIFACT_TYPE=lclFile ARTIFACT_URL='${ctrImg}' \
        PRD_CFG_INF='${PRD_CFG_INF}' PRJ_MAP_PATH= \
        PRD_NAME='${PRD_NAME}' PRD_VER='${PRD_VER}' \
        SVC_NAME='${SVC_NAME}' SVC_VER='${SVC_VER}' \
        SCANNER='${SCANNER}' SCNR_PAR='${SCNR_PAR}' \
        BDHUB_URL='${BDHUB_URL}' BDHUB_API_TOKEN=\"\${BDHUB_API_TOKEN}\" \
        OPT_CFG_FILE='${OPT_CFG_FILE}' OPT_XTRA_PAR='${OPT_XTRA_PAR}' \
        ${execEnv} \
        '${_scrPath}/${_scrName}' '$((skipParts | skipAll))'
fi
    " || eCode=$?
    case ${SCANNER} in
      (bin) ${xCmd} "rm -f '${ctrImg}'";;
      (*)   ${xCmd} "mv -f '${ctrImg}' '${imgLcl}'";;
    esac
    ((eCode)) || ((dryRun)) || mv -f "${imgLcl}" "${imgLcl}_"
    ((! eCode))

    : Clean up Project Version for Container Image: "${SVC_NAME} - ${bdPrjVerNameClone}"
    ((svcPrj)) || ((dryRun)) ||
        BDcleanUpPrjVer "${SVC_NAME}" "${bdPrjVerNameClone}" \
            "${bdMainVerSch}" "${bdRelVerSch}" "${bdRelVerConv}" \
            "${PRD_NAME:-*}" \
            "${bdTopMainVerSch}" "${bdTopRelVerSch}" "${bdTopRelVerConv}"
    ;;
  (ctrImg:s)
    : Scanning \`ctrImg\`s - "${SCANNER}".
    typeset imgList="${1}"; [ $# != 0 ] && shift
    # List (newline-delimited) `imgList`:
    #   imgName|imgURL
    #     Where:
    #       imgName:    Name of `ctrImg` in form of `NAME[:TAG]`.
    #       imgURL:     URL of `ctrImg` in form of
    #                   `HOST[:PORT]/[NAMESPACES/]REPOSITORY(:TAG|@DIGEST)`.
    typeset imgPkgName="${1:-ctrImg}"; [ $# != 0 ] && shift
    # imgPkgName: Name of the enclosing package (ex. `imgpkg-bundle`), where the
    #   Container Images are from, in form of `NAME[:TAG]`. Empty string means
    #   this is a stand-alone Container Images.

    typeset imgInfo=

    while read -r imgInfo; do
        [ -z "${imgInfo}" ] && continue
        ${xCmd} "
AUTH=\"\${AUTH}\" $(
    typeset -x | grep -E 'BD_CFG__[^=[:space:]]+=' |
        sed -E 's/^((\S+ ){2})//' | tr '\n' ' '
)   ARTIFACT_TYPE=ctrImg ARTIFACT_URL='docker://${imgInfo#*|}' \
    PRD_CFG_INF='${PRD_CFG_INF}' PRJ_MAP_PATH='${PRJ_MAP_PATH}' \
    PRD_NAME='${PRD_NAME}' PRD_VER='${PRD_VER}' \
    SVC_NAME='${SVC_NAME}' SVC_VER='${SVC_VER}' \
    SCANNER='${SCANNER}' SCNR_PAR='${SCNR_PAR}' \
    BDHUB_URL='${BDHUB_URL}' BDHUB_API_TOKEN=\"\${BDHUB_API_TOKEN}\" \
    OPT_CFG_FILE='${OPT_CFG_FILE}' OPT_XTRA_PAR='${OPT_XTRA_PAR}' \
    '${_scrPath}/${_scrName}' '$((skipParts | skipAll))' \
    '${imgInfo%|*}' '${imgPkgName}'
        "
    done 0<<<"${imgList}"
    ;;
  (imgpkg-bundle)
    : Scanning \`imgpkg-bundle\` - "${SCANNER}": "${ARTIFACT_URL:=ARTIFACT_URL--NotSet}"
    typeset imgpkgName="${1}"; [ $# != 0 ] && shift
    # imgpkgName: Name of `imgpkg-bundle` in form of `NAME[:TAG]`.
    typeset -i asTar="${1:-0}"; [ $# != 0 ] && shift

    typeset imgInfo= imgList= execEnv=
    typeset bdPrjVerNameClone=

    typeset mapPath="${PRJ_MAP_PATH}" svcName="${SVC_NAME}" svcVer="${SVC_VER}"
    typeset imgpkgURL="${urlNetPath}"
    typeset bdMainVerSch="${BD_CFG___VAR_bdMainVerSch}"
    typeset bdRelVerSch="${BD_CFG___VAR_bdRelVerSch}"
    typeset bdRelVerConv="${BD_CFG___VAR_bdRelVerConv}"
    typeset bdTopMainVerSch="${bdMainVerSch}"
    typeset bdTopRelVerSch="${bdRelVerSch}"
    typeset bdTopRelVerConv="${bdRelVerConv}"

    export BD_CFG__DETECT_PROJECT_CODELOCATION_PREFIX="${imgpkgName}"

    case ${urlSch} in
      (!(oci-reg))
        echo "Error - Unsupported scheme: ${urlSch}" 1>&2
        false
        ;;
    esac
    if ((asTar)); then
        typeset imgLcl="${urlNetPath////#}"; imgLcl="$(
            source "${_scrPath}/sh_libs/utils.sh"
            TruncFN "${imgDir}/${imgLcl//:/=}.tar" ${fnAdd}
        )"
        ((! dryRun)) && [ -f "${imgLcl}_" ] && exit
    else
        typeset infoLcl="${urlNetPath////#}"; infoLcl="$(
            source "${_scrPath}/sh_libs/utils.sh"
            TruncFN "${imgDir}/${infoLcl//:/=}.yaml" ${fnAdd}
        )"
        ((! dryRun)) && [ -f "${infoLcl}_" ] && exit
    fi

    [ -n "${mapPath}" ] && {
        eval "$(
            GetNameVerFromOCIurl "${urlNetPath}" "${imgpkgName}" svcName svcVer
        )"
        svcName="$(
            GetMappedName "${PRD_CFG_INF}" .mapping.name.service \
                "${svcName##*/}"
        )"
        execEnv="$(echo $(
            SetExecEnv "${PRD_CFG_INF}" ".mapping.services.${svcName}"
        ))"
        eval "$(ReadCfg "${PRD_CFG_INF}" ".mapping.services.${svcName}" '(
            bdMainVerSch:bdMainVerSch
            bdRelVerSch:bdRelVerSch
            bdRelVerConv:bdRelVerConv
        )')"
        eval "$(
            ResolvePrjNameVer "${PRD_CFG_INF}" mapPath svcName svcVer ||
                echo "(exit $?)"
        )"
    }
    [ -z "${mapPath}" ] && [ -z "${svcName}" ] && {
        echo 'Skipping Scanning Service.'
        exit
    }

    : Set clone information for Service: "${svcName} - ${svcVer}"
    BDprjVerExist "${svcName}" "${svcVer}" || {
        bdPrjVerNameClone="$(
            BDgetLatestPrjVer "${svcName}" "${svcVer}" \
                "${bdMainVerSch}" \
                "${bdRelVerSch}" \
                "${bdRelVerConv}"
        )"
        export BD_CFG__DETECT_CLONE_PROJECT_VERSION_NAME="${bdPrjVerNameClone}"
#   : Create Project Version for Service: "${svcName} - ${svcVer}"
#       ${xCmd} "
#           BDprjVerCreate '${svcName}' '${svcVer}' '${bdPrjVerNameClone}'
#       "
    }

    if ((asTar)); then
        typeset -i eCode=0

        [ -n "${mapPath}" ] && {
            echo 'Error - This Service is scanned as `tar`, so it can not' \
                "have sub-mapping: ${mapPath}" 1>&2
            false
        }

        [ -f "${imgLcl}" ] || {
            rm -f "${wrkDir}/f"
            i=0
            while ((maxScanTry && (i++ < maxScanTry) || (! i++))); do
                ((i > 1)) && sleep ${nextAttempWaitTime}
                ((maxScanTry)) && echo "Try no. ${i}."
                ${xCmd} "
                    imgpkg copy -b '${urlNetPath}' --to-tar '${wrkDir}/f'
                " && break
            done
            ((i < (maxScanTry + 2)))  # Fail if max. attempts is reached.
            ((dryRun)) || [ ! -f "${wrkDir}/f" ] ||
                mv -f "${wrkDir}/f" "${imgLcl}"
        }
        case ${SCANNER} in
          (bin) svcImg="${imgDir}/${imgpkgName//:/--}.gz";;
          (*)
            echo "Error - Unsupported SCANNER: ${SCANNER}" 1>&2
            false
            ;;
        esac
        svcImg="$(
            source "${_scrPath}/sh_libs/utils.sh"
            TruncFN "${svcImg}" ${fnAdd}
        )"
        case ${SCANNER} in
          (bin) ${xCmd} "gzip -c '${imgLcl}' 1> '${svcImg}'";;
        esac
        ${xCmd} "
AUTH=\"\${AUTH}\" $(
    typeset -x | grep -E 'BD_CFG__[^=[:space:]]+=' |
        sed -E 's/^((\S+ ){2})//' | tr '\n' ' '
)   ARTIFACT_TYPE=lclFile ARTIFACT_URL='${svcImg}' \
    PRD_CFG_INF='${PRD_CFG_INF}' PRJ_MAP_PATH= \
    PRD_NAME='${PRD_NAME}' PRD_VER='${PRD_VER}' \
    SVC_NAME='${svcName}' SVC_VER='${svcVer}' \
    SCANNER='${SCANNER}' SCNR_PAR='${SCNR_PAR}' \
    BDHUB_URL='${BDHUB_URL}' BDHUB_API_TOKEN=\"\${BDHUB_API_TOKEN}\" \
    OPT_CFG_FILE='${OPT_CFG_FILE}' OPT_XTRA_PAR='${OPT_XTRA_PAR}' \
    ${execEnv} \
    '${_scrPath}/${_scrName}' '$((skipParts | skipAll))'
        " || eCode=$?
        case ${SCANNER} in
          (bin) ${xCmd} "rm -f '${svcImg}'";;
        esac
        ((eCode)) || ((dryRun)) || mv -f "${imgLcl}" "${imgLcl}_"
        ((! eCode))
    else
        [ -f "${infoLcl}" ] || {
            rm -f "${wrkDir}/f"
            i=0
            while ((maxScanTry && (i++ < maxScanTry) || (! i++))); do
                ((i > 1)) && sleep ${nextAttempWaitTime}
                ((maxScanTry)) && echo "Try no. ${i}."
                imgpkg describe -b "${urlNetPath}" --output-type yaml \
                    1> "${wrkDir}/f" && break
            done
            ((i < (maxScanTry + 2)))  # Fail if max. attempts is reached.
            [ ! -f "${wrkDir}/f" ] || mv -f "${wrkDir}/f" "${infoLcl}"
        }
        while read -r imgInfo; do
            imgList+="${imgList:+$'\n'}${imgInfo}"
        done 0< <(
            cat "${infoLcl}" | yq eval '
                .content.images[] | select(.imageType == "Image") |
                (.annotations."kbld.carvel.dev/id" | split("/"))[-1] + "|" +
                    .image
            '
        )
        if [ -n "${imgList}" ]; then
            ${xCmd} "
AUTH=\"\${AUTH}\" $(
    typeset -x | grep -E 'BD_CFG__[^=[:space:]]+=' |
        sed -E 's/^((\S+ ){2})//' | tr '\n' ' '
)   ARTIFACT_TYPE=ctrImg:s ARTIFACT_URL= \
    PRD_CFG_INF='${PRD_CFG_INF}' PRJ_MAP_PATH='${mapPath}' \
    PRD_NAME='${PRD_NAME}' PRD_VER='${PRD_VER}' \
    SVC_NAME='${svcName}' SVC_VER='${svcVer}' \
    SCANNER='${SCANNER}' SCNR_PAR='${SCNR_PAR}' \
    BDHUB_URL='${BDHUB_URL}' BDHUB_API_TOKEN=\"\${BDHUB_API_TOKEN}\" \
    OPT_CFG_FILE='${OPT_CFG_FILE}' OPT_XTRA_PAR='${OPT_XTRA_PAR}' \
    ${execEnv} \
    '${_scrPath}/${_scrName}' '$((skipParts | skipAll))' \
    '${imgList}' '${imgpkgName}'
            "
        else
            echo 'Can not find Container Image inside `imgpkg-bundle`.'
            echo 'Trying to pull the whole `imgpkg-bundle` as tar and' \
                'scan as `BINARY`.'
            ${xCmd} "
AUTH=\"\${AUTH}\" $(
    typeset -x | grep -E 'BD_CFG__[^=[:space:]]+=' |
        sed -E 's/^((\S+ ){2})//' | tr '\n' ' '
)   ARTIFACT_TYPE=imgpkg-bundle ARTIFACT_URL='${urlSch}://${urlNetPath}' \
    PRD_CFG_INF='${PRD_CFG_INF}' PRJ_MAP_PATH='${mapPath}' \
    PRD_NAME='${PRD_NAME}' PRD_VER='${PRD_VER}' \
    SVC_NAME='${svcName}' SVC_VER='${svcVer}' \
    SCANNER=bin SCNR_PAR= \
    BDHUB_URL='${BDHUB_URL}' BDHUB_API_TOKEN=\"\${BDHUB_API_TOKEN}\" \
    OPT_CFG_FILE='${OPT_CFG_FILE}' OPT_XTRA_PAR='${OPT_XTRA_PAR}' \
    '${_scrPath}/${_scrName}' '$((skipParts | skipAll))' \
    '${imgpkgName}' 1
            "
        fi
        ((dryRun)) || mv -f "${infoLcl}" "${infoLcl}_"
    fi

    : Clean up Project Version for Service: "${svcName} - ${bdPrjVerNameClone}"
    ((dryRun)) || BDcleanUpPrjVer "${svcName}" "${bdPrjVerNameClone}" \
        "${bdMainVerSch}" "${bdRelVerSch}" "${bdRelVerConv}" \
        "${PRD_NAME:-*}" \
        "${bdTopMainVerSch}" "${bdTopRelVerSch}" "${bdTopRelVerConv}"
    ;;
  (imgpkg-bundle:s)
    : Scanning \`imgpkg-bundle\`s - "${SCANNER}".
    typeset imgpkgList="${1}"; [ $# != 0 ] && shift
    # List (newline-delimited) `imgpkgList`:
    #   imgpkgName|imgpkgURL
    #     Where:
    #       imgpkgName: Name of `imgpkg-bundle` in form of `NAME[:TAG]`.
    #       imgpkgURL:  URL of `imgpkg-bundle` in form of
    #                   `HOST[:PORT]/[NAMESPACES/]REPOSITORY(:TAG|@DIGEST)`.

    typeset imgpkgInfo=

    while read -r imgpkgInfo; do
        [ -z "${imgpkgInfo}" ] && continue
        ${xCmd} "
AUTH=\"\${AUTH}\" $(
    typeset -x | grep -E 'BD_CFG__[^=[:space:]]+=' |
        sed -E 's/^((\S+ ){2})//' | tr '\n' ' '
)   ARTIFACT_TYPE=imgpkg-bundle ARTIFACT_URL='oci-reg://${imgpkgInfo#*|}' \
    PRD_CFG_INF='${PRD_CFG_INF}' PRJ_MAP_PATH='${PRJ_MAP_PATH}' \
    PRD_NAME='${PRD_NAME}' PRD_VER='${PRD_VER}' \
    SVC_NAME='${SVC_NAME}' SVC_VER='${SVC_VER}' \
    SCANNER='${SCANNER}' SCNR_PAR='${SCNR_PAR}' \
    BDHUB_URL='${BDHUB_URL}' BDHUB_API_TOKEN=\"\${BDHUB_API_TOKEN}\" \
    OPT_CFG_FILE='${OPT_CFG_FILE}' OPT_XTRA_PAR='${OPT_XTRA_PAR}' \
    '${_scrPath}/${_scrName}' '$((skipParts | skipAll))' \
    '${imgpkgInfo%|*}'
        "
    done 0<<<"${imgpkgList}"
    ;;
  (SBoM|MetaData)
    : Scanning Product\'s "${ARTIFACT_TYPE}" - "${SCANNER}".
    typeset artURL= fileLcl= prdVer= svcVer= execEnv=
    typeset artContent= subArtType= subArtInfo= subArtSrc= useSubArtSrc=
    typeset bdPrjVerNameClone=
    typeset mapPath=.mapping.products
    typeset subArtTypes='imgpkg-bundle ctrImg pkg incMnfst'

    typeset prdName="${eProduct// /-}${eSubProduct:+--"${eSubProduct// /-}"}"

    export BD_CFG___VAR_bdMainVerSch
    export BD_CFG___VAR_bdRelVerSch
    export BD_CFG___VAR_bdRelVerConv

    artURL="${ARTIFACT_URL:-$(
        set +x
        i=0
        while ((maxScanTry && (i++ < maxScanTry) || (! i++))); do
            ((i > 1)) && sleep ${nextAttempWaitTime}
            ((maxScanTry)) && echo "Try no. ${i}." 1>&2
            eval "
                '${_scrPath}/inspector_gadget.py' --log-level 10,-1 \
                    get-build-url \
                    ${eSubProduct:+--sub-product '${eSubProduct}'} \
                    ${AUTH:+--auth '${AUTH}'} \
                    ${eRelease:+--release '${eRelease}'} \
                    ${eArtifactBuildID:+--build-id '${eArtifactBuildID}'} \
                    $(
                        eval "typeset -a eExtraQpars=${eExtraQpars}"
                        for e in "${eExtraQpars[@]}"; do
                            echo "--extra-q-pars '${e}' \\"
                        done
                        echo \\
                    )
                    '${eProduct}' 2> &1
            " | sed -nE '
                /^.{24}INFO: Identified build URL:/ s/.* ([^ ]+)$/\1/p
            ' && break
        done
        ((i < (maxScanTry + 2)))  # Fail if max. attempts is reached.
    )}"

    case ${eProduct} in
      (TCx|TPS)
        prdVer="$(
            echo "${artURL}" |
                sed -nE 's/^.+-([0-9.]+-[0-9]+)\.yaml/\1/p'
        )"
        ;;
      (TCA)
        # Mainline build:   https://usw1.packages.broadcom.com/sp-tcabuild-generic-dev-local/official/tca-cnva/main/6401730efd5468629a961b7e12fd587866944cd3/publish/generic/ova/VMware-Telco-Cloud-Automation-3.4.0-1731548167357_222.ova
        # Release build:    https://usw1.packages.broadcom.com/sp-tcabuild-generic-dev-local/official/tca-cnva/3.3.0/4dec85d44b1d1582634aef49f66a99bb7686d464/publish/generic/ova/VMware-Telco-Cloud-Automation-3.3.0-1729572012247_75.ova
        prdVer="$(
            echo "${artURL}" | sed -nE \
                -e 's|^(([^/]+)/+){5}main/.+-([0-9.]+-[0-9]+_[0-9]+)\.ova|Main-\3|p;t   # Check if a Mainline version.' \
                -e 's|^(([^/]+)/+){5}[0-9.]+/.+-([0-9.]+-[0-9]+_[0-9]+)\.ova|Rel-\3|p;t # Check if a Release version.' \
                -e 'q1                                                                  # Unexpected version pattern.'

        )"
        subArtSrc="${artURL}"
        artURL="${artURL:0:-4}_metadata.yaml"
        ;;
      (TCSA)
        prdVer="$(
            echo "${artURL}" |
                sed -nE 's/^.+-([0-9.]+(-SNAPSHOT)?-[0-9]+)\.tar\.gz/\1/p'
        )"
        subArtSrc="${artURL}"
        artURL="${artURL:0:-7}_metadata.yaml"
        ;;
      (RIC|'TCx K8s Installer')
        prdVer="$(
            echo "${artURL}" |
                sed -nE 's/^.+-([0-9.]+_[0-9]+)\.tar\.gz/\1/p'
        )"
        subArtSrc="${artURL}"
        artURL="${artURL:0:-7}_metadata.yaml"
        ;;
      (Smart-DM)
        prdVer="$(
            echo "${artURL}" |
                sed -nE 's/^.+-([0-9.]+)_metadata\.yaml/\1/p'
        )"
        ;;
      (UHANA|Uhana-Cluster)
        prdVer="$(
            echo "${artURL}" |
                sed -nE 's|^http://[^/]+/([^/]+)/.+-([0-9]+)\.tar\.gz|\1-\2|p'
        )"
        subArtSrc="${artURL}"
        artURL="${artURL:0:-7}_metadata.yaml"
        ;;
    esac
    eval "$(
        source "${_scrPath}/sh_libs/utils.sh"
        ParseURI "${artURL}" urlSch,,,urlNetPath
    )"
    fileLcl="${urlNetPath////#}"; fileLcl="$(
        source "${_scrPath}/sh_libs/utils.sh"
        TruncFN "${imgDir}/${fileLcl//:/=}" ${fnAdd}
    )"
    ((! dryRun)) && [ -f "${fileLcl}_" ] && exit

    prdName="$(
        GetMappedName "${PRD_CFG_INF}" .mapping.name.product "${prdName}"
    )"
    execEnv="$(echo $(
        SetExecEnv "${PRD_CFG_INF}" ".mapping.products.${prdName}"
    ))"
    eval "$(ReadCfg "${PRD_CFG_INF}" ".mapping.products.${prdName}" '(
        bdMainVerSch:BD_CFG___VAR_bdMainVerSch
        bdRelVerSch:BD_CFG___VAR_bdRelVerSch
        bdRelVerConv:BD_CFG___VAR_bdRelVerConv
    )')"
    eval "$(
        ResolvePrjNameVer "${PRD_CFG_INF}" mapPath prdName prdVer ||
            echo "(exit $?)"
    )"
    [ -n "${mapPath}" ] && {
        echo "Error - Product level can not have sub-mapping: ${mapPath}" 1>&2
        false
    }
    [ -z "${prdName}" ] && { echo 'Skipping Scanning Product.'; exit; }

    [ -f "${fileLcl}" ] || {
        rm -f "${wrkDir}/f"
        case ${urlSch} in
          (http?(s))
            i=0
            while ((maxScanTry && (i++ < maxScanTry) || (! i++))); do
                ((i > 1)) && sleep ${nextAttempWaitTime}
                ((maxScanTry)) && echo "Try no. ${i}."
                wget \
                    ${AUTH:+--user "${AUTH%%:*}" --password "${AUTH#*:}"} \
                    -O "${wrkDir}/f" "${artURL}" && break
            done
            ((i < (maxScanTry + 2)))  # Fail if max. attempts is reached.
            ;;
          (file)    ln -s "${urlNetPath}" "${wrkDir}/f";;
        esac
        [ ! -f "${wrkDir}/f" ] || mv -f "${wrkDir}/f" "${fileLcl}"
    }
    case ${ARTIFACT_TYPE} in
      (SBoM)
        : Processing SBoM: "${artURL}"
        artContent="$(
            cat "${fileLcl}" | yq eval '
                with(
                    (.helm-charts[].services[], .container-images[]);
                    . = .name + ":" + .tag + "|" + .location + (
                        with(
                            select(.digest != null);
                            . = "@sha256:" + .digest
                        ) | with(
                            select(.digest == null);
                            . = ":" + .tag
                        ) | .
                    ) | sub(":\|", "|")
                ) | with(
                    .packages[];
                    . = .name + ":" + .tag + "|" + .location
                ) | with(
                    .included-manifest[];
                    . = (.URL | split("/"))[-1] + "|" +
                        .Type + "|" + .URL + "|" + (
                        [(.Meta[] | key + ":" + .)] | join(";")
                    )
                ) | {
                    "imgpkg-bundles": .helm-charts[].services,
                    "ctrImgs": .container-images,
                    "pkgs": .packages,
                    "incMnfsts": .included-manifest
                }
            '
        )"
        ;;
      (MetaData)
        : Processing MetaData: "${artURL}"
        artContent="$(
            cat "${fileLcl}" | yq eval '
                with(
                    .LayerMappings.ImgpkgBundles[];
                    . = (.URL | sub("^.*?([^/]+?)(?:@sha256)?:.+", "${1}")) +
                        ":" + .Tag + "|" + .URL | sub(":\|", "|")
                ) | with(
                    .LayerMappings.ContainerImgs[];
                    . = (.URL | sub("^.*?([^/]+?)(?:@sha256)?:.+", "${1}")) +
                        ":" + .Tag + "|" + .URL | sub(":\|", "|")
                ) | with(
                    .app-packages[];
                    . = ((split("?"))[0] | (split("/"))[-1]) + "|" + .
                ) | with(
                    .IncludedManifest[];
                    . = (.URL | split("/"))[-1] + "|" +
                        .Type + "|" + .URL + "|" + (
                        [(.Meta[] | key + ":" + .)] | join(";")
                    )
                ) | {
                    "imgpkg-bundles": .LayerMappings.ImgpkgBundles,
                    "ctrImgs": .LayerMappings.ContainerImgs,
                    "pkgs": .app-packages,
                    "incMnfsts": .IncludedManifest
                }
            '
        )"
        ;;
    esac

    : Create Project Version for Product: "${prdName} - ${prdVer}"
    ((dryRun)) || BDprjVerExist "${prdName}" "${prdVer}" || {
        bdPrjVerNameClone="$(
            BDgetLatestPrjVer "${prdName}" "${prdVer}" \
                "${BD_CFG___VAR_bdMainVerSch}" \
                "${BD_CFG___VAR_bdRelVerSch}" \
                "${BD_CFG___VAR_bdRelVerConv}"
        )"
        ${xCmd} "
            BDprjVerCreate '${prdName}' '${prdVer}' '${bdPrjVerNameClone}'
        "
    }

    for subArtType in ${subArtTypes}; do
        : Scanning "${subArtType}:s"
        typeset subArtList=
        typeset subArtFile="${fileLcl}--${subArtType}s.yaml"

        ((! dryRun)) && [ -f "${subArtFile}_" ] && continue
        [ -f "${subArtFile}" ] || {
            while read -r subArtInfo; do
                echo "${subArtInfo}" 1>> "${subArtFile}"
            done 0< <(yq eval ".${subArtType}s" 0<<<"${artContent}")
        }
        subArtList="yq eval '.[]' '${subArtFile}'"
        [ "$(eval "${subArtList}")" = '' ] && subArtList=
        svcVer= useSubArtSrc=
        case ${subArtType} in
          (incMnfst)        mapPath=.mapping.includedManifests;;&
          (imgpkg-bundle)   mapPath=.mapping.services;;
          (ctrImg)          mapPath=.mapping.containerImages;;&
          (pkg)             mapPath=.mapping.applications useSubArtSrc=1;;&
          (pkg)             svcVer="${prdVer}";;
        esac
        if [ -n "${subArtList}" ]; then
            ${xCmd} "
AUTH=\"\${AUTH}\" $(
    typeset -x | grep -E 'BD_CFG__[^=[:space:]]+=' |
        sed -E 's/^((\S+ ){2})//' | tr '\n' ' '
)   ARTIFACT_TYPE='${subArtType}:s' ARTIFACT_URL= \
    PRD_CFG_INF='${PRD_CFG_INF}' PRJ_MAP_PATH='${mapPath}' \
    PRD_NAME='${prdName}' PRD_VER='${prdVer}' \
    SVC_NAME= SVC_VER='${svcVer}' \
    SCANNER='${SCANNER}' SCNR_PAR='${SCNR_PAR}' \
    BDHUB_URL='${BDHUB_URL}' BDHUB_API_TOKEN=\"\${BDHUB_API_TOKEN}\" \
    OPT_CFG_FILE='${OPT_CFG_FILE}' OPT_XTRA_PAR='${OPT_XTRA_PAR}' \
    ${execEnv} \
    '${_scrPath}/${_scrName}' '$((skipParts | skipAll))' \
    \"\$(${subArtList})\" ${useSubArtSrc:+'${subArtSrc}'}
            "
        fi
        ((dryRun)) || mv -f "${subArtFile}" "${subArtFile}_"
    done
    ((dryRun)) || mv -f "${fileLcl}" "${fileLcl}_"

    : Clean up Project Version for Product: "${prdName} - ${bdPrjVerNameClone}"
    ((dryRun)) || BDcleanUpPrjVer "${prdName}" "${bdPrjVerNameClone}" \
        "${BD_CFG___VAR_bdMainVerSch}" \
        "${BD_CFG___VAR_bdRelVerSch}" "${BD_CFG___VAR_bdRelVerConv}" ''
    ;;
  (incMnfst:s)
    : Scanning included Manifests - "${SCANNER}".
    typeset mList="${1}"; [ $# != 0 ] && shift
    # List (newline-delimited) `mList`:
    #   mName|mType|mURL|mMeta
    #     Where:
    #       mName:  Name of manifest in form of `NAME`.
    #       mType:  Type of manifest. Supported value:
    #                 SBoM, MetaData
    #       mURL:   URL of manifest in form of `SCHEME://HOST[:PORT]/PATH`.
    #       mMeta:  List (`;`-delimited) of supplemental information, depending
    #               on `mType`:
    #                 SBoM:     None
    #                 MetaData:
    #                   ArtifactURL:SCHEME://HOST[:PORT]/PATH

    typeset mInfo= mMeta artURL= prd= subPrd= prdCfg=
    typeset -i eCode=0
    typeset -a mInfoArr=() mMetaArr=()
    typeset -A mMetaMap=()

    typeset mapPath="${PRJ_MAP_PATH}"

    while read -r mInfo; do
        [ -z "${mInfo}" ] && continue

        prd="${PRODUCT}" subPrd="${SUB_PRODUCT}" prdCfg="${PRD_CFG_INF}"
        IFS=\| read -ra mInfoArr 0<<<"${mInfo}"
        IFS=\; read -ra mMetaArr 0<<<"${mInfoArr[3]}"
        for mMeta in "${mMetaArr}"; do
            mMetaMap["${mMeta%%:*}"]="${mMeta#*:}"
        done
        case ${mInfoArr[1]} in
          (SBoM)        artURL=${mInfoArr[2]};;
          (MetaData)    artURL=${mMetaMap[ArtifactURL]};;
        esac
        artURL="$(
            i=0
            while ((maxScanTry && (i++ < maxScanTry) || (! i++))); do
                ((i > 1)) && sleep ${nextAttempWaitTime}
                ((maxScanTry)) && echo "Try no. ${i}." 1>&2
                {
#                   curl -fsSl -Iw '%{url_effective}' "${artURL}" | tail -n1
                    wget --spider "${artURL}" 2>&1 |
                        sed -nE 's/^--([0-9 :-]+){2}//p' |
                        tail -n1
                } && break
            done
            ((i < (maxScanTry + 2)))  # Fail if max. attempts is reached.
        )"
        eval "$(
            source "${_scrPath}/sh_libs/utils.sh"
            ParseURI "${artURL}" urlSch,,,urlNetPath
        )"

        eCode=0
        [ -n "${mapPath}" ] && {
            prd="$(
                GetMappedName "${PRD_CFG_INF}" .mapping.name.manifest \
                    "${mInfoArr[0]}"
            )"
            [ -n "${PRD_CFG_INF}" ] && {
                eval "$(
                    GetMappingInfo "${PRD_CFG_INF}" "${mapPath}" "${prd}" \
                        'prd prdCfg subPrd' \| || echo "(exit $?)"
                )" || eCode=$?
                case ${eCode} in
                  (0)
                    [ -z "${prd}" ] &&
                        echo 'Skipping Scanning included Manifest.' && exit
                    ;;
                  (254)
                    echo 'Error - Included Manifest level can not have' \
                        "sub-mapping: ${mapPath}.${prd}" 1>&2
                    false
                    ;;
                  (*)   false;;
                esac
                [ "${prdCfg:0:1}" != / ] && {
                    prdCfg="$(cd -L "$(
                        [ "${PRD_CFG_INF:0:1}" != / ] && echo "./"
                    )${PRD_CFG_INF%/*}" 2> /dev/null; pwd)/${prdCfg}"
                    prdCfg="${prdCfg#${PWD}/}"
                }
            }
        }

        eCode=0
        ${xCmd} "
AUTH=\"\${AUTH}\" $(
    typeset -x | grep -E 'BD_CFG__[^=[:space:]]+=' |
        sed -E 's/^((\S+ ){2})//' | tr '\n' ' '
)   PRODUCT='${prd}' SUB_PRODUCT='${subPrd}' \
    ARTIFACT_TYPE='${mInfoArr[1]}' ARTIFACT_URL='${artURL}' \
    PRD_CFG_INF='${prdCfg}' PRJ_MAP_PATH= \
    PRD_NAME= PRD_VER= SVC_NAME= SVC_VER= \
    SCANNER='${SCANNER}' SCNR_PAR='${SCNR_PAR}' \
    BDHUB_URL='${BDHUB_URL}' BDHUB_API_TOKEN=\"\${BDHUB_API_TOKEN}\" \
    OPT_CFG_FILE='${OPT_CFG_FILE}' OPT_XTRA_PAR='${OPT_XTRA_PAR}' \
    '${_scrPath}/${_scrName}' '$((skipParts | skipAll))'
        " || eCode=$?
        case ${urlSch} in
          (file)
            ((eCode)) || ((dryRun)) || mv -f "${pkgLcl}" "${pkgLcl}_"
            ;;
        esac
        ((! eCode))
    done 0<<<"${mList}"
    ;;
  (srcCode)
    : Scanning Source Code - "${SCANNER}".
    typeset appName="${1}"; [ $# != 0 ] && shift

    typeset mapPath= execEnv=
    typeset bdPrjVerNameClone=

    typeset prdName="${eProduct// /-}${eSubProduct:+--"${eSubProduct// /-}"}"
    typeset prdVer="${PRD_VER:-PRD_VER--NotSet}"
    typeset appVer="${SVC_VER:-SVC_VER--NotSet}"
    typeset bdMainVerSch="${BD_CFG___VAR_bdMainVerSch}"
    typeset bdRelVerSch="${BD_CFG___VAR_bdRelVerSch}"
    typeset bdRelVerConv="${BD_CFG___VAR_bdRelVerConv}"
    typeset bdTopMainVerSch="${bdMainVerSch}"
    typeset bdTopRelVerSch="${bdRelVerSch}"
    typeset bdTopRelVerConv="${bdRelVerConv}"

    case ${urlSch} in
      (!(file))
        echo "Error - Unsupported scheme: ${urlSch}" 1>&2
        false
        ;;
    esac

    mapPath=.mapping.products
    prdName="$(
        GetMappedName "${PRD_CFG_INF}" .mapping.name.product "${prdName}"
    )"
    execEnv="$(echo $(
        SetExecEnv "${PRD_CFG_INF}" "${mapPath}.${prdName}"
    ))"
    eval "$(
        ResolvePrjNameVer "${PRD_CFG_INF}" mapPath prdName prdVer ||
            echo "(exit $?)"
    )"
    [ -n "${mapPath}" ] && {
        echo "Error - Product level can not have sub-mapping: ${mapPath}" 1>&2
        false
    }
    [ -z "${prdName}" ] && {
        echo 'Skipping Scanning Product Source Code.'
        exit
    }

    mapPath=.mapping.sourceCodes
    appName="$(
        GetMappedName "${PRD_CFG_INF}" .mapping.name.sourceCode "${appName}"
    )"
    execEnv="$(echo $(
        SetExecEnv "${PRD_CFG_INF}" "${mapPath}.${appName}"
    ))"
    eval "$(ReadCfg "${PRD_CFG_INF}" "${mapPath}.${appName}" '(
        bdMainVerSch:bdMainVerSch
        bdRelVerSch:bdRelVerSch
        bdRelVerConv:bdRelVerConv
    )')"
    eval "$(
        ResolvePrjNameVer "${PRD_CFG_INF}" mapPath appName appVer ||
            echo "(exit $?)"
    )"
    [ -n "${mapPath}" ] && {
        echo "Error - Src. Code level can not have sub-mapping: ${mapPath}" 1>&2
        false
    }
    [ -z "${appName}" ] && {
        appName="${prdName}"; appVer="${prdVer}"
        prdName=; prdVer=
    }

    : Set clone information for Product Source Code: "${appName} - ${prdVer}"
    BDprjVerExist "${appName}" "${appVer}" || {
        bdPrjVerNameClone="$(
            BDgetLatestPrjVer "${appName}" "${appVer}" \
                "${bdMainVerSch}" \
                "${bdRelVerSch}" \
                "${bdRelVerConv}"
        )"
        export BD_CFG__DETECT_CLONE_PROJECT_VERSION_NAME="${bdPrjVerNameClone}"
#   : Create Project Version for Product Source Code: "${appName} - ${prdVer}"
#       ${xCmd} "
#           BDprjVerCreate '${appName}' '${appVer}' '${bdPrjVerNameClone}'
#       "
    }

    ${xCmd} "
AUTH=\"\${AUTH}\" $(
    typeset -x | grep -E 'BD_CFG__[^=[:space:]]+=' |
        sed -E 's/^((\S+ ){2})//' | tr '\n' ' '
)   ARTIFACT_TYPE=lclFile ARTIFACT_URL='file://${urlNetPath}' \
    PRD_CFG_INF='${PRD_CFG_INF}' PRJ_MAP_PATH= \
    PRD_NAME='${prdName}' PRD_VER='${prdVer}' \
    SVC_NAME='${appName}' SVC_VER='${appVer}' \
    SCANNER='${SCANNER}' SCNR_PAR='${SCNR_PAR}' \
    BDHUB_URL='${BDHUB_URL}' BDHUB_API_TOKEN=\"\${BDHUB_API_TOKEN}\" \
    OPT_CFG_FILE='${OPT_CFG_FILE}' OPT_XTRA_PAR='${OPT_XTRA_PAR}' \
    ${execEnv} \
    '${_scrPath}/${_scrName}' '$((skipParts | skipAll))'
    "

    : Clean up Project Version for Project Version: "${appName} - ${bdPrjVerNameClone}"
    BDcleanUpPrjVer "${appName}" "${bdPrjVerNameClone}" \
        "${bdMainVerSch}" "${bdRelVerSch}" "${bdRelVerConv}" \
        "${prdName:-*}" \
        "${bdTopMainVerSch}" "${bdTopRelVerSch}" "${bdTopRelVerConv}"
    ;;
esac
true
