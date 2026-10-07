#!/bin/bash
typeset _scrName="${BASH_SOURCE[0]##*/}"
typeset _scrPath="$(CDPATH= \command cd -L "${BASH_SOURCE[0]%/*}" 2> /dev/null;\command pwd)"
typeset _useMsg=;
while read -rd '' _useMsg; do :; done 0<<'_useMsg-EOF'
Inventory all Open Source items for Licensing.

Usage:
    osl-inventory.sh [-i] [-s PHASES] ARCHIVE METADATA SCNR_LIST OSM_PARS
        MAX_REC

Where:
    -i  Install required tools.
    -s  Skip certain phases.
        This option may be given multiple times.
        PHASES  List (comma delimited) of phases to be skipped.
                Format:
                    X,Y-Z...
                        X    -> Skip phase X.
                        Y-Z  -> Skip phases Y to Z (inclusively).
                Phases:
                  1  -> Scan archive for container images.
                  2  -> Process METADATA:
                          - Store container images from METADATA locally.
                          - Fetch OSL Manifest.
                  3  -> Do scan on the reduced of archive.
                  4  -> Do scan on identified container images.
                  5  -> Upload to OSM Server.
    ARCHIVE     Top level archive (or directory path) to scan.
    METADATA    Path to the file (in YAML) containing the extra information.
                Used in phase 2.
                File content:
                    images: # List of container images.
                      - [HOST[:PORT]]/[NAMESPACE]/REPOSITORY(:TAG|@DIGEST)
                      - ...
                    oslManifestURLs:    # [Optional]
                      # List of URL of OSL Manifest (Inventory Report).
                      [HOST[:PORT]]/[NAMESPACE]/REPOSITORY(:TAG|@DIGEST):
                        - URL
                        - ...
                      ...
    SCNR_LIST   OSSPI Scanners to use (`|` delimited).
                Used in phase 3-4.
                Format:
                    ARCHIVE_SCNRS|CONTAINER_SCNRS
                Where:
                    ARCHIVE_SCNRS       List (comma delimited) of OSSPI Scanners
                                        to use during phase 3.
                        binary       -> Use `osspi scan binary` (default).
                        signature    -> Use `osspi scan signature`.
                    CONTAINER_SCNRS     List (comma delimited) of OSSPI Scanners
                                        to use during phase 4.
                        docker       -> Use `osspi scan docker` (default).
                        binary       -> Use `osspi scan binary`.
                        signature    -> Use `osspi scan signature`.
    OSM_PARS    Parameter to `osstp-load` utility (`|` delimited).
                Used in phase 5.
                Format:
                    KEY|[SERVER]|CT_LIST|REL_INFO|INTERACTION
                Where:
                    KEY         Key string (`USER@DOMAIN KEY`).
                    SERVER      Name of OSM Server.
                        production   -> Alias to official OSM Server
                                        (default).
                        beta         -> Alias to beta OSM Server.
                        URL          -> URL of the OSM Server.
                    CT_LIST     The `ct-tracker` id list (comma
                                delimited).
                        Format:
                            OS_NAME:CT_TICKET[,...]
                                OS          Base OS name.
                                CT_TICKET   The `ct-tracker` ticket.
                    REL_INFO    OSM Release name and version.
                        Format:
                            NAME/VERSION
                                NAME    OSM Release name.
                                VERSION OSM Release version.
                    INTERACTION Default Interaction Type for all packages.
    MAX_REC     Max. no. of records in an OSL Manifest file. If the generated
                manifest file has more record than this setting, it will be
                split and indexed with `-00000` suffix (default: 100).
_useMsg-EOF

set -o pipefail
shopt -s extglob


typeset gCLIdir=__bin
typeset gTARextLst='\.t(bz|gz|lz(ma)?|xz|zo|ar(\.(bz2|gz|lz(ma)?|xz|lzo))?)'


function CleanUpEmptySubDirs() {
    typeset dir="${1%%/}"; [ $# != 0 ] && shift; : "${dir:=/}"

    find -L "${dir}/" -mindepth 1 -type d -exec bash -exc '
        [ -z "$(find -L "{}/" ! -type d)" ] && rm -rf "{}/"
    ' \; -prune
}

function DLctImgAoslMan() {
    ########
    # Pull container image from registry and save it locally as docker archive.
    # Fetch OSL Manifest.
    #
    # Args:
    #   mdPath: See `METADATA` in `_useMsg`.
    #   imgDir: Directory to store container images.
    #   oslDir: Directory to store OSL Manifest files.
    ########
    typeset mdPath="${1%%/}"; [ $# != 0 ] && shift; : "${mdPath:=/}"
    typeset imgDir="${1%%/}"; [ $# != 0 ] && shift; : "${imgDir:=/}"
    typeset oslDir="${1%%/}"; [ $# != 0 ] && shift; : "${oslDir:=/}"

    yq eval '.images[] | select(. == "?*")' "${mdPath}" |
        xargs -d\\n -I'{}' bash -exc "
            _fail_xargs() { exit 255; }; trap _fail_xargs ERR
            : Processing: '{}'
            typeset cliDir='${gCLIdir}'
            typeset imgDir='${imgDir}'
            typeset imgReg='{}'"'
            # Replace `/` with `#` AND `tag` or `digest` separator with `%`.
            typeset imgLcl="${imgReg////#}"; imgLcl="${imgLcl//:/%}.tar"

            mkdir -p "${imgDir}"
            [ -f "${imgDir}/${imgLcl}" ] ||
                "${cliDir}/osspi/bin/crane" pull "${imgReg}" \
                    "${imgDir}/${imgLcl}" --format legacy
        '

    yq eval '.oslManifestURLs[][] | select(. == "?*")' "${mdPath}" |
        xargs -d\\n -I'{}' bash -exc "
            _fail_xargs() { exit 255; }; trap _fail_xargs ERR
            : Processing: '{}'
            typeset oslDir='${oslDir}'
            typeset oslRmt='{}'"'
            # Remove URL Scheme.
            typeset oslLcl="${oslRmt#*://}"; {
                # Replace `/` with `#` AND `:` with `%`.
                oslLcl="${oslLcl////#}"; oslLcl="${oslLcl//:/%}"
            }

            mkdir -p "${oslDir}"
            wget -O "${oslDir}/oslScan--${oslLcl}" "${oslRmt}"
        '
}

function DoOSLscan() {
    ########
    # Perform OSL scan using OSSPI CLI.
    #
    # Args:
    #   scanType:       Type of scan should be performed.
    #                       binary       -> Binary scan on archives.
    #                       signature    -> Signature scan on archives.
    #                       docker       -> Docker scan on archives.
    #   oslMnfstDir:    Directory to store OSL Manifest files.
    #   imgPath:        Path of the container image.
    #   maxRec:         See `MAX_REC` in `_useMsg`.
    ########
    typeset scanType="${1}"; [ $# != 0 ] && shift
    typeset oslMnfstDir="${1%%/}"; [ $# != 0 ] && shift; : "${oslMnfstDir:=/}"
    typeset imgPath="${1%%/}"; [ $# != 0 ] && shift; : "${imgPath:=/}"
    typeset -i maxRec="${1:-100}"; [ $# != 0 ] && shift

    typeset scanReqScript="$(
        cat - 0<<'DoOSLscan-EOF'
: Processing: '{}'
typeset _scrPath="$0"
typeset cliDir="${1}"; [ $# != 0 ] && shift
typeset oslMnfstDir="${1}"; [ $# != 0 ] && shift
typeset imgPath="${1}"; [ $# != 0 ] && shift
typeset -i maxRec="${1}"; [ $# != 0 ] && shift
typeset scanner="${1}"; [ $# != 0 ] && shift

typeset mFN= mFP= baseOS= tmpDir=
typeset -i phase=1 skipScan=0

typeset url='{}'

mFN="${url#${imgPath}/}"    # Strip top parent directories.
case ${scanner} in
  (binary|docker)
    [ "${imgPath: -4}" = .sup ] && mFN="${mFN%.tar}"
    ;;
  (signature)
    mFN="./${mFN}"  # In case the `mFN` does not have directories.
    [ "${imgPath:0:1}" = / ] && {
        tmpDir="${imgPath:1}"
        tmpDir="${tmpDir%%/*}"; [ "${tmpDir}" = "/${imgPath}" ] && tmpDir=/
    } || {
        tmpDir="${imgPath%%/*}"; [ "${tmpDir}" = "${imgPath}" ] && tmpDir=
    }
    tmpDir="${tmpDir}/__wrk"; mkdir -p "${tmpDir}/${mFN%/*}"
    mFN="${mFN#./}" # Restore `mFN`.
    ln -f "${url}" "${tmpDir}/${mFN}"
    url="${tmpDir}"
    [ "${imgPath: -4}" = .sup ] && mFN="${mFN%.tar}"
    ;;
esac

mkdir -p "${oslMnfstDir}"
while ((phase)); do
    case ${phase} in
      (1)
        : Phase ${phase} - OSL Scan: ${scanner} - ${url}
        ((phase++))
        mFN="${oslMnfstDir}/oslScan--${mFN////#}--report-${scanner}"
        mFP="${mFN}.manifest"
        # Skip if the corresponding Scan Result is already exist.
        [ -n "$(find -L "${oslMnfstDir}/" -path "${mFN}*")" ] && skipScan=1 &&
            continue
        "${_scrPath}/inspector_gadget.py" \
            osspi-scan osm \
            --scanner "${scanner}" --artifact-url "${url}" \
            --output "${mFN}" \
            "${cliDir}/osspi/osspi" ""
        ;;
      (2)
        : Phase ${phase} - Detect \`baseos\`: ${mFP}
        ((phase++))
        [ -n "${tmpDir}" ] && rm -rf "${tmpDir}/"
        # Some time the Scan failed but no error indication. So check in here
        #   that if the Scan is not skipped, the OSL Scan Result must exist.
        ((skipScan)) || [ -f "${mFP}" ]
        [ -f "${mFP}" ] || {
            # Recombine split Scan Result.
            find -L "${oslMnfstDir}/" -path "${mFN}*" |
                grep -E -- '--report-[^-.]+(-[^-.]+)?--[0-9]+\.manifest$' |
                sort | xargs -d\\n -I{''} bash -exc '
                    _fail_xargs() { exit 255; }; trap _fail_xargs ERR
                    f="{''}"
                    cat "${f}" 1>> "${f%--*.manifest}.manifest"
                    rm "${f}"
                '
        }
        {
            # Skip if the corresponding Scan Result with detected `baseos` is
            #   already exist.
            [ -f "${mFP}" ] || {
                mFP="$(find -L "${oslMnfstDir}/" -path "${mFN}-*")"
                mFN="${mFP%.manifest}"
                false
            }
        } && {
            baseOS="$(
                yq eval \
                    '
                        .[[
                            (keys | .[] | select(. == "baseos:*"))
                        ][0]] | select(. != null) | .baseos-osname
                    ' \
                    "${mFP}"
            )"
            [ -n "${baseOS}" ] && {
                mv "${mFN}.manifest" "${mFN}-${baseOS}.manifest"
                mFN="${mFN}-${baseOS}"; mFP="${mFN}.manifest"
            }
        }
        ;;
      (3)
        : WORKAROUNDS: Handling issues with upstream tools.
        ((phase++))
        typeset pattern1= pattern2=

        :   Fix malform URL.
        pattern1='^\s+url: [^:]+(:[0-9]+\/.*)?$'
        pattern2='^\s+url: (null|'\'\''|"")$'
        [ -n "$(
            # Missing URL Scheme
            grep -E "${pattern1}" "${mFP}" |
            # Not `null` YAML value
            grep -vE "${pattern2}"
        )" ] &&
            sed -E -i \
                `# If YAML :null: then jump to the end.` \
                -e "/${pattern2}/b" \
                `# Add :https: URL Scheme assumed default.` \
                -e "/${pattern1}/"'s|^([^:]+: ['\''"]?)(.*)$|\1http://\2|' \
                "${mFP}"

        :   Split the Scan Result if it is too big.
        pattern1='^(\w|['\''"])'
        ((
            $(
                grep -cE "${pattern1}" "${mFN}.manifest"
            ) > maxRec
        )) && {
            awk -v maxRec=${maxRec} -v mPfxFN="${mFN}" '
                BEGIN {
                    i=0; c=0
                    mFN=mPfxFN"--"sprintf("%05d", c)
                }
                /'"${pattern1}"'/ {
                    if (++i > maxRec) {
                        i=1; c++
                        mFN=mPfxFN"--"sprintf("%05d", c)
                    }
                }
                    {print > mFN".manifest"}
            ' "${mFP}"
            rm "${mFP}"
        }
        ;;
      (*)
        phase=0
        ;;
    esac
done
DoOSLscan-EOF
    )"

    : Do OSL Scan: ${scanType}
    find -L "${imgPath}/" -type f \( \
        -exec bash -exc "${scanReqScript}" "${_scrPath}" \
            "${gCLIdir}" "${oslMnfstDir}" "${imgPath}" ${maxRec} \
            "${scanType}" \; -o \
        \( -exec false '{}' + -quit \) \
    \)
}

function ExtractCtrImg() {
    ########
    # Extract container image from an archive and save it locally as docker
    # archive.
    #
    # Args:
    #   arcType:    Type of the archive.
    #               Supported type:
    #                 - imgpkg
    #   arcDir:     Top level directory of the archives.
    #   imgDir:     Directory to store the container images.
    ########
    typeset arcType="${1}"; [ $# != 0 ] && shift
    typeset arcDir="${1%%/}"; [ $# != 0 ] && shift; : "${arcDir:=/}"
    typeset imgDir="${1%%/}"; [ $# != 0 ] && shift; : "${imgDir:=/}"

    typeset extractScript="$(
        cat - 0<<'ExtractCtrImg-EOF'
: Processing: '{}'
typeset arcType="${1}"; [ $# != 0 ] && shift
typeset imgDir="${1}"; [ $# != 0 ] && shift
typeset cliDir="${1}"; [ $# != 0 ] && shift

typeset arcFile='{}'

mkdir -p "${imgDir}"
case ${arcType} in
  (imgpkg)
    typeset regSvrName="registry--$(pwd -P)"; regSvrName="${regSvrName////_}"
    typeset e= regIP= regImgPkg= imgNames= imgReg= imgLcl=
    typeset -i isBundle=1

    (
        docker inspect --type container -f ' ' "${regSvrName}" 1> /dev/null 2>&1
    ) && {
        docker container stop "${regSvrName}"
        docker container rm "${regSvrName}"
    }
    docker container run -d --restart=always --name "${regSvrName}" \
        -e REGISTRY_STORAGE_DELETE_ENABLED=true \
        harbor-repo.vmware.com/dockerhub-proxy-cache/library/registry:latest
    regIP="$(
        docker container inspect \
            -f '{{.NetworkSettings.Networks.bridge.IPAddress}}' "${regSvrName}"
    )"
    regImgPkg="$(
        tar xOf "${arcFile}" manifest.json |
        jq -r '
            .[] | select(
                .Image.Labels["dev.carvel.imgpkg.copy.root-bundle"] != null
            ) | .Image.Refs[0]
        '
    )"  # First assume the imgpkg archive is a bundle.
    [ -z "${regImgPkg}" ] && {
        # The imgpkg archive contains only an image.
        isBundle=0
        imgReg="$(
            tar xOf "${arcFile}" manifest.json |
            jq -r '
                "\(.[0].Image.Refs[0] | split(":")[0] | split("@")[0])" +
                ":\(.[0].Image.Tag)"
            '
        )"
        regImgPkg="${imgReg%%:*}"
    }
    imgpkg copy --tar "${arcFile}" --to-repo "${regIP}:5000/${regImgPkg%%@*}"
    if ((isBundle)); then
        imgNames="$(
            imgpkg describe -b "${regIP}:5000/${regImgPkg}" \
                --output-type yaml |
            yq eval '
                .content.images.[] | select(.imageType == "Image") |
                [.image, .origin] | join(",")
            '
        )"
    else
        imgNames="${regIP}:5000/${imgReg},${imgReg}"
    fi
    for e in ${imgNames}; do
        imgReg="$(echo "${e}" | cut -d, -f1)"
        imgLcl="$(echo "${e}" | cut -d, -f2)"
        imgLcl="${imgLcl////#}"; imgLcl="${imgLcl//:/%}.tar"
        [ -f "${imgDir}/${imgLcl}" ] ||
            "${cliDir}/osspi/bin/crane" pull "${imgReg}" \
                "${imgDir}/${imgLcl}" --format legacy
    done
    docker container stop "${regSvrName}"
    docker container rm "${regSvrName}"
    ;;
  (*)
    echo "Unsupported Archive Type: ${arctype}"
    ;;
esac
ExtractCtrImg-EOF
    )"

    : Extract Container Images: ${arcType}
    find -L "${arcDir}/" -type f \( \
        -exec bash -exc "${extractScript}" '' \
            "${arcType}" "${imgDir}" "${gCLIdir}" \; -o \
        \( -exec false '{}' + -quit \) \
    \)
}

function FindImgInTar() {
    ########
    # Scan the given archive for images and extract them.
    #
    # Supported images:
    #   - Docker
    #   - ImgPkg
    #
    # It will inspect the content of the archive and perform a recursive scan
    # then pull the images out, if any, and remove them from the archive.
    #
    # Any (sub-)archive that does not contain any image will be left as is
    # (un-extracted).
    #
    # Args:
    #   tarPath:    See `ARCHIVE` in `_useMsg`.
    #   unTar:      If the (sub-)archive contain any image, whether to re-create
    #               the archive without those images or leave it unpacked.
    #                    0   -> Re-create the archive (default).
    #                   !0   -> Leave it unpacked.
    #   chkSelf:    Whether to check the `tarPath` first before recursing to it.
    #               Only valid if `tarPath` is an archive.
    #                    0   -> Do not check `tarPath` (default).
    #                   !0   -> Check `tarPath`.
    ########
    set -e
    typeset tarPath="${1%%/}"; [ $# != 0 ] && shift; : "${tarPath:=/}"
    typeset -i unTar="${1}"; [ $# != 0 ] && shift
    typeset -i chkSelf="${1}"; [ $# != 0 ] && shift

    typeset i= modTar= sub= subTar= subTarDir= subTarList=
    typeset -i exitStat=0 found=0 phase=1 rmSubTar=0 tarPathNoDel=0
    typeset -a subsToAdd=() subsToRmv=()

    typeset rootDir="${tarPath%/*}"; [ "${rootDir:=/}" != / ] && [ \
        "${rootDir}" = "${tarPath}" \
    ] && rootDir=.
    typeset parent="${tarPath##*/}"; : "${parent:=.}"

    if [ -d "${tarPath}" ]; then
        tarPathNoDel=1
        pushd "${rootDir}/"
        # Skip direct sub-directory with leading `__` as the internal
        #   working sub-directory structures are prefixed with it.
        typeset subTarList="$(
            find -L "${parent}/" ! -path "${parent}/__*" |
            sed -nE "/${gTARextLst}$/ s|^${parent}/||p"
        )"
        popd
        [ "${parent}" != . ] && { rootDir="${rootDir}/${parent}"; parent=.; }
    elif ((chkSelf)); then
        tarPathNoDel=1
        subTarList="${parent}"
        parent=.
    else
        typeset subTarList="$(tar tf "${tarPath}" | grep -E "${gTARextLst}\$")"
    fi

    : Processing "[${PWD}]: ${tarPath}"
    pushd "${rootDir}/"
    mkdir -p __img __tar __wrk
    while read -r sub; do
        [ -z "${sub}" ] && continue
        rmSubTar=0
        subTar="${parent}/${sub}"
        subTarDir="${subTar%/*}"
        mkdir -p "__wrk/${parent}"
        if ((tarPathNoDel)); then
            mkdir -p "__wrk/${subTarDir}"
            mv "${sub}" "__wrk/${subTarDir}"
            i="${sub%%/*}"
            [ -d "${i}" ] && CleanUpEmptySubDirs "${i}" &&
                [ -z "$(find -L "${i}/" -mindepth 1)" ] && rmdir "${i}"
        else
            tar xvf "${parent}" -C "__wrk/${parent}/" "${sub}"
            chmod -R u+w "__wrk/${parent}/"
        fi
        phase=1
        while ((phase)); do
            case ${phase} in
              (1)
                : Phase ${phase} - Check for docker image \
                    "[${PWD}]: __wrk/${subTar}"
                set +e
                exitStat=0; IsDockerImg "__wrk/${subTar}"; exitStat=$?
                set -e
                if ((exitStat)); then
                    : Not docker image "[${PWD}]: __wrk/${subTar}"
                    ((phase++))
                else
                    : Docker image "[${PWD}]: __wrk/${subTar}"
                    found=1; rmSubTar=1; phase=0
                    :   Move container image to \`__img/docker/\`.
                    mkdir -p __img/docker
                    MergeDir __wrk/ __img/docker/
                fi
                ;;
              (2)
                : Phase ${phase} - Check for ImgPkg image \
                    "[${PWD}]: __wrk/${subTar}"
                set +e
                exitStat=0; IsImgPkg "__wrk/${subTar}"; exitStat=$?
                set -e
                if ((exitStat)); then
                    : Not ImgPkg image "[${PWD}]: __wrk/${subTar}"
                    ((phase++))
                else
                    : ImgPkg image "[${PWD}]: __wrk/${subTar}"
                    found=1; rmSubTar=1; phase=0
                    :   Move container image to \`__img/imgpkg/\`.
                    mkdir -p __img/imgpkg
                    MergeDir __wrk/ __img/imgpkg/
                fi
                ;;
              (*)
                : Phase ${phase} - Recursive check "[${PWD}]: __wrk/${subTar}"
                phase=0
                set +e
                exitStat=0; FindImgInTar "__wrk/${subTar}" ${unTar}; exitStat=$?
                set -e
                if ((exitStat)); then
                    : No image has been found in "[${PWD}]: __wrk/${subTar}"
                    :   The \`subTar\` has not been modified, move it to \
                            \`__tar/\` if processing directory, otherwise \
                            discard it.
                    if ((tarPathNoDel)); then
                        mkdir -p "__tar/${subTarDir}"
                        mv "__wrk/${subTar}" "__tar/${subTarDir}/"
                    else
                        rm -f "__wrk/${subTar}"
                    fi
                else
                    : Some images have been found in "[${PWD}]: __wrk/${subTar}"
                    found=1; rmSubTar=1
                    :   Move found images to \`__img/\`.
                    for i in \
                        __img/{docker,imgpkg} \
                    ; do
                        [ -d "__wrk/${subTarDir}/${i}" ] && {
                            mkdir -p "${i}/${subTarDir}"
                            MergeDir "__wrk/${subTarDir}/${i}/" \
                                "${i}/${subTarDir}/"
                        }
                    done
                    :   The \`subTar\` has been modified, move or unpack it to \
                            \`__tar/\`.
                    if ((unTar)); then
                        mkdir -p "__tar/${subTar}"
                        tar xvf "__wrk/${subTar}" -C "__tar/${subTar}/"
                        chmod -R u+w "__tar/${subTar}/"
                        rm -f "__wrk/${subTar}"
                    else
                        if [ -n "$( # Check if archive contains any file.
                            tar tf "__wrk/${subTar}" | grep -vE '/$'
                        )" ]; then
                            mkdir -p "__tar/${subTarDir}"
                            mv "__wrk/${subTar}" "__tar/${subTarDir}/"
                        fi
                    fi
                    :   Move extracted files to \`__tar/\`.
                    MergeDir "__wrk/${subTarDir}/__tar/" "__tar/${subTarDir}/"

                    CleanUpEmptySubDirs __wrk/
                    for i in \
                        "__wrk/${subTarDir}/"{__img{/docker,/imgpkg,},__tar} \
                    ; do
                        :   Removing directory "[${PWD}]: ${i}/"
                        [ -e "${i}" ] && {
                            if [ -z "$(find -L "${i}/" -mindepth 1)" ]; then
                                rmdir "${i}"
                            else
                                echo "Error: Directory is not empty: ${i}/"
                                return 1
                            fi
                        }
                    done
                fi
                ;;
            esac
        done
        [ "${parent}" != . ] && rm -rf "__wrk/${parent}/"
        ((rmSubTar)) && ((! tarPathNoDel)) && {
            subsToRmv+=("${sub}")
            ((! unTar)) && [ -e "__tar/${parent}/${sub}" ] &&
                subsToAdd+=("${sub}")
        }
    done <<< "${subTarList}"
    if ((found)); then
        ((${#subsToRmv[@]})) && ModTar "${parent}" 0 "${subsToRmv[@]}"
        ((${#subsToAdd[@]})) && {
            pushd "__tar/${parent}/"
            modTar="../../${parent}"
            ModTar "${modTar}" 1 "${subsToAdd[@]}"
            popd
        }
        CleanUpEmptySubDirs __tar/
    else
        rmdir __img
        ((tarPathNoDel)) || rm -rf __tar/
    fi
    rmdir __wrk
    popd
    : Completed "[${PWD}]: ${tarPath}"

    set +e
    ((found))
}

function IsDockerImg() {
    set -e
    typeset imgPath="${1}"; [ $# != 0 ] && shift

    typeset -i found=0 phase=1

    while ((phase)); do
        case ${phase} in
          (1)
            : Phase ${phase} - Test using \`docker image load\`.
            typeset imgName="$(
                docker image load -qi "${imgPath}" 2> /dev/null |
                sed -ne 's/^Loaded image: //p'
            )"
            if [ -n "${imgName}" ]; then
                found=1; phase=0
                docker image rm "${imgName}" 1> /dev/null
                # The upstream tooling can not handle compressed archive.
                typeset imgFileType="$(file -b --mime-type "${imgPath}")"
                case ${imgFileType} in
                  (application/x-tar);;
                  (application/gzip)
                    gunzip "${imgPath}"
                    ;;
                  (*)
                    echo "Unsupported archive type (${imgFileType}): ${imgPath}"
                    return 1
                    ;;
                esac
            else
                ((phase++))
            fi
            ;;
          (*)
            phase=0
            ;;
        esac
    done

    set +e
    ((found))
}

function IsImgPkg() {
    set -e
    typeset imgPath="${1}"; [ $# != 0 ] && shift

    typeset -i found=0 phase=1

    while ((phase)); do
        case ${phase} in
          (1)
            : Phase ${phase} - Check the name pattern of the content.
            # Content of an `imgpkg` image:
            #   manifest.json
            #   sha256-0a02fbe90943440971a40646e455fd1d4b4dbde4f2afccaf02875c9834e39924.tar.gz
            #   sha256-1c83e9acc099900b7feb89d994f15a3129530e58e8e96c697e3708e4ad057d3d.tar.gz
            #   sha256-d1a69a5a4f2922733a349b59866986724971445ee76ea89edcb546c3dafe68bf.tar.gz
            if (
                mnfstPat='manifest\.json'
                filesPat='sha[0-9]+-[0-9a-f]+\.tar\.gz'
                f="$(tar tf "${imgPath}")"
                [ -n "$(
                    echo "${f}" | grep -E "^${mnfstPat}\$"
                )" ] && [ -n "$(
                    echo "${f}" | grep -E "^${filesPat}\$"
                )" ] && [ -z "$(
                    echo "${f}" | grep -vE "^(${mnfstPat}|${filesPat})\$"
                )" ]
            ); then
                found=1; phase=0
            else
                ((phase++))
            fi
            ;;
          (*)
            phase=0
            ;;
        esac
    done

    set +e
    ((found))
}

function MergeDir() {
    typeset src="${1%%/}"; [ $# != 0 ] && shift; : "${src:=/}"
    typeset tgt="${1%%/}"; [ $# != 0 ] && shift; : "${tgt:=/}"

    find -L "${src}/" -mindepth 1 \( \
        \( \
            -type d \( \
                -exec bash -exc "
                    : 'Moving directory: {}/'
                    src='${src}' tgt='${tgt}'"'
                    f="{}"; f="${f#${src}/}"                                    # Strip prefix `src` directory.
                    d="${f%/*}"; [ "${d}" = "${f}" ] && d=.                     # Get parent directory.
                    [ ! -e "${tgt}/${f}" ] && mv "${src}/${f}" "${tgt}/${d}/"   # Move if directory does not exist in `dst`.
                ' \; -a \
                -prune -o \
                -exec bash -exc "
                    : 'Check destination for: {}/'
                    src='${src}' tgt='${tgt}'"'
                    f="{}"; f="${f#${src}/}"                                    # Strip prefix `src` directory.
                    d="${f%/*}"; [ "${d}" = "${f}" ] && d=.                     # Get parent directory.
                    [ -d "${tgt}/${f}" ] || {                                   # Ensure it is a directory in `dst`.
                        echo "Error: File (non-directory) exist: ${tgt}/${f}"
                        exit 1
                    }
                ' \; \
            \) \
        \) -o \
        \( \
            ! -type d -exec bash -exc "
                : 'Moving file: {}'
                src='${src}' tgt='${tgt}'"'
                f="{}"; f="${f#${src}/}"                                        # Strip prefix `src` directory.
                d="${f%/*}"; [ "${d}" = "${f}" ] && d=.                         # Get parent directory.
                [ -e "${tgt}/${f}" ] && {                                       # Move if file does not exist in `dst`.
                    echo "Error: File exist: ${tgt}/${f}"
                    exit 1
                } || mv "${src}/${f}" "${tgt}/${d}/"
            ' \; \
        \) -o \
        \( -exec false '{}' + -quit \) \
    \)

    find -L "${src}/" -mindepth 1 -maxdepth 1 \( \
        -exec bash -exc '
            f="$(find -L "{}" ! -type d)"
            {
                [ -z "${f}" ] || {
                    echo -e "Error: Directory is not empty:\n${f}"
                    exit 1
                }
            } && rm -rf "{}/"
        ' \; -o \( -exec false '{}' + -quit \) \
    \)
}

function ModTar() {
    typeset parent="${1}"; [ $# != 0 ] && shift
    typeset -i action="${1}"; [ $# != 0 ] && shift

    typeset args= tarName=
    typeset -i execCmd=0

    typeset tarExt="$(echo "${parent}" | sed -nE "s/^.*(${gTARextLst})$/\1/p")"
    typeset -i maxArgs="$((
        $(
            xargs --show-limits 0< /dev/null |&
            sed -nE '/^Size of command buffer/ s/^[^:]+: //p'
        ) - 1024
    ))"

    args=
    while (($#)); do
        execCmd=0
        # The length of ` ''` is 3.
        if ((${#args} + ${#1} + 3 > maxArgs)); then
            execCmd=1
        else
            ((${#} == 1)) && execCmd=2
            [ -n "${1}" ] && args+=" '${1}'"
        fi
        if ((execCmd)); then
            [ -n "${args}" ] && {
                ((action)) && args="--append${args}" || args="--delete${args}"
            }
            case ${tarExt} in
              (.tar)
                eval "tar f '${parent}' ${args}"
                ;;
              (.tgz|.tar.gz)
                [ -z "${tarName}" ] && {
                    tarName="$(
                        gzip -ql "${parent}" |
                        sed -nE 's/^([[:space:]]*(-)?[0-9]+){3}\.?[0-9]% //p'
                    )"
                    gzip -d "${parent}"
                }
                eval "tar f '${tarName}' ${args}"
                ((execCmd == 2)) && {
                    gzip -c "${tarName}" 1> "${parent}"
                    rm "${tarName}"
                }
                ;;
              (*)
                echo "Error: Unsupported compression: ${tarExt}"
                return 1
                ;;
            esac
            ((action)) && eval "rm ${args#--* }"    # Remove added files.
            args=
            ((execCmd == 2)) && shift
        else
            shift
        fi
    done
}

function UL2OSM() {
    typeset oslMnfstDir="${1%%/}"; [ $# != 0 ] && shift; : "${oslMnfstDir:=/}"
    typeset osmPars="${1}"; [ $# != 0 ] && shift

    typeset i=
    typeset -a osmArgs=()

    typeset ulScript="$(
        cat - 0<<'UL2SOM-EOF'
set -o pipefail
shopt -s extglob

: Processing: '{}'
typeset cliDir="${1}"; [ $# != 0 ] && shift
typeset key="${1}"; [ $# != 0 ] && shift
typeset server="${1:-production}"; [ $# != 0 ] && shift
typeset ctList="${1}"; [ $# != 0 ] && shift
typeset relInfo="${1}"; [ $# != 0 ] && shift
typeset interaction="${1}"; [ $# != 0 ] && shift

typeset e=
typeset -i ctTrkID=
typeset -a a1=() a2=()
typeset -Ai ctTrk=()

typeset mFP='{}'
typeset os="$(
    echo "${mFP}" |
    sed -E \
        `# mFP: ...--report-SCAN_TYPE[-OS][--00000].manifest` \
        -e 's/.*--report-[^-]+(-([^-].*)|--.+)?\.manifest$/\2/' \
        `# Remove split Scan Result index, if any.` \
        -e 's/--[0-9]+$//'
)"

# Skip if the manifest file has no entry.
[ "$(yq eval 'keys' "${mFP}")" = "[]" ] && {
    mv -f "${mFP}" "${mFP%/*}/_${mFP##*/}"
    exit 0
}

# Create `ct-tracker` array.
IFS=, read -ra a1 <<< "${ctList}"
for e in "${a1[@]}"; do
    IFS=: read -ra a2 <<< "${e}"
    eval "ctTrk+=(['${a2[0]}']='${a2[1]}')"
done

# Create temporary credential file.
exec 9<> __credFile; rm -f __credFile
echo "${key}" 1>&9

[ -n "${os}" ] && {
    if [ -n "${ctTrk["${os}"]}" ]; then
        ctTrkID="${ctTrk["${os}"]}"
    else
        echo "Error: Unsupported OS: ${os}"
        exit 1
    fi
}
e="$(
     PYTHONUNBUFFERED=1 "${cliDir}/osstp-load" \
        -F -A <({ cat /dev/stdin; } 0<&9) -S "${server}" \
        ${os:+--baseos-ct-tracker "${ctTrk["${os}"]}"} --baseos-append \
        -R "${relInfo}" "${mFP}" |
#   Temporary workaround. See https://jira.eng.vmware.com/browse/TCX-4864.
#       -R "${relInfo}" -I "${interaction}" "${mFP}" |
    # [otc-00023]: Warning: Can't create the BaseOS package
    #   "baseos:rpm:<pkgName>:<pkgVer>:<osName>" since there is no source
    #   bundle provided. Please ensure the source bundle is available in
    #   directory specified by --baseos-srcdir
    tee >(grep -E '^\[otc-00023\]:') 1>&2
)" && {
    [ -z "${e}" ] || {
        if [[ "${e}" == '[otc-00023]'* ]]; then
            echo "Contact OSM Team to create \`${os}\` BaseOS package \`$(
                echo "${e}" | sed -nE 's/^[^"]+"([^"]*)".*/\1/p'
            )\`."
        fi
        exit 1
    }
} && mv -f "${mFP}" "${mFP%/*}/_${mFP##*/}"
UL2SOM-EOF
    )"

    IFS=\| read -ra osmArgs <<< "${osmPars}"
    find -L "${oslMnfstDir}/" -type f -name 'oslScan--*' \( \
        -exec bash -exc "${ulScript}" '' "${gCLIdir}" "${osmArgs[@]}" \; -o \
        \( -exec false '{}' + -quit \) \
    \)

    # Close temporary credential file.
    exec 9<&-
}

function Main() {
    typeset opts= sArg=
    while getopts 'his:' opts; do
        case ${opts} in
          (h)
            echo "${_useMsg}"; return 0
            ;;
          (i)
            : Install required tools.
            mkdir -p "${gCLIdir}"
            OSSPI_HOME="${gCLIdir}" "${_scrPath}/inspector_gadget.py" \
                install-osspi \
                'https://packages.vcfd.broadcom.net/osspicli-local/beta/osspicli/install.sh'
            curl -fsSL 'https://osm.eng.vmware.com/utilities/osstpclients3.tar.bz2' |
                tar xj -C "${gCLIdir}/" --strip-components 3 \
                    bin/client_executables/linux-amd64/osstp-load
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

    typeset topLvlTar="${1%%/}"; [ $# != 0 ] && shift; : "${topLvlTar:=/}"
    typeset metadata="${1}"; [ $# != 0 ] && shift
    typeset scnrList="${1:-|}|"; [ $# != 0 ] && shift
    typeset osmPars="${1}|"; [ $# != 0 ] && shift
    typeset -i maxRec="${1:-100}"; [ $# != 0 ] && shift
    typeset -i unTar="${1}"; [ $# != 0 ] && shift     # Debug option.
    typeset -i chkSelf="${1}"; [ $# != 0 ] && shift   # Debug option.

    typeset e= imgPath=
    typeset -i i=0 exitStat=0 phase=1 skipPhaseBM=0
    typeset -ai skipPhases=()

    typeset -a osspiScnrs=(
        binary
        signature
        docker
    )
    IFS=\| read -ra scnrList <<< "${scnrList}"
    for i in ${!scnrList[@]}; do
        if [ -z "${scnrList[${i}]}" ]; then
            case ${i} in
              (0)   scnrList[${i}]=binary;;
              (1)   scnrList[${i}]=docker;;
            esac
                scnrList[${i}]=${scnrList[${i}]//,/ }
        else
            scnrList[${i}]=${scnrList[${i}]//,/ }
        fi
    done
    typeset imgpkgDir="${topLvlTar}/__img/imgpkg"
    typeset oslMnfstDir="${topLvlTar}/__oslMnfst"

    IFS=, read -ra skipPhases <<< "${sArg}"
    for i in "${skipPhases[@]}"; do
        ((i > 0)) && ((skipPhaseBM |= (1 << (i-1))))
    done

    # The `set -e` is ignored if the function call is part of conditional
    #   expression, such as `if FUNC; then ... fi` or `FUNC || ...`.
    set -ex
    while ((phase)); do
        case ${phase} in
          (1)
            : Phase ${phase} - Scan archive for container images.
            ((skipPhaseBM & (1 << (phase++ - 1)))) && continue
            set +e
            exitStat=0; FindImgInTar "${topLvlTar}" ${unTar} ${chkSelf}; exitStat=$?
            set -e
            ;;
          (2)
            : Phase ${phase} - Extract / store container images from imgpkg \
                bundle and/or METADATA locally. Fetch OSL Manifest from \
                METADATA.
            ((skipPhaseBM & (1 << (phase++ - 1)))) && continue
            imgPath="${topLvlTar}/__img/docker.sup"
            [ -d "${imgpkgDir}" ] && ExtractCtrImg imgpkg "${imgpkgDir}/" \
                "${imgPath}/"
            [ -n "${metadata}" ] && DLctImgAoslMan "${metadata}" "${imgPath}/" \
                "${oslMnfstDir}/"
            ;;
          (3)
            : Phase ${phase} - Do scan on the reduced archive.
            ((skipPhaseBM & (1 << (phase++ - 1)))) && continue
            imgPath="${topLvlTar}/__tar"
            [ -d "${imgPath}" ] || continue
            for e in ${scnrList[0]}; do
                if [[ "${osspiScnrs[*]:0:2}" =~ (^| )"${e}"( |$) ]]; then
                    DoOSLscan ${e} "${oslMnfstDir}/" "${imgPath}/" ${maxRec}
                else
                    echo "Not supported OSSPI Scanner in this phase: ${e}"
                    exit 1
                fi
            done
            ;;
          (4)
            : Phase ${phase} - Do scan on identified container images.
            ((skipPhaseBM & (1 << (phase++ - 1)))) && continue
            for imgPath in "${topLvlTar}/__img/docker"{,.sup}; do
                [ -d "${imgPath}" ] || continue
                for e in ${scnrList[1]}; do
                    if [[ "${osspiScnrs[*]:0:3}" =~ (^| )"${e}"( |$) ]]; then
                        DoOSLscan ${e} "${oslMnfstDir}/" "${imgPath}/" ${maxRec}
                    else
                        echo "Not supported OSSPI Scanner in this phase: ${e}"
                        exit 1
                    fi
                done
            done
            ;;
          (5)
            : Phase ${phase} - Upload to OSM Server.
            ((skipPhaseBM & (1 << (phase++ - 1)))) && continue
            UL2OSM "${oslMnfstDir}" "${osmPars}"
            ;;
          (*)
            phase=0
            ;;
        esac
    done
}


Main "$@"
