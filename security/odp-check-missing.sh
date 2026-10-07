#!/bin/bash
typeset _scrName="${BASH_SOURCE[0]##*/}"
typeset _scrPath="$(CDPATH= \command cd -L "${BASH_SOURCE[0]%/*}" 2> /dev/null;\command pwd)"

set -ex
set -o pipefail


typeset projWS="${1%%/}"; [ $# != 0 ] && shift; : "${projWS:=/}"

find "${projWS}/" -mindepth 1 -type d -prune \( \
    -name 'ct-tracker-*' -a \( \
        -exec bash -c '
            shopt -s extglob
            if [ -f "{}/oss.yaml" ]; then
                os="{}"; os="${os##*/ct-tracker-}"; os="${os%%-*}"
                while read -r n v; do
                    case ${os} in
                      (ubuntu);&
                      (debian)
                        v="${v#*:}"
                        ;;
                    esac
                    ls "{}/${n}"[_-]"${v}."* 1> /dev/null 2>&1 ||
                        echo "Missing source: {}/ ${n} ${v}"
                done <<< "$(
                    yq eval ".[] | .name + \" \" + .version" "{}/oss.yaml"
                )"
            else
                echo "Missing source: {}/"
            fi
        ' \; \
    \) -o \( \
        -exec bash -c '
            shopt -s extglob
            ls "{}/"*.@(gz|jar|t@(ar|gz)|zip|deb|rpm) 1> /dev/null 2>&1 ||
                echo "Missing source: {}/"
        ' \; \
    \) \
\)
