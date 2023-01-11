#!/usr/bin/env bash

echo $0
. $(dirname $0)/common.sh

#echo ${BasePath}
#echo ${CMD}
#echo ${Hour}

VERSION=$(genVersion $1)
OUTPATH="${BasePath}/out/apinto-${VERSION}"
buildApp apinto $VERSION

cp -af ${BasePath}/build/resources/*  ${OUTPATH}/
cd "${BasePath}/out/apinto-${VERSION}"
docker build . -t harbor.160.kayicloud.com/linx/apinto:${VERSION}
cd ${ORGPATH}
