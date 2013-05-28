#!/bin/sh -x

REPO="$1"
TAG="$2"

copy()
{
    SRCDIR="$1"
    DSTDIR="$2"
    HEADER="$3"

    CWD=$(pwd)

    mkdir -p ${DSTDIR}
    cd ${DSTDIR}

    URL="${REPO}/raw-file/${TAG}/xen/include/${SRCDIR}/${HEADER}"

    wget ${URL}

    mv ${HEADER} ${HEADER}.orig
    sed -e 's/ unsigned long/ ULONG_PTR/g' \
        -e 's/(unsigned long/(ULONG_PTR/g' \
        -e 's/ long/ LONG_PTR/g' \
        -e 's/(long/(LONG_PTR/g' \
        < ${HEADER}.orig > ${HEADER}

    cd ${CWD}
}

rm -rf xen
mkdir -p xen
cd xen

copy public . xen.h
copy public . xen-compat.h
copy public . grant_table.h

copy public/arch-x86 arch-x86 xen.h
copy public/arch-x86 arch-x86 xen-x86_32.h
copy public/arch-x86 arch-x86 xen-x86_64.h
     
copy public/io io netif.h
copy public/io io ring.h
copy public/io io xenbus.h


