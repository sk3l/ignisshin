#!/bin/bash

if [[ -d ./build ]]; then
    rm -rf build
fi

mkdir build
cd build

echo -e "\n>>> Starting CMake <<<\n"

cmake3 -DCMAKE_BUILD_TYPE=Debug ..

echo -e "\n>>> Starting make <<<\n"

make -j 3

