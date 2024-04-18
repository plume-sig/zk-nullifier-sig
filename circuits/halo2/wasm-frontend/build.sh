#!/bin/bash

if [ "$1" = "wasm-gen" ]; then
  cd wasm/
  wasm-pack build --target web
  cd ../
fi

npm run dev
