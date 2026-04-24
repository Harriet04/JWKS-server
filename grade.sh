#!/bin/bash
rm -f totally_not_my_privateKeys.db
npm install
./gradebot project-2 --run="node server.js"
