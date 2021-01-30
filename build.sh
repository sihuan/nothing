#!/usr/bin/bash

cd server
go build -o ../build/server

cd ../client

go build -o ../build/client