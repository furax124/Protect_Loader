@echo off
cd GUI
go mod tidy
start /B /MIN go run encrypt.go