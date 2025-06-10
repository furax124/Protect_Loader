@echo off
cd GUI
go mod tidy
go install mvdan.cc/garble@latest
start /B /MIN go run GUI.go
