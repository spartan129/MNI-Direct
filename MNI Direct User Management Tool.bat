@echo off
powershell.exe -Command "Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File ""%~dp0MNIDirect_UM_Tool.ps1""' -Verb RunAs"

