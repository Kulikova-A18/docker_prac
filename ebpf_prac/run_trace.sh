#!/bin/bash

if [[ ! -f requirements.txt ]]; then
    echo "Файл requirements.txt не найден!"
    exit 1
fi

while IFS= read -r package; do
    echo "Установка пакета: $package"
    if ! dpkg -l | grep -q "$package"; then
        sudo apt install -y "$package"
    else
        echo "Пакет $package уже установлен."
    fi
done < requirements.txt

python3 trace_syscalls.py