#!/bin/bash

# Очистить logs/
echo "Cleaning logs..."
rm -rf logs/*

# Очистить сессии старше 7 дней
echo "Cleaning old sessions..."
find sessions/ -name "*.session" -mtime +7 -delete

# Очистить uploads старше 24 часов
echo "Cleaning old uploads..."
find uploads/ -type f -mtime +1 -delete

echo "Cleanup complete."
