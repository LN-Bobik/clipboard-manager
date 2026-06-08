#!/bin/bash

# Рабочий монитор буфера обмена
# Поддерживает CLIPBOARD, PRIMARY и SECONDARY selections

INTERVAL=0.5  # Проверка каждые 0.5 секунды
LAST_CLIPBOARD=""
LAST_PRIMARY=""
COUNTER=0


echo "  WORKING CLIPBOARD MONITOR"
echo ""

# Функция для получения всех типов буфера
get_all_clipboards() {
    echo "=== CLIPBOARD ==="
    xclip -selection clipboard -o 2>/dev/null
    echo "=== PRIMARY ==="
    xclip -selection primary -o 2>/dev/null
    echo "=== SECONDARY ==="
    xclip -selection secondary -o 2>/dev/null
}

# Функция проверки и сохранения
check_and_store() {
    local content="$1"
    local type="$2"
    
    if [ ! -z "$content" ] && [ ${#content} -gt 0 ]; then
        COUNTER=$((COUNTER + 1))
        local preview="${content:0:60}"
        local len=${#content}
        
        echo "[$(date '+%H:%M:%S')] #$COUNTER [$type] ($len chars)"
        echo "  > $preview..."
        
        # Сохраняем через клиент
        echo "$content" | ./clipboard_client store 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "  Сохранено в историю"
        else
            echo "  Ошибка сохранения"
        fi
        echo ""
    fi
}

# Основной цикл
while true; do
    # Получаем CLIPBOARD (Ctrl+C)
    CURRENT_CLIPBOARD=$(xclip -selection clipboard -o 2>/dev/null)
    
    # Получаем PRIMARY (выделение мышкой)
    CURRENT_PRIMARY=$(xclip -selection primary -o 2>/dev/null)
    
    # Проверяем CLIPBOARD
    if [ "$CURRENT_CLIPBOARD" != "$LAST_CLIPBOARD" ] && [ ! -z "$CURRENT_CLIPBOARD" ]; then
        check_and_store "$CURRENT_CLIPBOARD" "CLIPBOARD (Ctrl+C)"
        LAST_CLIPBOARD="$CURRENT_CLIPBOARD"
    fi
    
    # Проверяем PRIMARY (выделение мышкой)
    if [ "$CURRENT_PRIMARY" != "$LAST_PRIMARY" ] && [ ! -z "$CURRENT_PRIMARY" ]; then
        # Не сохраняем PRIMARY автоматически, только показываем
        echo "[$(date '+%H:%M:%S')]  PRIMARY selection: ${CURRENT_PRIMARY:0:40}..."
        LAST_PRIMARY="$CURRENT_PRIMARY"
    fi
    
    sleep $INTERVAL
done
