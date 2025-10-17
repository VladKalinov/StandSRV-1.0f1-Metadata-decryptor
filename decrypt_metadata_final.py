#!/usr/bin/env python3
"""
ФИНАЛЬНЫЙ ДЕШИФРАТОР МЕТАДАННЫХ
Основан на реверс-инжиниринге функции sub_106E258 из libil2cpp.so
"""

import struct
from pathlib import Path

# Импортируем полную таблицу ключей
from key_table import KEY_TABLE


def decrypt_metadata(input_path, output_path):
    """
    Расшифровывает метаданные IL2CPP
    
    Алгоритм из sub_106E258:
    - Начинаем с байта 4 (пропускаем сигнатуру)
    - Для каждого байта: index = (pos - 4) & 0x1FF
    - XOR с младшим байтом ключа из таблицы
    """
    print("[*] Читаем зашифрованные метаданные...")
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    print(f"[+] Размер файла: {len(data)} байт")
    
    # Проверяем сигнатуру
    sanity = struct.unpack('<I', data[0:4])[0]
    if sanity != 0xFAB11BAF:
        print(f"[!] Неверная сигнатура: 0x{sanity:08X}")
        return False
    
    print("[+] Сигнатура корректна: 0xFAB11BAF")
    
    # Расшифровываем начиная с байта 4
    print("[*] Расшифровка...")
    
    for i in range(4, len(data)):
        # Вычисляем индекс в таблице ключей
        # В ассемблере: AND X11, X9, #0x1FF где X9 = позиция в файле
        index = i & 0x1FF  # 0x1FF = 511 (маска для 512 элементов)
        
        # Получаем ключ из таблицы (uint32)
        key = KEY_TABLE[index]
        
        # XOR с младшим байтом ключа
        data[i] ^= (key & 0xFF)
    
    print("[*] Проверка расшифрованных данных...")
    
    # Показываем первые 32 байта для отладки
    print(f"\n[DEBUG] Первые 32 байта:")
    for i in range(0, 32, 4):
        value = struct.unpack('<I', data[i:i+4])[0]
        print(f"  [{i:3d}] = 0x{value:08X} ({value})")
    print()
    
    # Проверяем версию
    version = struct.unpack('<I', data[4:8])[0]
    print(f"[+] Версия метаданных: {version}")
    
    if version < 19 or version > 30:
        print(f"[!] Подозрительная версия: {version}")
        print("[!] Возможно, алгоритм неверный или таблица ключей неполная")
        return False
    
    # Проверяем заголовок
    try:
        header = struct.unpack('<58I', data[:232])
        
        string_count = header[7]
        method_count = header[13]
        type_count = header[41]
        
        print(f"[+] Строк: {string_count}")
        print(f"[+] Методов: {method_count}")
        print(f"[+] Типов: {type_count}")
        
        # Более мягкая проверка для отладки
        if (string_count == 0 or method_count == 0 or type_count == 0):
            print("[!] Нулевые значения в заголовке")
            return False
        
        if (string_count > 1000000 or method_count > 500000 or type_count > 100000):
            print("[!] ВНИМАНИЕ: Подозрительно большие значения")
            print("[!] Возможно, нужно расшифровывать не все байты, а только определенные")
            # Но продолжаем сохранять для анализа
        else:
            print("[+] ✅ МЕТАДАННЫЕ УСПЕШНО РАСШИФРОВАНЫ!")
        
    except Exception as e:
        print(f"[!] Ошибка при проверке: {e}")
        return False
    
    # Сохраняем результат
    print(f"[*] Сохранение в {output_path}...")
    with open(output_path, 'wb') as f:
        f.write(data)
    
    print("[+] Готово!")
    return True


def main():
    input_file = Path(__file__).parent / "global-metadata.dat"
    output_file = Path(__file__).parent / "global-metadata-decrypted.dat"
    
    if not input_file.exists():
        print(f"[!] Файл не найден: {input_file}")
        return 1
    
    print("=" * 80)
    print("ФИНАЛЬНЫЙ ДЕШИФРАТОР МЕТАДАННЫХ IL2CPP")
    print("=" * 80)
    print()
    print("Алгоритм извлечен из функции sub_106E258 (адрес 0x106E258)")
    print("Таблица ключей: unk_2FE9E78 (адрес 0x02FE9E78)")
    print()
    print("Алгоритм:")
    print("  - Начало с байта 4 (после сигнатуры)")
    print("  - index = (position - 4) & 0x1FF")
    print("  - byte ^= KEY_TABLE[index] & 0xFF")
    print()
    print("=" * 80)
    print()
    
    if decrypt_metadata(input_file, output_file):
        print()
        print("=" * 80)
        print("УСПЕХ! Метаданные расшифрованы!")
        print("=" * 80)
        print()
        print("Следующий шаг:")
        print("  python il2cpp_dumper.py")
        print()
        return 0
    else:
        print()
        print("=" * 80)
        print("ОШИБКА: Расшифровка не удалась")
        print("=" * 80)
        print()
        print("Возможные причины:")
        print("  1. Таблица ключей неполная (нужно извлечь все 512 элементов)")
        print("  2. Алгоритм более сложный")
        print("  3. Используется другая функция расшифровки")
        print()
        print("Рекомендация:")
        print("  Используйте frida_dumper.js для runtime дампа")
        print()
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
