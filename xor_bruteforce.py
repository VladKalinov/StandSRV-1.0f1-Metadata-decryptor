#!/usr/bin/env python3
"""
Попытка найти XOR ключ для расшифровки метаданных
"""

import struct
import sys
from pathlib import Path


def try_xor_decrypt(data, key):
    """Применяет XOR с ключом"""
    if isinstance(key, int):
        key = key.to_bytes(4, 'little')
    
    result = bytearray()
    key_len = len(key)
    
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % key_len])
    
    return bytes(result)


def check_metadata_validity(data):
    """Проверяет, похожи ли данные на валидные метаданные"""
    if len(data) < 232:
        return False, 0
    
    try:
        # Проверяем sanity
        sanity = struct.unpack('<I', data[0:4])[0]
        if sanity != 0xFAB11BAF:
            return False, 0
        
        # Проверяем версию (должна быть 19-27 для Unity 2018-2021)
        version = struct.unpack('<I', data[4:8])[0]
        if version < 19 or version > 30:
            return False, 0
        
        # Проверяем разумность счетчиков
        header = struct.unpack('<58I', data[:232])
        
        # Количество типов, методов, строк должны быть разумными
        type_count = header[41]  # type_definitions_count
        method_count = header[13]  # methods_count
        string_count = header[7]   # string_count
        
        # Проверяем, что значения не слишком большие
        if type_count > 100000 or method_count > 500000 or string_count > 1000000:
            return False, 0
        
        # Проверяем, что значения не нулевые
        if type_count == 0 or method_count == 0 or string_count == 0:
            return False, 0
        
        score = 100
        score += min(type_count / 100, 50)
        score += min(method_count / 1000, 50)
        
        return True, score
        
    except:
        return False, 0


def bruteforce_xor_key(filepath):
    """Перебор возможных XOR ключей"""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    print(f"[+] Размер файла: {len(data)} байт")
    print(f"[*] Начинаем перебор XOR ключей...")
    print()
    
    # Sanity уже правильный, значит первые 4 байта не зашифрованы
    # Или используется более сложное шифрование
    
    # Попробуем найти ключ для остальных данных
    # Предполагаем, что версия должна быть 24 (0x18)
    expected_version = 24
    
    # Текущее значение версии
    current_version_bytes = data[4:8]
    current_version = struct.unpack('<I', current_version_bytes)[0]
    
    print(f"[*] Текущая версия: {current_version} (0x{current_version:08X})")
    print(f"[*] Ожидаемая версия: {expected_version} (0x{expected_version:08X})")
    print()
    
    # Вычисляем возможный XOR ключ
    xor_key = current_version ^ expected_version
    print(f"[*] Вычисленный XOR ключ: 0x{xor_key:08X}")
    
    # Пробуем расшифровать с этим ключом
    decrypted = bytearray(data)
    
    # XOR начиная с 4-го байта
    key_bytes = xor_key.to_bytes(4, 'little')
    for i in range(4, len(decrypted)):
        decrypted[i] ^= key_bytes[(i - 4) % 4]
    
    is_valid, score = check_metadata_validity(bytes(decrypted))
    
    if is_valid:
        print(f"[+] НАЙДЕН ВАЛИДНЫЙ КЛЮЧ: 0x{xor_key:08X}")
        print(f"[+] Оценка: {score}")
        
        # Сохраняем расшифрованные данные
        output_path = Path(filepath).parent / "global-metadata-decrypted.dat"
        with open(output_path, 'wb') as f:
            f.write(decrypted)
        print(f"[+] Расшифрованные данные сохранены в: {output_path}")
        return True
    
    print(f"[-] Простой XOR не подходит")
    print()
    
    # Пробуем другие варианты
    print("[*] Пробуем перебор односложных ключей...")
    
    best_score = 0
    best_key = None
    
    # Перебираем популярные ключи
    common_keys = [
        0x00000000, 0xFFFFFFFF, 0x12345678, 0xDEADBEEF,
        0xCAFEBABE, 0xFEEDFACE, 0xBAADF00D, 0xDEADC0DE
    ]
    
    for key in common_keys:
        decrypted = bytearray(data)
        key_bytes = key.to_bytes(4, 'little')
        
        for i in range(4, len(decrypted)):
            decrypted[i] ^= key_bytes[(i - 4) % 4]
        
        is_valid, score = check_metadata_validity(bytes(decrypted))
        
        if is_valid and score > best_score:
            best_score = score
            best_key = key
            print(f"[+] Найден кандидат: 0x{key:08X}, оценка: {score}")
    
    if best_key:
        print(f"\n[+] ЛУЧШИЙ КЛЮЧ: 0x{best_key:08X}")
        
        # Расшифровываем с лучшим ключом
        decrypted = bytearray(data)
        key_bytes = best_key.to_bytes(4, 'little')
        
        for i in range(4, len(decrypted)):
            decrypted[i] ^= key_bytes[(i - 4) % 4]
        
        output_path = Path(filepath).parent / "global-metadata-decrypted.dat"
        with open(output_path, 'wb') as f:
            f.write(decrypted)
        print(f"[+] Расшифрованные данные сохранены в: {output_path}")
        return True
    
    print("\n[!] Не удалось найти XOR ключ")
    print("[*] Возможно используется более сложное шифрование")
    return False


def analyze_encryption_pattern(filepath):
    """Анализирует паттерны шифрования"""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    print("[*] Анализ паттернов шифрования...")
    print()
    
    # Проверяем, есть ли повторяющиеся паттерны
    print("[*] Поиск повторяющихся последовательностей...")
    
    # Ищем 4-байтовые паттерны
    patterns = {}
    for i in range(0, min(10000, len(data) - 4), 4):
        pattern = data[i:i+4]
        if pattern in patterns:
            patterns[pattern] += 1
        else:
            patterns[pattern] = 1
    
    # Сортируем по частоте
    sorted_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)
    
    print(f"[+] Найдено уникальных 4-байтовых паттернов: {len(patterns)}")
    print(f"[+] Топ-10 самых частых:")
    for pattern, count in sorted_patterns[:10]:
        hex_str = ' '.join(f'{b:02X}' for b in pattern)
        print(f"    {hex_str}: {count} раз")


def main():
    filepath = Path(__file__).parent / "global-metadata.dat"
    
    if not filepath.exists():
        print(f"[!] Файл не найден: {filepath}")
        return 1
    
    print("=" * 80)
    print("IL2CPP Metadata XOR Bruteforce")
    print("=" * 80)
    print()
    
    # Сначала анализируем паттерны
    analyze_encryption_pattern(filepath)
    print()
    
    # Затем пробуем найти ключ
    if bruteforce_xor_key(filepath):
        print("\n[+] Успех! Попробуйте запустить il2cpp_dumper.py с расшифрованным файлом")
    else:
        print("\n[!] Не удалось расшифровать автоматически")
        print("[*] Рекомендации:")
        print("    1. Используйте Frida скрипт (frida_dumper.js) для дампа из памяти")
        print("    2. Исследуйте libil2cpp.so на наличие функций расшифровки")
        print("    3. Попробуйте найти ключ в коде приложения")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
