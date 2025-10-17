#!/usr/bin/env python3
"""
Продвинутый дешифратор метаданных с использованием найденных ключей
"""

import struct
import sys
from pathlib import Path
from multiprocessing import Pool, cpu_count


def check_metadata_validity(data):
    """Проверяет валидность метаданных"""
    if len(data) < 232:
        return False, 0, {}
    
    try:
        sanity = struct.unpack('<I', data[0:4])[0]
        if sanity != 0xFAB11BAF:
            return False, 0, {}
        
        version = struct.unpack('<I', data[4:8])[0]
        if version < 19 or version > 30:
            return False, 0, {}
        
        header = struct.unpack('<58I', data[:232])
        
        type_count = header[41]
        method_count = header[13]
        string_count = header[7]
        image_count = header[43]
        assembly_count = header[45]
        
        # Проверяем разумность значений
        if (type_count > 100000 or method_count > 500000 or 
            string_count > 1000000 or image_count > 1000 or 
            assembly_count > 500):
            return False, 0, {}
        
        if (type_count == 0 or method_count == 0 or string_count == 0):
            return False, 0, {}
        
        # Вычисляем оценку
        score = 100
        score += min(type_count / 100, 50)
        score += min(method_count / 1000, 50)
        
        # Бонус за правильную версию
        if version == 24:
            score += 100
        
        info = {
            'version': version,
            'types': type_count,
            'methods': method_count,
            'strings': string_count,
            'images': image_count,
            'assemblies': assembly_count
        }
        
        return True, score, info
        
    except:
        return False, 0, {}


def try_decrypt_with_key(args):
    """Пробует расшифровать с заданным ключом"""
    data, key, key_index = args
    
    try:
        decrypted = bytearray(data)
        key_bytes = key.to_bytes(4, 'little')
        
        # XOR начиная с 4-го байта (версия)
        for i in range(4, len(decrypted)):
            decrypted[i] ^= key_bytes[(i - 4) % 4]
        
        is_valid, score, info = check_metadata_validity(bytes(decrypted))
        
        if is_valid:
            return (True, key, score, info, bytes(decrypted))
        
        return (False, key, 0, {}, None)
        
    except Exception as e:
        return (False, key, 0, {}, None)


def load_potential_keys(filepath):
    """Загружает потенциальные ключи из файла"""
    keys = []
    
    if not filepath.exists():
        print(f"[!] Файл с ключами не найден: {filepath}")
        return keys
    
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith('0x'):
                try:
                    key = int(line, 16)
                    keys.append(key)
                except:
                    pass
    
    return keys


def bruteforce_with_keys(metadata_path, keys_path):
    """Перебор ключей из файла"""
    
    # Загружаем метаданные
    with open(metadata_path, 'rb') as f:
        data = f.read()
    
    print(f"[+] Загружено метаданных: {len(data)} байт")
    
    # Загружаем ключи
    keys = load_potential_keys(keys_path)
    print(f"[+] Загружено ключей: {len(keys)}")
    
    if not keys:
        print("[!] Нет ключей для проверки")
        return False
    
    print(f"[*] Начинаем перебор с использованием {cpu_count()} ядер...")
    print()
    
    # Подготавливаем аргументы для параллельной обработки
    args_list = [(data, key, i) for i, key in enumerate(keys)]
    
    best_result = None
    best_score = 0
    
    # Используем пул процессов для параллельной обработки
    chunk_size = 1000
    total_checked = 0
    
    with Pool(cpu_count()) as pool:
        for i in range(0, len(args_list), chunk_size):
            chunk = args_list[i:i + chunk_size]
            results = pool.map(try_decrypt_with_key, chunk)
            
            for is_valid, key, score, info, decrypted in results:
                total_checked += 1
                
                if is_valid and score > best_score:
                    best_score = score
                    best_result = (key, score, info, decrypted)
                    
                    print(f"[+] Найден кандидат! Ключ: 0x{key:08X}, Оценка: {score:.1f}")
                    print(f"    Версия: {info['version']}")
                    print(f"    Типов: {info['types']}")
                    print(f"    Методов: {info['methods']}")
                    print(f"    Строк: {info['strings']}")
                    print(f"    Сборок: {info['assemblies']}")
                    print()
            
            if (i + chunk_size) % 10000 == 0:
                print(f"[*] Проверено {total_checked}/{len(keys)} ключей...")
    
    print(f"\n[*] Всего проверено: {total_checked} ключей")
    
    if best_result:
        key, score, info, decrypted = best_result
        print(f"\n[+] ЛУЧШИЙ РЕЗУЛЬТАТ:")
        print(f"    Ключ: 0x{key:08X}")
        print(f"    Оценка: {score:.1f}")
        print(f"    Версия метаданных: {info['version']}")
        print(f"    Типов: {info['types']}")
        print(f"    Методов: {info['methods']}")
        print(f"    Строк: {info['strings']}")
        
        # Сохраняем расшифрованные данные
        output_path = metadata_path.parent / "global-metadata-decrypted.dat"
        with open(output_path, 'wb') as f:
            f.write(decrypted)
        
        print(f"\n[+] Расшифрованные метаданные сохранены: {output_path}")
        print(f"[+] Теперь запустите: python il2cpp_dumper.py")
        
        return True
    
    print("\n[!] Валидный ключ не найден среди предложенных")
    return False


def try_alternative_algorithms(metadata_path):
    """Пробует альтернативные алгоритмы расшифровки"""
    print("\n[*] Пробуем альтернативные алгоритмы...")
    
    with open(metadata_path, 'rb') as f:
        data = f.read()
    
    # Алгоритм 1: XOR с позиционным ключом
    print("\n[1] XOR с позиционным ключом (key ^ position)...")
    
    for base_key in [0x12345678, 0xDEADBEEF, 0xCAFEBABE]:
        decrypted = bytearray(data)
        
        for i in range(4, len(decrypted)):
            key = base_key ^ i
            decrypted[i] ^= (key & 0xFF)
        
        is_valid, score, info = check_metadata_validity(bytes(decrypted))
        if is_valid:
            print(f"[+] Найдено! База: 0x{base_key:08X}, Оценка: {score}")
            return True
    
    # Алгоритм 2: Простой сдвиг
    print("\n[2] Простой сдвиг байтов...")
    
    for shift in range(1, 256):
        decrypted = bytearray(data)
        
        for i in range(4, len(decrypted)):
            decrypted[i] = (decrypted[i] + shift) & 0xFF
        
        is_valid, score, info = check_metadata_validity(bytes(decrypted))
        if is_valid:
            print(f"[+] Найдено! Сдвиг: {shift}, Оценка: {score}")
            return True
    
    # Алгоритм 3: XOR с предыдущим байтом (CBC-подобный)
    print("\n[3] XOR с предыдущим байтом...")
    
    for init_key in [0x00, 0xFF, 0xAA, 0x55]:
        decrypted = bytearray(data)
        prev = init_key
        
        for i in range(4, len(decrypted)):
            decrypted[i] ^= prev
            prev = data[i]
        
        is_valid, score, info = check_metadata_validity(bytes(decrypted))
        if is_valid:
            print(f"[+] Найдено! Init: 0x{init_key:02X}, Оценка: {score}")
            return True
    
    print("[-] Альтернативные алгоритмы не дали результата")
    return False


def main():
    base_path = Path(__file__).parent
    metadata_path = base_path / "global-metadata.dat"
    keys_path = base_path / "potential_keys.txt"
    
    if not metadata_path.exists():
        print(f"[!] Файл метаданных не найден: {metadata_path}")
        return 1
    
    print("=" * 80)
    print("Advanced IL2CPP Metadata Decryptor")
    print("=" * 80)
    print()
    
    # Сначала пробуем с найденными ключами
    if keys_path.exists():
        if bruteforce_with_keys(metadata_path, keys_path):
            return 0
    else:
        print("[!] Файл с ключами не найден, пропускаем перебор")
    
    # Если не помогло, пробуем альтернативные алгоритмы
    if try_alternative_algorithms(metadata_path):
        return 0
    
    print("\n" + "=" * 80)
    print("ЗАКЛЮЧЕНИЕ")
    print("=" * 80)
    print()
    print("Автоматическая расшифровка не удалась.")
    print()
    print("Рекомендуемые действия:")
    print("1. Используйте Frida для runtime дампа (frida_dumper.js)")
    print("2. Анализируйте libil2cpp.so в IDA Pro/Ghidra")
    print("3. Ищите функции с именами содержащими 'decrypt', 'init', 'metadata'")
    print("4. Проверьте наличие защиты типа Obfuscator или других протекторов")
    
    return 1


if __name__ == "__main__":
    sys.exit(main())
