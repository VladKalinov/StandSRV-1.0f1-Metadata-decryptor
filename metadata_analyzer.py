#!/usr/bin/env python3
"""
IL2CPP Metadata Analyzer - исследует структуру файла метаданных
"""

import struct
import sys
from pathlib import Path


def analyze_metadata(filepath):
    """Анализирует файл метаданных"""
    with open(filepath, 'rb') as f:
        data = f.read()
    
    print(f"[+] Размер файла: {len(data)} байт")
    print(f"[+] Первые 256 байт (hex):")
    print()
    
    # Показываем первые 256 байт в hex формате
    for i in range(0, min(256, len(data)), 16):
        hex_str = ' '.join(f'{b:02X}' for b in data[i:i+16])
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f"{i:08X}:  {hex_str:<48}  {ascii_str}")
    
    print()
    print("[*] Анализ возможных форматов заголовка:")
    print()
    
    # Пробуем разные интерпретации первых байтов
    print("Вариант 1: Little-endian uint32")
    for i in range(0, min(64, len(data)), 4):
        if i + 4 <= len(data):
            value = struct.unpack('<I', data[i:i+4])[0]
            print(f"  Offset {i:3d}: 0x{value:08X} ({value})")
    
    print()
    print("Вариант 2: Big-endian uint32")
    for i in range(0, min(64, len(data)), 4):
        if i + 4 <= len(data):
            value = struct.unpack('>I', data[i:i+4])[0]
            print(f"  Offset {i:3d}: 0x{value:08X} ({value})")
    
    print()
    print("[*] Поиск сигнатуры IL2CPP (0xFAB11BAF):")
    
    # Ищем magic number в файле
    magic = 0xFAB11BAF
    magic_bytes_le = struct.pack('<I', magic)
    magic_bytes_be = struct.pack('>I', magic)
    
    pos_le = data.find(magic_bytes_le)
    pos_be = data.find(magic_bytes_be)
    
    if pos_le != -1:
        print(f"  [+] Найдено (little-endian) на смещении: {pos_le}")
        # Читаем следующие несколько значений
        print(f"      Следующие значения:")
        for i in range(0, min(64, len(data) - pos_le), 4):
            if pos_le + i + 4 <= len(data):
                value = struct.unpack('<I', data[pos_le + i:pos_le + i + 4])[0]
                print(f"        +{i:3d}: 0x{value:08X} ({value})")
    else:
        print(f"  [-] Не найдено (little-endian)")
    
    if pos_be != -1:
        print(f"  [+] Найдено (big-endian) на смещении: {pos_be}")
    else:
        print(f"  [-] Не найдено (big-endian)")
    
    print()
    print("[*] Поиск строковых данных:")
    
    # Ищем читаемые строки
    strings_found = []
    current_string = b''
    
    for i, byte in enumerate(data[:10000]):  # Первые 10KB
        if 32 <= byte < 127 or byte in (9, 10, 13):  # Печатные символы
            current_string += bytes([byte])
        else:
            if len(current_string) >= 4:
                try:
                    s = current_string.decode('utf-8')
                    strings_found.append((i - len(current_string), s))
                except:
                    pass
            current_string = b''
    
    if strings_found:
        print(f"  [+] Найдено {len(strings_found)} строк в первых 10KB:")
        for offset, string in strings_found[:20]:
            print(f"      @{offset:6d}: {string[:60]}")
    
    print()
    print("[*] Статистика байтов:")
    
    # Подсчитываем частоту байтов
    byte_counts = [0] * 256
    for byte in data[:1000]:
        byte_counts[byte] += 1
    
    # Проверяем на энтропию
    zero_count = byte_counts[0]
    print(f"  Нулевых байтов в первой 1000: {zero_count}")
    print(f"  Ненулевых байтов: {1000 - zero_count}")
    
    # Проверяем, похоже ли на зашифрованные данные
    non_zero = sum(1 for c in byte_counts if c > 0)
    print(f"  Уникальных значений байтов: {non_zero}/256")
    
    if non_zero > 200 and zero_count < 100:
        print("  [!] ВНИМАНИЕ: Высокая энтропия - возможно, данные зашифрованы или сжаты!")


def main():
    filepath = Path(__file__).parent / "global-metadata.dat"
    
    if not filepath.exists():
        print(f"[!] Файл не найден: {filepath}")
        return 1
    
    print("=" * 80)
    print("IL2CPP Metadata Analyzer")
    print("=" * 80)
    print()
    
    analyze_metadata(filepath)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
