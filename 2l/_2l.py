import sys
import msvcrt
import hashlib
import os
import struct

BLOCK_SIZE = 8  # 64 бит
ROUNDS = 16

# ввод с '*'
def get_password(prompt="Введите пароль: "):
    print(prompt, end="", flush=True)
    password = ""
    while True:
        ch = msvcrt.getch()
        if ch in {b"\r", b"\n"}:  # Enter
            print()
            break
        elif ch == b"\x08":  # Backspace
            if len(password) > 0:
                password = password[:-1]
                sys.stdout.write("\b \b")
        else:
            try:
                ch_decoded = ch.decode("utf-8")
            except UnicodeDecodeError:
                continue
            password += ch_decoded
            sys.stdout.write("*")
    return password

# дополнение до размера блока
def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len] * pad_len)

# удаление дополнения
def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]


def bytes_to_bits(b):
    return ''.join(f'{byte:08b}' for byte in b)


def bits_to_bytes(bits):
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def left_rotate(bits, n):
    return bits[n:] + bits[:n]


# DES
def des_encrypt_block(block, key_bits):
    block_bits = bytes_to_bits(block)
    for _ in range(ROUNDS):
        left, right = block_bits[:32], block_bits[32:]
        f = ''.join('1' if a != b else '0' for a, b in zip(right, key_bits[:32]))
        new_right = ''.join('1' if a != b else '0' for a, b in zip(left, f))
        block_bits = right + new_right
        key_bits = left_rotate(key_bits, 3)
    return bits_to_bytes(block_bits)


def des_decrypt_block(block, key_bits):
    block_bits = bytes_to_bits(block)
    round_keys = [key_bits]
    for _ in range(ROUNDS - 1):
        key_bits = left_rotate(key_bits, 3)
        round_keys.append(key_bits)
    for r in reversed(range(ROUNDS)):
        key_bits = round_keys[r]
        left, right = block_bits[:32], block_bits[32:]
        f = ''.join('1' if a != b else '0' for a, b in zip(left, key_bits[:32]))
        new_left = ''.join('1' if a != b else '0' for a, b in zip(right, f))
        block_bits = new_left + left
    return bits_to_bytes(block_bits)


# 3DES (EDE)
def triple_des_encrypt_block(block, k1, k2, k3):
    b1 = des_encrypt_block(block, k1)
    b2 = des_decrypt_block(b1, k2)
    b3 = des_encrypt_block(b2, k3)
    return b3


def triple_des_decrypt_block(block, k1, k2, k3):
    b1 = des_decrypt_block(block, k3)
    b2 = des_encrypt_block(b1, k2)
    b3 = des_decrypt_block(b2, k1)
    return b3


# ключи
def derive_keys_from_password(password):
    digest = hashlib.sha256(password.encode('utf-8')).digest()
    k1 = bytes_to_bits(digest[0:8])
    k2 = bytes_to_bits(digest[8:16])
    k3 = bytes_to_bits(digest[16:24])
    return k1, k2, k3


# шифровка/расшифровка
def encrypt_file(input_file, output_file, password):
    k1, k2, k3 = derive_keys_from_password(password)
    with open(input_file, 'rb') as f:
        data = f.read()
    data = pad(data)
    encrypted = b''
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        encrypted += triple_des_encrypt_block(block, k1, k2, k3)
    with open(output_file, 'wb') as f:
        f.write(encrypted)
    print("[+] Файл успешно зашифрован.")


def decrypt_file(input_file, output_file, password):
    k1, k2, k3 = derive_keys_from_password(password)
    with open(input_file, 'rb') as f:
        data = f.read()
    decrypted = b''
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        decrypted += triple_des_decrypt_block(block, k1, k2, k3)
    decrypted = unpad(decrypted)
    with open(output_file, 'wb') as f:
        f.write(decrypted)
    print("[+] Файл успешно расшифрован.")


# меню
def main():
    while True:
        print("\nВыберите режим:")
        print("1 - Шифрование файла")
        print("2 - Расшифрование файла")
        print("0 - Выход")
        mode = input(">>> ").strip()

        if mode == "0":
            print("Выход из программы.")
            break

        elif mode in {"1", "2"}:
            input_file = input("Введите имя исходного файла: ").strip()
            output_file = input("Введите имя выходного файла: ").strip()
            password = get_password("Введите пароль: ")

            try:
                if mode == "1":
                    encrypt_file(input_file, output_file, password)
                else:
                    decrypt_file(input_file, output_file, password)
            except FileNotFoundError:
                print("[-] Ошибка: файл не найден.")
            except Exception as e:
                print(f"[-] Ошибка: {e}")
        else:
            print("[-] Неизвестный режим. Повторите ввод.")


if __name__ == "__main__":
    main()
