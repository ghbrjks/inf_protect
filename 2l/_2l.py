import hashlib
import msvcrt
import sys
import os

# ввод пароля со звёздочками
def get_password(prompt="Введите пароль: "):
    print(prompt, end="", flush=True)
    password = ""
    while True:
        ch = msvcrt.getch()
        if ch in {b"\r", b"\n"}:
            print()
            break
        elif ch == b"\x08":
            if len(password) > 0:
                password = password[:-1]
                sys.stdout.write("\b \b")
                sys.stdout.flush()
        else:
            try:
                char = ch.decode("utf-8")
            except:
                continue
            password += char
            sys.stdout.write("*")
            sys.stdout.flush()
    return password


# таблицы DES (сокращённый комментарий, те же что у тебя)
IP = [...]
IP_INV = [...]
E = [...]
P = [...]
PC1 = [...]
PC2 = [...]
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
S_BOXES = [...]


# функции Фейштеля
def permute(block, table):
    return [block[i - 1] for i in table]


def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]


def split_half(lst):
    return lst[:len(lst)//2], lst[len(lst)//2:]


def left_shift(bits, n):
    return bits[n:] + bits[:n]


def s_box_substitution(bits):
    output = []
    for i in range(8):
        block = bits[i * 6:(i + 1) * 6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        val = S_BOXES[i][row][col]
        output += [(val >> i) & 1 for i in reversed(range(4))]
    return output


def feistel(right, subkey):
    expanded = permute(right, E)
    temp = xor(expanded, subkey)
    temp = s_box_substitution(temp)
    temp = permute(temp, P)
    return temp


# битовые функции
def bytes_to_bits(data):
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> (7 - i)) & 1)
    return bits


def bits_to_bytes(bits):
    res = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        res.append(byte)
    return bytes(res)


# генерация подключей DES
def generate_subkeys(key_bits):
    key56 = permute(key_bits, PC1)
    C, D = split_half(key56)
    subkeys = []
    for shift in SHIFT_SCHEDULE:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        CD = C + D
        subkey = permute(CD, PC2)
        subkeys.append(subkey)
    return subkeys


# DES
def des_encrypt_block(block_bits, subkeys):
    block = permute(block_bits, IP)
    left, right = split_half(block)
    for k in subkeys:
        temp = feistel(right, k)
        left, right = right, xor(left, temp)
    block = right + left
    return permute(block, IP_INV)


def des_decrypt_block(block_bits, subkeys):
    return des_encrypt_block(block_bits, list(reversed(subkeys)))


# 3DES
def triple_des_encrypt(block_bits, keys):
    b1 = des_encrypt_block(block_bits, keys[0])
    b2 = des_decrypt_block(b1, keys[1])
    b3 = des_encrypt_block(b2, keys[2])
    return b3


def triple_des_decrypt(block_bits, keys):
    b1 = des_decrypt_block(block_bits, keys[2])
    b2 = des_encrypt_block(b1, keys[1])
    b3 = des_decrypt_block(b2, keys[0])
    return b3


# работа с файлами
def process_file(input_file, output_file, password, encrypt=True):
    # проверка существования файла
    if not os.path.exists(input_file):
        print("[-] Ошибка: файл не найден.")
        return

    # проверка размера
    size = os.path.getsize(input_file)
    if size < 32:
        print("[-] Ошибка: файл слишком маленький (< 32 байт).")
        return
    if size > 4 * 1024 * 1024:
        print("[-] Ошибка: файл слишком большой (> 4 МБ).")
        return

    # генерация ключей
    key_material = hashlib.sha256(password.encode()).digest()
    keys_bits = [bytes_to_bits(key_material[i*8:(i+1)*8]) for i in range(3)]
    subkeys = [generate_subkeys(k) for k in keys_bits]

    with open(input_file, "rb") as f:
        data = f.read()

    # дополнение до кратности 8 байт
    while len(data) % 8 != 0:
        data += b"\x00"

    result = bytearray()
    for i in range(0, len(data), 8):
        block_bits = bytes_to_bits(data[i:i+8])
        if encrypt:
            new_bits = triple_des_encrypt(block_bits, subkeys)
        else:
            new_bits = triple_des_decrypt(block_bits, subkeys)
        result += bits_to_bytes(new_bits)

    with open(output_file, "wb") as f:
        f.write(result)


# главное меню с циклом
def main():
    while True:
        print("1 - Шифрование файла")
        print("2 - Расшифрование файла")
        print("3 - Выход")
        choice = input(">>> ").strip()

        if choice == "3":
            print("Выход из программы...")
            break

        input_file = input("Введите имя исходного файла: ").strip()
        output_file = input("Введите имя выходного файла: ").strip()
        password = get_password("Введите пароль: ")

        if choice == "1":
            process_file(input_file, output_file, password, encrypt=True)
            print("[+] Файл зашифрован успешно.")
        elif choice == "2":
            process_file(input_file, output_file, password, encrypt=False)
            print("[+] Файл расшифрован успешно.")
        else:
            print("[-] Ошибка: неизвестный режим")


if __name__ == "__main__":
    main()
