import tkinter as tk
from tkinter import StringVar, Entry, Label, Button
#加密操作：
# 字节替换
# 定义S-Box
s_box = [
    [0x9, 0x4, 0xA, 0xB],
    [0xD, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xC, 0xE, 0xF, 0x7]
]
def sub_bytes(state):
    """替换状态矩阵中的每个元素"""
    for row in range(2):
        for col in range(2):
            value = state[row][col]
            if not (0 <= value <= 15):
                raise ValueError(f"Invalid value in state matrix: {value}")           
            # 获取对应的i和j
            i = value >> 2  # 获取前两位
            j = value & 0x3  # 获取后两位
            # 根据i和j查找S-盒中的元素并替换
            state[row][col] = s_box[i][j]       
    return state
def shift_rows(state):
    """行移位"""
    return [state[0], [state[1][1], state[1][0]]]  # 仅交换第二行元素
# 列混淆
# 定义列混淆所需的固定矩阵
MIX_COLUMNS_MATRIX = [
    [1, 4],
    [4, 1]
]
def gf_mult(a, b):
    """在GF(2^4)上的乘法运算"""
    p = 0
    for i in range(4):
        if b & 1:
            p ^= a
        hi_bit_set = a & 8
        a <<= 1
        if hi_bit_set:
            a ^= 0b1011  # x^4 + x + 1
        b >>= 1
    return p & 0xF
def mix_columns(state):
    """列混淆操作"""
    new_state = [[0, 0], [0, 0]]
    for c in range(2):
        for r in range(2):
            new_state[r][c] = gf_mult(MIX_COLUMNS_MATRIX[r][0], state[0][c]) ^ gf_mult(MIX_COLUMNS_MATRIX[r][1], state[1][c])
    return new_state
# 密钥加
def add_round_key(state, round_key):
    """密钥加"""
    return [[state[row][col] ^ round_key[row][col] for col in range(2)] for row in range(2)]
def format_input(input_str):
    """将16位二进制字符串格式化为2x2状态矩阵"""
    if not set(input_str).issubset({'0', '1'}):
        raise ValueError("Invalid binary string")
    
    if len(input_str) != 16:
        raise ValueError("Input string length must be 16 bits")
    
    return [[int(input_str[i:i+4], 2) for i in range(0, 8, 4)],       
            [int(input_str[i:i+4], 2) for i in range(8, 16, 4)]]

#将密文转换为16位字符串
def state_to_16bit_string(state):
    result = ''
    for row in state:
        for value in row:
            result += format(value, '04b')  # 转换为4位二进制字符串
    return result

def s_aes_encrypt(plaintext, key):
    flag=0
    # 检查输入数据是否为ASCII
    if is_ascii(plaintext):
        plaintext = ascii_to_binary(plaintext)
        print(plaintext)
        flag=1
    # 把plaintext和key正确格式化为状态矩阵
    plaintext = format_input(plaintext)
    key = format_input(key)
    state = plaintext

    # 初始化轮密钥
    round_keys = generate_round_keys(key)

    # 初始轮密钥加
    state = add_round_key(state, round_keys[0])

    # 第一轮加密
    state = sub_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, round_keys[1])

    # 第二轮加密
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[2])
    state=state_to_16bit_string(state)
    print("16bit密文:",state)
    if flag==1:
        state=binary_to_ascii(state)
    return state  # 返回加密结果
def generate_round_keys(key):
    """生成轮密钥"""
    def sub_nib(nibble):
        if not (0 <= nibble < 16):  # 确保 nibble 是4位数
            raise ValueError(f"Invalid nibble value: {nibble}")
        return s_box[nibble >> 4][nibble & 0x3]
    def rot_nib(word):
        """旋转并交换前后4比特"""
        return [word[1], word[0]]
    w = [None] * 6
    w[0], w[1] = key[0][0] << 4 | key[0][1], key[1][0] << 4 | key[1][1]  # 将2x2数组转为整数
    RCON_1 = 0x80
    RCON_2 = 0x30
    # w2
    rot_w1 = rot_nib([w[1] >> 4, w[1] & 0xF])
    w2_temp = (sub_nib(rot_w1[0]) << 4 | sub_nib(rot_w1[1]))
    w[2] = w[0] ^ RCON_1 ^ w2_temp
    # w3
    w[3] = w[2] ^ w[1]
    # w4
    rot_w3 = rot_nib([w[3] >> 4, w[3] & 0xF])
    w4_temp = (sub_nib(rot_w3[0]) << 4 | sub_nib(rot_w3[1]))
    w[4] = w[2] ^ RCON_2 ^ w4_temp
    # w5
    w[5] = w[4] ^ w[3]
    print("Input Key:")
    print(key)
    print("w Array:")
    print(w)
    print(hex(w[2]))
    print(hex(w[3]))
    print(hex(w[4]))
    print(hex(w[5]))
    round_keys = [
        [[w[0] >> 4, w[0] & 0xF], [w[1] >> 4, w[1] & 0xF]], 
        [[w[2] >> 4, w[2] & 0xF], [w[3] >> 4, w[3] & 0xF]], 
        [[w[4] >> 4, w[4] & 0xF], [w[5] >> 4, w[5] & 0xF]]
    ]
    return round_keys
#判断输入是否为ascii值
def is_ascii(s):
    if set(s).issubset({'0', '1'}):
        return False
    try:
        s.encode('ascii')
        return True
    except UnicodeEncodeError:
        return False

#将ascii装换成16bit
def ascii_to_binary(ascii_str):
    return ''.join(format(ord(char), '08b') for char in ascii_str)
#把16bit转换为ascii
def binary_to_ascii(binary_str):
    return ''.join(chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8))
#解密操作：
# 定义逆S-Box
inv_s_box = [
    [0xA, 0x5, 0x9, 0xB],
    [0x1, 0x7, 0x8, 0xF],
    [0xC, 0x0, 0x2, 0xE],
    [0x3, 0x4, 0x6, 0xD]
]
def inv_sub_bytes(state):
    """逆字节替换"""
    for row in range(2):
        for col in range(2):
            value = state[row][col]
            if not (0 <= value <= 15):
                raise ValueError(f"Invalid value in state matrix: {value}")
            
            i = value >> 2  # 获取前两位
            j = value & 0x3  # 获取后两位

            # 根据i和j查找逆S盒中的元素并替换
            state[row][col] = inv_s_box[i][j]          
    return state
def inv_shift_rows(state):
    """逆行移位"""
    return [state[0], [state[1][1], state[1][0]]]  # 仅交换第二行元素
# 定义逆列混淆所需的固定矩阵
INV_MIX_COLUMNS_MATRIX = [
    [9, 2],
    [2, 9]
]
def inv_mix_columns(state):
    """逆列混淆操作"""
    new_state = [[0, 0], [0, 0]]
    for c in range(2):
        for r in range(2):
            new_state[r][c] = gf_mult(INV_MIX_COLUMNS_MATRIX[r][0], state[0][c]) ^ gf_mult(INV_MIX_COLUMNS_MATRIX[r][1], state[1][c])
    return new_state
def s_aes_decrypt(ciphertext, key):
    flag1=0
    # 检查输入数据是否为ASCII
    if is_ascii(ciphertext):
        ciphertext = ascii_to_binary(ciphertext)
        print(ciphertext)
        flag1=1
    # 把ciphertext和key正确格式化为状态矩阵
    ciphertext = format_input(ciphertext)
    key = format_input(key)
    state = ciphertext
    # 初始化轮密钥
    round_keys = generate_round_keys(key)
    # 初始轮密钥加
    state = add_round_key(state, round_keys[2])
    # 第一轮解密
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[1])
    state = inv_mix_columns(state)
    # 第二轮解密
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    state=state_to_16bit_string(state)
    print("16bit明文:",state)
    if flag1==1:
        state=binary_to_ascii(state)
    return state  # 返回加密结果
# UI：
#加密
def encrypt():
    plaintext = plaintext_entry.get()
    key = key_entry.get()
    print("Plaintext before format:", plaintext)
    print("Key before format:", key)

    # 检查输入
    if not plaintext:
        # 显示错误消息
        return
    if not key:
        # 显示错误消息
        return
    ciphertext = s_aes_encrypt(plaintext, key)
    result_label.config(text=f'Ciphertext: {ciphertext}')
#双重加密(按钮命令)
def double_encrypt():
    plaintext = plaintext_entry.get()
    key = key_entry.get()
    print("Plaintext before format:", plaintext)
    print("Key before format:", key)

    # 检查输入
    if not plaintext:
        # 显示错误消息
        return
    if not key:
        # 显示错误消息
        return
    ciphertext =double_s_aes_encrypt(plaintext, key)
    result_label.config(text=f'Ciphertext: {ciphertext}')
#三重加密(按钮命令)
def triple_encrypt():
    plaintext = plaintext_entry.get()
    key = key_entry.get()
    print("Plaintext before format:", plaintext)
    print("Key before format:", key)

    # 检查输入
    if not plaintext:
        # 显示错误消息
        return
    if not key:
        # 显示错误消息
        return
    ciphertext =triple_s_aes_encrypt(plaintext, key)
    result_label.config(text=f'Ciphertext: {ciphertext}')
#解密
def decrypt():
    ciphertext = ciphertext_entry.get()
    print("ciphertext before format:",ciphertext)
    key = key_entry.get()
    print("Key before format:",key)
        # 检查输入
    if not ciphertext:
        # 显示错误消息
        return
    if not key:
        # 显示错误消息
        return
    plaintext =s_aes_decrypt(ciphertext, key)
    result_label1.config(text=f'plaintext: {plaintext}')

#双重解密（按钮命令）
def double_decrypt():
    ciphertext = ciphertext_entry.get()
    print("ciphertext before format:",ciphertext)
    key = key_entry.get()
    print("Key before format:",key)
        # 检查输入
    if not ciphertext:
        # 显示错误消息
        return
    if not key:
        # 显示错误消息
        return
    plaintext =double_s_aes_decrypt(ciphertext, key)
    result_label1.config(text=f'plaintext: {plaintext}')

#三重解密（按钮命令）
def triple_decrypt():
    ciphertext = ciphertext_entry.get()
    print("ciphertext before format:",ciphertext)
    key = key_entry.get()
    print("Key before format:",key)
        # 检查输入
    if not ciphertext:
        # 显示错误消息
        return
    if not key:
        # 显示错误消息
        return
    plaintext =triple_s_aes_decrypt(ciphertext, key)
    result_label1.config(text=f'plaintext: {plaintext}')
#双重加密
def double_s_aes_encrypt(plaintext, key):
    # 检查密钥长度是否为32 bits
    if len(key) != 32:
        raise ValueError("Key length must be 32 bits")
    
    # 分割32位密钥为两个16位子密钥
    key1, key2 = key[:16], key[16:]
    
    # 第一次加密
    intermediate_ciphertext = s_aes_encrypt(plaintext, key1)
    
    # 第二次加密
    final_ciphertext = s_aes_encrypt(intermediate_ciphertext, key2)
    
    return final_ciphertext

#双重解密
def double_s_aes_decrypt(ciphertext, key):
    # 检查密钥长度是否为32 bits
    if len(key) != 32:
        raise ValueError("Key length must be 32 bits")
    
    # 分割32位密钥为两个16位子密钥
    key1, key2 = key[:16], key[16:]
    
    # 第一次解密
    intermediate_plaintext = s_aes_decrypt(ciphertext, key2)
    
    # 第二次解密
    final_plaintext = s_aes_decrypt(intermediate_plaintext, key1)
    
    return final_plaintext
#三重加密
def triple_s_aes_encrypt(plaintext, key):
    # 检查密钥长度是否为48 bits
    if len(key) != 48:
        raise ValueError("Key length must be 48 bits")
        # 分割48位密钥为三个16位子密钥
    k1, k2,k3 = key[:16], key[16:32],key[32:]
    
    intermediate1 = s_aes_encrypt(plaintext, k1)
    intermediate2 = s_aes_encrypt(intermediate1, k2)
    final_ciphertext = s_aes_encrypt(intermediate2, k3)
    return final_ciphertext
#三重解密
def triple_s_aes_decrypt(ciphertext,key):
    # 检查密钥长度是否为48 bits
    if len(key) != 48:
        raise ValueError("Key length must be 48 bits")
    # 分割48位密钥为三个16位子密钥
    k1, k2,k3 = key[:16], key[16:32],key[32:]
    intermediate1 = s_aes_decrypt(ciphertext, k3)
    intermediate2 = s_aes_decrypt(intermediate1, k2)
    final_plaintext = s_aes_decrypt(intermediate2, k1)
    return final_plaintext



#cbc工作模式
def XOR(bit_string1, bit_string2):
    result = ""
    for b1, b2 in zip(bit_string1, bit_string2):
        if b1 == b2:
            result += "0"
        else:
            result += "1"
    return result

def cbc_encrypt(plaintext, key, IV):
    plaintext_blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    ciphertext = ""
    previous_ciphertext_block = IV
    for block in plaintext_blocks:
        block_to_encrypt = XOR(block, previous_ciphertext_block)
        encrypted_block = s_aes_encrypt(block_to_encrypt, key)
        ciphertext += encrypted_block
        previous_ciphertext_block = encrypted_block
    return ciphertext

def cbc_decrypt(ciphertext, key, IV):
    ciphertext_blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    decrypted_text = ""
    previous_ciphertext_block = IV
    for block in ciphertext_blocks:
        decrypted_block = s_aes_decrypt(block, key)
        decrypted_text_block = XOR(decrypted_block, previous_ciphertext_block)
        decrypted_text += decrypted_text_block
        previous_ciphertext_block = block
    return decrypted_text

def modify_a_block(ciphertext):
    # 将第一个密文块中的每个位反转
    first_block = ciphertext[:16]
    modified_block = ""
    for bit in first_block:
        modified_block += "1" if bit == "0" else "0"
    return modified_block + ciphertext[16:]

IV = "1010101010101010"
key = "1010101010101010"  

plaintexttest = "10101010101010101010101010101010"
ciphertext1 = cbc_encrypt(plaintexttest, key, IV)
decrypted_text1=cbc_decrypt(ciphertext1, key, IV)
print("对密文分组替换修改前的解密结果：",decrypted_text1)

# 修改密文的某个块
ciphertext2 = modify_a_block(ciphertext1)

decrypted_text = cbc_decrypt(ciphertext2, key, IV)

print("修改后：",decrypted_text)

# 创建主窗口
window = tk.Tk()
window.title("S-AES Encryption")
# 创建并放置标签和输入字段
plaintext_label = Label(window, text="Plaintext (16 bits):")
plaintext_label.pack()
plaintext_entry = Entry(window)
plaintext_entry.pack()

key_label = Label(window, text="Key (16 bits):")
key_label.pack()
key_entry = Entry(window)
key_entry.pack()

ciphertext_label = Label(window, text="ciphertext (16 bits):")
ciphertext_label.pack()
ciphertext_entry = Entry(window)
ciphertext_entry.pack()
# 创建并放置加密按钮
encrypt_button = Button(window, text="加密", command=encrypt)
encrypt_button.pack()
#创建并放置解密按钮
decrypt_button = Button(window, text="解密", command=decrypt)
decrypt_button.pack()
# 创建并放置加密按钮
double_encrypt_button = Button(window, text="双重加密", command=double_encrypt)
double_encrypt_button.pack()
#创建并放置解密按钮
double_decrypt_button = Button(window, text="双重解密", command=double_decrypt)
double_decrypt_button.pack()
# 创建并放置加密按钮
triple_encrypt_button = Button(window, text="三重加密", command=triple_encrypt)
triple_encrypt_button.pack()
#创建并放置解密按钮
triple_decrypt_button = Button(window, text="三重解密", command=triple_decrypt)
triple_decrypt_button.pack()
# 创建并放置结果标签
result_label = Label(window, text="Ciphertext: ")
result_label.pack()
result_label1 = Label(window, text="plaintext: ")
result_label1.pack()
# 启动事件循环
window.mainloop()


