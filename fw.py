import os

# --- 配置 ---
# 输入文件是上一个脚本生成的、拼接好的、过滤掉坏包的原始数据文件
INPUT_RAW_PAYLOAD_FILE = 'ota_raw_payload_filtered.bin' 
# 输出的将是纯净的固件文件，可用于Ghidra
OUTPUT_FIRMWARE_FILE = 'firmware.bin' 

# --- 协议参数 ---
CHUNK_SIZE = 4108      # 完整数据块的大小 (头部 + 载荷)
HEADER_SIZE = 12       # 我们刚刚发现的头部大小
PAYLOAD_SIZE = 4096    # 固件数据的大小 (4KB)

def extract_pure_firmware(input_file, output_file):
    """
    从拼接好的OTA数据流中剥离协议头，提取纯净的固件。
    """
    if not os.path.exists(input_file):
        print(f"错误: 输入文件 '{input_file}' 不存在。")
        print("请先运行上一个脚本来生成它。")
        return

    print(f"正在读取原始数据流: {input_file}")

    try:
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            firmware_size = 0
            chunk_count = 0
            while True:
                # 读取一个完整的数据块
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    # 文件读取完毕
                    break
                
                # 检查数据块长度是否符合预期
                if len(chunk) < CHUNK_SIZE:
                    # 处理最后一个可能不完整的块
                    # 假设最后一个块也带有12字节的头
                    if len(chunk) > HEADER_SIZE:
                        payload = chunk[HEADER_SIZE:]
                        f_out.write(payload)
                        firmware_size += len(payload)
                        chunk_count += 1
                        print(f"处理了最后一个不完整的块，提取了 {len(payload)} 字节的固件数据。")
                    else:
                         print(f"最后一个数据块太小({len(chunk)}字节)，已忽略。")
                    break

                # 提取数据载荷 (跳过前12个字节的头)
                payload = chunk[HEADER_SIZE : HEADER_SIZE + PAYLOAD_SIZE]
                
                # 写入到输出文件
                f_out.write(payload)
                firmware_size += len(payload)
                chunk_count += 1

        print("\n处理完成！")
        print(f"共处理了 {chunk_count} 个数据块。")
        print(f"提取的总固件大小: {firmware_size} 字节 (~{firmware_size / 1024:.2f} KB)")
        print(f"纯净的固件已保存到: {OUTPUT_FIRMWARE_FILE}")
        print("你现在可以将这个文件加载到Ghidra中进行逆向分析了。")

    except Exception as e:
        print(f"处理过程中发生错误: {e}")


if __name__ == '__main__':
    extract_pure_firmware(INPUT_RAW_PAYLOAD_FILE, OUTPUT_FIRMWARE_FILE)