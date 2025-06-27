import pyshark
import os
from collections import defaultdict

# --- 配置 ---
PCAP_FILE_PATH = 'Right_Joy-Con_OTA.pcapng'  # 替换为你的抓包文件名
TARGET_HANDLE = '0x0018'                  # 目标句柄
OUTPUT_FILE_PATH_RAW = 'ota_raw_payload_filtered.bin' # 临时存储拼接后的原始数据
OUTPUT_FILE_PATH_ANALYSIS = 'ota_chunk_analysis_filtered.txt' # 分析结果输出文件

# --- 新增配置：要排除的坏报文的帧ID ---
# 使用集合(set)以便快速查找，效率更高
BAD_PACKET_FRAME_IDS = {3809, 7113, 8594} 

# --- 协议参数 ---
BYTES_PER_GROUP = 4108 

def analyze_ota_chunks_with_filter(pcap_file, handle, bad_ids):
    """
    拼接OTA数据流，分块后提取并分析每块的边界数据，同时排除已知的坏报文。
    """
    if not os.path.exists(pcap_file):
        print(f"错误: 抓包文件 '{pcap_file}' 不存在。")
        return

    print(f"正在打开抓包文件: {pcap_file}")
    print(f"筛选目标句柄: {handle}")
    print(f"将要排除的坏报文帧ID: {sorted(list(bad_ids))}") # 排序后打印，更清晰

    packet_data = defaultdict(dict)
    
    capture_filter = f'btatt.handle == {handle} && (btatt.opcode.method == 0x52 || btatt.opcode.method == 0x12)'
    
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter=capture_filter)
        
        group_counter = -1
        
        # --- 步骤 1: 提取并排序所有数据包，同时过滤坏报文 ---
        print("\n步骤 1: 正在提取、过滤并排序所有数据包...")
        for packet in cap:
            # --- 关键的过滤逻辑 ---
            # pyshark中的 .number 是字符串，需要转换为整数进行比较
            frame_number = int(packet.frame_info.number)
            if frame_number in bad_ids:
                print(f"信息: 跳过已知的坏报文，帧ID: {frame_number}")
                continue # 跳过此循环的剩余部分，处理下一个包
            # --- 过滤逻辑结束 ---

            try:
                raw_value_hex = packet.btatt.value
                cleaned_value_hex = raw_value_hex.replace(':', '')
                value_bytes = bytes.fromhex(cleaned_value_hex)
                
                control_header = value_bytes[:4]
                payload = value_bytes[4:]

                opcode = control_header[0]
                seq_num = control_header[1]

                if opcode == 0x01:
                    group_counter += 1
                
                if group_counter >= 0:
                    packet_data[group_counter][seq_num] = payload

            except (AttributeError, IndexError):
                pass
        
        print(f"数据提取完成，共发现 {group_counter + 1} 个有效的数据组。")

        # --- 步骤 2: 拼接成完整的数据流 ---
        print("\n步骤 2: 正在拼接成完整的数据流...")
        full_payload = bytearray()
        sorted_groups = sorted(packet_data.keys())

        for group_idx in sorted_groups:
            sorted_packets_in_group = sorted(packet_data[group_idx].keys())
            for seq_idx in sorted_packets_in_group:
                full_payload.extend(packet_data[group_idx][seq_idx])
        
        with open(OUTPUT_FILE_PATH_RAW, 'wb') as f_raw:
            f_raw.write(full_payload)
        print(f"过滤后的完整原始数据流已保存到: {OUTPUT_FILE_PATH_RAW} ({len(full_payload)} 字节)")


        # --- 步骤 3: 分块并分析边界数据 ---
        print("\n步骤 3: 正在分块并分析边界数据...")
        with open(OUTPUT_FILE_PATH_ANALYSIS, 'w') as f_analysis:
            f_analysis.write("OTA 数据块边界分析 (已过滤坏报文)\n")
            f_analysis.write("="*50 + "\n\n")

            num_groups = len(full_payload) // BYTES_PER_GROUP
            for i in range(num_groups):
                chunk_start_index = i * BYTES_PER_GROUP
                chunk_end_index = chunk_start_index + BYTES_PER_GROUP
                chunk = full_payload[chunk_start_index:chunk_end_index]

                if len(chunk) < BYTES_PER_GROUP:
                    print(f"警告: 第 {i+1} 块数据不完整 (长度 {len(chunk)})，跳过分析。")
                    continue

                header = chunk[:12]
                footer = chunk[-12:]

                f_analysis.write(f"--- 数据块 {i+1:02d} ---\n")
                f_analysis.write(f"在过滤后数据流中的偏移量: 0x{chunk_start_index:08X}\n")
                
                header_hex = header.hex(' ')
                f_analysis.write(f"前 12 字节: {header_hex}\n")
                int1 = int.from_bytes(header[0:4], 'little')
                int2 = int.from_bytes(header[4:8], 'little')
                int3 = int.from_bytes(header[8:12], 'little')
                f_analysis.write(f"  解析为3个32位整数 (小端): 0x{int1:08X}, 0x{int2:08X}, 0x{int3:08X}\n\n")

                footer_hex = footer.hex(' ')
                f_analysis.write(f"后 12 字节: {footer_hex}\n")
                int4 = int.from_bytes(footer[0:4], 'little')
                int5 = int.from_bytes(footer[4:8], 'little')
                int6 = int.from_bytes(footer[8:12], 'little')
                f_analysis.write(f"  解析为3个32位整数 (小端): 0x{int4:08X}, 0x{int5:08X}, 0x{int6:08X}\n\n")
                f_analysis.write("-" * 20 + "\n\n")

        print("分析完成！")
        print(f"边界数据分析结果已保存到: {OUTPUT_FILE_PATH_ANALYSIS}")

    except Exception as e:
        print(f"处理过程中发生错误: {e}")
    finally:
        if 'cap' in locals() and cap.close:
            cap.close()


if __name__ == '__main__':
    analyze_ota_chunks_with_filter(PCAP_FILE_PATH, TARGET_HANDLE, BAD_PACKET_FRAME_IDS)