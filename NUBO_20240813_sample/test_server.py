# 메커니즘
# 요청 signal 기다림
# 접속 요청 들어옴 F1
# 접속 요청 확인 보냄 F2

# 정보 저장 요청 받음 F3
# 정보 저장 요청 확인 보냄 F4

# 다운로드 준비 정보 보냄 FD
# 데이터 전송
# 다운로드 완료 정보 받음 FE
# 정보 저장 완료 보냄 F5


import os
import socket
##import CDHFrame_pb2 as CDH
import time
import re
import argparse
import select

server_ip = "192.168.137.1"
#server_ip = "127.0.0.1"

server_port = 50000
server_addr_port = (server_ip, server_port)

buffersize = 10000000
udp_server_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
udp_server_socket.bind(server_addr_port)
udp_server_socket.setblocking(False)

print("UDP server is up and listening")

def bytes_trans(int_val, bytes_info, start, end):
    hex_arr = [256**i for i in range(end - start + 1)  ][::-1]
    for (idx, h) in (zip(range(end, start -1, -1), hex_arr )) :
        if h == 1:
            bytes_info[idx] = int_val % 256
        else:
            bytes_info[idx] = int_val // h
            int_val = int_val % h

    return bytes_info



# def send_large_message(sock, message, addr, chunk_size=1024):
#     for i in range(0, len(message), chunk_size):
#         chunk = message[i:i+chunk_size]
#         sock.sendto(chunk, addr)

def send_large_message(sock, message, addr, chunk_size=1024, timeout=0.5):
    sock.setblocking(False)
    
    total_sent = 0
    while total_sent < len(message):
        ready = select.select([], [sock], [], timeout)
        if ready[1]:
            chunk = message[total_sent:total_sent + chunk_size]
            try:
                time.sleep(0.01)
                sent = sock.sendto(chunk, addr)
                total_sent += sent
            except BlockingIOError:
                time.sleep(0.01)  # 잠시 대기
    sock.setblocking(True)


class cliSock:
	startCode = bytes([0x55, 0x55, 0x55, 0x55])
	endcode = bytes([0xee, 0xee, 0xee, 0xee])
	last_send = ["0","0","0"]

def calculate_checksum(data):
	checksum = bytearray(4)
	for index in range(len(data)):
		checksum[index % 4] ^= data[index]
	return checksum

def sendCDH(directory):
##    cdh_hdr = CDH.CDH_hdr()
##    cdh_item = cdh_hdr.data.add()
##    cdh_item.file = os.path.basename(directory)
##
##    for file in os.listdir(directory):
##        cdh_item = cdh_hdr.data.add()
##        cdh_item.file = file
##        cdh_item.size = os.path.getsize(os.path.join(directory + "\\" + file))
##
##    encode_proto = cdh_hdr.SerializeToString()
##    sizess = len(encode_proto)
    
    data_head = cliSock.startCode #+ sizess.to_bytes(4, byteorder="little") + encode_proto
    ll = b''
    print("DEBUG")
    for file in os.listdir(directory):
        f = open(os.path.join(directory + "\\" + file), "rb")
        l = f.read(os.path.getsize(os.path.join(directory + "\\" + file)))
        check = calculate_checksum(l)
        data_ch = l + check
        ll += data_ch
        f.close()
        print(ll)
    data_head += ll
    
    return data_head

def msg_gen(msg_type):

    header_STX = b'0x44'
    header = bytearray(6)
    
    tail_d = b'0x44'
    tail = bytearray(1)
    tail[0] = int(tail_d,16)

    if "connect_check" == msg_type: # 접속 확인 후 보냄
        # 페이로드 4
        header_PL = b'0x07'
        header[0] = int(header_STX,16)
        header[1] = int(header_PL,16)
        header = bytes_trans(4,header,2,5 )
        ACK_data = bytearray(4)
        ACK_data[0] = ord("A")
        ACK_data[1] = ord("C")
        ACK_data[2] = ord("K")
        ACK_data[3] = 242 # F2
        
        msg = header + ACK_data + tail

    elif "Rep" == msg_type: # 정보 저장 요청
        # 페이로드 8
        header_PL = b'0x07'
        header[0] = int(header_STX,16)
        header[1] = int(header_PL,16)
        header = bytes_trans(8,header,2,5 )
        
        ACK_data = bytearray(4)
        ACK_data[0] = ord("A")
        ACK_data[1] = ord("C")
        ACK_data[2] = ord("K")
        ACK_data[3] = 244 # F4
        DNM_Rep = 5678
        DNM_Rep_data = bytearray(4)
        DNM_Rep_data = bytes_trans(DNM_Rep, DNM_Rep_data,0,3)
        
        msg = header + ACK_data + DNM_Rep_data + tail
    elif "Done" == msg_type:
        # 페이로드 8
        header_PL = b'0x07'
        header[0] = int(header_STX,16)
        header[1] = int(header_PL,16)
        header = bytes_trans(8,header,2,5 )
        
        ACK_data = bytearray(4)
        ACK_data[0] = ord("A")
        ACK_data[1] = ord("C")
        ACK_data[2] = ord("K")
        ACK_data[3] = 253 # F4
        DNM_Done = os.path.getsize("C:/Works/Jobs/Secure_OTA/Code_Dev/NUBO_20240813_sample/2024610_044658_000")
        DNM_Done_data = bytearray(4)
#         DNM_Rep = 5678
#         DNM_Rep_data = bytearray(4)
#         DNM_Rep_data = bytes_trans(DNM_Rep, DNM_Rep_data,0,3)
        DNM_Done_data = bytes_trans(DNM_Done, DNM_Done_data,0,3)
        msg = header + ACK_data + DNM_Done_data + tail
        
    elif "Down_start" == msg_type:
        bytes_data = sendCDH("C:/Works/Jobs/Secure_OTA/Code_Dev/NUBO_20240813_sample/2024610_044658_000")
        header_PL = b'0x07'
        header[0] = int(header_STX,16)
        header[1] = int(header_PL,16)
        header = bytes_trans(8,header,2,5 )
        ACK_data = bytearray(4)
        ACK_data[0] = ord("A")
        ACK_data[1] = ord("C")
        ACK_data[2] = ord("K")
        ACK_data[3] = 253 # FD
        Down_start = len(bytes_data)
        Down_start_data = bytearray(4)
        Down_start_data = bytes_trans(Down_start, Down_start_data,0,3)
        message = header + bytes_data + tail
        send_large_message(udp_server_socket, message, addr)
        #udp_server_socket.sendto(header + bytes_data + tail , addr)
        
        header = bytearray(6)
        header_PL = b'0x08'
        header[0] = int(header_STX,16)
        header[1] = int(header_PL,16)
        header = bytes_trans(len(bytes_data),header,2,5 )
        msg = header + bytes_data + tail
    return msg


if __name__ == "__main__":
    data_send = False
    while(True):
        try:
            byte_addr_pair = udp_server_socket.recvfrom(buffersize)
        except BlockingIOError:
            continue
        msg  = byte_addr_pair[0]
        addr = byte_addr_pair[1]
        print(" addr :", addr )
        print(" msg : ",msg)
        
        hd = msg[:6]
        recv_STX = hd[0]
        print("recv_STX , ", recv_STX)
        recv_payload = hd[1]
        print("recv_payload, ", recv_payload)
        recv_payload_length = hd[2] + hd[3]*256 + hd[4]*256*256 + hd[5] *256*256*256
        print("recv_payload_length, ",recv_payload_length)
        msg_len = recv_payload_length
        rev_sig = msg[6: 6 + msg_len ]
        print( "rev_sig : ", rev_sig )
        ack = rev_sig[:3]
        nuvo_sig = rev_sig[3]
        print("ACK : ", ack )
        if data_send:
            mk_msg = msg_gen("Down_start")
            udp_server_socket.sendto(mk_msg, addr)
        else:
            if nuvo_sig == 0xF1:
                mk_msg = msg_gen("connect_check")
                udp_server_socket.sendto(mk_msg, addr)

            elif nuvo_sig == 0xF3:
                # DNM
                mk_msg = msg_gen("Rep")
                udp_server_socket.sendto(mk_msg, addr)
                data_send = True
                mk_msg = msg_gen("Done")
                udp_server_socket.sendto(mk_msg, addr)
                data_send = False
            #elif nuvo_sig == 0xFD:
                mk_msg = msg_gen("Down_start")
                #udp_server_socket.sendto(mk_msg, addr)
                
            elif nuvo_sig == 0xFE:
                data_send = False
                mk_msg = msg_gen("Done")
                udp_server_socket.sendto(mk_msg, addr)
                
            elif int(nuvo_sig) < 241 :
                print(f"Connection[{nuvo_sig}]")
