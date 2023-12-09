prefix = "0001"
hash = "31CC7BDDC220BC0707D7CA4AA2795D2B64E8E6759DC276620BE6D3119158729E"
A = "30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20".replace(' ','')
total_len = 256
pad_len = total_len - 1 - (len(A)+len(prefix)+len(hash))//2
body = prefix + "FF" * pad_len + "00" + A + hash

print(body)