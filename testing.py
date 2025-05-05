from scapy.all import get_if_list
print("Available interfaces:")
for i in get_if_list():
    print(repr(i))
