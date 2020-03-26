import BinaryNode
import MultibitNode
import timeit

binary_root = BinaryNode.Create("0")
multibit_root = MultibitNode.Create()

# starting performing lookups
with open('tosearch.txt', 'r') as t:
    my_list = [line.rstrip('\n') for line in t]

times = []
for entry in my_list:
    binary_address = entry.split(',')[1]

    start = timeit.default_timer()
    binary_root.Lookup(binary_address)
    end = timeit.default_timer() - start
    times.append(end * 1000)

print("binary_trie (avg per lookup): " + str(sum(times)/len(times)) + "ms")
print("binary_trie (sum of all times): " + str(sum(times)) + "ms")

times = []
for entry in my_list:
    binary_address = entry.split(',')[1]

    start = timeit.default_timer()
    multibit_root.Lookup(binary_address, "0")
    end = timeit.default_timer() - start
    times.append(end * 1000)

print("multibit trie (avg per lookup): " + str(sum(times)/len(times)) + "ms")
print("multibit trie (sum of all times): " + str(sum(times)) + "ms")

# custom ips to search

switch = {}
switch["195.0.0.254"] = ["195.0.0.254", "8", "1"]
switch["128.128.0.254"] = ["128.128.0.254", "12", "2"]
switch["154.128.0.254"] = ["154.128.0.254", "16", "3"]
switch["197.160.0.254"] = ["197.160.0.254", "24", "4"]
switch["192.168.0.254"] = ["192.168.0.254", "24", "5"]
switch["192.169.0.254"] = ["192.169.0.254", "24", "6"]
switch["192.170.0.254"] = ["192.170.0.254", "24", "7"]

_root_multibit = MultibitNode.MultibitNode()
_root_binary = BinaryNode.BinaryNode("0")

tuples = []
for key, value in switch.iteritems():  # creating list of tuples for ordering
    ip = value[0]
    mask = int(value[1])
    tuples.append((ip, mask))

for entry in sorted(tuples, key=lambda x: x[1]):
    ip, mask = entry
    binary_address = MultibitNode.convert_in_bin(ip)[:mask]
    _root_multibit.AddChild(ip, binary_address)
    _root_binary.AddChild(ip, binary_address)

binary_address = MultibitNode.convert_in_bin("195.0.128.1")
print (_root_multibit.LookupNonRecursive(binary_address, "0"))
print (_root_binary.LookupNonRecursive(binary_address, "0"))
