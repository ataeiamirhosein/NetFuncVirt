
 # author Amirhosein Ataei
 # date March 2020

import timeit

class BinaryNode(object):
    def __init__(self, NextHop=""):
        self.NextHop = NextHop  # here we save the value of the leaf node
        self.Left = None  # 0's branch
        self.Right = None  # 1's branch

    def AddChild(self, prefix, path):
        if len(path) == 0:
            return

        if len(path) == 1:
            if path == "0":
                self.Left = BinaryNode(NextHop=prefix)
            else:
                self.Right = BinaryNode(NextHop=prefix)
        elif len(path) > 1:
            if path.startswith("0"):
                if self.Left is None:
                    self.Left = BinaryNode()

                self.Left.AddChild(prefix, path[1:])

            else:
                if self.Right is None:
                    self.Right = BinaryNode()

                self.Right.AddChild(prefix, path[1:])

    def Lookup(self, address, backtrack=""):

        if self.NextHop != "":  # saving the last hop visited
            backtrack = self.NextHop

        if address == "" or (self.Left is None and self.Right is None):  # if we are on a leaf node return the last prefix
            return backtrack

        if address.startswith("0"):  # for each hop we check whether go to the left or right branch
            if self.Left is not None:  # if there's still a child, look deeper in the trie
                return self.Left.Lookup(address[1:], backtrack)
            else:  # otherwise return the last valid prefix
                return backtrack
        else:
            if self.Right is not None:
                return self.Right.Lookup(address[1:], backtrack)
            else:
                return backtrack

    def LookupNonRecursive(self, address, rootPrefix = "0"):
        backtrack = ""
        partialAddress =address
        node = self

        while (node is not None):
            if node.NextHop != "":
                backtrack = node.NextHop

            if partialAddress == "" or (node.Left is None and node.Right is None):
                return backtrack

            if partialAddress.startswith("0"):
                if node.Left is not None:
                    partialAddress = partialAddress[1:]
                    node = node.Left
                else:
                    return backtrack
            else:
                if node.Right is not None:
                    partialAddress = partialAddress[1:]
                    node = node.Right
                else:
                    return backtrack

        return backtrack

def Create(default_value='0'):
    # helper method to rapidly create the trie reading the db.txt

    _root = BinaryNode(default_value)

    with open("db.txt", 'r') as f:
        my_list = [line.rstrip('\n') for line in f]

    for address in my_list:
        addr, binary_address = address.split(',')
        ip, mask = addr.split("\\")

        _root.AddChild(ip, binary_address)

    return _root

def convert_in_bin(address):
    # simple method to convert an IP address in its binary representation
    if address.find('\\') != -1:
        ip = address.split("\\")[0]
        mask = int(address.split("\\")[1])
        return ''.join([bin(int(x) + 256)[3:] for x in ip.split('.')])[:mask]
    else:
        return ''.join([bin(int(x) + 256)[3:] for x in address.split('.')])

def _is_binary(string):
    is_binary = True
    try:
        int(string, 2)
    except ValueError:
        is_binary = False
    return is_binary

# DEBUG
if __name__ == "__main__":

    root = Create("0")

    with open('tosearch.txt', 'r') as t:
        my_list = [line.rstrip('\n') for line in t]

    times = []
    for entry in my_list:
        addr = entry.split(",")[0]
        ip = addr.split("\\")[0]
        mask = int(addr.split("\\")[1])
        binary_address = convert_in_bin(ip)[:mask]

        start = timeit.default_timer()
        root.Lookup(binary_address)
        end = timeit.default_timer() - start
        times.append(end * 1000)

    print ("binary trie: " + str(sum(times)) + "ms")
