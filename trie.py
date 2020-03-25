
class Node:

	def __init__(self):
		self.right = None
		self.left = None
		self.value = None

class Trie:

	def __init__(self):
		self.root = Node()

	def _longest_prefix_value(self, node, key, values):
		n = len(key)

		if node.value != None:
			values.append(node.value)

		if n == 0: return values

		for i in range(n):
			x = key[i]
			if x == "1":
				if node.right != None:
					return self._longest_prefix_value(node.right,
					 	key[i+1:], values)
				else :
					return values
			if x == "0":
				if node.left != None:
					return self._longest_prefix_value(node.left, 
						key[i+1:], values)
				else :
					return values

	def longest_prefix_value(self, key):
		values = []
		values = self._longest_prefix_value(self.root, key, values)
		if len(values) == 0: return None
		return values[-1]

	def lookup(self, ip):
		x = ip.split(".")

		for i in range(4):
			x[i] = format(int(x[i]), "#010b")[2:]

		binary = "".join(x)
		return self.longest_prefix_value(binary)


	def add_bin(self, key, value):
		n = len(key)
		node = self.root
		for i in range(n):
			x = key[i]
			if x == "1":
				if node.right == None:
					node.right = Node()
				node = node.right
			elif x == "0":
				if node.left == None:
					node.left = Node()
				node = node.left
		node.value = value

	# accepts input of form a.b.c.d/e
	def add_ip_prefix(self, prefix, value):
		x = prefix.split(".")
		n = int(x[3].split("/")[1]) # getting the length of prefix
		x[3] = x[3].split("/")[0]

		for i in range(4):
			x[i] = format(int(x[i]), "#010b")[2:]

		binary = "".join(x)
		binary = binary[:n]
		self.add_bin(binary, value)




