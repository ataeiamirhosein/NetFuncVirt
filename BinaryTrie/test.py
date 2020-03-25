import unittest
from trie import *

class TestForwardingTable(unittest.TestCase):
  
  def setUp(self):
      table = open("table.txt", "r")
      self.trie = Trie()

      n = int(table.readline())
      for i in range(n):
        entry = table.readline().split(":")
        self.trie.add_ip_prefix(entry[0], int(entry[1]))

  def test_lookup1(self):
      self.assertEqual(self.trie.lookup("63.19.5.3"), 3)

  def test_lookup2(self):
      self.assertEqual(self.trie.lookup("171.15.15.0"), 4)

  def test_lookup3(self):
      self.assertEqual(self.trie.lookup("63.19.5.32"), 1)

  def test_lookup4(self):
      self.assertEqual(self.trie.lookup("44.199.230.1"), 1)

  def test_lookup5(self):
      self.assertEqual(self.trie.lookup("171.128.16.0"), 2)

  def test_lookup6(self):
      self.assertEqual(self.trie.lookup("18.1.1.1"), 5)

  def test_lookup7(self):
      self.assertEqual(self.trie.lookup("55.64.0.0"), 1)

  def test_lookup8(self):
      self.assertEqual(self.trie.lookup("55.150.0.0"), 6)
