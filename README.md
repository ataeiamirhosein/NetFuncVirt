# Tries data structures made for IP lookups


### Binary Trie
![nfv binary-trie](https://www.iotco.net/binarytrie.jpg)
#### Usage:
```
import BinaryNode
```

to use a custom prefix table:
- just edit the db.txt file. Be careful to respect the file format (ip\mask, ip_in_binary)


create the Binary Trie:
```
root = BinaryNode.Create('Default value')
```
where the 'Default value' is the default prefix that is returned whenever the lookup fails (e.g. '0')

find longest prefix match:
```
root.Lookup(ip_bin)
```
where ip_bin is the binary representation of the ip. 
> e.g. ip to lookup =189.xxx.xxx.xxx\6 -> 101111 :
```
result = root.Lookup("001101")
```

#### Alternative:
You can also build manually the trie (the 'db.txt' file will be ignored):
```
import BinaryTrie

root = BinaryNode.BinaryNode('0')
root.AddChild("189.xxx.xxx.xxx", '101111')
```

#

### Multibit Trie
![nfv multibit-trie](https://www.iotco.net/multibit.jpg)
#### Usage:
```
import MultibitNode
```

to use a custom prefix table:
- just edit the db.txt file. Be careful to respect the file format (ip\mask, ip_in_binary)


> EXPERIMENTAL: You can also change the Stride of the Trie:
```
MultibitTrie.STRIDE = 2
```

Create the Trie:
```
root = MultibitNode.Create()
```

find longest prefix match:
```
MultibitNode.Lookup(binary_address, 'Default value')
```
where:
 - binary_address is the binary representation of an IP address 
 - 'Default value' is the value the is returned in case Lookup fails (e.g. '0')  
 
## Result  

result with considering the time complexity of algorithm

![nfv resault](https://www.iotco.net/nfv.jpg)  

## reference
https://www.youtube.com/channel/UCebZ51n9g-B-bBMtgjMqm2w  

## link of prj repo (gitlab)
https://gitlab.com/switching-and-routing-polimi-code-repository/2019-2020/project-11  

#
for course prof maier course S&R polimi
