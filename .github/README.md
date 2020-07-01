# Tries data structures made for IP lookups
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/cf4d062267be4cb9bcd93e3174d77362)](https://www.codacy.com/manual/ataeiamirhosein/NetFuncVirt?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=ataeiamirhosein/NetFuncVirt&amp;utm_campaign=Badge_Grade)
### Binary Trie
![nfv binary-trie](binarytrie.jpg)
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
![nfv multibit-trie](multibit.jpg)
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
![nfv resault](nfv.jpg)  

## Virtual machines
Download the following virtual machines to develop your project:  

NFV projects: [ubuntu 16.04 LTS-server.ova](https://www.dropbox.com/s/f5tho1f01ms9f8b/ubuntu%2016.04%20LTS-server.ova?dl=0) and [ubuntu 16.04 LTS-client.ova](https://www.dropbox.com/s/b60olfpisw0q15h/ubuntu%2016.04%20LTS-client.ova?dl=0)

# Menu (selecting lookup algorithm)
also for testing in to the virtual machine we write a simple user friendly menu to select easily between the binary and multibit lookup in a sar nfv file.  

## References
- https://www.youtube.com/channel/UCebZ51n9g-B-bBMtgjMqm2w  
- special thanks to [Emanuele Gallone](https://github.com/EmanueleGallone) that helped us in the hard section of this project by providing code of the various [tries](https://github.com/EmanueleGallone/RyuTries)  

#
for course prof maier, S&R polimi  
