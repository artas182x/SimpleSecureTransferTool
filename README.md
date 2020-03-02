Secure file transfer tool
===

Simple file transfer sender and receiver tool using TCP written in go (GUI included). Transfer is done by using AES symmetric encryption. Before sending files both computers exchange their public keys (asymmetric encryption) so that session key used for encrypting file can be securely sent to second computer. 

Files should be encrypted using symmetric alghorytms because this method is much faster (many modern processors have AES instruction set included). Asymmetric encryption should be used for encrypting small amount of data (like our session key used for encrypting file).

