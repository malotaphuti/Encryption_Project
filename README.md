# Encryption_Project

The project a variation of the substitution table method. Our first step was creating an array containing all the ASCII characters.
We then created a second array that took all the values from the first array and scrambled them so that the values of the arrays were the same, but the 
indexes in the second array were randomized every time. We then enter the plaintext file and key(int) into the algorithm where every character in the plaintext 
would be substituted with the value of the index at the corresponding character in the second array. The value would be multiplied by the value of the key entered by the 
user. The values of each substituted character are then split by commas. With all these steps completed, the file is encrypted.

To decrypt the file, we take the index of each character of our ciphertext represented in the scrambled ascii table and store them in an array. 
The index is now divided by the value of the key entered by the user, to get the original values of the index. The index of the normal ASCII table is converted back to 
characters after division. The divided index is now compared to the index of the normal ASCII table. Each character of the ciphertext is then replaced by the original 
ASCII characters. Upon completion of this step, the plain text will be retrieved.
