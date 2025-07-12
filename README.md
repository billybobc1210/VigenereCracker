# Vigener Cipher Cracker

This is a program for cracking a message enciphered using a Vigenere Cipher.  The class for doing the cracking is called
VigenereCracker.  It also includes a class, VigenereCipher,for enciphering and deciphering such messages with a known 
key.

## How it works

A Vigenere Cipher works as follows.  Given a plain text message such as:

```
All we have to fear is fear itself.
```
First we normalize the data by getting getting rid of everything except alphabetic characters and coverting 
to upper case.

```
ALLWEHAVETOFEARISFEARITSELF
```

Next pick a key, such as "DOG", and place the key repeating above the plain text message

```
DOGDOGDOGDOGDOGDOGDOGDOGDOG
ALLWEHAVETOFEARISFEARITSELF
```

Use the following table called the Tabula Recta to encipher each character.

```
    Plain text character  
    
    ABCDEFGHIJKLMNOPQRSTUVWXYZ  
    --------------------------
A   ABCDEFGHIJKLMNOPQRSTUVWXYZ  
B   BCDEFGHIJKLMNOPQRSTUVWXYZA  
C   CDEFGHIJKLMNOPQRSTUVWXYZAB  
D   DEFGHIJKLMNOPQRSTUVWXYZABC  
E   EFGHIJKLMNOPQRSTUVWXYZABCD  
F   FGHIJKLMNOPQRSTUVWXYZABCDE  
G   GHIJKLMNOPQRSTUVWXYZABCDEF  
H   HIJKLMNOPQRSTUVWXYZABCDEFG  
I   IJKLMNOPQRSTUVWXYZABCDEFGH  
J   JKLMNOPQRSTUVWXYZABCDEFGHI  
K   KLMNOPQRSTUVWXYZABCDEFGHIJ  
L   LMNOPQRSTUVWXYZABCDEFGHIJK  
M   MNOPQRSTUVWXYZABCDEFGHIJKL  
N   NOPQRSTUVWXYZABCDEFGHIJKLM  
O   OPQRSTUVWXYZABCDEFGHIJKLMN  
P   PQRSTUVWXYZABCDEFGHIJKLMNO  
Q   QRSTUVWXYZABCDEFGHIJKLMNOP  
R   RSTUVWXYZABCDEFGHIJKLMNOPQ  
S   STUVWXYZABCDEFGHIJKLMNOPQR  
T   TUVWXYZABCDEFGHIJKLMNOPQRS  
U   UVWXYZABCDEFGHIJKLMNOPQRST  
V   VWXYZABCDEFGHIJKLMNOPQRSTU  
W   WXYZABCDEFGHIJKLMNOPQRSTUV  
X   XYZABCDEFGHIJKLMNOPQRSTUVW  
Y   YZABCDEFGHIJKLMNOPQRSTUVWX  
Z   ZABCDEFGHIJKLMNOPQRSTUVWXY
```
For each plain text character in the message, use the key character above it to find the correct row to
use in the tabula recta to encipher the character.  E.g. the first 'A' in the plain text will be enciphered using the 'D' in "DOG".  So
find the row in the table with a heading of 'D' and the column that is headed by the 'A' character.  Where those two 
intersect is the enciphered character ('D').  The next plain text character is an 'L' enciphered by the 'O' character.
The character at the intersection of the 'O' row and the 'L' column is 'Z'. etc, giving a cipher text of:

```
DZRZSNDJKWCLHOXLGLHOXLHYHZL
```

The goal of the Vigenere cipher is to make deciphering using frequency analysis more difficult by flattening the
character frequency distribution in the enciphered text, since the same character can be enciphered to any other 
character at any time, including itself.

## Cracking the Vigenere Cipher

The strategy for cracking the Vigenere cipher is to:
1) determine the most likely length of the key
2) once the key length, k,  is known we can break the cipher text into k-length substrings where each character at
position in in the substring was encrypted using the same alphabet, allowing us to use character frequency analysis
on the substring.

### Determining the length of the key.

Given a cipher text of, that was enciphered with a key of length 3,

```
DZRZSNDJKWCLHOXLGLHOXLHYHZL
```

if we conjecture a key length of 3 and rewrite the cipher text like this:

```
DOG <- KEY
---
DZR
ZSN
DJK
WCL
HOX
LGL
HOX
LHY
HZL
```
We can see that every character in column 0 was enciphered using the 'D' character in the key, meaning that all those
characters came from the same enciphering alphabet in the tabula recta. Similar for column 1 ('O' character in the key) 
and 2 ('G' character in the key). Therefore if we construct 3 strings from the characters in each of these 3 columns 
like this:
```
Column 1: DZDWHLHOX  
Column 2: ZSJCOGOHZ
Column 3: RNKLXLXYL
```
each of these strings will be subject to frequency analysis.  If we take the standard deviation of all the characters
frequencies in these strings, we should find that the standard deviation will be higher than similar strings constructed
using the incorrect key length.  If we conjecture a range of key lengths and keep track of the best std dev score among
them, the true key length should give the highest score. 

### Determining the key.
Using the key length determined in the previous step, we again construct the 3 strings:
```
Column 1: DZDWHLHOX  
Column 2: ZSJCOGOHZ
Column 3: RNKLXLXYL
```
Looking at the most frequent cipher character from each of these strings we can start making conjectures about what the
plain text character was that it was enciphered from by assuming that it must be a common letter in the english
language. Then we can work backwards to the key character that would have enciphered it that way. We can then 
iteratively refine our best guess at what the key character is in each position, eventually arriving at the correct key.

### Testing the "Goodness" of a key

In order to iteratively refine the key that best fits, we need some way to test to see how well of a fit it is.  To
do this we use a conjectured key to decipher the cipher text and then test how english-y the generated plain text is
and give it a numeric score.  The way we do this is to search the plain text for common english bigrams, trigrams and
quadrigrams and use a formula to give it a numeric score. More weight will be give to trigrams and quadrigrams since
it is less likely that that those would shou up by random chance then bigrams. The highest score should correspond to
the correct key.
