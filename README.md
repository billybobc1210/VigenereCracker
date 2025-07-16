# Vigenere Cipher Cracker

This is a program for cracking a message enciphered using a Vigenere Cipher.  The class for doing the cracking is called
VigenereCracker.  The project also includes a class, VigenereCipher, for enciphering and deciphering such messages given
a key.  

## How the Vigenere Cipher works

Given a plain text message such as:

```
All we have to fear is fear itself.
```
First, we normalize the data by getting rid of everything except alphabetic characters and converting 
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
     ABCDEFGHIJKLMNOPQRSTUVWXYZ  <- plain text characters
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
 
 ^
 |
 +--- key characters
```
For each plain text character in the message, use the key character above it to find the correct row to
use in the Tabula Recta to encipher the character.  E.g. the first 'A' in the plain text will be enciphered using 
the 'D' in "DOG".  So find the row in the table with a heading of 'D' and the column that is headed by the 'A' 
character.  Where those two intersect is the enciphered character ('D').  The next plain text character is an 'L' 
enciphered by the 'O' character. The character at the intersection of the 'O' row and the 'L' column is 'Z'. etc. 
Eventually we end up with the complete cipher text of:

```
DZRZSNDJKWCLHOXLGLHOXLHYHZL
```
The goal of the Vigenere cipher is to make deciphering using frequency analysis more difficult by flattening the
character frequency distribution in the enciphered text, since the same character can be enciphered to any other 
character at any time, including itself.

## Cracking the Vigenere Cipher

The strategy for cracking the Vigenere cipher is to:  

1) Determine the most likely length of the key
2) Once the key length, k, is known, we can break the cipher text into k-length substrings where each character at
position p in the substring was encrypted using the same alphabet. We can then build k substrings using characters
all from the same enciphering alphabet and use frequency analysis to work backwards to finding the key.

### Determining the length of the key

*Note: the example used here is too short to work in practice, but using it here for illustrative purposes.*

Using our example of a text that was enciphered with the key, "DOG", for example

```
DZRZSNDJKWCLHOXLGLHOXLHYHZL
```

if we conjecture a key length of 3 and break the cipher text up into multiple strings of length 3 and rewrite it 
like this:

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
we can see that every character in column 1 was enciphered using the 'D' character in the key, meaning that all those
characters came from the same enciphering alphabet in the Tabula Recta. Similar for column 2 ('O' character in the key) 
and 3 ('G' character in the key). This will only be true for key lengths of 3 (or multiples of 3).  Therefore, if we 
construct 3 strings from the characters in each of these 3 columns like this:
```
Column 1: DZDWHLHLH  
Column 2: ZSJCOGOHZ
Column 3: RNKLXLXYL
```
each of these strings will be subject to frequency analysis.  If we take the standard deviation of all the character
frequencies in these strings, we should find that the standard deviation will be higher than similar strings constructed
using an incorrect key length. This is because the character frequency distribution should be basically the same as 
that of english, which is going to be less flat than an enciphered message that used multiple different alphabets 
in the enciphering process. If we conjecture a range of key lengths and keep track of the best std dev score among
them, the true key length should give the highest score.

*Note: This is not typically how the key length is determined.  Usually the Kasiski Test or the Index of Coincidence
is used.  This  is just what I came up with before I knew that and it seems to work okay so, but may fall over if I
start allowing longer keys. Leaving it alone for now and will revisit later.*

### Determining the key
Using the key length determined in the previous step, we again construct the 3 strings:
```
Column 1: DZDWHLHLH  
Column 2: ZSJCOGOHZ
Column 3: RNKLXLXYL
```
Looking at the most frequent cipher character from each of these strings, we can start making conjectures about what the
plain text character was that it was enciphered from by assuming that it must be a common letter in the english
language. Then we can work backwards to the key character that would have enciphered it that way. We can then 
iteratively refine our best guess at what the key character is in each position, eventually (hopefully) arriving at the 
correct key.

### Testing the "English-ness" of plain text

In order to iteratively refine the key that best fits, we need some way to test to see how good of a fit it is.  To
do this we use a conjectured key to decipher the cipher text and then test how english-y the generated plain text is
and give it a numeric score.  The way we do this is to search the plain text for common english bigrams, trigrams and
quadrigrams and use a formula to give it a numeric score. More weight will be given to trigrams and quadrigrams since
it is less likely that that these would show up by random chance than bigrams. The highest score should correspond to
the correct key.
