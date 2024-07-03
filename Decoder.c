/*Write a C program that reads the file ciphertext.txt, 
  and outputs the keyword used to encode that plaintext and the plaintext.*/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>

#define FILENAME "ciphertext.txt"
#define MAX_SIZE 10000
#define SHIFTS 100
#define ALPHABET_SIZE 26

// Function to calculate the mean of an array
double calculate_mu(int arr[], int n) {
    double sum = 0.0;
    for (int i = 0; i < n; i++)
        sum += arr[i];
    return sum / n;
}

// Function to calculate the standard deviation of an array
double calculate_sigma(int arr[], int n, double mean) {
    double sum = 0.0;
    for (int i = 0; i < n; i++)
        sum += pow(arr[i] - mean, 2);
    return sqrt(sum / n);
}

// Function to find the probable key length using index of coincidence method
int KeyLength(char operable_string[], int size) {
    // Array to store the number of 'coincidences' for each jump size
    int coincidence[SHIFTS];

    // We compare the adjacent letters in the original and shifted string, if the letters are same the count of coincidence is increased  
    for (int c = 1; c < SHIFTS; c++) {
        int ct = 0;
        for (int i = 0; i < size; i++) {
            if (i + c < size) {
                if (operable_string[i] == operable_string[i + c])
                    ct++;
            }
        }
        coincidence[c - 1] = ct;
    }

    // Calculate mean and standard deviation of the matches
    double mu = calculate_mu(coincidence, SHIFTS - 1);
    double sigma = calculate_sigma(coincidence, SHIFTS - 1, mu);

    
    // Array to store frequencies of potential key lengths
    int frequencies[SHIFTS];
    int next = -1, gap = 0;

    // Identify potential key lengths based on matches
    for (int i = 0; i < SHIFTS - 1; i++) {
        if (coincidence[i] > mu + 1.2 * sigma) {
            if (next >= 0)
                frequencies[next] = gap;
            next++;
            gap = 0;
        }
        gap++;
    }

    // The key length occuring most often will give us the key length, hence calculating argmax of frequencies
    int argmax = frequencies[0];
    int maxCount = 0;

    for (int i = 0; i < next; i++) {
        int count = 0;
        for (int j = 0; j < next; j++) {
            if (frequencies[j] == frequencies[i]) {
                count++;
            }
        }
        if (count > maxCount) {
            maxCount = count;
            argmax = frequencies[i];
        }
    }

    return argmax;
}

// Function to find the decryption key
void findDecryptionKey(char *key, char operable_string[], int size, int n) {
    // Now that we have the possible key length, we can use the same to treat the message as n different substitution ciphers and perform frequency analysis
    // Standard English letter frequencies
    double alphabetFrequencies[ALPHABET_SIZE] = {
        8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03,
        2.41, 6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15,
        1.97, 0.07
    };

    // Loop through the key to find each character
    for (int i = 0; i < n; i++) {
        double tempFreq[ALPHABET_SIZE] = {0.0};
        double count = 0;

        // Calculate frequencies of characters at each key position
        for (int j = i; j < size; j += n) {
            if (isalpha(operable_string[j])) {
                tempFreq[operable_string[j] - 'A'] += 1;
                count++;
            }
        }

        // Normalize frequencies and compare with standard frequencies
        for (int j = 0; j < ALPHABET_SIZE; j++)
            tempFreq[j] = tempFreq[j] * 100 / count;

        double maxTotalFreq = 0.0;
        double maxIdx = -1;

        // Calculate total frequency for each possible key character
        for (int j = 0; j < ALPHABET_SIZE; j++) {
            double tempTotal = 0.0;
            for (int k = 0; k < ALPHABET_SIZE; k++) {
                tempTotal += tempFreq[(k + j) % ALPHABET_SIZE] * alphabetFrequencies[k];
            }

            // Find the character with maximum total frequency
            if (tempTotal > maxTotalFreq) {
                maxTotalFreq = tempTotal;
                maxIdx = j;
            }
        }

        key[i] = 'A' + maxIdx;
    }

    key[n] = '\0'; // Null-terminate the key string
}

// Function to decrypt the message using the key
void decryptMessage(char message[], int messageLen, char key[], int n) {
    for (int i = 0, j = 0; i < messageLen; i++) {
        if (isalpha(message[i])) {
            char base = isupper(message[i]) ? 'A' : 'a';
            message[i] = ((message[i] - base) - (key[j] - 'A') + 26) % 26 + base;
            j = (j + 1) % n;
        }
    }
    printf("Decrypted Message is as follows :\n\n%s\n\n", message);
}

int main(int argc, char const *argv[]) {
    // Reading the file using standard libraries
    char operable_string[MAX_SIZE];
    char message[MAX_SIZE];

    FILE *filePointer = fopen(FILENAME, "r");

    if (filePointer == NULL) {
        printf("File not found.\n");
        return 1;
    }

    int index = 0;
    int m_Index = 0;
    char ch;

    
    while ((ch = fgetc(filePointer)) != EOF && index < MAX_SIZE && m_Index < MAX_SIZE) {
        if (isalpha(ch)) {
            operable_string[index++] = ch; //reads all alphabets
        }
        message[m_Index++] = ch; //reads the entire message
    }
    // Adding a terminators to the string containing only alphabets as to facilitate conclusion of code
    operable_string[index] = '\0'; 
    fclose(filePointer);
    // File closed

    // We try to find the ideal key length using Index of co incidence method, this information is used to find the key later
    int n = KeyLength(operable_string, index);
    // Finding the key by treating the operable_string as n different substitution ciphers
    char key[n + 1];
    findDecryptionKey(key, operable_string, index, n);

    // Print the decryption key
    printf("The probable key is: %s\n", key);
    printf("The key length is: %i\n",n);
    printf("___________________________________________________________________________________________________________________________________________________");

    // Decrypt the message and print it
    decryptMessage(message, m_Index, key, n);

    return 0;
}
