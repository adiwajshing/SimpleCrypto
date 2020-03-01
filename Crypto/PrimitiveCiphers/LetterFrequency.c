//
//  LetterFrequency.c
//  Crypto
//
//  Created by Adhiraj Singh on 2/16/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "LetterFrequency.h"
#define CHAR_LOWERBOUND2 97

const FrequencyMeasure _letterFrequencies[] = {
    {"e", 0.123},
    {"t", 0.091},
    {"a", 0.081},
    {"o", 0.0768},
    {"i", 0.0731},
    {"n", 0.0695},
    {"s", 0.0628},
    {"r", 0.0602},
    {"h", 0.0592},
    {"d", 0.0427},
    {"l", 0.0394},
    {"u", 0.0288},
    {"c", 0.0271},
    {"m", 0.0261},
    {"f", 0.023},
    {"y", 0.0211},
    {"w", 0.0209},
    {"g", 0.0203},
    {"p", 0.0182},
    {"b", 0.0149},
    {"v", 0.0110},
    {"k", 0.0069},
    {"x", 0.0017},
    {"q", 0.0011},
    {"j", 0.0010},
    {"z", 0.0007}
};
FrequencyMeasure const *letterFrequencies (void) {
    return _letterFrequencies;
}


int *simpleSort (const int *arr, int len) {
    int *map = malloc( len * sizeof(int) );
    
    int i, p, j;
    for (i = 0; i < len;i++) {
        p = 0;
        for (j = 0; j < len;j++) {
            if ((arr[j] < arr[i]) || (arr[j] == arr[i] && i > j)) {
                p += 1;
            }
        }
        map[p] = i; // character at pth position is available at index i of str
    }
    return map;
}
FrequencyMeasure *frequencyCount (const char *text, int textlen, int patternLength) {
    
    if (patternLength != 1) {
        return NULL; // TODO
    }
    
    const int arrlen = 26;
    
    int arr[arrlen];
    memset(arr, 0, sizeof(int) * arrlen);
    
    for (int i = 0; i < textlen;i++) {
        arr[ text[i] - CHAR_LOWERBOUND2 ] += 1;
    }
    
    int *sorted = simpleSort(arr, arrlen);
    
    FrequencyMeasure *frequencies = (FrequencyMeasure *) malloc( sizeof(FrequencyMeasure) * FREQUENCY_COUNT );
    memset(frequencies, 0, sizeof(FrequencyMeasure) * FREQUENCY_COUNT);
    
    for (int i = 0; i < FREQUENCY_COUNT;i++) {
        int index = sorted[arrlen-i-1];
        frequencies[i].pattern[0] = (char) (index+CHAR_LOWERBOUND2);
        frequencies[i].frequency = (float)arr[ index ] / textlen;
    }
    free(sorted);
    
    return frequencies;
}
/// chi square test of frequency of letters in a given text with respect to the frequency of letters generally found in the english alphabet
float goodnessOfFit (const char *text, int textlen) {

    const int numCharacters = 26; // number of letters in the English alphabet
    
    int frequencies[numCharacters] = {0}; // array to store the frequencies of each character
    
    for (int i = 0; i < textlen;i++) {
        frequencies[ text[i] - CHAR_LOWERBOUND2 ] += 1;
    }
    
    float fit = 0.0f; // the overall fit of the plaintext's letter frequency to the expected frequency
    
    char letter;
    float expectedFreq, freq;
    for (int i = 0; i < FREQUENCY_COUNT; i++) {
        letter = _letterFrequencies[i].pattern[0]-CHAR_LOWERBOUND2; //
        expectedFreq = _letterFrequencies[i].frequency; //the frequency we expect to see of a given character
        
        freq = (float)frequencies[letter]/(float)textlen; //the frequency of the letter in the plaintext
        fit += (freq-expectedFreq)*(freq-expectedFreq)/expectedFreq; // finally compute the variance
    }
    return fit;
}
int numberOfMatches (const char *text, int textlen, const char *substr) {
    int sublen = (int)strlen(substr);
    int matches = 0;
    
    const char *ptr = text;
    while ((ptr-text) < textlen) {
        ptr = strstr(ptr, substr);
        if (ptr) {
            ptr += sublen;
            matches += 1;
        } else {
            break;
        }
    }
    return matches;
}
float goodnessOfFitWords (const char *text, int textlen) {
    
    const FrequencyMeasure _threeLetterFrequencies[] = {
        {"the", 0.0339},
        {"and", 0.0115},
        {"ing", 0.0121},
        {"hat", 0.0096},
        {"you", 0.0091},
        {"her", 0.0088},
        {"tha", 0.0083},
        {"his", 0.0074},
        {"ere", 0.0068},
        {"was", 0.0061},
        {"ver", 0.0054},
        {"for", 0.0054},
        {"thi", 0.0051},
        {"have", 0.0001},
        {"that", 0.0001},
        {"with", 0.0001}
    };
    
    const int freqLen = 16;
  //  int m;
    //float freq, expectedFreq;
    float fit = 0.0f;
    for (int i = 0; i < freqLen;i++) {
        if (strstr(text, _threeLetterFrequencies[i].pattern) == NULL) {
            fit += (float)1/(float)freqLen;
        }
        /*m = numberOfMatches(text, textlen, _threeLetterFrequencies[i].pattern);
        expectedFreq = _threeLetterFrequencies[i].frequency;
        freq = (float)m/(float)(textlen*3*3);
        
        fit += (freq-expectedFreq)*(freq-expectedFreq)/expectedFreq;*/
    }
    return fit;
}
