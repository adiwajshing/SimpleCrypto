//
//  LetterFrequency.h
//  Crypto
//
//  Created by Adhiraj Singh on 2/16/20.
//  Copyright © 2020 Adhiraj Singh. All rights reserved.
//

#ifndef LetterFrequency_h
#define LetterFrequency_h

#define FREQUENCY_COUNT 26

struct FrequencyMeasure {
    char pattern[4];
    float frequency;
};
typedef struct FrequencyMeasure FrequencyMeasure;

FrequencyMeasure const *letterFrequencies (void);

FrequencyMeasure *frequencyCount (const char *text, int textlen, int patternLength);
float goodnessOfFit (const char *text, int textlen);
float goodnessOfFitWords (const char *text, int textlen);
#endif /* LetterFrequency_h */
