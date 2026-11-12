#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#define true 1
#define false 0

/* --- Juliet support (io.c subset) --- */
void printHexCharLine (char charHex)
{
    printf("%02x\n", charHex);
}

void printLine (const char * line)
{
    if(line != NULL) 
    {
        printf("%s\n", line);
    }
}

/* --- Juliet testcase CWE191_Integer_Underflow__char_fscanf_sub_01 --- */
/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE191_Integer_Underflow__char_fscanf_sub_01.c
Label Definition File: CWE191_Integer_Underflow.label.xml
Template File: sources-sinks-01.tmpl.c
*/
/*
 * @description
 * CWE: 191 Integer Underflow
 * BadSource: fscanf Read data from the console using fscanf()
 * GoodSource: Set data to a small, non-zero number (negative two)
 * Sinks: sub
 *    GoodSink: Ensure there will not be an underflow before subtracting 1 from data
 *    BadSink : Subtract 1 from data, which can cause an Underflow
 * Flow Variant: 01 Baseline
 *
 * */


#ifndef OMITBAD

void CWE191_Integer_Underflow__char_fscanf_sub_01_bad()
{
    char data;
    data = ' ';
    /* POTENTIAL FLAW: Use a value input from the console */
    fscanf (stdin, "%c", &data);
    {
        /* POTENTIAL FLAW: Subtracting 1 from data could cause an underflow */
        char result = data - 1;
        printHexCharLine(result);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char data;
    data = ' ';
    /* FIX: Use a small, non-zero value that will not cause an underflow in the sinks */
    data = -2;
    {
        /* POTENTIAL FLAW: Subtracting 1 from data could cause an underflow */
        char result = data - 1;
        printHexCharLine(result);
    }
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    char data;
    data = ' ';
    /* POTENTIAL FLAW: Use a value input from the console */
    fscanf (stdin, "%c", &data);
    /* FIX: Add a check to prevent an underflow from occurring */
    if (data > CHAR_MIN)
    {
        char result = data - 1;
        printHexCharLine(result);
    }
    else
    {
        printLine("data value is too large to perform subtraction.");
    }
}

void CWE191_Integer_Underflow__char_fscanf_sub_01_good()
{
    goodG2B();
    goodB2G();
}

#endif /* OMITGOOD */

int main(int argc, char *argv[])
{
    const char *mode = argc > 1 ? argv[1] : "both";
    int run_good = strcmp(mode, "bad") != 0;
    int run_bad = strcmp(mode, "good") != 0;
    if (run_good)
    {
        printLine("Calling good()...");
        CWE191_Integer_Underflow__char_fscanf_sub_01_good();
        printLine("Finished good()");
    }
    if (run_bad)
    {
        printLine("Calling bad()...");
        CWE191_Integer_Underflow__char_fscanf_sub_01_bad();
        printLine("Finished bad()");
    }
    return 0;
}
