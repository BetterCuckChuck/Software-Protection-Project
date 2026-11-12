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

/* --- Juliet testcase CWE197_Numeric_Truncation_Error__short_fscanf_01 --- */
/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE197_Numeric_Truncation_Error__short_fscanf_01.c
Label Definition File: CWE197_Numeric_Truncation_Error__short.label.xml
Template File: sources-sink-01.tmpl.c
*/
/*
 * @description
 * CWE: 197 Numeric Truncation Error
 * BadSource: fscanf Read data from the console using fscanf()
 * GoodSource: Less than CHAR_MAX
 * Sink:
 *    BadSink : Convert data to a char
 * Flow Variant: 01 Baseline
 *
 * */


#ifndef OMITBAD

void CWE197_Numeric_Truncation_Error__short_fscanf_01_bad()
{
    short data;
    /* Initialize data */
    data = -1;
    /* FLAW: Use a number input from the console using fscanf() */
    fscanf (stdin, "%hd", &data);
    {
        /* POTENTIAL FLAW: Convert data to a char, possibly causing a truncation error */
        char charData = (char)data;
        printHexCharLine(charData);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    short data;
    /* Initialize data */
    data = -1;
    /* FIX: Use a positive integer less than CHAR_MAX*/
    data = CHAR_MAX-5;
    {
        /* POTENTIAL FLAW: Convert data to a char, possibly causing a truncation error */
        char charData = (char)data;
        printHexCharLine(charData);
    }
}

void CWE197_Numeric_Truncation_Error__short_fscanf_01_good()
{
    goodG2B();
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
        CWE197_Numeric_Truncation_Error__short_fscanf_01_good();
        printLine("Finished good()");
    }
    if (run_bad)
    {
        printLine("Calling bad()...");
        CWE197_Numeric_Truncation_Error__short_fscanf_01_bad();
        printLine("Finished bad()");
    }
    return 0;
}
