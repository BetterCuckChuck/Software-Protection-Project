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
void printIntLine (int intNumber)
{
    printf("%d\n", intNumber);
}

void printLine (const char * line)
{
    if(line != NULL) 
    {
        printf("%s\n", line);
    }
}

/* --- Juliet testcase CWE190_Integer_Overflow__short_fscanf_preinc_01 --- */
/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE190_Integer_Overflow__short_fscanf_preinc_01.c
Label Definition File: CWE190_Integer_Overflow.label.xml
Template File: sources-sinks-01.tmpl.c
*/
/*
 * @description
 * CWE: 190 Integer Overflow
 * BadSource: fscanf Read data from the console using fscanf()
 * GoodSource: Set data to a small, non-zero number (two)
 * Sinks: increment
 *    GoodSink: Ensure there will not be an overflow before incrementing data
 *    BadSink : Increment data, which can cause an overflow
 * Flow Variant: 01 Baseline
 *
 * */


#ifndef OMITBAD

void CWE190_Integer_Overflow__short_fscanf_preinc_01_bad()
{
    short data;
    data = 0;
    /* POTENTIAL FLAW: Use a value input from the console */
    fscanf (stdin, "%hd", &data);
    {
        /* POTENTIAL FLAW: Incrementing data could cause an overflow */
        ++data;
        short result = data;
        printIntLine(result);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    short data;
    data = 0;
    /* FIX: Use a small, non-zero value that will not cause an overflow in the sinks */
    data = 2;
    {
        /* POTENTIAL FLAW: Incrementing data could cause an overflow */
        ++data;
        short result = data;
        printIntLine(result);
    }
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    short data;
    data = 0;
    /* POTENTIAL FLAW: Use a value input from the console */
    fscanf (stdin, "%hd", &data);
    /* FIX: Add a check to prevent an overflow from occurring */
    if (data < SHRT_MAX)
    {
        ++data;
        short result = data;
        printIntLine(result);
    }
    else
    {
        printLine("data value is too large to perform arithmetic safely.");
    }
}

void CWE190_Integer_Overflow__short_fscanf_preinc_01_good()
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
        CWE190_Integer_Overflow__short_fscanf_preinc_01_good();
        printLine("Finished good()");
    }
    if (run_bad)
    {
        printLine("Calling bad()...");
        CWE190_Integer_Overflow__short_fscanf_preinc_01_bad();
        printLine("Finished bad()");
    }
    return 0;
}
