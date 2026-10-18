/**
 * @file segment_tree.c
 * @brief Segment trees with only point updates
 * @details
 * This code implements segment trees. Segment trees are general structures
 * which allow range based queries in a given array in logN time.
 * Segment tree with point updates allow update of single element in the array
 * in logN time.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Function that combines two data elements to generate a new one.
 * @param a pointer to first data
 * @param b pointer to second data
 * @param result pointer to memory location where combined result is stored
 */
typedef void (*combine_function)(const void *a, const void *b, void *result);

/**
 * Structure holding all data required by a segment tree.
 */
typedef struct segment_tree
{
    void *root;               /**< The root / internal nodes buffer of formed segment tree */
    void *identity;           /**< Identity element for combine function */
    size_t elem_size;         /**< Size in bytes of each data element */
    size_t length;            /**< Total size of array which segment tree represents */
    combine_function combine; /**< Function used to combine two nodes' data to form parent */
} segment_tree;

/**
 * Builds a Segment tree.
 * It is assumed that leaves of tree already contain data.
 * @param tree pointer to segment tree to be built
 */
void segment_tree_build(segment_tree *tree)
{
    size_t elem_size = tree->elem_size;
    int index = (int)(tree->length - 2);
    size_t b, l, r;
    char *ptr = (char *)tree->root;
    for (; index >= 0; index--)
    {
        b = (size_t)index * elem_size;
        l = (size_t)(2 * index + 1) * elem_size;
        r = (size_t)(2 * index + 2) * elem_size;
        tree->combine(ptr + l, ptr + r, ptr + b);
    }
}

/**
 * For point updates.
 * Updates the element at given index and updates segment tree accordingly.
 *
 * @param tree pointer to segment tree
 * @param index the index whose element is to be updated (0-based)
 * @param val pointer to value that is to be replaced at given index
 */
void segment_tree_update(segment_tree *tree, size_t index, void *val)
{
    size_t elem_size = tree->elem_size;
    index = index + tree->length - 1;
    char *base = (char *)tree->root;
    char *t = base + index * elem_size;
    memcpy(t, val, elem_size);
    while (index > 0)
    {
        index = ((index - 1) >> 1);
        tree->combine(base + (2 * index + 1) * elem_size,
                      base + (2 * index + 2) * elem_size,
                      base + index * elem_size);
    }
}

/**
 * Query the segment tree.
 * Performs range query in range [l, r].
 *
 * @param tree pointer to segment tree
 * @param l start of range (inclusive)
 * @param r end of range (inclusive)
 * @param res pointer to memory where result of query is stored
 */
void segment_tree_query(segment_tree *tree, long long l, long long r, void *res)
{
    size_t elem_size = tree->elem_size;
    memcpy(res, tree->identity, elem_size);
    char *root = (char *)tree->root;
    l += (long long)(tree->length - 1);
    r += (long long)(tree->length - 1);
    while (l <= r)
    {
        if (!(l & 1))
        {
            tree->combine(res, root + (size_t)l * elem_size, res);
        }
        if (r & 1)
        {
            tree->combine(res, root + (size_t)r * elem_size, res);
        }
        r = (r >> 1) - 1;
        l = (l >> 1);
    }
}

/**
 * Initializes Segment Tree.
 * Allocates memory for segment tree and fills leaves with data from array.
 *
 * @param arr array data upon which segment tree is built
 * @param elem_size size of each element in segment tree
 * @param len total number of elements in array
 * @param identity identity element for combine_function
 * @param func combine_function used to build segment tree
 * @return pointer to allocated segment tree
 */
segment_tree *segment_tree_init(void *arr, size_t elem_size, size_t len,
                                void *identity, combine_function func)
{
    segment_tree *tree = (segment_tree *)malloc(sizeof(segment_tree));
    if (!tree)
    {
        return NULL;
    }
    tree->elem_size = elem_size;
    tree->length = len;
    tree->combine = func;
    tree->root = malloc(sizeof(char) * elem_size * (2 * len - 1));
    tree->identity = malloc(sizeof(char) * elem_size);
    char *ptr = (char *)tree->root;
    memset(ptr, 0, (len - 1) * elem_size);
    ptr = ptr + (len - 1) * elem_size;
    memcpy(ptr, arr, elem_size * len);
    memcpy(tree->identity, identity, elem_size);
    return tree;
}

/**
 * Dispose Segment Tree.
 * Frees memory acquired by segment tree buffers.
 * @param tree pointer to segment tree
 */
void segment_tree_dispose(segment_tree *tree)
{
    if (tree)
    {
        free(tree->root);
        free(tree->identity);
    }
}

/**
 * Prints the data in segment tree (assuming int type elements).
 * @param tree pointer to segment tree
 */
void segment_tree_print_int(segment_tree *tree)
{
    char *base = (char *)tree->root;
    size_t i = 0;
    for (; i < 2 * tree->length - 1; i++)
    {
        printf("%d ", *(int *)(base + i * tree->elem_size));
    }
    printf("\n");
}

/**
 * Utility combine function for Range Minimum Queries (RMQ).
 * Stores min(a, b) into result c.
 *
 * @param a pointer to integer a
 * @param b pointer to integer b
 * @param c pointer where minimum is stored
 */
void minimum(const void *a, const void *b, void *c)
{
    *(int *)c = *(int *)a < *(int *)b ? *(int *)a : *(int *)b;
}

/**
 * Self-test routine using Range Minimum Queries.
 */
static void test(void)
{
    int32_t arr[10] = {1, 0, 3, 5, 7, 2, 11, 6, -2, 8};
    int32_t identity = __INT32_MAX__;
    segment_tree *tree =
        segment_tree_init(arr, sizeof(*arr), 10, &identity, minimum);
    segment_tree_build(tree);
    int32_t result;
    segment_tree_query(tree, 3, 6, &result);
    assert(result == 2);
    segment_tree_query(tree, 8, 9, &result);
    assert(result == -2);
    result = 12;
    segment_tree_update(tree, 5, &result);
    segment_tree_update(tree, 8, &result);
    segment_tree_query(tree, 0, 3, &result);
    assert(result == 0);
    segment_tree_query(tree, 8, 9, &result);
    assert(result == 8);
    segment_tree_dispose(tree);
}

/**
 * Main function.
 * @returns 0 on exit
 */
int main(void)
{
    test();
    return 0;
}
