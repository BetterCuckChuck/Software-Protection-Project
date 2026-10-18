/**
 * @file
 * @brief Printing the words contained in a file named `file.txt` in alphabetical
 * order and also their frequencies into another file `wordcount.txt`.
 * @details
 * Given a file (`file.txt`) containing words (like a publication or a novel),
 * where words are separated by a space, newline, or underscore.
 * This program prints (writes or outputs) to another file (`wordcount.txt`),
 * the individual words contained in 'file.txt' with their frequencies (number
 * of occurrences) each on a newline and in alphabetical order. This program uses
 * the binary tree data structure to accomplish this task.
 */

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Structure defining a node in the binary tree
 */
struct Node {
    char *word;          ///< the word (value) of the node
    uint64_t frequency;  ///< number of occurrences of the word
    struct Node *left;   ///< pointer to the left child node
    struct Node *right;  ///< pointer to the right child node
};

/**
 * @brief Ends program due to an error
 * @param errorMessage the error message to be printed
 */
void endProgramAbruptly(char *errorMessage) {
    fprintf(stderr, "%s\n", errorMessage);
    exit(EXIT_FAILURE);
}

/**
 * @brief Frees memory when program is terminating
 * @param node pointer to current node
 */
void freeTreeMemory(struct Node *node) {
    if (node != NULL) {
        freeTreeMemory(node->left);
        freeTreeMemory(node->right);
        free(node->word);
        free(node);
    }
}

/**
 * @brief Stores word in memory
 * @param word word to be stored in memory
 * @returns a pointer to the newly allocated word if the word IS stored successfully
 * @returns `NULL` if the word is NOT stored
 */
char *getPointerToWord(char *word) {
    char *string = (char *)malloc((strlen(word) + 1) * sizeof(char));
    if (string != NULL) {
        strcpy(string, word);
        return string;
    }
    endProgramAbruptly("\nA problem occurred while reserving memory for the word\n");
    return NULL;
}

/**
 * @brief Closes the file after reading or writing
 * @param file pointer to the file to be closed
 */
void closeFile(FILE *file) {
    if (fclose(file)) {
        endProgramAbruptly("\nA Problem Occurred while closing a file\n");
    }
}

/**
 * @brief Reserves memory for new node
 * @returns a pointer to the newly allocated node if memory IS successfully reserved
 * @returns `NULL` if memory is NOT reserved
 */
struct Node *allocateMemoryForNode(void) {
    struct Node *node = (struct Node *)malloc(sizeof(struct Node));
    if (node != NULL) {
        return node;
    }
    endProgramAbruptly("\nA problem occurred while reserving memory for the structure\n");
    return NULL;
}

/**
 * @brief Writes contents of tree to another file alphabetically
 * @param node pointer to current node
 * @param file pointer to file
 */
void writeContentOfTreeToFile(struct Node *node, FILE *file) {
    static uint64_t i = 1;
    if (node != NULL) {
        writeContentOfTreeToFile(node->left, file);
        fprintf(file, "%-5lu \t %-9lu \t %s \n", i++, node->frequency, node->word);
        writeContentOfTreeToFile(node->right, file);
    }
}

/**
 * @brief Adds word (node) to the correct position in tree
 * @param word word to be inserted in to the tree
 * @param currentNode node which is being compared
 * @returns a pointer to the root node
 */
struct Node *addWordToTree(char *word, struct Node *currentNode) {
    if (currentNode == NULL) {
        struct Node *newNode = allocateMemoryForNode();
        newNode->word = getPointerToWord(word);
        newNode->frequency = 1;
        newNode->left = NULL;
        newNode->right = NULL;
        return newNode;
    }

    int64_t compared = strcmp(word, currentNode->word);

    if (compared > 0) {
        currentNode->right = addWordToTree(word, currentNode->right);
    } else if (compared < 0) {
        currentNode->left = addWordToTree(word, currentNode->left);
    } else {
        currentNode->frequency++;
    }

    return currentNode;
}

/**
 * @brief Reads words from file to tree
 * @param file file to be read from
 * @param root root node of tree
 * @returns a pointer to the root node
 */
struct Node *readWordsInFileToTree(FILE *file, struct Node *root) {
    char *inputString = (char *)malloc(46 * sizeof(char));

    char inputChar;
    bool isPrevCharAlpha = false;
    uint8_t pos = 0;

    while ((inputChar = fgetc(file)) != EOF) {
        if (pos > 0) {
            isPrevCharAlpha = isalpha(inputString[pos - 1]);
        }

        if (isalpha(inputChar)) {
            inputString[pos++] = tolower(inputChar);
            continue;
        }

        if ((inputChar == '\'' || inputChar == '-') && isPrevCharAlpha) {
            inputString[pos++] = inputChar;
            continue;
        }

        if (pos == 0) {
            continue;
        }

        if (!isPrevCharAlpha && inputString[pos - 1] != '\'') {
            pos--;
        }
        inputString[pos] = '\0';
        pos = 0;
        isPrevCharAlpha = false;
        root = addWordToTree(inputString, root);
    }

    if (pos > 0) {
        if (!isPrevCharAlpha && inputString[pos - 1] != '\'') {
            pos--;
        }
        inputString[pos] = '\0';
        root = addWordToTree(inputString, root);
    }

    free(inputString);
    return root;
}

/**
 * @brief Self-test implementations
 */
static void test(void) {
    struct Node *root = NULL;
    FILE *file = NULL;

    file = fopen("file.txt", "w");
    fprintf(file, "hey_this, is a. test input \n to a_file");
    closeFile(file);

    file = fopen("file.txt", "r");
    root = readWordsInFileToTree(file, root);

    assert(strcmp(root->word, "hey") == 0);
    assert(root->frequency == 1);
    assert(strcmp(root->left->word, "a") == 0);
    assert(root->left->frequency == 2);
    assert(strcmp(root->right->word, "this") == 0);
    assert(strcmp(root->left->right->word, "file") == 0);
    assert(strcmp(root->right->left->word, "is") == 0);

    closeFile(file);
    remove("file.txt");

    file = fopen("wordcount.txt", "a");
    fprintf(file, "%-5s \t %9s \t %s \n", "S/N", "FREQUENCY", "WORD");
    writeContentOfTreeToFile(root, file);

    char const *correctString =
        "S/N   	 FREQUENCY 	 WORD \n"
        "1     	 2         	 a \n"
        "2     	 1         	 file \n"
        "3     	 1         	 hey \n"
        "4     	 1         	 input \n"
        "5     	 1         	 is \n"
        "6     	 1         	 n \n"
        "7     	 1         	 test \n"
        "8     	 1         	 this \n"
        "9     	 1         	 to \n";

    int16_t inputChar;
    uint64_t i = 0;

    while ((inputChar = fgetc(file)) != EOF) {
        assert(inputChar == correctString[i++]);
    }

    closeFile(file);
    remove("wordcount.txt");

    freeTreeMemory(root);
}

/**
 * @brief Main function
 * @returns 0 on exit
 */
int main(void) {
    test();
    return 0;
}
