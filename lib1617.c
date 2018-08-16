#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include"lib1617.h"

#define MAX_BUFFER_SIZE 256
#define INVALID_BIT_READ -1
#define INVALID_BIT_WRITE -1

#define FAILURE 1
#define SUCCESS 0
#define FILE_OPEN_FAIL -1
#define END_OF_FILE -1
#define MEM_ALLOC_FAIL -1

int num_alphabets = 256;
int num_active = 0;
int *frequency = NULL;
unsigned int original_size = 0;

typedef struct {
	int index;
	unsigned int weight;
} node_t;

node_t *nodes = NULL;
int num_nodes = 0;
int *leaf_index = NULL;
int *parent_index = NULL;

int free_index = 1;

int *stack;
int stack_top;

unsigned char buffer[MAX_BUFFER_SIZE];
int bits_in_buffer = 0;
int current_bit = 0;

int eof_input = 0;

int read_header(FILE *f);
int write_header(FILE *f);
int read_bit(FILE *f);
int write_bit(FILE *f, int bit);
int flush_buffer(FILE *f);
void decode_bit_stream(FILE *fin, FILE *fout);
int decode(const char* ifile, const char *ofile);
void encode_alphabet(FILE *fout, int character);
int encode(const char* ifile, const char *ofile);
void build_tree();
void add_leaves();
int add_node(int index, int weight);
void init();

int contatore = 0;
int cow = -1;

static char *ciao(NODO* dictionary, int index);

//Ricerca di un nodo
NODO *search(NODO *dictionary, char* word) {
	NODO* tmp = dictionary;
	if (tmp == NULL)
		return NULL;
	if (strcmp(tmp->word, word) == 0)
		return tmp;
	if (strcmp(tmp->word, word) >0)
		return search(tmp->left, word);
	else
		return search(tmp->right, word);
}
//Dato un file salva e crea la struttura restituendo il puntatore alla testa
NODO* createFromFile(char* nameFile) {
	NODO *testa = (NODO*)malloc(sizeof(NODO));
	testa->def = NULL;
	testa->left = NULL;
	testa->parent = NULL;
	testa->right = NULL;
	testa->word = NULL;
	int c;
	FILE *fo;
	if ((fo = fopen(nameFile, "r")) == NULL)
		return 0;
	char appoggio[MAX_WORD];
	char* parray;
	for (int j = 0; j < MAX_WORD; j++)
		appoggio[j] = NULL;
	int iconta = 0;
	int flag1 = 0;
	int found_word;
	while ((c = fgetc(fo)) != EOF) {
		if (flag1 == 1) {
			parray = appoggio;
			if (iconta >= 2)
				insertWord(&testa, parray);
			for (int i = 0; i < MAX_WORD; i++)
				appoggio[i] = NULL;
			puts("\n");
			flag1 = 0;
			iconta = 0;
		}

		if (isalpha(c)) {
			found_word = 1;
			c = tolower(c);
			appoggio[iconta] = c;
			iconta++;
		}
		else if (found_word) {
			found_word = 0;
			flag1 = 1;
		}
	}
	return testa;
}
//Confronta e inserisce nella posizione giusta
int confronta(NODO *testa, NODO *nuovo)
{
	NODO *tmp = testa;
	if (strcmp(tmp->word, nuovo->word)>0)
	{
		if (tmp->left == NULL)
		{
			tmp->left = nuovo;
			nuovo->parent = tmp;
			return 0;
		}
		confronta(tmp->left, nuovo);
	}
	if (strcmp(tmp->word, nuovo->word)<0)
	{
		if (tmp->right == NULL)
		{
			tmp->right = nuovo;
			nuovo->parent = tmp;
			return 0;
		}
		confronta(tmp->right, nuovo);
	}
	return 0;
}
//Allocazione e inserimento di un nodo 
int insertWord(NODO** dictionary, char* word) {
	if (strlen(word) < 2)
		return -1;
	NODO *tmp = *dictionary;
	NODO *nuovo = NULL;
	nuovo = (NODO*)malloc(sizeof(NODO));
	if (nuovo == NULL)
		return 0;
	nuovo->word = (char*)malloc(MAX_DEF * sizeof(char));
	strcpy(nuovo->word, word);
	nuovo->left = NULL;
	nuovo->right = NULL;
	nuovo->def = NULL;
	nuovo->parent = NULL;
	if (tmp->word == NULL)
	{
		*dictionary = nuovo;
		return 0;
	}
	confronta(tmp, nuovo);
}
//Stampa dell'albero
void printDictionary(NODO*  dictionary) {
	NODO *tmp = dictionary;
	if (tmp == NULL)
		return;
	printDictionary(tmp->left);
	printf("\"%s\" : [%s]\n", tmp->word, tmp->def);
	printDictionary(tmp->right);
}

//Conteggio parole salvate 
int countWord(NODO* dictionary) {
	NODO *tmp = dictionary;
	int c = 1;
	if (tmp == NULL)
		return 0;
	else {
		c += countWord(tmp->left);
		c += countWord(tmp->right);
		return c;
	}
}
//Cancellazione di un nodo
int cancWord(NODO** dictionary, char* word) {
	NODO *tmp = (NODO*)malloc(sizeof(NODO));
	if (tmp == NULL)
		return 0;
	NODO *yo = (NODO*)malloc(sizeof(NODO));
	if (yo == NULL)
		return 0;
	NODO *prec = (NODO*)malloc(sizeof(NODO));
	if (prec == NULL)
		return 0;
	NODO *trovato = (NODO*)malloc(sizeof(NODO));
	if (trovato == NULL)
		return 0;
	trovato = search(*dictionary, word);
	if (trovato == NULL)
		return 0;
	else
	{
		if (trovato->left == NULL && trovato->right == NULL)
		{
			tmp = trovato->parent;
			if (tmp->left == trovato)
				tmp->left = NULL;
			else
				tmp->right = NULL;
			free(trovato);
			return 0;
		}
		if (trovato->left == NULL && trovato->right != NULL)
		{
			tmp = trovato->right;
			prec = trovato->parent;
			tmp->parent = prec;
			if (prec->left == trovato)
				prec->left = tmp;
			else
				prec->right = tmp;
			free(trovato);
			return 1;
		}
		else if (trovato->right == NULL && trovato->left != NULL)
		{
			tmp = trovato->left;
			prec = trovato->parent;
			tmp->parent = prec;
			if (prec->left == trovato)
				prec->left = tmp;
			else
				prec->right = tmp;
			free(trovato);
			return 1;
		}
		tmp = trovato->left;
		prec = trovato;
		while (tmp->right != NULL)
		{
			prec = tmp;
			tmp = tmp->right;
		}
		char *word = tmp->word;
		char *def = tmp->def;
		trovato->word = word;
		trovato->def = def;
		if (tmp->left != NULL && trovato->left == tmp)
		{
			trovato->left = tmp->left;
			yo = tmp->left;
			yo->parent = trovato;
			free(tmp);
			return 3;
		}
		if (tmp->left == NULL && prec == trovato)
		{
			prec->left = NULL;
			free(tmp);
			return 4;
		}
		if (tmp->left != NULL)
		{
			yo = tmp->left;
			prec->right = yo;
			yo->parent = prec;
			free(tmp);
			return 2;
		}
		prec->left = NULL;
		free(tmp);
		return 5;
	}
}
//RIcerca della parola con indice
char* getWordAt(NODO* dictionary, int index)
{
	char *p = NULL;
	cow = -1;
	p = ciao(dictionary, index);
	return p;
}
static char* ciao(NODO* dictionary, int index) {
	NODO *tmp = dictionary;
	static char *p2 = NULL;

	if (tmp == NULL)
		return p2;

	ciao(tmp->left, index);
	cow++;
	if (cow == index) {
		p2 = tmp->word;
	}
	ciao(tmp->right, index);
	return p2;
}

//Inserimento definizione
int insertDef(NODO* dictionary, char* word, char* def) {
	NODO* trovato = search(dictionary, word);
	if (trovato == NULL)
		return 1;
	else if (trovato->def == NULL) {
		trovato->def = (char*)malloc(MAX_DEF * sizeof(char));
		strcpy(trovato->def, def);
	}
	else {
		free(trovato->def);
		trovato->def = (char*)malloc(MAX_DEF * sizeof(char));
		strcpy(trovato->def, def);
	}
	return 0;
}
//Ricerca definizione 
char* searchDef(NODO* dictionary, char* word) {
	NODO* trovato = search(dictionary, word);
	if (trovato == NULL)
		return NULL;
	else
		return trovato->def;
}
//Salva dizionario in un file
int saveDictionary(NODO* dictionary, char* fileOutput) {
	FILE *fp = NULL;
	NODO *tmp = dictionary;
	if (tmp == NULL)
		return 0;
	saveDictionary(tmp->left, fileOutput);
	if ((fp = fopen(fileOutput, "a")) == NULL)
		return -1;
	fprintf(fp, "\n\"%s\": [(%s)]\n", tmp->word, tmp->def);
	saveDictionary(tmp->right, fileOutput);
}
//ImportaDizionario
NODO* importDictionary(char *fileInput) {
	NODO *testa = (NODO*)malloc(sizeof(NODO));
	if (testa == NULL)
		return 0;
	testa->word = NULL;
	testa->left = NULL;
	testa->right = NULL;
	testa->def = NULL;
	testa->parent = NULL;
	FILE *fp;
	if ((fp = fopen("text1.txt", "r")) == NULL)
		return 0;
	int i = 0;
	int j = 0;
	char *frase;
	char word[MAX_WORD];
	char def[MAX_DEF];
	char line[80];
	while (fgets(line, 80, fp) != NULL)
	{
		char *de = NULL;
		char *wo = NULL;
		frase = line;
		for (i = 0; i < MAX_WORD; i++)
			word[i] = NULL;
		for (i = 0; i < MAX_DEF; i++)
			def[i] = NULL;
		i = 0;
		j = 0;
		int k = 0;
		int flag = 0;
		int flag2 = 0;
		while (frase[i] != '\n' && flag2 != 1)
		{
			if (flag == 1)
			{
				if (frase[i] == '[')
				{
					i++;
				}
				if (frase[i] == ']')
				{
					i++;
					flag2 = 1;
				}
				else
				{
					def[j] = frase[i];
					j++;
					i++;
				}
			}
			if (flag == 0)
			{
				if (frase[i] == '\"')
					i++;
				else
				{
					word[k] = frase[i];
					i++;
					k++;
				}
				if (frase[i] == ':')
				{
					i++;
					flag = 1;
				}
			}
		}
		wo = word;
		de = def;
		insertWord(&testa, wo);
		insertDef(testa, wo, de);
	}
	return testa;
}
//ricerca differenza di bit
char distanzaHamming(char *str1, char *str2)
{
	int i = 0, count = 0;
	while (str1[i] != '\0')
	{
		if (str1[i] != str2[i])
			count++;
		i++;
	}
	return count;
}
//Ricerca avazata
int searchAdvance(NODO* dictionary, char* word, char** first, char** second, char** third) {
	static int c = 0;
	static int flag1, flag2, flag3;
	int primo, secondo, terzo;
	NODO *tmp = dictionary;

	if (tmp == NULL)
	{
		if (c == 0) {
			return 0;
		}
		if (c == countWord(dictionary)) {
			printf("\n%s\t%s\t%s\t%s \n", word, *first, *second, *third);
			c++;
		}
		return 1;
	}
	if (distanzaHamming(word, tmp->word) < primo && distanzaHamming(word, tmp->word) < secondo && distanzaHamming(word, tmp->word) < terzo)
	{
		if (primo > secondo && primo > terzo) {
			primo = distanzaHamming(word, tmp->word);
			*first = tmp->word;
		}
		else if (secondo > primo && secondo > terzo) {
			secondo = distanzaHamming(word, tmp->word);
			*second = tmp->word;
		}
		else if (terzo > primo && terzo > secondo) {
			terzo = distanzaHamming(word, tmp->word);
			*third = tmp->word;
		}
	}
	if ((distanzaHamming(word, tmp->word) < primo && distanzaHamming(word, tmp->word) > secondo && distanzaHamming(word, tmp->word) > terzo)) {
		primo = distanzaHamming(word, tmp->word);
		*first = tmp->word;
	}
	if ((distanzaHamming(word, tmp->word) >primo && distanzaHamming(word, tmp->word) < secondo && distanzaHamming(word, tmp->word) > terzo)) {
		secondo = distanzaHamming(word, tmp->word);
		*second = tmp->word;
	}
	if ((distanzaHamming(word, tmp->word) >primo && distanzaHamming(word, tmp->word) > secondo && distanzaHamming(word, tmp->word) < terzo)) {
		terzo = distanzaHamming(word, tmp->word);
		*third = tmp->word;
	}
	if ((distanzaHamming(word, tmp->word) < primo && distanzaHamming(word, tmp->word) < secondo && distanzaHamming(word, tmp->word) > terzo)) {
		if (primo > secondo) {
			primo = distanzaHamming(word, tmp->word);
			*first = tmp->word;
		}
		else {
			secondo = distanzaHamming(word, tmp->word);
			*second = tmp->word;
		}
	}
	if ((distanzaHamming(word, tmp->word) < primo && distanzaHamming(word, tmp->word) > secondo && distanzaHamming(word, tmp->word) < terzo)) {
		if (terzo < primo) {
			primo = distanzaHamming(word, tmp->word);
			*first = tmp->word;
		}
		else {
			terzo = distanzaHamming(word, tmp->word);
			*third = tmp->word;
		}
	}
	if ((distanzaHamming(word, tmp->word) > primo && distanzaHamming(word, tmp->word) < secondo && distanzaHamming(word, tmp->word) < terzo)) {
		if (secondo < terzo) {
			terzo = distanzaHamming(word, tmp->word);
			*third = tmp->word;
		}
		else {
			secondo = distanzaHamming(word, tmp->word);
			*second = tmp->word;
		}
	}
	c++;
	searchAdvance(tmp->left, word, first, second, third);
	searchAdvance(tmp->right, word, first, second, third);

}
void determine_frequency(FILE *f) {
	int c;
	while ((c = fgetc(f)) != EOF) {
		++frequency[c];
		++original_size;
	}
	for (c = 0; c < num_alphabets; ++c)
		if (frequency[c] > 0)
			++num_active;
}

void init() {
	frequency = (int *)
		calloc(2 * num_alphabets, sizeof(int));
	leaf_index = frequency + num_alphabets - 1;
}

void allocate_tree() {
	nodes = (node_t *)
		calloc(2 * num_active, sizeof(node_t));
	parent_index = (int *)
		calloc(num_active, sizeof(int));
}

int add_node(int index, int weight) {
	int i = num_nodes++;
	while (i > 0 && nodes[i].weight > weight) {
		memcpy(&nodes[i + 1], &nodes[i], sizeof(node_t));
		if (nodes[i].index < 0)
			++leaf_index[-nodes[i].index];
		else
			++parent_index[nodes[i].index];
		--i;
	}

	++i;
	nodes[i].index = index;
	nodes[i].weight = weight;
	if (index < 0)
		leaf_index[-index] = i;
	else
		parent_index[index] = i;

	return i;
}

void add_leaves() {
	int i, freq;
	for (i = 0; i < num_alphabets; ++i) {
		freq = frequency[i];
		if (freq > 0)
			add_node(-(i + 1), freq);
	}
}

void build_tree() {
	int a, b, index;
	while (free_index < num_nodes) {
		a = free_index++;
		b = free_index++;
		index = add_node(b / 2,
			nodes[a].weight + nodes[b].weight);
		parent_index[b / 2] = index;
	}
}


int encode(const char* ifile, const char *ofile) {
	FILE *fin, *fout;
	if ((fin = fopen(ifile, "rb")) == NULL) {
		perror("impossibile aprire file");
		return FILE_OPEN_FAIL;
	}
	if ((fout = fopen(ofile, "wb")) == NULL) {
		perror("impossibile aprire il file");
		fclose(fin);
		return FILE_OPEN_FAIL;
	}

	determine_frequency(fin);
	stack = (int *)calloc(num_active - 1, sizeof(int));
	allocate_tree();

	add_leaves();
	write_header(fout);
	build_tree();
	fseek(fin, 0, SEEK_SET);
	int c;
	while ((c = fgetc(fin)) != EOF)
		encode_alphabet(fout, c);
	flush_buffer(fout);
	free(stack);
	fclose(fin);
	fclose(fout);

	return 0;
}

void encode_alphabet(FILE *fout, int character) {
	int node_index;
	stack_top = 0;
	node_index = leaf_index[character + 1];
	while (node_index < num_nodes) {
		stack[stack_top++] = node_index % 2;
		node_index = parent_index[(node_index + 1) / 2];
	}
	while (--stack_top > -1)
		write_bit(fout, stack[stack_top]);
}

int decode(const char* ifile, const char *ofile) {
	FILE *fin, *fout;
	if ((fin = fopen(ifile, "rb")) == NULL) {
		perror("impossibile aprire il file");
		return FILE_OPEN_FAIL;
	}
	if ((fout = fopen(ofile, "wb")) == NULL) {
		perror("impossibile aprire il file");
		fclose(fin);
		return FILE_OPEN_FAIL;
	}

	if (read_header(fin) == 0) {
		build_tree();
		decode_bit_stream(fin, fout);
	}
	fclose(fin);
	fclose(fout);

	return 0;
}

void decode_bit_stream(FILE *fin, FILE *fout) {
	int i = 0, bit, node_index = nodes[num_nodes].index;
	while (1) {
		bit = read_bit(fin);
		if (bit == -1)
			break;
		node_index = nodes[node_index * 2 - bit].index;
		if (node_index < 0) {
			char c = -node_index - 1;
			fwrite(&c, 1, 1, fout);
			if (++i == original_size)
				break;
			node_index = nodes[num_nodes].index;
		}
	}
}

int write_bit(FILE *f, int bit) {
	if (bits_in_buffer == MAX_BUFFER_SIZE << 3) {
		size_t bytes_written =
			fwrite(buffer, 1, MAX_BUFFER_SIZE, f);
		if (bytes_written < MAX_BUFFER_SIZE && ferror(f))
			return INVALID_BIT_WRITE;
		bits_in_buffer = 0;
		memset(buffer, 0, MAX_BUFFER_SIZE);
	}
	if (bit)
		buffer[bits_in_buffer >> 3] |=
		(0x1 << (7 - bits_in_buffer % 8));
	++bits_in_buffer;
	return SUCCESS;
}

int flush_buffer(FILE *f) {
	if (bits_in_buffer) {
		size_t bytes_written =
			fwrite(buffer, 1,
			(bits_in_buffer + 7) >> 3, f);
		if (bytes_written < MAX_BUFFER_SIZE && ferror(f))
			return -1;
		bits_in_buffer = 0;
	}
	return 0;
}

int read_bit(FILE *f) {
	if (current_bit == bits_in_buffer) {
		if (eof_input)
			return END_OF_FILE;
		else {
			size_t bytes_read =
				fread(buffer, 1, MAX_BUFFER_SIZE, f);
			if (bytes_read < MAX_BUFFER_SIZE) {
				if (feof(f))
					eof_input = 1;
			}
			bits_in_buffer = bytes_read << 3;
			current_bit = 0;
		}
	}

	if (bits_in_buffer == 0)
		return END_OF_FILE;
	int bit = (buffer[current_bit >> 3] >>
		(7 - current_bit % 8)) & 0x1;
	++current_bit;
	return bit;
}

int write_header(FILE *f) {
	int i, j, byte = 0,
		size = sizeof(unsigned int) + 1 +
		num_active * (1 + sizeof(int));
	unsigned int weight;
	char *buffer = (char *)calloc(size, 1);
	if (buffer == NULL)
		return MEM_ALLOC_FAIL;

	j = sizeof(int);
	while (j--)
		buffer[byte++] =
		(original_size >> (j << 3)) & 0xff;
	buffer[byte++] = (char)num_active;
	for (i = 1; i <= num_active; ++i) {
		weight = nodes[i].weight;
		buffer[byte++] =
			(char)(-nodes[i].index - 1);
		j = sizeof(int);
		while (j--)
			buffer[byte++] =
			(weight >> (j << 3)) & 0xff;
	}
	fwrite(buffer, 1, size, f);
	free(buffer);
	return 0;
}

int read_header(FILE *f) {
	int i, j, byte = 0, size;
	size_t bytes_read;
	unsigned char buff[4];

	bytes_read = fread(&buff, 1, sizeof(int), f);
	if (bytes_read < 1)
		return END_OF_FILE;
	byte = 0;
	original_size = buff[byte++];
	while (byte < sizeof(int))
		original_size =
		(original_size << (1 << 3)) | buff[byte++];

	bytes_read = fread(&num_active, 1, 1, f);
	if (bytes_read < 1)
		return END_OF_FILE;

	allocate_tree();

	size = num_active * (1 + sizeof(int));
	unsigned int weight;
	char *buffer = (char *)calloc(size, 1);
	if (buffer == NULL)
		return MEM_ALLOC_FAIL;
	fread(buffer, 1, size, f);
	byte = 0;
	for (i = 1; i <= num_active; ++i) {
		nodes[i].index = -(buffer[byte++] + 1);
		j = 0;
		weight = (unsigned char)buffer[byte++];
		while (++j < sizeof(int)) {
			weight = (weight << (1 << 3)) |
				(unsigned char)buffer[byte++];
		}
		nodes[i].weight = weight;
	}
	num_nodes = (int)num_active;
	free(buffer);
	return 0;
}

/*Funzione per la compressione del file di output, compresso con Huffman*/
int compressHuffman(NODO* dictionary, char* fileOutput)
{
	saveDictionary(dictionary, "huff1.txt");
	init();
	encode("huff1.txt", fileOutput);
	return 0;
}
/*Funzione per la decompressione del file di input ,compresso con Huffman*/
int decompressHuffman(char *fileInput, NODO** dictionary)
{
	init();
	decode(fileInput, "huff2.txt");
	importDictionary("huff2.txt");
	return 0;
}