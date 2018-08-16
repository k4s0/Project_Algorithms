#define MAX_DEF 50
#define MAX_WORD 20
#define MIN_WORD 2


typedef struct NODO {
	char* word;
	char* def;
	struct NODO	*parent;
	struct NODO *left;
	struct NODO *right;
	//altri campi
}NODO;


/*
Input:
-nameFile: contiene il nome del file di testo da cui viene creato un primo dizionario con definizioni assenti, ad esempio Text.txt
Output:
-l'indirizzo alla struttura dati contenente il "dizionario" ordinato.
Gestione errori: si ritorni in caso di un qualsiasi tipo di errore NULL. specificare nella relazione
gli errori che si possono verificare*/
NODO* createFromFile(char* nameFile);

//stampa tutto l'albero per debug

/*
Input:
-dictionary: la struttura dati in cui avete memorizzato il dizionario
La funzione deve stampare le parole del dizionario una per riga con a fianco la propria definizione, se presente,
ESATTAMENTE in questo modo:

"tavolo" : [Mobile formato da un piano di legno o di altro materiale, sostenuto da quattro gambe]
"tazza" : [(null)]
"tovaglia" : [Pezzo di tessuto o di altro materiale che si stende sulla tavola per apparecchiare la mensa]

*/
void printDictionary(NODO*  dictionary);


/*
Input:
-dictionary: la struttura dati in cui avete memorizzato il dizionario
Output:
-il numero di parole salvato nel dizionario
*/
int countWord(NODO* dictionary);



/*
Input:
-dictionary: la struttura dati in cui avete memorizzato il dizionario
-word: la parola da inserire nel dizionario , senza la definizione
Output:
-0 in caso di assenza di errori
-1 in caso di presenza di errori
*/
int insertWord(NODO** dictionary, char* word);


/*
Input:
-dictionary: la struttura dati in cui avete memorizzato il dizionario
-word: la parola da cancellare nel dizionario
Output:
-0 in caso di assenza di errori
-1 in caso di presenza di errori
*/
int cancWord(NODO** dictionary, char* word);



/*
Input:
-dictionary: la struttura dati in cui avete memorizzato il dizionario
-index: indice che indica la iesima parola ( secondo l'ordine del dizionario)
Output:
-la word che si trova nel dizionario all'i-esimo posto secondo l'ordine di salvataggio
-NULL in caso di errori o di parola non presente
*/
char* getWordAt(NODO* dictionary, int index);


/*
Input:
-dictionary: la struttura dati in cui avete memorizzato il dizionario
-word: la parola per cui si deve inserire la definizione
-def: la definizione da inserire nel dizionario
Output:
-0 in caso di assenza di errori
-1 in caso di presenza di errori, ad esempio se la word non esiste nel dizionario
la funzione non produrrà alcun effetto
nel caso in cui una definizione sia già presente, questa deve essere totalmente sovrascritta
*/
int insertDef(NODO* dictionary, char* word, char* def);


/*
Input:
-dictionary: la struttura dati in cui avete memorizzato il dizionario
-word: la parola per cui si deve cercare la definizione
Output:
-la definizione nel caso essa sia presente, altrimenti NULL
*/
char* searchDef(NODO* dictionary, char* word);


/*
Input:
-dictionary: la struttura dati in cui avete memorizzato il dizionario
-fileOutput: il nome del file in cui si vuole salvare il dizionario
Output:
-(-1) in caso di errori
- 0 altrimenti
*/
int saveDictionary(NODO* dictionary, char* fileOutput);


/*
Input:
-fileInput: il nome del file contenente il dizionario [stesso formato usato nel salvataggio e nella stampa]
Output:
-il dictionary letto dal file
*/
NODO* importDictionary(char *fileInput);


/*
Input:
-dictionary: la struttura dati in cui avete memorizzato il dizionario
-word: la parola per cui si vuole cercare la presenza
-first,second,third: in queste tre variabili occorre memorizzare
le tre voci più simili/vicine alla word da cercare.
Output:
-0 in caso di assenza del termine nel dizionario
-1 in caso di presenza del termine nel dizionario
-(-1) in caso di altri errori
*/
int searchAdvance(NODO* dictionary, char* word, char** first, char** second, char** third);



/*
Input:
-dictionary: la struttura dati in cui avete memorizzato il dizionario
-fileOutput: il nome del file in cui si vuole salvare il risultato della compressione
Output:
-0 in caso si successo
-(-1) in caso di presenza di errori
*/
int compressHuffman(NODO* dictionary, char* fileOutput);


/*
Input:
-fileInput: il nome del file contenente i dati compressi
-dictionary : la struttura dati in cui deve essere memorizzato il dizionario
Output:
-0 in caso si successo
-(-1) in caso di presenza di errori
*/
int decompressHuffman(char *fileInput, NODO** dictionary);

