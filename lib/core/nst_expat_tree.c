#include <stdio.h>
#include <expat.h>
#include <nst_expat_tree.h>

#define BUFFSIZE        8192

char Buff[BUFFSIZE];

void nst_expat_tree_elem_character (void * data, const XML_Char * s, int len);
void nst_expat_tree_elem_start (void *data, const char *el, const char **attr);
void nst_expat_tree_elem_end (void *data, const char *el);

void nst_expat_tree_free_attrs (nst_pool_t * pool, nst_expat_attr_t * attr);

void
nst_expat_tree_elem_character (void * data, const XML_Char * s, int len)
{
    volatile nst_expat_tree_t    * tree = (nst_expat_tree_t *)data;
    volatile nst_expat_node_t    * n;
    char                    * str;

    if (tree->current == NULL) return;
    n = tree->current;

    if (s[0] == '\n')
        return;
    if (n->end)
        return;

    if (n->vlen == 0 &&  s[0] == ' ') {
        /* Let's not add noice to the value */
        return;
    }

    if (n->value == NULL || (n->vlen + len) >= n->vsize) {
        char *  tstr;
        //int     l = n->vsize + NST_EXPAT_TREE_VALUE_SSIZE;
        int     l = n->vsize + len + NST_EXPAT_TREE_VALUE_SSIZE;
        tstr = nst_palloc (tree->pool, l+1);
        if (tstr == NULL)
            return;
        if (n->value) {
            strncpy (tstr, n->value, n->vlen);
            nst_pfree (tree->pool, n->value);
        }
        n->value = tstr;
        n->vsize = l;
    }

    str = n->value + n->vlen;
    strncpy (str, s, len);
    n->vlen += len;
    n->value[n->vlen] = '\0';
}

void
nst_expat_tree_elem_start (void *data, const char *el, const char **attr)
{
    volatile nst_expat_tree_t    * tree = (nst_expat_tree_t *)data;
    nst_expat_node_t             * node;
    nst_expat_node_t             * current;
    int                            i;
    nst_expat_attr_t             * a;

    tree->depth++;

    node = nst_pcalloc (tree->pool, sizeof(nst_expat_node_t));
    if (node == NULL) {
        return;
    }

    node->name = nst_pool_strdup (tree->pool, strlen(el), (char *)el);
    if (node->name == NULL)
        return;

    for (i = 0; attr[i]; i += 2) {
        a = nst_palloc (tree->pool, sizeof(nst_expat_attr_t));
        if (a == NULL) {
            nst_pfree (tree->pool, node->name);
            nst_pfree (tree->pool, node);
            return;
        }
        a->name = nst_pool_strdup (tree->pool, strlen(attr[i]),
                                   (char *)attr[i]);
        a->value = nst_pool_strdup (tree->pool, strlen(attr[i+1]),
                                    (char *)attr[i+1]);
        if (a->name == NULL || a->value == NULL) {
            nst_expat_tree_free_attrs (tree->pool, a);
            nst_pfree (tree->pool, node->name);
            nst_pfree (tree->pool, node);
            return;
        }
        a->next = node->attr;
        node->attr = a;
    }

    if (tree->root == NULL) {
        node->depth = tree->depth;
        tree->parent = node;
        tree->root =node;
        tree->current = node;
    }

    current = tree->current;
    if (current->depth == tree->depth && tree->root != node) {
        /* We are still at the same depth */
        current->next = node;
        node->prev = current;
    }
    else {
        current->children = node;
        tree->parent = current;
    }

    tree->current  = node;
    node->depth    = tree->depth;
    if (node != tree->root)
        node->parent = tree->parent;

    NST_ASSERT(tree->current != NULL);
}

void
nst_expat_tree_elem_end (void *data, const char *el)
{
    volatile nst_expat_tree_t    * tree = (nst_expat_tree_t *)data;
    nst_expat_node_t    * node;

    node = tree->current;

    if (node->value) {
        int i, len;
        len = strlen (node->value);
        for (i = len-1; i >= 0; i--) {
            if (node->value[i] == ' ') {
                node->value[i] = '\0';
            }
            else
                break;
        }
    }
    if (node->depth == tree->depth) {
        /* We are still at the same depth; */
        tree->current = node;
        tree->parent = node->parent;
    }
    else {
        /*char * s = (node->parent) ? node->parent->name : " ";
          printf ("node=%s, parent=%s\n", node->name, s);*/
        tree->current = node->parent;
        tree->parent = tree->current->parent;
    }
    tree->depth--;
    node->end = 1;

#if 0
    if (node->parent) {
        nst_expat_node_t    * parent;
        char                    * s;
        s = (node->prev) ? node->prev->name : " ";
        printf ("node: %s, prev: %s, parent: ",
                node->name, s);
        for (parent = node->parent; parent != NULL; parent = parent->parent) {
            printf ("%s, ", parent->name);
        }
        printf ("\n");
    }

    {
        int i;
        for (i = 0; i  < node->depth * 2; i++) {
            printf (" ");
        }
        printf ("%s ", node->name);
        if (node->value) printf ("%s", node->value);
        printf ("\n");
    }
#endif
}

void
nst_expat_tree_free_attrs (nst_pool_t * pool, nst_expat_attr_t * attr)
{
    nst_expat_attr_t   * next;

    while (attr != NULL) {
        next = attr->next;
        if (attr->name)
            nst_pfree (pool, attr->name);
        if (attr->value)
            nst_pfree (pool, attr->value);

        attr = next;
    }
}

void
nst_expat_tree_free_node (nst_pool_t * pool,
                                nst_expat_node_t * node)
{
    nst_expat_tree_free_attrs (pool, node->attr);

    if (node->name)
        nst_pfree (pool, node->name);
    if (node->value)
        nst_pfree (pool, node->value);
    nst_pfree (pool, node);
}

void
nst_expat_tree_free_tree (nst_expat_tree_t * tree,
                                nst_expat_node_t * root)
{
    nst_expat_node_t   * node, * next;

    if (root != NULL) {
        node = root;
        while (node != NULL) {
            next = node->next;
            if (node->children)
                nst_expat_tree_free_tree (tree, node->children);
            nst_expat_tree_free_node (tree->pool, node);
            node = next;
        }
    }
}

nst_expat_tree_t *
nst_expat_tree_cleanup (nst_expat_tree_t * tree)
{
    if (tree == NULL)
        return NULL;

    nst_expat_tree_free_tree (tree, tree->root);
    tree->root = NULL;

    if (tree->parser)
        XML_ParserFree(tree->parser);
    tree->parser = NULL;

    if (tree->fp)
        fclose (tree->fp);
    tree->fp = NULL;

    return NULL;
}

nst_expat_tree_t *
nst_expat_tree_from_file (nst_pool_t * pool, char * filename)
{
    nst_expat_tree_t         * tree;
    FILE                     * fp;
    XML_Parser                 p;

    tree = nst_pcalloc (pool, sizeof(nst_expat_tree_t));
    if (tree == NULL) return NULL;

    tree->pool = (void *)pool;
    p = XML_ParserCreate(NULL);
    if (p == NULL) {
        return NULL;
    }

    tree->parser = (void *)p;

    fp = fopen (filename, "r");
    if (fp == NULL) {
        return nst_expat_tree_cleanup (tree);
    }
    tree->fp = (void *)fp;

    XML_SetElementHandler(p, nst_expat_tree_elem_start,
                          nst_expat_tree_elem_end);
    XML_SetCharacterDataHandler(p, nst_expat_tree_elem_character);
    XML_SetUserData(p, (void*)tree);

    for (;;) {
        int done;
        int len;

        len = (int)fread(Buff, 1, BUFFSIZE, fp);
        if (ferror(stdin)) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR, "Read Error: %s", filename);
            fprintf(stderr, "Read error\n");
            return nst_expat_tree_cleanup (tree);
        }
        done = feof(fp);

        if (XML_Parse(p, Buff, len, done) == XML_STATUS_ERROR) {
            NST_NOC_LOG(NST_LOG_LEVEL_ERROR, "%s: Parse error at line %d  %s\n",
                        filename, (int)XML_GetCurrentLineNumber(p),
                        XML_ErrorString(XML_GetErrorCode(p)));
            fprintf(stderr, "Parse error at line %d  %s\n",
                    (int)XML_GetCurrentLineNumber(p),
                    XML_ErrorString(XML_GetErrorCode(p)));

            return nst_expat_tree_cleanup (tree);
        }

        if (done)
            break;
    }

    tree->parser = NULL;
    XML_ParserFree(p);
    tree->fp = NULL;
    fclose (fp);

    if (tree->root != NULL) {
        return tree;
    }

    nst_pfree (pool, tree);

    return NULL;
}
