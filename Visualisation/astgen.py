from pycparser import c_parser, c_ast

# C code to parse
c_code = """
typedef struct Node {
    char *value;
    char *type;
    struct Node *child;
    struct Node *sibling;
} Node;
Node* newNode(char *value, char *type) {
    Node *node = (Node*)malloc(sizeof(Node));
    node->value = strdup(value);
    node->type = strdup(type);
    node->child = NULL;
    node->sibling = NULL;
    return node;
}
void addChild(Node *parent, Node *child) {
    if (parent->child == NULL) {
        parent->child = child;
    } else {
        Node *temp = parent->child;
        while (temp->sibling != NULL) {
            temp = temp->sibling;
        }
        temp->sibling = child;
    }
}
int performSemanticAnalysis(Node *root) {
    Node *node = root->child;

    while (node != NULL) {
        if (strcmp(node->type, "input_url") == 0) {
            char *url = node->value;
            if (strstr(url, "http://") == url || strstr(url, "https://") == url) {
                url += 7; 
            }
            char *domain = strchr(url, '/') + 2;
            if (domain == NULL) {
                return 1;
            }
            char *domainEnd = strchr(domain, '/');
            if (domainEnd == NULL) {
                domainEnd = strchr(domain, '\\0');
            }
            char domainName[256];
            strncpy(domainName, domain, domainEnd - domain);
            domainName[domainEnd - domain] = '\\0';

            if (strstr(domainName, "phish") != NULL || strstr(domainName, "malware") != NULL ||
                strstr(domainName, "attack") != NULL || strstr(domainName, "exploit") != NULL) {
                return 1;
            }
            char *dot = strrchr(url, '.');
            if (dot != NULL) {
                *dot = '\\0';
                char *domainName = dot + 1;
                *dot = '.';

                
                char *countryCode = strrchr(url, '.');
                if (countryCode != NULL) {
                    countryCode++; 

                    const char *country_domains[] = {
                        "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "an", "ao", "aq", "ar", "as", "at", "au", "aw", "ax", "az",
                        "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bl", "bm", "bn", "bo", "bq", "br", "bs", "bt", "bv", "bw", "by", "bz", "ca", "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "cr", "cu", "cv", "cw", "cx", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz",
                        "ec", "ee", "eg", "eh", "er", "es", "et", "eu",
                        "fi", "fj", "fk", "fm", "fo", "fr",  "ga", "gb", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw", "gy",
                        "hk", "hm", "hn", "hr", "ht", "hu", "id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it",
                        "je", "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky", "kz",
                        "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly",
                        "ma", "mc", "md", "me", "mf", "mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na", "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz",
                        "om", "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py",
                        "qa", "re", "ro", "rs", "ru", "rw",  "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sj", "sk", "sl", "sm", "sn", "so", "sr", "ss", "st", "sv", "sx", "sy", "sz", "tc", "td", "tf", "tg", "th", "tj", "tk", "tl", "tm", "tn", "to", "tr", "tt", "tv", "tw", "tz", "ua", "ug", "uk", "us", "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws", "xk", "ye", "yt", "za", "zm", "zw",
                        NULL 
                    };
                    int i;
                    for (i = 0; country_domains[i] != NULL; ++i) {
                        if (strcmp(country_domains[i], countryCode) == 0) {
                            break;
                        }
                    }
                    if (country_domains[i] == NULL) {
                    }
                }

            }
        }
        node = node->sibling;
    }

    node = root->child;
    while (node != NULL) {
        if (strcmp(node->type, "input_url") == 0) {
            char *url = node->value;
            if (strstr(url, "http://") == url || strstr(url, "https://") == url) {
                url += 7;
            }
            char *domain = strchr(url, '/') + 2;
            if (domain == NULL) {
                return 1;
            }
            char *domainEnd = strchr(domain, '/');
            if (domainEnd == NULL) {
                domainEnd = strchr(domain, '\\0');
            }
            char domainName[256];
            strncpy(domainName, domain, domainEnd - domain);
            domainName[domainEnd - domain] = '\\0';

            int dots = 0;
            for (char *c = domainName; *c != '\\0'; ++c) {
                if (*c == '.') {
                    ++dots;
                }
            }
            if (dots == 3) {
                return 1;
            }

            int spchrs = 0;
            for (char *c = node->value; *c != '\\0'; ++c) {
                if (*c == '.' || *c == '-' || *c == '_' || *c == ':' || *c == '?' || *c == '%' || *c == '$' || *c == '!') {
                    ++spchrs;
                }
            }
            if (spchrs >= 7) {
                return 1;
            }
        }
        node = node->sibling;
    }

    node = root->child;
    while (node != NULL) {
        if (strcmp(node->type, "input_url") == 0) {
            const char *malicious_urls[] = {
                    "000owamail0.000webhostapp.com",
                    "0q2.sitey.me",
                    NULL 
                };

            for (int i = 0; malicious_urls[i] != NULL; ++i) {
                if (strstr(node->value, malicious_urls[i]) != NULL) {
                    return 1;
                }
            }
        }
        node = node->sibling;
    }

    node = root->child;
    while (node != NULL) {
        if (strcmp(node->type, "input_url") == 0) {
            if (strstr(node->value, "bit.ly") != NULL || strstr(node->value, "goo.gl") != NULL ||
                strstr(node->value, "tinyurl.com") != NULL || strstr(node->value, "t.co") != NULL || strstr(node->value, "shorturl.at") != NULL) {
                return 1;
            }
        }
        node = node->sibling;
    }

    node = root->child;
    while (node != NULL) {
        if (strcmp(node->type, "input_url") == 0) {
            if (strstr(node->value, ":8080") != NULL || strstr(node->value, ":4444") != NULL ||
                strstr(node->value, ":12345") != NULL) {
                return 1;
            }
        }
        node = node->sibling;
    }

    return 0;
}

void generateParseTreeAndAnalyze() {
    Node *root = newNode("Root", "program");

    char url[1000]; 
    fgets(url, sizeof(url), stdin);

    if (url[strlen(url) - 1] == '\\n') {
        url[strlen(url) - 1] = '\\0';
    }

    Node *urlNode = newNode(url, "input_url");
    addChild(root, urlNode);
    url_regex;
    int reti = regcomp(&url_regex, "^https?://[a-zA-Z0-9.-]+(/.*)?$", REG_EXTENDED);
    if (reti) {
        fprintf(stderr, "Could not compile regex\\n");
        return;
    }
    reti = regexec(&url_regex, url, 0, NULL, 0);
    if (reti) {
        Node *invalidUrlNode = newNode("Invalid URL format", "error");
        addChild(root, invalidUrlNode);
        return;
    }

    performSemanticAnalysis(root);
}

int main() {
    generateParseTreeAndAnalyze();
    return 0;
}
"""

# Parse the C code
parser = c_parser.CParser()
ast = parser.parse(c_code)

# Open a file for writing
with open("ast_output.txt", "w") as f:
    # Print the AST to the file
    ast.show(buf=f)

print("AST has been written to 'ast_output.txt'")
