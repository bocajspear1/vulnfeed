# This parses the rule language

from util.normalizer import Normalizer

BINARY_OPERATORS = ("AND", "OR", "ANDOR")
UNARY_OPERATORS = ("NOT")


class VulnFeedRuleParser():

    def __init__(self):
        self.tree = None
        self.depth = 0

    def _parse_phrase(self, phrase):
        phrase_split = phrase.split(" ")

        left = None
        right = None
        op = None

        i = 0

        init_weight = 1
        while i < len(phrase_split):
            token = phrase_split[i]
            
            if "(" in token:
                paren_find = " ".join(phrase_split[i:])
                paren_start = paren_find.find("(")
                paren_end = paren_find.rfind(")")
                if paren_start == -1 or paren_end == -1:
                    raise ValueError("Could not find closing parenthesis in phrase '" + paren_find + "'")
                self.depth += 1
                substring = paren_find[paren_start+1:paren_end]
                paren_result = self._parse_phrase(substring)
                self.depth -= 1
                if left is None:
                    left = paren_result
                elif right is None:
                    right = paren_result
                
                space_count = len(substring.split(" "))
                i += space_count-1

            else:
                
                if token in BINARY_OPERATORS and left is None:
                    raise ValueError("Invalid token at position " + str(i) + " in phrase " + phrase)

                if token == "NOT":
                    if i+1 > len(phrase_split)-1:
                        raise ValueError("Incomplete NOT at position " + str(i) + " in phrase " + phrase)
                    else:
                        init_weight = -1
                elif token in BINARY_OPERATORS:
                    print(("  " * self.depth) + "- Setting op to " + token)
                    op = token
                else:
                    print(("  " * self.depth) + "s String " + token)
                    if ":" in token:
                        token_split = token.split(":")
                        token_string = token_split[0]
                        if init_weight != -1:
                            init_weight = int(token_split[1])
                    else:
                        token_string = token
                    if left is None:
                        left = {"string": token_string, "weight": init_weight}
                    elif right is None:
                        right = {"string": token_string, "weight": init_weight}
                    init_weight = 1

            i+=1
            if not left is None and not right is None:
                if op is None:
                    raise ValueError("Unexpected token(" + str(right) + ") at position " + str(i) + " in phrase '" + phrase + "'")
                else:
                    left = (op, left, right)
                    right = None
                    op = None

        if not left is None and not op is None and right is None:
            raise ValueError("Incomplete statement at position the end of phrase '" + phrase + "'")

        return left

    def parse_rule(self, rule_string):
        self.tree = self._parse_phrase(rule_string)


    def process_text(self, text, text_freq):
        return self._process_tree(text, text_freq, self.tree)

    def process_raw_text(self, text):
        n = Normalizer()
        text_freq = n.get_word_frequency(n.normalize_text(text))
        return self.process_text(text, text_freq)

    def _process_item(self, item, text, text_freq):
        if isinstance(item, tuple):
            self.depth += 1
            result, result_strings = self._process_tree(text, text_freq, item)
            self.depth -= 1
            return result, result_strings
        else:
            # print(item)
            print(("  " * self.depth) + "Checking " + item['string'] + "...")
            # print(text_freq)
            if item['string'] in text_freq:
                print(("  " * self.depth) + item['string'] + " found")
                if item['weight'] >= 0:
                    return (text_freq[item['string']] * item['weight']), [item['string']]
                else: 
                    return 0, [item['string']]
            elif item['weight'] == -1:
                return 1, [item['string']]

            return 0, []

    def _process_tree(self, text, text_freq, tree):
        if not isinstance(self.tree, tuple):
            (single, single_strings) = self._process_item(self.tree, text, text_freq)
            return single, single_strings

        op = tree[0]
        
        if op in BINARY_OPERATORS:
            left,left_strings = self._process_item(tree[1], text, text_freq)
            right,right_strings = self._process_item(tree[2], text, text_freq)
            # print(left, left_strings, right, right_strings)
            if op == "AND":
                multi = 1
                return_strings = left_strings + right_strings
                for left_item in left_strings:
                    for right_item in right_strings:
                        full_string = left_item + " " + right_item
                        print(("  " * self.depth) + " Trying " + full_string)
                        if full_string in text:
                            multi += 2
                            return_strings.append(left_item + " " + right_item)

                if left > 0 and right > 0:
                    return (left + right) * multi, return_strings
                else:
                    return 0, []
            elif op == "OR":
                if left > 0 and right > 0:
                    return left + right, left_strings + right_strings
                elif left > 0:
                    return left, left_strings
                elif right > 0:
                    return right, right_strings
                else:
                    return 0, []
            elif op == "ANDOR":
                multi = 1
                return_strings = left_strings + right_strings
                for left_item in left_strings:
                    for right_item in right_strings:
                        full_string = left_item + " " + right_item
                        print(("  " * self.depth) + " Trying " + full_string)
                        if full_string in text:
                            multi += 2
                            return_strings.append(left_item + " " + right_item)

                if left > 0 and right > 0:
                    return (left + right) * multi, return_strings
                elif left > 0:
                    return left, left_strings
                elif right > 0:
                    return right, right_strings
                else:
                    return 0, []
            