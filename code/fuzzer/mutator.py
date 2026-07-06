import random
import utils
import os

#######
#
# ParamMutators
#
########


class ParamMutator():
    def mutate(self, string):
        pass


class EquallyRandomCharParamMutator(ParamMutator):
    def mutate(self, string):
        # all characers are equally likely to appear
        if len(string) == 0:
            index = 0
        else:
            index = random.randint(0, len(string))
        char = chr(random.randint(32, 126))
        return f'{string[:index]}{char}{string[index + 1:]}'


class FiftyFiftyCharParamMutator(ParamMutator):
    def mutate(self, string):
        # digits are 50% more likely to appear than letters
        number_probability = 0.50
        if len(string) == 0:
            index = 0
        else:
            index = random.randint(0, len(string))

        if random.random() < number_probability:
            char = str(random.randint(0, 9))
        else:
            char = chr(random.randint(32, 126))

        return f'{string[:index]}{char}{string[index + 1:]}'


class NumberParamMutator(ParamMutator):
    def mutate(self, string):
        # digits are 95% more likely to appear than letters if the string denotes a number
        number_probability = 0.95
        if not utils.string_is_number(string):
            return None

        if len(string) == 0:
            index = 0
        else:
            index = random.randint(0, len(string))

        if random.random() < number_probability:
            char = str(random.randint(0, 9))
        else:
            char = chr(random.randint(32, 126))
    
        return f'{string[:index]}{char}{string[index + 1:]}'


class StringParamMutator(ParamMutator):
    def mutate(self, string):
        # letters are 95% more likely to appear than digits if the string does not denote a number
        number_probability = 0.95
        if utils.string_is_number(string):
            return None

        if len(string) == 0:
            index = 0
        else:
            index = random.randint(0, len(string))

        if random.random() < number_probability:
            char = chr(random.randint(48, 57))
        else:
            char = chr(random.randint(32, 126))
        return f'{string[:index]}{char}{string[index + 1:]}'


class DigitExtensionParamMutator(ParamMutator):
    def mutate(self, string):
        # extends or reduces the string with a random digit in a random position
        if len(string) == 0:
            index = 0
        else:
            index = random.randint(0, len(string))
        
        if random.random() <= 0.5:
            char = chr(random.randint(0, 9))
            return f"{string[:index]}{char}{string[index:]}"
        else:
            index = index -1 if index > 0 else 0
            return string[:index] + string[index + 1:]


class CharExtensionParamMutator(ParamMutator):
    def mutate(self, string):
        # extends or reduces the string with a random character in a random position
        if len(string) == 0:
            index = 0
        else:
            index = random.randint(0, len(string))

        if random.random() <= 0.5:
            char = chr(random.randint(32, 126))
            return f"{string[:index]}{char}{string[index:]}"
        else:
            index = index -1 if index > 0 else 0
            return string[:index] + string[index + 1:]


class SwapCharParamMutator(ParamMutator):
    def mutate(self, string):
        index = random.randint(0, len(string))
        return f'{string[:index]}{string[index + 1:]}'


class XSSPayloadParamMutator(ParamMutator):
    def mutate(self, string):
        rand1 = random.random()
        rand2 = random.random()
        rand3 = random.random()
        if rand1 < 0.05:
            # returns a XSS payload for debugging purposes
            payload = "<script>alert(0xdeadbeef)</script>"
        elif rand2 < 0.05:
            payload = "<img src='x' onerror='alert(0xdeadbeef)'>"
        elif rand3 < 0.05:
            payload = "<a href='javascript:alert(0xdeadbeef)'"
        else:
            return None

        index = random.randint(0, len(string))
        return string[:index] + payload + string[index:]

class PathTraversalPayloadParamMutator(ParamMutator):
    def mutate(self, string):
        if random.random() < 0.05:
            payload = "/etc/passwd"
        elif random.random() < 0.05:
            payload = "../"
        else:
            return None

        index = random.randint(0, len(string))
        return string[:index] + payload + string[index:]

class ChangeCharParamMutator(ParamMutator):
    def mutate(self, string):
        if not string:
            return None
        chars = list(string)
        i = random.randint(0,len(chars)-1)
        chars[i] = chr((ord(chars[i]) + random.randint(0, 2**7)) % (2**7))
        return ''.join(chars)

class IterateCharParamMutator(ParamMutator):
    def mutate(self, string):
        if not string:
            return None
        chars = list(string)
        i = random.choices(range(len(chars)))[0]         
        chars[i] = chr((ord(chars[i]) + 1) % (2**7-1))
        return ''.join(chars)

class AddCharParamMutator(ParamMutator):
    def mutate(self, string):
        return string + "\x00"

class ProtocolPrefixMutator(ParamMutator):
    protocols = ['http://', 'https://', 'ftp://']

    def mutate(self, string):
        for p in ProtocolPrefixMutator.protocols:
            if string.startswith(p):
                return None
        p = random.choice(ProtocolPrefixMutator.protocols)
        return f"{p}{string}"


class SuperRandomMutator(ParamMutator):
    def mutate(self, string):
        mutation_type = random.choice(["flip", "extend", "delete"])

        if mutation_type == "flip" and len(string) > 0:
            index = random.randint(0, len(string) - 1)
            flipped_char = chr(((ord(string[index]) - 32) % 94) + 32)
            mutated_string = string[:index] + flipped_char + string[index + 1:]
        elif mutation_type == "extend":
            extension_length = random.randint(1, 3)
            random_chars = "".join(
                chr(random.randint(32, 126)) for _ in range(extension_length)
            )
            index = random.randint(0, len(string))
            mutated_string = string[:index] + random_chars + string[index:]
        elif mutation_type == "delete" and len(string) > 0:
            delete_length = random.randint(1, min(1, len(string)))

            index = random.randint(0, len(string) - delete_length)
            mutated_string = string[:index] + string[index + delete_length:]
        else:
            mutated_string = string

        return mutated_string
    
class BlindSQLiPayloadParamMutator(ParamMutator):
    SCHEMA = {
        "tables": {
            "normal": ["users"],
            "sensors": ["__phuzz_sensor_insert", "__phuzz_sensor_update", "__phuzz_sensor_delete"]
        },
        "columns": {
            "users": ["id", "username", "password", "role"],
            "__phuzz_sensor_insert": ["id", "marker"],
            "__phuzz_sensor_update": ["id", "canary"],
            "__phuzz_sensor_delete": ["id", "marker"]
        }
    }

    def generate_random_dml(self):
        """Sinh ngẫu nhiên các câu lệnh INSERT, UPDATE, hoặc DELETE hợp lệ dựa trên SCHEMA rút gọn"""
        action = random.choice(["INSERT", "UPDATE", "DELETE"])
        target_table = random.choice(self.SCHEMA["tables"]["normal"] + self.SCHEMA["tables"]["sensors"])
        available_cols = self.SCHEMA["columns"][target_table]
        
        # Không thực hiện DELETE trên các bảng cảm biến để bảo toàn trạng thái
        if target_table in self.SCHEMA["tables"]["sensors"] and action == "DELETE":
            action = random.choice(["INSERT", "UPDATE"])
        
        if action == "INSERT":
            cols_to_insert = [c for c in available_cols if c != "id"]
            values = [f"'fuzz_{random.randint(1, 999)}'" for _ in cols_to_insert]
            return f"INSERT INTO {target_table} ({', '.join(cols_to_insert)}) VALUES ({', '.join(values)})"
            
        elif action == "UPDATE":
            cols_to_update = [c for c in available_cols if c != "id"]
            if not cols_to_update:
                return f"UPDATE {target_table} SET id = {random.randint(1000, 999999)}"
            target_col = random.choice(cols_to_update)
            new_val = f"'fuzz_up_{random.randint(1, 999)}'"
            return f"UPDATE {target_table} SET {target_col} = {new_val} WHERE id = 1"
            
        elif action == "DELETE":
            return f"DELETE FROM {target_table} WHERE id = {random.randint(1, 10)}"

    def mutate(self, string):
        """
        Thực hiện đột biến chuỗi mồi (Seed) thành duy nhất kịch bản ghi/xóa DML (INSERT, UPDATE, DELETE)
        để kiểm thử trạng thái side-effect của database.
        """
        if not string:
            string = "admin"
        string_str = str(string).strip()
        
        # Bóc tách phần tiền tố gốc trước nháy đơn hoặc chấm phẩy
        prefix = string_str.split(';')[0].split("'")[0].strip()
        if not prefix:
            prefix = "admin"

        return f"{prefix}'; {self.generate_random_dml()}; -- '"


#######
#
# Mutators
#
########


class Mutator():
    def __init__(self):
        self.param_mutators = []

    def mutate(self, string):
        output = set()
        for mutator in self.param_mutators:
            new_str = mutator.mutate(string)
            if new_str is not None:
                output.add(new_str)
        return list(output)


class DefaultMutator(Mutator):
    def __init__(self):
        super(Mutator, self).__init__()
        self.param_mutators = [
            IterateCharParamMutator(),
            AddCharParamMutator(),
            EquallyRandomCharParamMutator(),
            FiftyFiftyCharParamMutator(),
            NumberParamMutator(),
            StringParamMutator(),
            DigitExtensionParamMutator(),
            CharExtensionParamMutator(),
            SwapCharParamMutator(),
            XSSPayloadParamMutator(),
            PathTraversalPayloadParamMutator(),
            #ProtocolPrefixMutator(),
            BlindSQLiPayloadParamMutator()

        ]

class SingleMutator(Mutator):
    def __init__(self):
        super(Mutator, self).__init__()
        self.param_mutators = [
            IterateCharParamMutator(),
            AddCharParamMutator(),
            EquallyRandomCharParamMutator(),
            FiftyFiftyCharParamMutator(),
            NumberParamMutator(),
            StringParamMutator(),
            DigitExtensionParamMutator(),
            CharExtensionParamMutator(),
            SwapCharParamMutator(),
            XSSPayloadParamMutator(),
            PathTraversalPayloadParamMutator(),
            #ProtocolPrefixMutator(),
            SuperRandomMutator(),
            BlindSQLiPayloadParamMutator()
        ]

        self.iterator = self.mutation_iterator()

    def mutation_iterator(self):
        random.shuffle(self.param_mutators)
        for pm in self.param_mutators:
            yield pm

    def mutate(self, string):
        new_str = None
        while new_str is None:
            try:
                mutator = next(self.iterator)
                new_str = mutator.mutate(string)
            except StopIteration:
                self.iterator = self.mutation_iterator()
                continue
        return new_str

class EmptyQueueMutator(Mutator):
    def __init__(self):
        super(Mutator, self).__init__()
        self.param_mutators = [
            AddCharParamMutator(),
        ]
