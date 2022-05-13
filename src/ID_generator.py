class ID_generator:
    # an instance of this class can generate unique ids
    def __init__(self):
        self.char_index = 0
        self.chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVW!@#$%^&*()abcdefghijklmnopqrstuvwxyz"
        self.id = ""
    
    def generate_id(self):
        if self.char_index == 0:
            self.id.append(self.chars[self.chars_index])
            self.char_index += 1
        else:
            self.id[-1] = self.chars[self.chars_index]
            self.char_index = (1 + self.chars_index) % len(self.chars)
        return self.id