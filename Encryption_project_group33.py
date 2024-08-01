import tkinter as tk
from tkinter import filedialog, messagebox
import os
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import struct
import base64
import hashlib

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
#functions needed to pad for encryption and to unpad for decryption, only when the length of the user input is not a multiple of 16


class EncryptionApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("CMPG215 Encryption Algorithm")
        self.window.geometry("500x400")
        self.window.resizable(False, False)

        #label
       
         

        # Encryption type section
        encryption_type_label = tk.Label(self.window, text="Encryption Type:")
        encryption_type_label.pack(pady=10)

       

        self.encryption_type_var = tk.StringVar(value="AES")
       
        aes_radiobutton = tk.Radiobutton(self.window, text="AES", variable=self.encryption_type_var, value="AES")
        aes_radiobutton.pack(side=tk.TOP)

        own_algorithm_radiobutton = tk.Radiobutton(self.window, text="Own Algorithm", variable=self.encryption_type_var,
                                                   value="Own Algorithm")
        own_algorithm_radiobutton.pack(side=tk.TOP)

        # File path section
        file_path_label = tk.Label(self.window, text="File Path:")
        file_path_label.pack(pady=10)

        file_path_frame = tk.Frame(self.window)
        file_path_frame.pack(pady=5)

        self.file_path_entry = tk.Entry(file_path_frame, width=50)
        self.file_path_entry.pack(side=tk.LEFT)

        browse_button = tk.Button(file_path_frame, text="Browse", command=self.browse_file)
        browse_button.pack(side=tk.LEFT, padx=5)

        # Key section
        key_frame = tk.Frame(self.window)
        key_frame.pack(pady=10)

        self.toggle_key_entry_var = tk.BooleanVar(value=False)
        toggle_key_entry_checkbutton = tk.Checkbutton(key_frame, text="Generate Key?", variable=self.toggle_key_entry_var, command=self.toggle_gen_type)
                                               
        toggle_key_entry_checkbutton.pack(side=tk.LEFT)

        self.security_level_var = tk.StringVar(value="Low")
        security_level_label = tk.Label(key_frame, text="Security Level:")
        security_level_label.pack(side=tk.LEFT, padx=10)

        self.security_level_menu = tk.OptionMenu(key_frame ,self.security_level_var, "Low", "Medium", "High")
        self.security_level_menu.config(state = tk.DISABLED)
        self.security_level_menu.pack(side=tk.LEFT)

        self.generate_key_button = tk.Button(key_frame, text = "Generate Key", command = self.toggle_key_entry)
        self.generate_key_button.config(state = tk.DISABLED)
        self.generate_key_button.pack(side = tk.LEFT)

        self.key_entry = tk.Entry(self.window, width=50, state=tk.NORMAL)
        self.key_entry.pack(pady=5)
        #self.key_entry.insert(0, str(key))

        # Encryption/Decryption buttons
        encryption_frame = tk.Frame(self.window)
        encryption_frame.pack(pady=10)

       
        encrypt_button = tk.Button(encryption_frame, text="Encrypt",command= self.decide_enc )

        encrypt_button.pack(side=tk.LEFT, padx=5)

        decrypt_button = tk.Button(encryption_frame, text="Decrypt", command=  self.decide_dec)
       
        decrypt_button.pack(side=tk.LEFT, padx=5)

    def run(self):
        self.window.mainloop()

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, file_path)

    def toggle_key_entry(self):

        key = get_random_bytes(16)
        
        
           
        security_level = self.security_level_var.get()
            
           
        if security_level == "Low":
            key = get_random_bytes(16)
        elif security_level == "Medium":
            key = get_random_bytes(24)
        elif security_level == "High":
             key = get_random_bytes(32)

        if  not (self.encryption_type_var.get() == "AES" ):

            if security_level == "Low":
                key = random.randrange(1,1000,1)
            elif security_level == "Medium":
                key = random.randrange(1001,1000000,1)
            elif security_level == "High":
                key = random.randrange(1000001,100000000,1)


               

           

        self.current_key = key
        self.key_entry.config(state = tk.NORMAL)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)
        self.key_entry.config(state=tk.DISABLED)
        

            
        

        
        return key

    def toggle_gen_type(self):
        if(self.toggle_key_entry_var.get()):
            self.key_entry.config(state = tk.DISABLED)
            self.security_level_menu.config(state = tk.NORMAL)
            self.generate_key_button.config(state = tk.NORMAL)

        else:
            self.key_entry.config(state = tk.NORMAL)
            self.key_entry.delete(0, tk.END)
            self.security_level_menu.config(state = tk.DISABLED)
            self.generate_key_button.config(state = tk.DISABLED)

    #Choose encryption method 
    def decide_enc(self):
        if (self.encryption_type_var.get() == "AES"):

            self.encrypt_file( self.file_path_entry.get())
            print("yes")

        else:
            self.own_encryption()
            print("yes")

        


    def decide_dec(self):
        if (self.encryption_type_var.get() == "AES"):
            self.decrypt_file()

        else:
            self.own_decryption()



    #Own encryption Algorithm

    

    def own_encryption(self):
        

        ASC = ''.join(chr(i) for i in range(128)) + '\xa0'

       
        asckey = list(ASC)
        random.shuffle(asckey)

        in_filename = self.file_path_entry.get()
        out_filename = in_filename + ".enc"

        if not in_filename:
            messagebox.showerror("Error", "Please select a file!")
            return

        if not (self.toggle_key_entry_var.get()):      
            if not self.key_entry.get():
                messagebox.showerror("Error", "Please enter a key!")
            elif self.key_entry.get().isnumeric() == False:
                return messagebox.showerror("Error", "Invalid key: Must be an integer for own algorithm")

        in_key = int(self.key_entry.get())

        try:
            with open(in_filename, 'r') as infile, open(out_filename, 'a') as outfile:

                for line in infile:
                    lineout = []
                    s = ""
                    for i in range(len(line)):
                        char = line[i]
                        index = ASC.index(char)
                        lineout.append(asckey[index])

                    s = ''.join(lineout) + "\n"

                    outfile.write(s)
                

                outkey = []
                for i in range(len(asckey)):
                    outkey.append(str(ord(asckey[i]) * in_key))

                s = ",".join(outkey)
            
                outfile.write(s)

            infile.close()
            os.remove(in_filename)
            messagebox.showinfo("Success", f"The file has been encrypted and saved to:\n{out_filename}")

        except ValueError:
            messagebox.showerror("Error", "OWN ALGORITHM IS FOR TEXT FILES ONLY! ")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")



        

           
    def own_decryption(self):
        print("yes")

        
        ASC = ''.join(chr(i) for i in range(128)) + '\xa0'#original ascii characters retrieved

        in_filename = self.file_path_entry.get()#get file 
        out_filename = in_filename.replace(".enc", "")#remove encrypted file extension, and place file back into txt.

        if not in_filename:
            messagebox.showerror("Error", "Please select a file!")
            return

        if not (self.toggle_key_entry_var.get()):      
            if not self.key_entry.get():#get key
                messagebox.showerror("Error", "Please enter a key!")
            elif not self.key_entry.get().isnumeric():#ensures key is an int
                return messagebox.showerror("Error", "Invalid key: Must be an integer for own algorithm")
            self.key_entry.config(state = tk.NORMAL)

            in_key = int(self.key_entry.get())#store key

            self.key_entry.config(state = tk.DISABLED)
            try:
                with open(in_filename, 'r') as infile, open(out_filename, 'a') as outfile:

                        for i in infile:
                            pass
                        last_line = i

                        with open(in_filename, "r") as f:
                            lines = f.readlines()

                        # Remove the last line
                            lines.pop()

                        with open(in_filename, "w") as f:
                            f.writelines(lines)


                        akey = last_line.strip().split(",")
                        asckey = []

                        for i in akey:
                            if i.isdigit():
                                a = int(i) // in_key
                                a = chr(a)
                                asckey.append(a)

                        infile.seek(0)  # rewind the file, by going to the first line
                        o = 0
                        for line in infile:
                            lineout = []#store the characters as arrays
                
                            for i in line:
                    
                                 index = asckey.index(i)
                                 lineout.append(ASC[index])

                
                            s = ''.join(lineout)
                            outfile.write((s))
                            print(s)
                            o += 1

            
                        print(o)
                        outfile.close()
           

                        with open(out_filename, "r") as f:
                            a = []
                            out = []
                            z = -1

                            for line in f:        
                                a = []
                                if z == -1:
                                    z = 0
                                    out.append(line)
                                    continue

                                for ch in line:
                                    a.append(ch)


                                a.reverse()
                                a.pop()
                                a.reverse()

                    


                                a = ''.join(a)

                                out.append(a)

                                z += 1

                            out.pop()

                            d = []

                            for ch in a:
                                d.append(ch)

                            d.pop(0)
                            a = ''.join(d)
                
                            out.append(a)

                            f.close()

            
                

                            with open(out_filename, "w") as f:
                                for i in range(len(out)):
                                    f.write(out[i])

                                f.write("\n"+"SUCCESS!!!!")
                        


                        f.close()


                        os.remove(in_filename)
                        messagebox.showinfo("Success", f"The file has been decrypted and saved to:\n{out_filename}")


            except ValueError:
                messagebox.showerror("Error", "OWN ALGORITHM IS FOR TEXT FILES ONLY! ")
            except Exception as e:
                messagebox.showerror("Complete ", f" Additional ASCII characters to plain text: {e}")


        




    def encrypt_file(self, file_path):
         # Get the input file path from the entry widget
        in_filename = self.file_path_entry.get()
        if not in_filename:
            messagebox.showerror("Error", "Please select a file!")
            return
          # Check the encryption type selected
        encryption_type = self.encryption_type_var.get()
        if encryption_type == "AES":
            password = self.key_entry.get() # Get the password from the entry widget
            if not password:
                messagebox.showerror("Error", "Please enter a password!")
                return

            out_filename = in_filename + ".enc"# Set the output file name
            chunksize = 64 * 1024
             # Generate a private key using SHA-256 hash of the password
            private_key = hashlib.sha256(password.encode("utf-8")).digest()
            # Generate a random initialization vector (IV)
            iv = get_random_bytes(AES.block_size)
            # Create an AES encryptor object
            encryptor = AES.new(private_key, AES.MODE_CBC, iv)
            filesize = os.path.getsize(in_filename)# Get the file size

            with open(in_filename, 'rb') as infile:
                with open(out_filename, 'wb') as outfile:
                    outfile.write(struct.pack('<Q', filesize))
                    outfile.write(iv)

                    while True:
                        chunk = infile.read(chunksize)# Read a chunk of the file
                        if len(chunk) == 0:
                            break
                        elif len(chunk) % 16 != 0:# Reached the end of the file
                            chunk += b' ' * (16 - len(chunk) % 16)
                            # Pad the chunk if its length is not a multiple of 16
                        outfile.write(encryptor.encrypt(chunk)) # Encrypt and write the chunk to the output file
            os.remove(in_filename)# Remove the original file
            messagebox.showinfo("Success", "Encryption complete!")
        else:
            messagebox.showinfo("Info", "Encryption using 'Own Algorithm' is not yet implemented.")

    def decrypt_file(self):
        in_filename = self.file_path_entry.get() # Get the input file path from the entry widget
        if not in_filename:
            messagebox.showerror("Error", "Please select a file!")
            return
        # Check the encryption type selected
        encryption_type = self.encryption_type_var.get()
        if encryption_type == "AES":
            # Get the password from the entry widget
            password = self.key_entry.get()
            if not password:
                messagebox.showerror("Error", "Please enter a password!")
                return
              # Set the output file name by removing the extension from the input file
            out_filename = os.path.splitext(in_filename)[0]
            chunksize = 24 * 1024

            private_key = hashlib.sha256(password.encode("utf-8")).digest() # Generate a private key using

            with open(in_filename, 'rb') as infile:
                origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
                iv = infile.read(16)
                decryptor = AES.new(private_key, AES.MODE_CBC, iv)    # Create an AES decryptor object

                with open(out_filename, 'wb') as outfile:
                    while True:
                        chunk = infile.read(chunksize)
                        if len(chunk) == 0:
                            break
                        outfile.write(decryptor.decrypt(chunk))#decrypt the differnt chunks that were encrypted after chunking took place

                    outfile.truncate(origsize)#retreive original file size
            os.remove(in_filename)
            messagebox.showinfo("Success", "Decryption complete!")
        else:
            messagebox.showinfo("Info", "Decryption using 'Own Algorithm' is not yet implemented.")


if __name__ == "__main__":
    app = EncryptionApp()
    app.run()
