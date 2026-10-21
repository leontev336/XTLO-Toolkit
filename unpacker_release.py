import re
import os
from tqdm import tqdm
import pandas as pd

print("""XTLO unpacker v0.1 
by leontev336

Make sure your .loc files are in the same folder as the script.
""")

filename = str(input("Put the name, not the file path, of your .loc file here: "))

with (open(filename,'rb') as f):
    file = f.read()

#header inspection
table1start = 52
record_size = int((file[56:60].hex()), 16)
table2start = int((file[44:48].hex()), 16)
number_of_ids = int((file[52:56].hex()), 16)

#reading table 1
table1 = file[(table1start + record_size):(table1start + record_size) + (number_of_ids * record_size)]
table1_chunks = []
table1_hashes = []
table1_addresses = []
for j in range(0, len(table1), record_size):
    table1_chunks.append(table1[j:j + record_size])
for l in table1_chunks:
    table1_hashes.append(l[0:4].hex())
    table1_addresses_decimal = int((l[4:].hex()), 16) + (table1start + record_size) - record_size
    table1_addresses.append(table1_addresses_decimal)
table2 = file[(table2start + record_size):(table2start + record_size) + (number_of_ids * record_size)]
table2_chunks = []
table2_hashes = []
table2_addresses = []

#reading table 2
for j in range(0, len(table2), record_size):
    table2_chunks.append(table2[j:j + record_size])
for l in table2_chunks:
    table2_hashes.append(l[0:4].hex())
    table2_addresses_decimal = int((l[4:].hex()), 16) + table2start
    table2_addresses.append(table2_addresses_decimal)

#regular expressions to match strings and extract them
id_pattern = re.compile(rb"(\w{5,})(?=\x00)", re.DOTALL)
plaintext_pattern = re.compile(rb"(?:(?!\x00\x00)..)*", re.DOTALL)

complete_dict = dict()
df_to_csv_data = pd.DataFrame(columns=["hash", "IDS_address", "IDS_string", "Plaintext_address", "Plaintext"])

progress_bar =  tqdm(total=len(table1_hashes))

#checking that hashes exist in both tables, building a complete row, then appending everything into a pandas table
for h_element in table1_hashes:
    if h_element in table2_hashes and h_element in table1_hashes:
        table1_hash_address = table1_addresses[table1_hashes.index(h_element)]
        table2_hash_address = table2_addresses[table2_hashes.index(h_element)]
        ids_searchable_area = file[table1_hash_address:]
        all_ids = re.search(id_pattern, ids_searchable_area)
        if all_ids:
            ids_text = all_ids.group(1).decode('utf-8')
        else:
            ids_text = "error/not found"

        plaintext_searchable_area = file[table2_hash_address:]
        all_plaintext = re.search(plaintext_pattern, plaintext_searchable_area)
        if all_plaintext:
            plains_text = all_plaintext.group(0).decode('utf-16-be')
        else:
            plains_text = "error/not found"

        complete_dict = {"hash": h_element, "IDS_address":table1_hash_address, "IDS_string": ids_text, "Plaintext_address":table2_hash_address, "Plaintext": plains_text}
        df_to_csv_data.loc[table1_hashes.index(h_element)] = complete_dict

        progress_bar.update(1)

df_to_csv_data["Edit_here"] = ""
df_to_csv_data.to_csv(f"{filename[:-4]}_source.csv", index=False, sep=";")
print()
print(f"""Saved as: {filename[:-4]}_source.csv
Make sure you only edit the 'Edit_here' column of the new csv file and don't edit anything else!""")