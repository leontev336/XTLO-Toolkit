import pandas as pd

print("""XTLO repacker v0.1 
by leontev336

Make sure your .loc files are in the same folder as the script.
""")

loc_file_name = str(input("Put the name of your .loc file without the .loc extension here: "))

updated_csv = loc_file_name + "_source.csv"
df_source = pd.read_csv(updated_csv, keep_default_na=False, on_bad_lines='error', sep=";")

df_new = df_source.sort_values(by=["Plaintext_address"])

df_new["New_plaintext_addresses"] = int()
diffr = 0
for element in range(len(df_new["Edit_here"])):
    if df_new["Edit_here"].iloc[element] != "":
        diffr += len(df_new["Edit_here"].iloc[element].encode("utf-16-be")) - len(df_new["Plaintext"].iloc[element].encode("utf-16-be"))
        print("something here, at:", element,"| Original:", df_new["Plaintext"].iloc[element],"| What changed:",  df_new["Edit_here"].iloc[element], diffr)
        for changes in range(element + 1, len(df_new["Edit_here"])):
            df_new.loc[df_new.index[changes], "New_plaintext_addresses"] = df_new["Plaintext_address"].iloc[changes] + diffr

for f in range(len(df_new["New_plaintext_addresses"])):
    if df_new["New_plaintext_addresses"].iloc[f] == 0:
        df_new.loc[df_new.index[f], "New_plaintext_addresses"] = df_new["Plaintext_address"].iloc[f]

with (open(loc_file_name + ".loc",'rb') as loc_file):
    file_loc = loc_file.read()

table1start = 52
record_size = int((file_loc[56:60].hex()), 16)
table2start = int((file_loc[44:48].hex()), 16)
number_of_ids = int((file_loc[52:56].hex()), 16)

full_header = file_loc[0:table1start]
table1 = file_loc[table1start:(table1start + record_size) + (number_of_ids * record_size)]
IDS_block = file_loc[(table1start + record_size) + (number_of_ids * record_size):table2start]
table2 = file_loc[table2start:(table2start + record_size) + (number_of_ids * record_size)]
plaintext_block = file_loc[(table2start + record_size) + (number_of_ids * record_size):]

orig_plaintext = plaintext_block.split(b"\x00\x00")

for x in range(len(df_new["Edit_here"])):
    if df_new["Edit_here"].iloc[x] == "":
        df_new.loc[df_new.index[x], "Edit_here"] = orig_plaintext[x].decode("utf-16-be")

table2_chunks = []
table2_hashes = []
table2_addresses = []
new_addresses = [0]
new_table2 = []

for a in range(len(df_new["New_plaintext_addresses"])):
    new_addresses.append(int(df_new["New_plaintext_addresses"].iloc[a]) - table2start)

for j in range(0, len(table2), record_size):
    table2_chunks.append(table2[j:j + record_size])
for l in table2_chunks:
    table2_hashes.append(l[0:4].hex())
    table2_addresses_decimal = int((l[4:].hex()), 16)
    table2_addresses.append(table2_addresses_decimal)

new_table2.append(table2_chunks[0])

for k in range(1, len(table2_hashes)):
    hash_chunk = table2_chunks[k]
    new_table2.append(hash_chunk[0:4])
    new_table2.append(new_addresses[k].to_bytes(4, byteorder="big"))

new_table2 = b"".join(new_table2)

new_plaintext = []
separ = b"\x00\x00"
for p in range(len(df_new["Edit_here"])):
    new_plaintext.append((df_new["Edit_here"].iloc[p]).encode("utf-16-be"))
    new_plaintext_file = separ.join(new_plaintext)

new_header_part1 = file_loc[0:48]
new_header_part2 = (int((file_loc[48:52].hex()), 16) + diffr).to_bytes(4, byteorder="big")
new_header = new_header_part1 + new_header_part2

with (open(f"{loc_file_name}_new.loc", "wb")) as new_plaintext:
    full_xtlo2 = new_header + table1 + IDS_block + new_table2 + new_plaintext_file + b"\x00\x00"
    new_plaintext.write(full_xtlo2)
print(f"Success! New file created: {loc_file_name}_new.loc")